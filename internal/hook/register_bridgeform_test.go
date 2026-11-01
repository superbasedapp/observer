package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AP-119: the claude-code-windows bridge is written in a form that Git
// Bash (Claude Code's default hook shell on Windows) and PowerShell
// (Cortex Code, and Claude Code's "shell": "powershell" hooks) both run.
// These tests pin the writer, every reader of the command, and the
// migration off the legacy MSYS_NO_PATHCONV=1 form.

const (
	apBin    = "/home/u/superbased-observer/bin/observer"
	apCfg    = "/home/u/.observer/config.toml"
	apDistro = "Ubuntu-20.04"
)

func TestPortableBridgeCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                         string
		distro, bin, event, cfg, out string
	}{
		{
			name: "no config", distro: apDistro, bin: apBin, event: "pre-tool",
			out: "wsl.exe -d Ubuntu-20.04 -- //home/u/superbased-observer/bin/observer hook claude-code pre-tool; exit $LASTEXITCODE",
		},
		{
			name: "config", distro: apDistro, bin: apBin, event: "stop", cfg: apCfg,
			out: "wsl.exe -d Ubuntu-20.04 -- //home/u/superbased-observer/bin/observer hook claude-code stop --config '//home/u/.observer/config.toml'; exit $LASTEXITCODE",
		},
		{
			name: "binary path with a space is single-quoted", distro: apDistro, bin: "/home/u/my tools/observer", event: "stop",
			out: "wsl.exe -d Ubuntu-20.04 -- '//home/u/my tools/observer' hook claude-code stop; exit $LASTEXITCODE",
		},
		{
			name: "distro with a space is single-quoted", distro: "My Distro", bin: apBin, event: "stop",
			out: "wsl.exe -d 'My Distro' -- //home/u/superbased-observer/bin/observer hook claude-code stop; exit $LASTEXITCODE",
		},
		{
			name: "already-doubled path is not tripled", distro: apDistro, bin: "//home/u/observer", event: "stop",
			out: "wsl.exe -d Ubuntu-20.04 -- //home/u/observer hook claude-code stop; exit $LASTEXITCODE",
		},
		{
			name: "relative binary is left alone", distro: apDistro, bin: "observer", event: "stop",
			out: "wsl.exe -d Ubuntu-20.04 -- observer hook claude-code stop; exit $LASTEXITCODE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := portableBridgeCommand(tc.distro, tc.bin, "claude-code", tc.event, tc.cfg)
			if got != tc.out {
				t.Errorf("portableBridgeCommand = %q\n want %q", got, tc.out)
			}
			if strings.Contains(got, "MSYS_NO_PATHCONV") {
				t.Errorf("portable form carries the bash-only env prefix: %q", got)
			}
		})
	}
}

func TestMSYSLiteralPathRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, literal, back string }{
		{"/home/u/observer", "//home/u/observer", "/home/u/observer"},
		{"//home/u/observer", "//home/u/observer", "/home/u/observer"},
		{"///x", "///x", "///x"},
		{"observer", "observer", "observer"},
		{"", "", ""},
		{`C:\Users\u\observer.exe`, `C:\Users\u\observer.exe`, `C:\Users\u\observer.exe`},
	}
	for _, tc := range cases {
		if got := msysLiteralPath(tc.in); got != tc.literal {
			t.Errorf("msysLiteralPath(%q) = %q want %q", tc.in, got, tc.literal)
		}
		if got := unMSYSLiteralPath(msysLiteralPath(tc.in)); got != tc.back {
			t.Errorf("unMSYSLiteralPath(msysLiteralPath(%q)) = %q want %q", tc.in, got, tc.back)
		}
	}
}

func TestTrimBridgeExitTrailer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, body string
		ok       bool
	}{
		{"wsl.exe -d D -- //b hook claude-code stop; exit $LASTEXITCODE", "wsl.exe -d D -- //b hook claude-code stop", true},
		{"wsl.exe -d D -- //b hook claude-code stop; exit $LASTEXITCODE  ", "wsl.exe -d D -- //b hook claude-code stop", true},
		{"wsl.exe -d D -- /b hook claude-code stop", "wsl.exe -d D -- /b hook claude-code stop", false},
		{"x; exit $LASTEXITCODE; echo", "x; exit $LASTEXITCODE; echo", false},
	}
	for _, tc := range cases {
		body, ok := trimBridgeExitTrailer(tc.in)
		if body != tc.body || ok != tc.ok {
			t.Errorf("trimBridgeExitTrailer(%q) = (%q, %v) want (%q, %v)", tc.in, body, ok, tc.body, tc.ok)
		}
	}
}

// TestBridgeFormReaders runs every command reader over each generation of
// the claude-code-windows bridge: all must agree the command is an
// observer claude-code hook, and the native-target predicate must keep
// rejecting every bridge shape so the two registrars never fight.
func TestBridgeFormReaders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		cmd       string
		envPrefix bool
		trailer   bool
		config    string
	}{
		{
			name:    "portable (current)",
			cmd:     portableBridgeCommand(apDistro, apBin, "claude-code", "pre-tool", apCfg),
			trailer: true, config: apCfg,
		},
		{
			name: "portable, no config",
			cmd:  portableBridgeCommand(apDistro, apBin, "claude-code", "pre-tool", ""), trailer: true,
		},
		{
			name:      "legacy MSYS_NO_PATHCONV (v1.6.22 to AP-119)",
			cmd:       "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- " + apBin + " hook claude-code pre-tool --config '" + apCfg + "'",
			envPrefix: true, config: apCfg,
		},
		{
			name: "prefix-free (before v1.6.22)",
			cmd:  "wsl.exe -d Ubuntu-20.04 -- " + apBin + " hook claude-code pre-tool",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !isObserverWindowsClaudeEntry(tc.cmd) {
				t.Errorf("isObserverWindowsClaudeEntry rejected %q", tc.cmd)
			}
			if !IsObserverClaudeCodeHookCommand(tc.cmd) {
				t.Errorf("IsObserverClaudeCodeHookCommand rejected %q", tc.cmd)
			}
			if isObserverClaudeEntry(tc.cmd) {
				t.Errorf("native predicate isObserverClaudeEntry accepted bridge %q", tc.cmd)
			}
			inv, ok := parseObserverHookCommand(tc.cmd)
			if !ok {
				t.Fatalf("parseObserverHookCommand(%q) failed", tc.cmd)
			}
			if !inv.bridge || inv.distro != apDistro || inv.binary != apBin ||
				inv.tool != "claude-code" || inv.event != "pre-tool" || inv.config != tc.config ||
				len(inv.extra) != 0 || inv.envPrefix != tc.envPrefix || inv.exitTrailer != tc.trailer {
				t.Errorf("parseObserverHookCommand(%q) = %+v", tc.cmd, inv)
			}
		})
	}
}

// TestBridgeFormEquivalence pins the bridge-form equivalence row: a legacy
// entry is never kept as equivalent to the portable one, while a portable
// entry from another observer install still is.
func TestBridgeFormEquivalence(t *testing.T) {
	t.Parallel()
	want := portableBridgeCommand(apDistro, apBin, "claude-code", "pre-tool", "")
	env := hookEquivalenceEnv{binaryWorks: func(string) bool { return true }, defaultConfig: apCfg}
	cases := []struct {
		name     string
		have     string
		keep     bool
		wantRule string
	}{
		{"identical", want, true, ""},
		{"portable, other observer path", portableBridgeCommand(apDistro, "/opt/observer/bin/observer", "claude-code", "pre-tool", ""), true, ""},
		{"portable, explicit default config", portableBridgeCommand(apDistro, apBin, "claude-code", "pre-tool", apCfg), true, ""},
		{"legacy MSYS prefix", "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- " + apBin + " hook claude-code pre-tool", false, "bridge-form"},
		{"no exit trailer", "wsl.exe -d Ubuntu-20.04 -- //home/u/superbased-observer/bin/observer hook claude-code pre-tool", false, "bridge-form"},
		{"portable, other distro", portableBridgeCommand("Debian", apBin, "claude-code", "pre-tool", ""), false, "shape"},
		{"portable, other event", portableBridgeCommand(apDistro, apBin, "claude-code", "stop", ""), false, "tool-event"},
		{"portable, other config", portableBridgeCommand(apDistro, apBin, "claude-code", "pre-tool", "/home/u/elsewhere.toml"), false, "config"},
	}
	for _, tc := range cases {
		keep, rule, _ := decideHookEquivalence(tc.have, want, env)
		if keep != tc.keep || rule != tc.wantRule {
			t.Errorf("%s: decideHookEquivalence = (keep %v, rule %q) want (keep %v, rule %q)", tc.name, keep, rule, tc.keep, tc.wantRule)
		}
	}
}

// legacyWindowsClaudeSettings is a Windows-side settings.json carrying the
// legacy MSYS form for every event plus an unrelated top-level key.
func legacyWindowsClaudeSettings(t *testing.T, bin string) []byte {
	t.Helper()
	hooks := map[string][]claudeHookGroup{}
	for _, ev := range claudeCodeEvents {
		hooks[ev] = []claudeHookGroup{{Matcher: "*", Hooks: []claudeHookCommand{{
			Type: "command", Command: "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- " + bin + " hook claude-code " + hookEventArg(ev),
		}}}}
	}
	body, err := json.Marshal(map[string]any{"hooks": hooks, "theme": "dark"})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestRegisterClaudeCodeWindowsMigratesLegacyBridge: re-registration over
// the legacy MSYS form replaces it (never duplicates), under both the
// consented-init refresh and `observer start`'s KeepEquivalentHooks, keeps
// the unrelated key, and a second pass is a no-op.
func TestRegisterClaudeCodeWindowsMigratesLegacyBridge(t *testing.T) {
	t.Parallel()
	for _, keep := range []bool{false, true} {
		keep := keep
		name := "init refresh"
		if keep {
			name = "start keep-equivalent"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wslHome := t.TempDir()
			winHome := nestedWinHome(t, wslHome)
			settingsPath := filepath.Join(winHome, ".claude", "settings.json")
			writeAged(t, settingsPath, legacyWindowsClaudeSettings(t, apBin))
			opts := Options{
				BinaryPath:          apBin,
				HomeDir:             wslHome,
				ChecksumsPath:       filepath.Join(wslHome, ".observer", "hook_checksums.json"),
				WindowsClaudeHome:   winHome,
				WSLDistro:           apDistro,
				KeepEquivalentHooks: keep,
				binaryWorks:         func(string) bool { return true },
			}
			r, err := NewRegistry(opts)
			if err != nil {
				t.Fatal(err)
			}
			res := mustRegister(t, r, "claude-code-windows")
			if len(res.HooksAdded) != len(claudeCodeEvents) || len(res.KeptEquivalent) != 0 {
				t.Errorf("HooksAdded = %d KeptEquivalent = %v; want every event re-added", len(res.HooksAdded), res.KeptEquivalent)
			}
			if keep {
				for _, rw := range res.Rewrites {
					if rw.Rule != "bridge-form" {
						t.Errorf("event %s rewritten by rule %q, want bridge-form", rw.Event, rw.Rule)
					}
				}
			}
			groups := readClaudeHookGroups(t, settingsPath)
			for _, ev := range claudeCodeEvents {
				want := portableBridgeCommand(apDistro, apBin, "claude-code", hookEventArg(ev), "")
				var ours []string
				for _, c := range groups[ev] {
					if isObserverWindowsClaudeEntry(c) {
						ours = append(ours, c)
					}
				}
				if len(ours) != 1 || ours[0] != want {
					t.Errorf("event %s observer entries = %q, want exactly [%q]", ev, ours, want)
				}
			}
			body, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "MSYS_NO_PATHCONV") {
				t.Errorf("legacy form survived:\n%s", body)
			}
			if !strings.Contains(string(body), `"theme"`) {
				t.Errorf("unrelated key lost:\n%s", body)
			}
			again := mustRegister(t, r, "claude-code-windows")
			if len(again.HooksAdded) != 0 || len(again.AlreadySet) != len(claudeCodeEvents) {
				t.Errorf("second pass added %v (AlreadySet %d); want a no-op", again.HooksAdded, len(again.AlreadySet))
			}
			after, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(body) {
				t.Errorf("second pass changed the file")
			}
		})
	}
}

// TestUnregisterClaudeCodeWindowsRemovesEveryBridgeForm: uninstall takes
// out the portable and the legacy forms alike and keeps the foreign hook.
func TestUnregisterClaudeCodeWindowsRemovesEveryBridgeForm(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	settingsPath := filepath.Join(winHome, ".claude", "settings.json")
	hooks := map[string][]claudeHookGroup{}
	for i, ev := range claudeCodeEvents {
		cmd := portableBridgeCommand(apDistro, apBin, "claude-code", hookEventArg(ev), "")
		if i%2 == 1 {
			cmd = "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- " + apBin + " hook claude-code " + hookEventArg(ev)
		}
		hooks[ev] = []claudeHookGroup{{Matcher: "*", Hooks: []claudeHookCommand{{Type: "command", Command: cmd}}}}
	}
	hooks["Stop"] = append(hooks["Stop"], claudeHookGroup{Matcher: "*", Hooks: []claudeHookCommand{{Type: "command", Command: "C:/tools/notify.exe done"}}})
	body, err := json.Marshal(map[string]any{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	writeAged(t, settingsPath, body)
	r, err := NewRegistry(Options{
		BinaryPath:        apBin,
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         apDistro,
		Force:             true, // hand-planted file: no install-time checksum
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("claude-code-windows")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved = %d want %d", len(res.HooksRemoved), len(claudeCodeEvents))
	}
	groups := readClaudeHookGroups(t, settingsPath)
	if len(groups) != 1 || len(groups["Stop"]) != 1 || groups["Stop"][0] != "C:/tools/notify.exe done" {
		t.Errorf("after unregister hooks = %v, want only the foreign Stop hook", groups)
	}
}

// TestRegisterClaudeCodeWindowsRefusesUnquotablePath: a single quote has
// no spelling that both Git Bash and PowerShell read the same, so the
// registrar refuses and writes nothing.
func TestRegisterClaudeCodeWindowsRefusesUnquotablePath(t *testing.T) {
	t.Parallel()
	for _, o := range []struct{ bin, cfg string }{
		{"/home/o'brien/observer", ""},
		{apBin, "/home/o'brien/.observer/config.toml"},
	} {
		wslHome := t.TempDir()
		winHome := nestedWinHome(t, wslHome)
		claudeDir := filepath.Join(winHome, ".claude")
		if err := os.MkdirAll(claudeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistry(Options{
			BinaryPath:        o.bin,
			ConfigPath:        o.cfg,
			HomeDir:           wslHome,
			ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
			WindowsClaudeHome: winHome,
			WSLDistro:         apDistro,
		})
		if err != nil {
			t.Fatal(err)
		}
		res := r.Register("claude-code-windows")
		if res.Error == nil || !strings.Contains(res.Error.Error(), "single quote") {
			t.Errorf("bin %q cfg %q: error = %v, want a single-quote refusal", o.bin, o.cfg, res.Error)
		}
		if _, err := os.Stat(filepath.Join(claudeDir, "settings.json")); !os.IsNotExist(err) {
			t.Errorf("bin %q cfg %q: settings.json was written", o.bin, o.cfg)
		}
	}
}
