package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AP-119 follow-up: the CodeBuddy and VT Code "-windows" wsl.exe bridges are
// written in the portable bridge form (portableBridgeCommand), the one
// claude-code-windows uses, instead of the MSYS_NO_PATHCONV=1 prefix. These
// tests pin the written bytes, the upgrade of a legacy-form registration
// (recognised as Observer's, rewritten in place, never duplicated) and the
// byte-identical unregister of either form.

const (
	portableTestDistro = "Ubuntu-T"
	portableTestBin    = "/opt/observer/bin/observer"
	portableTestCfg    = "/etc/observer/config.toml"
)

// portableWaveCase is one bridge tool: where its Windows-side file sits, the
// user's own content that must survive, and the two command spellings.
type portableWaveCase struct {
	target string // base tool token
	rel    string // file relative to the Windows user home
	base   string // user content already in the file ("" = no file)
}

var portableWaveCases = []portableWaveCase{
	{
		target: "codebuddy", rel: ".codebuddy/settings.json",
		base: "{\n  \"model\": \"x\",\n  \"apiKey\": \"sk-never-read\"\n}\n",
	},
	{target: "codebuddy", rel: ".codebuddy/settings.json"},
	{
		target: "vtcode", rel: "AppData/Roaming/vinhnx/vtcode/config/vtcode.toml",
		base: "# my settings\n[agent]\nprovider = \"openai\"\n\n[hooks.lifecycle]\nquiet_success_output = true\n\n[[hooks.lifecycle.pre_tool_use]]\nmatcher = \"^shell$\"\nhooks = [{ type = \"command\", command = \"audit.sh\" }]\n",
	},
	{target: "vtcode", rel: "AppData/Roaming/vinhnx/vtcode/config/vtcode.toml"},
}

var portableWaveEvents = []string{"PreToolUse", "UserPromptSubmit"}

// portableWant is the command the writer must now produce for event.
func portableWant(tool, event string, withConfig bool) string {
	cfg := ""
	if withConfig {
		cfg = " --config '/" + portableTestCfg + "'"
	}
	return "wsl.exe -d " + portableTestDistro + " -- /" + portableTestBin + " hook " + tool + " " + event + cfg + "; exit $LASTEXITCODE"
}

// legacyWant is the MSYS-prefixed form the writer produced before.
func legacyWant(tool, event string, withConfig bool) string {
	cfg := ""
	if withConfig {
		cfg = " --config '" + portableTestCfg + "'"
	}
	return "MSYS_NO_PATHCONV=1 wsl.exe -d " + portableTestDistro + " -- " + portableTestBin + " hook " + tool + " " + event + cfg
}

// portableRegistry is a registry whose Windows user home is win (nested under
// home, as the sandbox gate requires) with the tool's directory created.
func portableRegistry(t *testing.T, home, win string, withConfig bool) *Registry {
	t.Helper()
	opts := Options{
		BinaryPath: portableTestBin, HomeDir: home, WindowsUserHome: win, WSLDistro: portableTestDistro,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	}
	if withConfig {
		opts.ConfigPath = portableTestCfg
	}
	reg, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// portableFixture creates the home, the Windows home with the tool's
// directory, and the pre-existing user file (when base is non-empty).
func portableFixture(t *testing.T, tc portableWaveCase) (home, win, path string) {
	t.Helper()
	home = t.TempDir()
	win = filepath.Join(home, "win")
	sub, ok := waveCrossOSFor(tc.target)
	if !ok {
		t.Fatalf("no cross-OS target for %s", tc.target)
	}
	if err := os.MkdirAll(filepath.Join(win, sub.winSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(win, filepath.FromSlash(tc.rel))
	if tc.base != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(tc.base), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, win, path
}

// TestPortableBridgeWaveWindows: a fresh registration writes the portable
// form per event, is idempotent, and unregisters back to the original bytes.
func TestPortableBridgeWaveWindows(t *testing.T) {
	for _, tc := range portableWaveCases {
		for _, withConfig := range []bool{false, true} {
			name := tc.target + "/base=" + map[bool]string{true: "user", false: "none"}[tc.base != ""] + "/config=" + map[bool]string{true: "yes", false: "no"}[withConfig]
			t.Run(name, func(t *testing.T) {
				home, win, path := portableFixture(t, tc)
				reg := portableRegistry(t, home, win, withConfig)
				label := tc.target + "-windows"
				res := reg.Register(label)
				if res.Error != nil || res.Skipped || len(res.HooksAdded) != len(portableWaveEvents) {
					t.Fatalf("register: %+v", res)
				}
				got := readOrEmpty(path)
				for _, ev := range portableWaveEvents {
					want := portableWant(tc.target, ev, withConfig)
					if !strings.Contains(got, want) {
						t.Errorf("missing %q in\n%s", want, got)
					}
				}
				if strings.Contains(got, "MSYS_NO_PATHCONV") {
					t.Errorf("legacy MSYS prefix written:\n%s", got)
				}
				for _, ev := range portableWaveEvents {
					if c := portableWant(tc.target, ev, withConfig); !isObserverAnyHookEntry(c, tc.target) {
						t.Errorf("own portable command not recognised: %q", c)
					}
				}
				again := reg.Register(label)
				if again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != len(portableWaveEvents) {
					t.Fatalf("second register not idempotent: %+v", again)
				}
				if readOrEmpty(path) != got {
					t.Fatal("second register changed the file")
				}
				un := reg.Unregister(label)
				if un.Error != nil || len(un.HooksRemoved) != len(portableWaveEvents) {
					t.Fatalf("unregister: %+v", un)
				}
				if back := readOrEmpty(path); back != tc.base {
					t.Fatalf("unregister did not restore the original bytes:\nwant %q\ngot  %q", tc.base, back)
				}
			})
		}
	}
}

// TestPortableBridgeWaveLegacyUpgrade: a registration in the old MSYS-prefixed
// form (all events, or only one of them) is recognised as Observer's, rewritten
// to the portable form in place (one entry per event, never a duplicate) and
// unregisters to the original bytes.
func TestPortableBridgeWaveLegacyUpgrade(t *testing.T) {
	for _, tc := range portableWaveCases {
		for _, legacyEvents := range [][]string{portableWaveEvents, {"PreToolUse"}} {
			for _, withConfig := range []bool{false, true} {
				name := tc.target + "/base=" + map[bool]string{true: "user", false: "none"}[tc.base != ""] +
					"/legacy=" + strings.Join(legacyEvents, "+") + "/config=" + map[bool]string{true: "yes", false: "no"}[withConfig]
				t.Run(name, func(t *testing.T) {
					label := tc.target + "-windows"
					// The portable file a fresh registration yields: the target
					// the upgrade must converge on, and the source of the legacy
					// file (same formatting, old spelling).
					fresh := func() string {
						home, win, path := portableFixture(t, tc)
						if res := portableRegistry(t, home, win, withConfig).Register(label); res.Error != nil {
							t.Fatalf("fresh register: %v", res.Error)
						}
						return readOrEmpty(path)
					}()
					legacy := fresh
					for _, ev := range legacyEvents {
						legacy = strings.Replace(legacy, portableWant(tc.target, ev, withConfig), legacyWant(tc.target, ev, withConfig), 1)
					}
					if legacy == fresh {
						t.Fatal("test bug: legacy file equals the portable one")
					}

					home, win, path := portableFixture(t, tc)
					if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
						t.Fatal(err)
					}
					for _, ev := range legacyEvents {
						if !isObserverAnyHookEntry(legacyWant(tc.target, ev, withConfig), tc.target) {
							t.Fatalf("legacy command not recognised as Observer's for %s", ev)
						}
					}
					reg := portableRegistry(t, home, win, withConfig)

					// A dry run reports the legacy events as changes and writes nothing.
					dry := portableRegistry(t, home, win, withConfig)
					dry.opts.DryRun = true
					if res := dry.Register(label); res.Error != nil || len(res.HooksAdded) < len(legacyEvents) {
						t.Fatalf("dry run: %+v", res)
					}
					if readOrEmpty(path) != legacy {
						t.Fatal("dry run wrote the file")
					}

					res := reg.Register(label)
					if res.Error != nil || res.Skipped {
						t.Fatalf("upgrade register: %+v", res)
					}
					// VT Code's line editor rewrites all of its groups together, so
					// only "every legacy event is reported changed" is common to both.
					for _, ev := range legacyEvents {
						if !containsString(res.HooksAdded, ev) {
							t.Fatalf("legacy event %s not reported rewritten: %+v", ev, res)
						}
					}
					got := readOrEmpty(path)
					if strings.Contains(got, "MSYS_NO_PATHCONV") {
						t.Fatalf("legacy form survived the upgrade:\n%s", got)
					}
					for _, ev := range portableWaveEvents {
						if n := strings.Count(got, " hook "+tc.target+" "+ev); n != 1 {
							t.Errorf("event %s has %d Observer entries, want exactly 1:\n%s", ev, n, got)
						}
					}
					if got != fresh {
						t.Errorf("upgraded file differs from a fresh registration:\nwant %q\ngot  %q", fresh, got)
					}
					un := reg.Unregister(label)
					if un.Error != nil || len(un.HooksRemoved) != len(portableWaveEvents) {
						t.Fatalf("unregister: %+v", un)
					}
					if back := readOrEmpty(path); back != tc.base {
						t.Fatalf("unregister did not restore the original bytes:\nwant %q\ngot  %q", tc.base, back)
					}
				})
			}
		}
	}
}

// TestPortableBridgeWaveLegacyUnregister: unregister removes a registration
// that is still entirely in the legacy form.
func TestPortableBridgeWaveLegacyUnregister(t *testing.T) {
	for _, tc := range portableWaveCases {
		t.Run(tc.target+"/base="+map[bool]string{true: "user", false: "none"}[tc.base != ""], func(t *testing.T) {
			label := tc.target + "-windows"
			home, win, path := portableFixture(t, tc)
			if res := portableRegistry(t, home, win, true).Register(label); res.Error != nil {
				t.Fatal(res.Error)
			}
			legacy := readOrEmpty(path)
			for _, ev := range portableWaveEvents {
				legacy = strings.Replace(legacy, portableWant(tc.target, ev, true), legacyWant(tc.target, ev, true), 1)
			}
			if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
				t.Fatal(err)
			}
			un := portableRegistry(t, home, win, true).Unregister(label)
			if un.Error != nil || len(un.HooksRemoved) != len(portableWaveEvents) {
				t.Fatalf("unregister: %+v", un)
			}
			if back := readOrEmpty(path); back != tc.base {
				t.Fatalf("unregister did not restore the original bytes:\nwant %q\ngot  %q", tc.base, back)
			}
		})
	}
}

// TestPortableBridgeWaveRejectsQuotePath: a binary path that cannot be quoted
// for both Git Bash and PowerShell is refused before anything is written.
func TestPortableBridgeWaveRejectsQuotePath(t *testing.T) {
	for _, tc := range portableWaveCases {
		t.Run(tc.target+"/base="+map[bool]string{true: "user", false: "none"}[tc.base != ""], func(t *testing.T) {
			home, win, path := portableFixture(t, tc)
			reg := portableRegistry(t, home, win, false)
			reg.opts.BinaryPath = "/opt/it's/observer"
			res := reg.Register(tc.target + "-windows")
			if res.Error == nil || !strings.Contains(res.Error.Error(), "single quote") {
				t.Fatalf("want a single-quote refusal, got %+v", res)
			}
			if readOrEmpty(path) != tc.base {
				t.Fatal("a refused registration wrote the file")
			}
		})
	}
}

// TestPortableBridgeWaveScope: only CodeBuddy and VT Code moved to the
// portable form; the other four wave bridges keep the shell-specific forms
// their hosts need (cmd.exe plain prefix; Dirac's PowerShell script).
func TestPortableBridgeWaveScope(t *testing.T) {
	for _, tc := range []struct{ target, rel, want string }{
		{"ibm-bob-windows", ".bob/settings/settings.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook ibm-bob PreToolUse"`},
		{"deepagents-code-windows", ".deepagents/hooks.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook deepagents-code PreToolUse"`},
		{"dimcode-windows", ".dimcode/v2/hooks.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook dimcode PreToolUse"`},
		{"dirac-windows", ".dirac/Hooks/PreToolUse.ps1", `$psi.Arguments = '-d Ubuntu-T -- /opt/observer/bin/observer hook dirac PreToolUse'`},
	} {
		t.Run(tc.target, func(t *testing.T) {
			home := t.TempDir()
			win := filepath.Join(home, "win")
			sub, _ := waveCrossOSFor(strings.TrimSuffix(tc.target, "-windows"))
			if err := os.MkdirAll(filepath.Join(win, sub.winSubdir), 0o755); err != nil {
				t.Fatal(err)
			}
			if res := portableRegistry(t, home, win, false).Register(tc.target); res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("register: %+v", res)
			}
			got := readOrEmpty(filepath.Join(win, filepath.FromSlash(tc.rel)))
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in\n%s", tc.want, got)
			}
			if strings.Contains(got, "exit $LASTEXITCODE") || strings.Contains(got, "//opt/observer") {
				t.Errorf("%s moved to the portable form:\n%s", tc.target, got)
			}
		})
	}
}
