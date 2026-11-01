package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// waveRegistry is a registry over a throwaway home, pinned to goos.
func waveRegistry(t *testing.T, home, goos string, env map[string]string, dryRun bool) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		ConfigPath:    "/etc/observer/config.toml",
		Getenv:        func(k string) string { return env[k] },
		GOOS:          goos,
		DryRun:        dryRun,
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// waveRoundTrip is one wave target's register/unregister case: the file it
// writes, the user content already there, and what must hold after the
// registration.
type waveRoundTrip struct {
	target string
	goos   string
	rel    string // config file relative to the home
	before string // "" = no file
	check  func(t *testing.T, after string)
}

var waveRoundTrips = []waveRoundTrip{
	{
		target: "ibm-bob", goos: "linux", rel: ".bob/settings/settings.json",
		// The user's own hooks member is re-rendered (two-space indent) when
		// Observer's entries come and go; every other member keeps its bytes.
		before: "{\n  \"theme\": \"dark\",\n  \"hooks\": {\n    \"Stop\": [\n      {\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"notify\"\n          }\n        ]\n      }\n    ]\n  }\n}\n",
		check: func(t *testing.T, after string) {
			for _, want := range []string{`"theme": "dark"`, `"notify"`, `hook ibm-bob PreToolUse`, `hook ibm-bob UserPromptSubmit`, `"timeout": 30`} {
				if !strings.Contains(after, want) {
					t.Errorf("missing %q in\n%s", want, after)
				}
			}
		},
	},
	{
		target: "codebuddy", goos: "linux", rel: ".codebuddy/settings.json",
		before: "{\n  \"model\": \"x\",\n  \"apiKey\": \"sk-never-read\"\n}\n",
		check: func(t *testing.T, after string) {
			if !strings.Contains(after, `"apiKey": "sk-never-read"`) || !strings.Contains(after, `"timeout": 60`) {
				t.Errorf("credential member or 60 s timeout lost:\n%s", after)
			}
		},
	},
	{
		target: "deepagents-code", goos: "linux", rel: ".deepagents/hooks.json",
		check: func(t *testing.T, after string) {
			if !strings.Contains(after, "hook deepagents-code PreToolUse") {
				t.Errorf("no tool gate:\n%s", after)
			}
		},
	},
	{
		target: "dimcode", goos: "linux", rel: ".dimcode/v2/hooks.json",
		check: func(t *testing.T, after string) {
			var top struct {
				Hooks map[string]json.RawMessage `json:"hooks"`
			}
			if err := json.Unmarshal([]byte(after), &top); err != nil {
				t.Fatalf("decode: %v", err)
			}
			for event := range top.Hooks {
				if event != "PreToolUse" && event != "UserPromptSubmit" {
					t.Errorf("unsupported event %q written (DimCode refuses the whole file)", event)
				}
			}
		},
	},
	{
		target: "dirac", goos: "linux", rel: ".dirac/Hooks/PreToolUse",
		check: func(t *testing.T, after string) {
			if !strings.HasPrefix(after, "#!/bin/sh\n") || !strings.Contains(after, "exec /opt/observer/bin/observer hook dirac PreToolUse") {
				t.Errorf("script:\n%s", after)
			}
		},
	},
	{
		target: "dirac", goos: "windows", rel: ".dirac/Hooks/UserPromptSubmit.ps1",
		check: func(t *testing.T, after string) {
			if !strings.Contains(after, "'hook dirac UserPromptSubmit --config /etc/observer/config.toml'") || !strings.Contains(after, "exit $p.ExitCode") {
				t.Errorf("script:\n%s", after)
			}
		},
	},
	{
		target: "autohand", goos: "linux", rel: ".autohand/config.json",
		before: "{\n  \"provider\": \"openrouter\",\n  \"openrouter\": {\"apiKey\": \"sk-never-read\"},\n  \"auth\": {\"token\": \"t\"}\n}\n",
		check: func(t *testing.T, after string) {
			if !strings.Contains(after, `"openrouter": {"apiKey": "sk-never-read"}`) || !strings.Contains(after, `"auth": {"token": "t"}`) {
				t.Errorf("a credential member changed bytes:\n%s", after)
			}
			if !strings.Contains(after, `"description": "superbased-observer pre-tool"`) || !strings.Contains(after, `"timeout": 30000`) {
				t.Errorf("entries:\n%s", after)
			}
		},
	},
	{
		target: "vtcode", goos: "linux", rel: ".config/vtcode/vtcode.toml",
		before: "# my settings\n[agent]\nprovider = \"openai\"\n\n[hooks.lifecycle]\nquiet_success_output = true\n\n[[hooks.lifecycle.pre_tool_use]]\nmatcher = \"^shell$\"\nhooks = [{ type = \"command\", command = \"audit.sh\" }]\n",
		check: func(t *testing.T, after string) {
			top := map[string]any{}
			if _, err := toml.Decode(after, &top); err != nil {
				t.Fatalf("decode: %v\n%s", err, after)
			}
			if !strings.HasPrefix(after, "# my settings\n[agent]\nprovider = \"openai\"\n") || !strings.Contains(after, "audit.sh") {
				t.Errorf("user content changed:\n%s", after)
			}
			groups, err := vtCodeLifecycle(top)
			if err != nil || len(groups["pre_tool_use"]) != 2 || len(groups["user_prompt_submit"]) != 1 {
				t.Errorf("groups %v err %v", groups, err)
			}
		},
	},
	{
		target: "kimchi", goos: "linux", rel: ".config/kimchi/harness/hooks/bash/superbased-observer.sh",
		check: func(t *testing.T, after string) {
			if !strings.Contains(after, "hook kimchi tool_call") {
				t.Errorf("script:\n%s", after)
			}
		},
	},
}

// TestWaveWritersRoundTrip: every 2026-10-21 writer registers into a home
// holding the user's own content, keeps that content, is idempotent, and
// unregisters back to the original bytes (or no file).
func TestWaveWritersRoundTrip(t *testing.T) {
	for _, tc := range waveRoundTrips {
		t.Run(tc.target+"/"+tc.goos, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, filepath.FromSlash(tc.rel))
			if tc.before != "" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// Dry run writes nothing.
			if res := waveRegistry(t, home, tc.goos, nil, true).Register(tc.target); res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("dry run: %+v", res)
			}
			if got := readOrEmpty(path); got != tc.before {
				t.Fatalf("dry run wrote:\n%s", got)
			}
			reg := waveRegistry(t, home, tc.goos, nil, false)
			res := reg.Register(tc.target)
			if res.Error != nil || res.Skipped || len(res.HooksAdded) == 0 {
				t.Fatalf("register: %+v", res)
			}
			after := readOrEmpty(path)
			tc.check(t, after)
			again := reg.Register(tc.target)
			if again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) == 0 {
				t.Fatalf("second register not idempotent: %+v", again)
			}
			if got := readOrEmpty(path); got != after {
				t.Fatalf("second register changed the file")
			}
			un := reg.Unregister(tc.target)
			if un.Error != nil || len(un.HooksRemoved) == 0 {
				t.Fatalf("unregister: %+v", un)
			}
			if got := readOrEmpty(path); got != tc.before {
				t.Fatalf("unregister did not restore the original bytes:\nwant %q\ngot  %q", tc.before, got)
			}
		})
	}
}

func readOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// TestWaveWritersSkip: the vendor switches Observer honours, and the shapes
// it never rewrites, are skipped with a reason and leave the file alone.
func TestWaveWritersSkip(t *testing.T) {
	for _, tc := range []struct {
		name, target, goos, rel, body string
		extra                         string // a sibling file to create
	}{
		{name: "bob global hooks off", target: "ibm-bob", goos: "linux", rel: ".bob/settings/settings.json", body: "{\"disableGlobalHooks\": true}\n"},
		{name: "deepagents legacy list", target: "deepagents-code", goos: "linux", rel: ".deepagents/hooks.json", body: "[{\"command\": \"x\", \"events\": [\"session.start\"]}]\n"},
		{name: "autohand hooks off", target: "autohand", goos: "linux", rel: ".autohand/config.json", body: "{\"hooks\": {\"enabled\": false, \"hooks\": []}}\n"},
		{name: "autohand toml sibling", target: "autohand", goos: "linux", rel: ".autohand/config.json", body: "{}\n", extra: ".autohand/config.toml"},
		{name: "kimchi on windows", target: "kimchi", goos: "windows", rel: ".config/kimchi/harness/hooks/bash/superbased-observer.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, filepath.FromSlash(tc.rel))
			if tc.body != "" {
				_ = os.MkdirAll(filepath.Dir(path), 0o755)
				if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.extra != "" {
				if err := os.WriteFile(filepath.Join(home, filepath.FromSlash(tc.extra)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			res := waveRegistry(t, home, tc.goos, nil, false).Register(tc.target)
			if res.Error != nil || !res.Skipped || res.SkipReason == "" {
				t.Fatalf("want a reasoned skip, got %+v", res)
			}
			if got := readOrEmpty(path); got != tc.body {
				t.Fatalf("skip changed the file:\n%s", got)
			}
		})
	}
}

// TestWaveWritersHonourHomeOverrides: the vendors' own home variables move
// the written file. DIRAC_DIR is not one of them for the Hooks folder
// (S-17; register_wave1021_s17_test.go), and KIMCHI_CODING_AGENT_DIR is not
// one for Kimchi's harness: entry.ts sets it to ~/.config/kimchi/harness
// unconditionally, so a user-exported value never moves the gate (FU-50).
func TestWaveWritersHonourHomeOverrides(t *testing.T) {
	home := t.TempDir()
	alt := filepath.Join(home, "alt")
	env := map[string]string{"DEEPAGENTS_HOME": alt, "DIMCODE_HOME": alt, "AUTOHAND_CONFIG": filepath.Join(alt, "ah.json"), "KIMCHI_CODING_AGENT_DIR": alt, "CODEBUDDY_CONFIG_DIR": filepath.Join(alt, "cb")}
	reg := waveRegistry(t, home, "linux", env, false)
	for target, rel := range map[string]string{
		"deepagents-code": "hooks.json", "dimcode": "v2/hooks.json",
		"autohand": "ah.json", "codebuddy": "cb/settings.json",
	} {
		if res := reg.Register(target); res.Error != nil {
			t.Fatalf("%s: %v", target, res.Error)
		}
		if _, err := os.Stat(filepath.Join(alt, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s: not written under the override: %v", target, err)
		}
	}
	if res := reg.Register("kimchi"); res.Error != nil {
		t.Fatalf("kimchi: %v", res.Error)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "kimchi", "harness", "hooks", "bash", "superbased-observer.sh")); err != nil {
		t.Errorf("kimchi: the gate is not in the forced harness dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(alt, "hooks")); !os.IsNotExist(err) {
		t.Errorf("kimchi: followed the exported KIMCHI_CODING_AGENT_DIR (err %v)", err)
	}
}

// TestWaveWritersHomeVariablesFU50 pins the FU-50 writer moves, one row per
// variable: AUTOHAND_HOME (the old writer honoured only AUTOHAND_CONFIG), a
// ~/-prefixed DEEPAGENTS_HOME (the old envDir dropped it) and VT Code's
// macOS user file (the old writer skipped macOS) and VTCODE_CONFIG.
func TestWaveWritersHomeVariablesFU50(t *testing.T) {
	for _, tc := range []struct {
		name, target, goos string
		env                func(home string) map[string]string
		want               func(home string) string
	}{
		{
			"AUTOHAND_HOME", "autohand", "linux",
			func(home string) map[string]string {
				return map[string]string{"AUTOHAND_HOME": filepath.Join(home, "ah")}
			},
			func(home string) string { return filepath.Join(home, "ah", "config.json") },
		},
		{
			"DEEPAGENTS_HOME with ~/", "deepagents-code", "linux",
			func(string) map[string]string { return map[string]string{"DEEPAGENTS_HOME": "~/dh"} },
			func(home string) string { return filepath.Join(home, "dh", "hooks.json") },
		},
		{
			"vtcode on macOS", "vtcode", "darwin",
			func(string) map[string]string { return nil },
			func(home string) string {
				return filepath.Join(home, "Library", "Application Support", "com.vinhnx.vtcode", "vtcode.toml")
			},
		},
		{
			"VTCODE_CONFIG", "vtcode", "linux",
			func(home string) map[string]string {
				return map[string]string{"VTCODE_CONFIG": filepath.Join(home, "vt")}
			},
			func(home string) string { return filepath.Join(home, "vt", "vtcode.toml") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			res := waveRegistry(t, home, tc.goos, tc.env(home), false).Register(tc.target)
			if res.Error != nil || res.Skipped {
				t.Fatalf("Register = %+v", res)
			}
			if want := tc.want(home); res.ConfigPath != want {
				t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
			}
		})
	}
}

// TestWaveOwnedScriptConflict: a foreign file at Observer's script path is a
// conflict without --force and is never removed by an unregister.
func TestWaveOwnedScriptConflict(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".dirac", "Hooks", "PreToolUse")
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	foreign := []byte("#!/bin/sh\necho mine\n")
	if err := os.WriteFile(path, foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	reg := waveRegistry(t, home, "linux", nil, false)
	if res := reg.Register("dirac"); res.Error == nil {
		t.Fatalf("want a conflict, got %+v", res)
	}
	if un := reg.Unregister("dirac"); un.Error != nil {
		t.Fatalf("unregister: %v", un.Error)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, foreign) {
		t.Fatal("unregister touched a foreign hook file")
	}
}

// TestWaveCrossOSBridgeShapes: each "-windows" target's command runs the
// WSL observer through the bridge its host's shell needs.
func TestWaveCrossOSBridgeShapes(t *testing.T) {
	for _, tc := range []struct{ target, rel, want string }{
		{"ibm-bob-windows", ".bob/settings/settings.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook ibm-bob PreToolUse`},
		{"codebuddy-windows", ".codebuddy/settings.json", `"wsl.exe -d Ubuntu-T -- //opt/observer/bin/observer hook codebuddy PreToolUse; exit $LASTEXITCODE"`},
		{"deepagents-code-windows", ".deepagents/hooks.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook deepagents-code`},
		{"dimcode-windows", ".dimcode/v2/hooks.json", `"wsl.exe -d Ubuntu-T -- /opt/observer/bin/observer hook dimcode`},
		{"dirac-windows", ".dirac/Hooks/PreToolUse.ps1", `$psi.Arguments = '-d Ubuntu-T -- /opt/observer/bin/observer hook dirac PreToolUse`},
		{"vtcode-windows", "AppData/Roaming/vinhnx/vtcode/config/vtcode.toml", `command = "wsl.exe -d Ubuntu-T -- //opt/observer/bin/observer hook vtcode PreToolUse; exit $LASTEXITCODE"`},
	} {
		t.Run(tc.target, func(t *testing.T) {
			home := t.TempDir()
			win := filepath.Join(home, "win")
			sub, _ := waveCrossOSFor(strings.TrimSuffix(tc.target, "-windows"))
			if err := os.MkdirAll(filepath.Join(win, sub.winSubdir), 0o755); err != nil {
				t.Fatal(err)
			}
			reg, err := NewRegistry(Options{
				BinaryPath: "/opt/observer/bin/observer", HomeDir: home, WindowsUserHome: win, WSLDistro: "Ubuntu-T",
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
			})
			if err != nil {
				t.Fatal(err)
			}
			res := reg.Register(tc.target)
			if res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("register: %+v", res)
			}
			got := readOrEmpty(filepath.Join(win, filepath.FromSlash(tc.rel)))
			if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q in\n%s", tc.want, got)
			}
			if un := reg.Unregister(tc.target); un.Error != nil || len(un.HooksRemoved) == 0 {
				t.Fatalf("unregister: %+v", un)
			}
		})
	}
}

// TestKimchiUnregisterPrunesItsDirs: the hooks/bash directories the writer
// created do not outlive Observer's script (live E2E 2026-10-21 found them
// left behind); a directory still holding a user's script stays.
func TestKimchiUnregisterPrunesItsDirs(t *testing.T) {
	home := t.TempDir()
	reg := waveRegistry(t, home, "linux", nil, false)
	if res := reg.Register("kimchi"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if un := reg.Unregister("kimchi"); un.Error != nil {
		t.Fatal(un.Error)
	}
	hooks := filepath.Join(home, ".config", "kimchi", "harness", "hooks")
	if _, err := os.Stat(hooks); !os.IsNotExist(err) {
		t.Fatalf("%s left behind: %v", hooks, err)
	}
	// A user's own script keeps the directory.
	if res := reg.Register("kimchi"); res.Error != nil {
		t.Fatal(res.Error)
	}
	mine := filepath.Join(hooks, "bash", "mine.sh")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if un := reg.Unregister("kimchi"); un.Error != nil {
		t.Fatal(un.Error)
	}
	if _, err := os.Stat(mine); err != nil {
		t.Fatalf("user script removed: %v", err)
	}
}
