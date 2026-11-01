package agentconfig

import (
	"strings"
	"testing"
)

// TestHomeRelocations pins the Wave 4 per-tool home rules (lane w4-homes-b;
// S-17, CLI-4, W-4, OI-1, FU-5) on every OS: one row per artifact and
// variable, with a fake Getenv. Red before the rules existed (every row
// resolved to its default path with RelocatedBy empty).
func TestHomeRelocations(t *testing.T) {
	for _, fx := range relocFixtures {
		e0 := envOf(fx, nil)
		j := e0.Join
		appData := j(fx.home, "AppData", "Roaming")
		localAppData := j(fx.home, "AppData", "Local")
		type row struct {
			name, id string
			goos     string // "" = every OS
			env      map[string]string
			want     string
			by       string
		}
		cases := []row{
			{"gemini home holds .gemini", "gemini-cli/user-settings", "", map[string]string{"GEMINI_CLI_HOME": fx.abs}, j(fx.abs, ".gemini", "settings.json"), "GEMINI_CLI_HOME"},
			{"qwen home", "qwen-code/user-settings", "", map[string]string{"QWEN_HOME": fx.abs}, j(fx.abs, "settings.json"), "QWEN_HOME"},
			{"goose root on linux", "goose/user-config", "linux", map[string]string{"GOOSE_PATH_ROOT": fx.abs, "XDG_CONFIG_HOME": fx.absV2}, j(fx.abs, "config", "config.yaml"), "GOOSE_PATH_ROOT"},
			{"goose root on windows", "goose/user-config", "windows", map[string]string{"GOOSE_PATH_ROOT": fx.abs}, j(fx.abs, "config", "config.yaml"), "GOOSE_PATH_ROOT"},
			{"goose xdg on darwin", "goose/user-permissions", "darwin", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "goose", "permission.yaml"), "XDG_CONFIG_HOME"},
			{"goose ignores xdg on windows", "goose/user-config", "windows", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(appData, "Block", "goose", "config", "config.yaml"), ""},
			{"pi agent dir", "pi/user-models", "", map[string]string{"PI_CODING_AGENT_DIR": fx.abs}, j(fx.abs, "models.json"), "PI_CODING_AGENT_DIR"},
			{"prime agent dir tilde", "prime-agent/user-models", "", map[string]string{"PRIME_AGENT_CODING_AGENT_DIR": "~/pa"}, j(fx.home, "pa", "models.json"), "PRIME_AGENT_CODING_AGENT_DIR"},
			{"hermes home", "hermes/user-config", "", map[string]string{"HERMES_HOME": fx.abs, "HERMES_DATA_DIR_SUFFIX": "-x"}, j(fx.abs, "config.yaml"), "HERMES_HOME"},
			{"hermes suffix posix", "hermes/observer-plugin", "linux", map[string]string{"HERMES_DATA_DIR_SUFFIX": "-dev"}, j(fx.home, ".hermes-dev", "plugins", "superbased-observer") + fx.sep, "HERMES_DATA_DIR_SUFFIX"},
			{"hermes suffix windows", "hermes/user-config", "windows", map[string]string{"HERMES_DATA_DIR_SUFFIX": "-dev"}, j(localAppData, "hermes-dev", "config.yaml"), "HERMES_DATA_DIR_SUFFIX"},
			// FU-103 (MAC-4): OPENCODE_CONFIG_DIR adds a dir and never moves
			// the global file; the extra file is its own row.
			{"opencode config dir does not move the global file", "opencode/user-config", "", map[string]string{"OPENCODE_CONFIG_DIR": fx.abs}, j(fx.home, ".config", "opencode", "opencode.json"), ""},
			{"opencode global file still follows xdg", "opencode/user-config", "", map[string]string{"OPENCODE_CONFIG_DIR": fx.abs, "XDG_CONFIG_HOME": fx.absV2}, j(fx.absV2, "opencode", "opencode.json"), "XDG_CONFIG_HOME"},
			{"opencode extra config dir file", "opencode/config-dir-config", "", map[string]string{"OPENCODE_CONFIG_DIR": fx.abs, "XDG_CONFIG_HOME": fx.absV2}, j(fx.abs, "opencode.json"), ""},
			{"opencode xdg", "opencode/user-tui", "", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "opencode", "tui.json"), "XDG_CONFIG_HOME"},
			{"kilo xdg", "kilo-code-cli/user-config", "", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "kilo", "kilo.jsonc"), "XDG_CONFIG_HOME"},
			{"kilo config dir does not move kilo.jsonc", "kilo-code-cli/user-config", "", map[string]string{"KILO_CONFIG_DIR": fx.abs}, j(fx.home, ".config", "kilo", "kilo.jsonc"), ""},
			{"grok home", "grok/user-config", "", map[string]string{"GROK_HOME": fx.abs}, j(fx.abs, "config.toml"), "GROK_HOME"},
			{"grok hooks follow the home", "grok/user-hooks", "", map[string]string{"GROK_HOME": fx.abs}, j(fx.abs, "hooks") + fx.sep, "GROK_HOME"},
			{"qoder config dir", "qoder/user-settings", "", map[string]string{"QODER_CONFIG_DIR": fx.abs}, j(fx.abs, "settings.json"), "QODER_CONFIG_DIR"},
			{"copilot home", "copilot-cli/user-settings", "", map[string]string{"COPILOT_HOME": fx.abs}, j(fx.abs, "settings.json"), "COPILOT_HOME"},
			{"copilot providers file beats the home", "copilot-cli/providers", "", map[string]string{"COPILOT_PROVIDERS_CONFIG": fx.absFile, "COPILOT_HOME": fx.abs}, e0.native(fx.absFile), "COPILOT_PROVIDERS_CONFIG"},
			{"vibe home", "mistral-code/user-hooks", "", map[string]string{"VIBE_HOME": fx.abs}, j(fx.abs, "hooks.toml"), "VIBE_HOME"},
			{"junie home", "junie/user-config", "", map[string]string{"JUNIE_HOME": fx.abs}, j(fx.abs, "config.json"), "JUNIE_HOME"},
			{"interpreter home", "open-interpreter/user-config", "", map[string]string{"INTERPRETER_HOME": fx.abs}, j(fx.abs, "config.toml"), "INTERPRETER_HOME"},
			{"kimi home", "kimi-code/user-config", "", map[string]string{"KIMI_CODE_HOME": fx.abs}, j(fx.abs, "config.toml"), "KIMI_CODE_HOME"},
			{"crush global config dir", "crush/user-json", "", map[string]string{"CRUSH_GLOBAL_CONFIG": fx.abs, "XDG_CONFIG_HOME": fx.absV2}, j(fx.abs, "crush.json"), "CRUSH_GLOBAL_CONFIG"},
			{"crush xdg", "crush/user-crushrc", "", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "crush", "crushrc"), "XDG_CONFIG_HOME"},
			{"crush CRUSH_CONFIG is not read", "crush/user-json", "", map[string]string{"CRUSH_CONFIG": fx.absFile}, j(fx.home, ".config", "crush", "crush.json"), ""},
			{"crush data dir", "crush/state", "", map[string]string{"CRUSH_GLOBAL_DATA": fx.abs}, j(fx.abs, "crush.json"), "CRUSH_GLOBAL_DATA"},
			{"kiro home", "kiro-cli/user-cli", "", map[string]string{"KIRO_HOME": fx.abs}, j(fx.abs, "settings", "cli.json"), "KIRO_HOME"},
			{"kiro refuses home", "kiro-cli/user-cli", "", map[string]string{"KIRO_HOME": fx.home}, j(fx.home, ".kiro", "settings", "cli.json"), ""},
			{"devin xdg on linux", "devin/user-config", "linux", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "devin", "config.json"), "XDG_CONFIG_HOME"},
			{"devin xdg on darwin", "devin/user-config", "darwin", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(fx.abs, "devin", "config.json"), "XDG_CONFIG_HOME"},
			{"a relative APPDATA is ignored", "devin/user-config", "windows", map[string]string{"APPDATA": "rel"}, j(appData, "devin", "config.json"), ""},
			{"devin windows uses APPDATA", "devin/user-config", "windows", map[string]string{"XDG_CONFIG_HOME": fx.abs}, j(appData, "devin", "config.json"), ""},
		}
		for _, tc := range cases {
			if tc.goos != "" && tc.goos != fx.goos {
				continue
			}
			got, err := ResolveArtifact(tc.id, envOf(fx, tc.env))
			if err != nil {
				t.Fatalf("%s/%s: %v", fx.goos, tc.name, err)
			}
			if got.Path != tc.want || got.RelocatedBy != tc.by {
				t.Errorf("%s/%s: got (%q, by %q), want (%q, by %q)", fx.goos, tc.name, got.Path, got.RelocatedBy, tc.want, tc.by)
			}
		}
	}
}

// TestRelocationVariablesAndDrift (CLI-4): the probe's name list is every
// variable that moves a file (sorted, distinct, no does-not-move-only
// name), and drift is reported only for a login-shell value this process
// lacks or spells differently.
func TestRelocationVariablesAndDrift(t *testing.T) {
	names := RelocationVariables()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("not sorted and distinct: %v", names)
		}
	}
	has := map[string]bool{}
	for _, n := range names {
		has[n] = true
	}
	// OPENCODE_CONFIG_DIR moves nothing (FU-103) but names the dir of the
	// opencode/config-dir-config row, so the probe still compares it.
	for _, want := range []string{"QWEN_HOME", "GROK_HOME", "COPILOT_HOME", "KIRO_HOME", "CLINE_DATA_DIR", "CODEX_HOME", "OPENCODE_CONFIG_DIR"} {
		if !has[want] {
			t.Errorf("%s missing from %v", want, names)
		}
	}
	for _, never := range []string{"DIRAC_DATA_DIR", "KIMCHI_CODING_AGENT_DIR", "KILO_CONFIG_DIR"} {
		if has[never] {
			t.Errorf("%s moves no file but is listed", never)
		}
	}
	login := map[string]string{"A": "/a", "B": "/b", "C": " /c "}
	proc := map[string]string{"B": "/other", "C": "/c", "D": "/d"}
	got := RelocationEnvDrift([]string{"A", "B", "C", "D"}, func(k string) string { return login[k] }, func(k string) string { return proc[k] })
	want := []EnvDrift{{Name: "A", Login: "/a"}, {Name: "B", Login: "/b", Process: "/other"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("drift = %+v, want %+v", got, want)
	}
}

// TestUngroundedHomesCarryNoRule pins the tools whose relocation the matrix
// marks UNV: no rule, so a writer never follows a guess.
func TestUngroundedHomesCarryNoRule(t *testing.T) {
	for _, id := range []string{"muse/user-settings", "poolside/personal-settings", "open-interpreter/desktop-config", "prime-agent/prime-config", "junie/user-mcp", "codebuddy/global-config"} {
		if r := RelocationsFor(id); r != nil {
			t.Errorf("%s carries %d rules; its relocation is unverified", id, len(r))
		}
	}
}

// TestEnvOnlyTokenRow pins the variable-only path token (FU-103): the
// opencode/config-dir-config row resolves only while OPENCODE_CONFIG_DIR
// names an absolute directory, and is env_unset otherwise, so no reader
// or writer ever names a default location the tool does not read.
func TestEnvOnlyTokenRow(t *testing.T) {
	for _, fx := range relocFixtures {
		for _, tc := range []struct {
			name string
			env  map[string]string
			want ResolvedPath
		}{
			{"unset", nil, ResolvedPath{Status: PathEnvUnset}},
			{"relative", map[string]string{"OPENCODE_CONFIG_DIR": "rel/dir"}, ResolvedPath{Status: PathEnvUnset}},
			{"absolute", map[string]string{"OPENCODE_CONFIG_DIR": fx.abs}, ResolvedPath{Status: PathResolved, Path: envOf(fx, nil).Join(fx.abs, "opencode.json")}},
		} {
			for _, relocate := range []bool{false, true} {
				e := envOf(fx, tc.env)
				e.Relocate = relocate
				var row FileRow
				for _, f := range Files() {
					if f.ID == "opencode/config-dir-config" {
						row = f
					}
				}
				if row.ID == "" {
					t.Fatal("opencode/config-dir-config row missing")
				}
				got := ResolvePath(row, e)
				if got.Status != tc.want.Status || got.Path != tc.want.Path {
					t.Errorf("%s/%s relocate=%v: got %+v, want %+v", fx.goos, tc.name, relocate, got, tc.want)
				}
			}
		}
	}
}

// TestFileEditableNamesTheUnsetVariable pins the fileEditableRules row for
// PathEnvUnset: an extra-directory row whose variable is unset says so,
// instead of the generic "no concrete file" reason.
func TestFileEditableNamesTheUnsetVariable(t *testing.T) {
	row := FileRow{ID: "opencode/config-dir-config", Kind: KindSettings, Format: FormatJSONC, WriteNeeds: PrivUser}
	ok, why := fileEditable(row, FileSnapshot{Resolved: ResolvedPath{Status: PathEnvUnset}}, Access{})
	if ok || why != "The tool reads this file only while its environment variable names a directory, and that variable is not set here." {
		t.Errorf("fileEditable = %v, %q", ok, why)
	}
	// FU-140: a relative relocation value says so, not "no concrete file".
	if _, why := fileEditable(row, FileSnapshot{Resolved: ResolvedPath{Status: PathRelocationUnresolved}}, Access{}); !strings.Contains(why, "relative path") {
		t.Errorf("relocation_unresolved reason = %q", why)
	}
	if _, why := fileEditable(row, FileSnapshot{Resolved: ResolvedPath{Status: PathNoOS}}, Access{}); !strings.HasPrefix(why, "No concrete file") {
		t.Errorf("no_os reason = %q", why)
	}
}
