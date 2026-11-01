package hookdisable

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// ownCommand stands in for internal/hook.IsObserverHookCommand.
func ownCommand(c string) bool { return strings.Contains(c, "observer hook") }

// rowCase is one switch row's fixture: the files (relative to the home for
// user scope, to the project for project scope, absolute for managed
// scope) or environment that set it.
type rowCase struct {
	id    string
	goos  string
	files map[string]string
	env   map[string]string
}

// dimHooks is a DimCode hooks.json holding Observer's PreToolUse entry and
// another tool's; dimOwnHash is the hash DimCode's own hashCommandHook
// (dimcode 0.5.21, run under node) gives Observer's entry.
const (
	dimHooks   = `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/home/u/.local/bin/observer hook dimcode --event PreToolUse <x> & y","timeout":30}]},{"hooks":[{"type":"command","command":"lint.sh"}]}]}}`
	dimOwnHash = "7d4d3df511b0a4a4d7649bf9c90ff3bdbd7390008f9f320016a425c2bfc54744"
)

// rowCases has one case per row of Switches (pinned by
// TestEverySwitchHasARowCase): each fails on a table without the row.
var rowCases = []rowCase{
	{id: "claude.disableAllHooks", files: map[string]string{".claude/settings.json": `{"disableAllHooks":true}`}},
	{id: "claude.managed.disableAllHooks", goos: "windows", files: map[string]string{`C:\Program Files\ClaudeCode\managed-settings.json`: `{"disableAllHooks":true}`}},
	{id: "claude.managed.allowManagedHooksOnly", goos: "linux", files: map[string]string{"/etc/claude-code/managed-settings.json": `{"allowManagedHooksOnly":true}`}},
	{id: "copilot-cli.disableAllHooks", files: map[string]string{".copilot/settings.json": `{"disableAllHooks":true}`}},
	{id: "qwen.disableAllHooks", files: map[string]string{".qwen/settings.json": `{"disableAllHooks":true}`}},
	{id: "gemini.hooksConfig.enabled", files: map[string]string{".gemini/settings.json": `{"hooksConfig":{"enabled":false}}`}},
	{id: "factory.hooksDisabled", files: map[string]string{".factory/settings.json": `{"hooksDisabled":true}`}},
	{id: "factory.userlocal.hooksDisabled", files: map[string]string{".factory/settings.local.json": `{"hooksDisabled":true}`}},
	{id: "factory.managed.hooksDisabled", goos: "linux", files: map[string]string{"/etc/factory/settings.json": `{"hooksDisabled":true}`}},
	{id: "factory.managed.allowManagedHooksOnly", goos: "windows", files: map[string]string{`C:\Program Files\Factory\settings.json`: `{"allowManagedHooksOnly":true}`}},
	{id: "factory.orgcache.hooksDisabled", files: map[string]string{".factory/org-managed-settings.cache.json": `{"orgId":"o","managedSettings":{"hooksDisabled":true}}`}},
	{id: "factory.orgcache.allowManagedHooksOnly", files: map[string]string{".factory/org-managed-settings.cache.json": `{"managedSettings":{"allowManagedHooksOnly":true,"modelPolicy":{}}}`}},
	{id: "codebuddy.disableAllHooks", files: map[string]string{".codebuddy/settings.json": `{"disableAllHooks":true}`}},
	{id: "codebuddy.userlocal.disableAllHooks", files: map[string]string{".codebuddy/settings.local.json": `{"disableAllHooks":true}`}},
	{id: "ibm-bob.disableGlobalHooks", files: map[string]string{".bob/settings/settings.json": `{"disableGlobalHooks":true}`}},
	{id: "autohand.hooks.enabled", files: map[string]string{".autohand/config.json": `{"provider":"x","auth":{"token":"t"},"hooks":{"enabled":false,"hooks":[]}}`}},
	{id: "cortex.disableAllHooks", files: map[string]string{".snowflake/cortex/settings.json": `{"disableAllHooks":true}`}},
	{id: "cortex.hooks.disableAllHooks", files: map[string]string{".snowflake/cortex/hooks.json": `{"disableAllHooks":true,"hooks":{}}`}},
	{id: "cortex.home.disableAllHooks", files: map[string]string{".cortex/settings.json": `{"disableAllHooks":true}`}},
	{id: "dirac.hooksEnabled", files: map[string]string{".dirac/data/globalState.json": `{"hooksEnabled":false}`}},
	{id: "dimcode.hooks-disabled", files: map[string]string{
		".dimcode/v2/hooks.json":          dimHooks,
		".dimcode/v2/hooks-disabled.json": `{"version":1,"disabled":{"` + dimOwnHash + `":{"command":"x"}}}`,
	}},
	{id: "command-code.mods.disableAll", files: map[string]string{".commandcode/settings.json": `{"mods":{"disableAll":true}}`}},
	{id: "goose.disabledPlugins", files: map[string]string{".config/goose/settings.json": `{"disabledPlugins":["other","superbased-observer"]}`}},
	{id: "junie.JUNIE_CONFIG_DEFAULT_LOCATIONS", env: map[string]string{"JUNIE_CONFIG_DEFAULT_LOCATIONS": " False "}},
	{id: "devin.read_config_from.claude", files: map[string]string{".config/devin/config.json": `{"read_config_from":{"claude":false,"cursor":true}}`}},
	{id: "claude.project.disableAllHooks", files: map[string]string{"P/.claude/settings.json": `{"disableAllHooks":true}`}},
	{id: "claude.local.disableAllHooks", files: map[string]string{"P/.claude/settings.local.json": `{"disableAllHooks":true}`}},
	{id: "copilot-cli.project.disableAllHooks", files: map[string]string{"P/.github/copilot/settings.json": `{"disableAllHooks":true}`}},
	{id: "copilot-cli.local.disableAllHooks", files: map[string]string{"P/.github/copilot/settings.local.json": `{"disableAllHooks":true}`}},
	{id: "qwen.project.disableAllHooks", files: map[string]string{"P/.qwen/settings.json": `{"disableAllHooks":true}`}},
	{id: "gemini.project.hooksConfig.enabled", files: map[string]string{"P/.gemini/settings.json": `{"hooksConfig":{"enabled":false}}`}},
	{id: "factory.project.hooksDisabled", files: map[string]string{"P/.factory/settings.json": `{"hooksDisabled":true}`}},
	{id: "factory.local.hooksDisabled", files: map[string]string{"P/.factory/settings.local.json": `{"hooksDisabled":true}`}},
	{id: "codebuddy.project.disableAllHooks", files: map[string]string{"P/.codebuddy/settings.json": `{"disableAllHooks":true}`}},
	{id: "codebuddy.local.disableAllHooks", files: map[string]string{"P/.codebuddy/settings.local.json": `{"disableAllHooks":true}`}},
	{id: "goose.project.disabledPlugins", files: map[string]string{"P/.config/goose/settings.json": `{"disabledPlugins":["superbased-observer"]}`}},
	{id: "goose.local.disabledPlugins", files: map[string]string{"P/.config/goose/settings.local.json": `{"disabledPlugins":["superbased-observer"]}`}},
	{id: "devin.project.read_config_from.claude", files: map[string]string{"P/.devin/config.json": `{"read_config_from":{"claude":false}}`}},
	{id: "devin.local.read_config_from.claude", files: map[string]string{"P/.devin/config.local.json": `{"read_config_from":{"claude":false}}`}},
	// Wave 4 (lane w4-layers): CLI-5, S-18, FU-51.
	{id: "gemini.system.hooksConfig.enabled", goos: "windows", files: map[string]string{`C:\ProgramData\gemini-cli\settings.json`: "{\n // admin\n \"hooksConfig\": {\"enabled\": false},\n}"}},
	{id: "qwen.system.disableAllHooks", goos: "linux", files: map[string]string{"/etc/qwen-code/settings.json": `{"disableAllHooks":true}`}},
	{id: "qwen.QWEN_CODE_SAFE_MODE", env: map[string]string{"QWEN_CODE_SAFE_MODE": "1"}},
	{id: "qwen.QWEN_CODE_SIMPLE", env: map[string]string{"QWEN_CODE_SIMPLE": " TRUE "}},
	{id: "command-code.mods.disabled", files: map[string]string{".commandcode/settings.json": `{"mods":{"disabled":["titling","observer-guard"]}}`}},
	{id: "kimchi.resources.hooks.bash", files: map[string]string{".config/kimchi/harness/settings.json": `{"defaultModel":"m","resources":{"hooks.bash":false,"hooks.bash.project.x":true}}`}},
	{id: "command-code.project.mods.disableAll", files: map[string]string{"P/.commandcode/settings.json": `{"mods":{"disableAll":true}}`}},
	{id: "command-code.local.mods.disableAll", files: map[string]string{"P/.commandcode/settings.local.json": `{"mods":{"disableAll":true}}`}},
	{id: "command-code.project.mods.disabled", files: map[string]string{"P/.commandcode/settings.json": `{"mods":{"disabled":["observer-guard"]}}`}},
	{id: "command-code.local.mods.disabled", files: map[string]string{"P/.commandcode/settings.local.json": `{"mods":{"disabled":["observer-guard"]}}`}},
	{id: "vtcode.workspace.use_root_config", files: map[string]string{"P/.vtcode/vtcode.toml": "[agent]\nprovider = \"x\"\n\n[workspace]\nuse_root_config = true\n"}},
	{id: "vtcode.root.use_root_config", files: map[string]string{"P/vtcode.toml": "[workspace]\nuse_root_config = true\n"}},
}

// testManagedFiles stands in for the caller's agentconfig resolver: the
// FileRow paths of the two managed files, per GOOS.
func testManagedFiles(id, goos string) []string {
	paths := map[string]map[string]string{
		claudeManagedSettingsFile:    {"linux": "/etc/claude-code/managed-settings.json", "windows": `C:\Program Files\ClaudeCode\managed-settings.json`},
		factorySystemSettingsFile:    {"linux": "/etc/factory/settings.json", "windows": `C:\Program Files\Factory\settings.json`},
		"gemini-cli/system-settings": {"linux": "/etc/gemini-cli/settings.json", "windows": `C:\ProgramData\gemini-cli\settings.json`},
		"qwen-code/system-settings":  {"linux": "/etc/qwen-code/settings.json", "windows": `C:\ProgramData\qwen-code\settings.json`},
	}
	if p := paths[id][goos]; p != "" {
		return []string{p}
	}
	return nil
}

// rowOptions builds the Options one row case runs under.
func rowOptions(c rowCase) Options {
	home, proj := "/h", "/w/app"
	files := map[string]string{}
	for rel, body := range c.files {
		switch {
		case strings.HasPrefix(rel, "P/"):
			files[filepath.Join(proj, filepath.FromSlash(strings.TrimPrefix(rel, "P/")))] = body
		case strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `C:\`):
			files[rel] = body
		default:
			files[filepath.Join(home, filepath.FromSlash(rel))] = body
		}
	}
	return Options{
		Home: home, GOOS: c.goos, ManagedFiles: testManagedFiles, ProjectRoots: []string{proj},
		Getenv: func(k string) string { return c.env[k] }, OwnHookCommand: ownCommand,
		IncludeReplayOnly: true, ReadFile: reader(files),
	}
}

// TestDetectEveryRow runs one case per switch row: the row, and only the
// row, is found; a write-guard-only row (FU-159) is never found, since no
// reader may claim its effect.
func TestDetectEveryRow(t *testing.T) {
	guardOnly := map[string]bool{}
	for _, s := range Switches {
		guardOnly[s.ID] = s.WriteGuardOnly
	}
	for _, c := range rowCases {
		t.Run(c.id, func(t *testing.T) {
			var ids []string
			for _, f := range Detect(rowOptions(c)) {
				ids = append(ids, f.SwitchID)
			}
			want := []string{c.id}
			if guardOnly[c.id] {
				want = nil
			}
			if !reflect.DeepEqual(ids, want) {
				t.Fatalf("Detect = %v, want %v", ids, want)
			}
		})
	}
}

// TestEverySwitchHasARowCase pins rowCases to the table.
func TestEverySwitchHasARowCase(t *testing.T) {
	have := map[string]bool{}
	for _, c := range rowCases {
		have[c.id] = true
	}
	for _, s := range Switches {
		if !have[s.ID] {
			t.Errorf("%s: no rowCases entry", s.ID)
		}
	}
}

// TestDetectManagedFromTheCaller pins CC-5: the managed path comes from the
// caller (Options.ManagedFiles), so the Windows file is the one under
// C:\Program Files, and no resolver means no managed row.
func TestDetectManagedFromTheCaller(t *testing.T) {
	legacy := `C:\ProgramData\ClaudeCode\managed-settings.json`
	current := `C:\Program Files\ClaudeCode\managed-settings.json`
	cases := []struct {
		name    string
		files   map[string]string
		managed func(string, string) []string
		want    []string
	}{
		{"program files read", map[string]string{current: `{"disableAllHooks":true}`}, testManagedFiles, []string{"claude.managed.disableAllHooks"}},
		{"legacy programdata not read", map[string]string{legacy: `{"disableAllHooks":true}`}, testManagedFiles, nil},
		{"no resolver", map[string]string{current: `{"disableAllHooks":true}`}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ids []string
			for _, f := range Detect(Options{GOOS: "windows", ManagedFiles: tc.managed, ReadFile: reader(tc.files)}) {
				ids = append(ids, f.SwitchID)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("Detect = %v, want %v", ids, tc.want)
			}
		})
	}
}

// TestDetectManagedDropInsMergeInOrder pins the drop-in rule: a later file
// replaces an earlier one's value, and the finding names the file that set
// the effective value.
func TestDetectManagedDropInsMergeInOrder(t *testing.T) {
	base, d1, d2 := "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/10-a.json", "/etc/claude-code/managed-settings.d/20-b.json"
	order := func(string, string) []string { return []string{base, d1, d2} }
	cases := []struct {
		name  string
		files map[string]string
		path  string
	}{
		{"drop-in turns it on", map[string]string{base: `{}`, d1: `{"disableAllHooks":true}`}, d1},
		{"later drop-in turns it back off", map[string]string{base: `{"disableAllHooks":true}`, d2: `{"disableAllHooks":false}`}, ""},
		{"later drop-in without the key keeps it", map[string]string{d1: `{"disableAllHooks":true}`, d2: `{"model":"x"}`}, d1},
		{"base only", map[string]string{base: `{"disableAllHooks":true}`}, base},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, f := range Detect(Options{GOOS: "linux", ManagedFiles: order, ReadFile: reader(tc.files)}) {
				if f.SwitchID == "claude.managed.disableAllHooks" {
					got = f.Path
				}
			}
			if got != tc.path {
				t.Fatalf("finding path = %q, want %q", got, tc.path)
			}
		})
	}
}

// TestDetectEnvRow pins the env-scope rule (S-13): only the documented off
// value counts, and no Getenv skips the row.
func TestDetectEnvRow(t *testing.T) {
	cases := []struct {
		name   string
		getenv func(string) string
		want   bool
	}{
		{"false", func(string) string { return "false" }, true},
		{"true", func(string) string { return "true" }, false},
		{"unset", func(string) string { return "" }, false},
		{"no getenv", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var getenv func(string) string
			if tc.getenv != nil {
				getenv = func(k string) string {
					if k == "JUNIE_CONFIG_DEFAULT_LOCATIONS" {
						return tc.getenv(k)
					}
					return ""
				}
			}
			fs := Detect(Options{Getenv: getenv, ReadFile: reader(nil)})
			got := len(fs) == 1 && fs[0].SwitchID == "junie.JUNIE_CONFIG_DEFAULT_LOCATIONS" && fs[0].Path == EnvPath
			if got != tc.want || (!tc.want && len(fs) != 0) {
				t.Fatalf("Detect = %+v, want found=%v", fs, tc.want)
			}
		})
	}
}

// TestDimCodeDenyList pins the hash-only membership read (W-3a, D5): a
// deny list holding Observer's entry hash is a finding; another tool's
// hash, a wrong version, a malformed record, a missing hooks file or no
// own-command recogniser is not.
func TestDimCodeDenyList(t *testing.T) {
	hooksRel := ".dimcode/v2/hooks.json"
	denyRel := ".dimcode/v2/hooks-disabled.json"
	lint := dimCodeEntry{Event: "PreToolUse", Command: "lint.sh"}.hash()
	cases := []struct {
		name  string
		hooks string
		deny  string
		own   func(string) bool
		want  bool
	}{
		{"observer entry denied", dimHooks, `{"version":1,"disabled":{"` + dimOwnHash + `":{"command":"x","at":1}}}`, ownCommand, true},
		{"record of any shape is skipped", dimHooks, `{"version":1,"disabled":{"` + dimOwnHash + `":"opaque"}}`, ownCommand, true},
		{"only another hook denied", dimHooks, `{"version":1,"disabled":{"` + lint + `":{}}}`, ownCommand, false},
		{"wrong version", dimHooks, `{"version":2,"disabled":{"` + dimOwnHash + `":{}}}`, ownCommand, false},
		{"malformed deny list", dimHooks, `{"version":1,"disabled":`, ownCommand, false},
		{"no hooks file", "", `{"version":1,"disabled":{"` + dimOwnHash + `":{}}}`, ownCommand, false},
		{"no recogniser", dimHooks, `{"version":1,"disabled":{"` + dimOwnHash + `":{}}}`, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{filepath.Join("/h", filepath.FromSlash(denyRel)): tc.deny}
			if tc.hooks != "" {
				files[filepath.Join("/h", filepath.FromSlash(hooksRel))] = tc.hooks
			}
			fs := Detect(Options{Home: "/h", OwnHookCommand: tc.own, ReadFile: reader(files)})
			if got := len(fs) == 1 && fs[0].SwitchID == "dimcode.hooks-disabled"; got != tc.want {
				t.Fatalf("Detect = %+v, want found=%v", fs, tc.want)
			}
		})
	}
}

// TestDimCodeHashMatchesTheVendor pins the canonical form against vectors
// computed by DimCode's own hashCommandHook under node (matcher, Windows
// command and statusMessage set; HTML characters unescaped).
func TestDimCodeHashMatchesTheVendor(t *testing.T) {
	str := func(s string) *string { return &s }
	thirty := 30.0
	cases := []struct {
		e    dimCodeEntry
		want string
	}{
		{dimCodeEntry{Event: "PreToolUse", Command: "/home/u/.local/bin/observer hook dimcode --event PreToolUse <x> & y", Timeout: &thirty}, dimOwnHash},
		{dimCodeEntry{Event: "UserPromptSubmit", Matcher: str("Bash|Edit"), Command: "observer hook dimcode", CommandWindows: str("observer.exe hook dimcode"), StatusMessage: str("gate")}, "28128be65c7d9480a24aef934b03819b27fd8cab9882e46ca84ad2ff95af23c0"},
	}
	for _, tc := range cases {
		if got := tc.e.hash(); got != tc.want {
			t.Errorf("%s: hash = %s, want %s", tc.e.Event, got, tc.want)
		}
	}
}

// TestDetectContainsRow pins list membership: the exact entry counts, a
// look-alike or a non-list does not.
func TestDetectContainsRow(t *testing.T) {
	p := filepath.Join("/h", ".config", "goose", "settings.json")
	cases := []struct {
		body string
		want bool
	}{
		{`{"disabledPlugins":["superbased-observer"]}`, true},
		{`{"disabledPlugins":["superbased-observer-old"]}`, false},
		{`{"disabledPlugins":"superbased-observer"}`, false},
		{`{"enabledPlugins":["superbased-observer"]}`, false},
	}
	for _, tc := range cases {
		fs := Detect(Options{Home: "/h", ReadFile: reader(map[string]string{p: tc.body})})
		if got := len(fs) == 1; got != tc.want {
			t.Errorf("%s: found=%v, want %v", tc.body, got, tc.want)
		}
	}
}

// TestDetectHomeRelOS pins Devin's per-OS user file (S-10): %APPDATA% on
// windows, ~/.config elsewhere.
func TestDetectHomeRelOS(t *testing.T) {
	body := `{"read_config_from":{"claude":false}}`
	win := filepath.Join("/h", "AppData", "Roaming", "devin", "config.json")
	lin := filepath.Join("/h", ".config", "devin", "config.json")
	cases := []struct {
		goos, file string
		want       bool
	}{
		{"windows", win, true},
		{"windows", lin, false},
		{"linux", lin, true},
		{"linux", win, false},
	}
	for _, tc := range cases {
		fs := Detect(Options{Home: "/h", GOOS: tc.goos, IncludeReplayOnly: true, ReadFile: reader(map[string]string{tc.file: body})})
		if got := len(fs) == 1; got != tc.want {
			t.Errorf("%s %s: found=%v, want %v", tc.goos, tc.file, got, tc.want)
		}
	}
}

// TestDetectReplayOnlyIsOptIn pins S-10's honesty rule: a switch that only
// stops a replay is invisible to a caller asking whether the tool's own
// hooks are off.
func TestDetectReplayOnlyIsOptIn(t *testing.T) {
	files := map[string]string{filepath.Join("/h", ".config", "devin", "config.json"): `{"read_config_from":{"claude":false}}`}
	if fs := Detect(Options{Home: "/h", ReadFile: reader(files)}); len(fs) != 0 {
		t.Fatalf("default Detect = %+v, want none", fs)
	}
	fs := Detect(Options{Home: "/h", IncludeReplayOnly: true, ReadFile: reader(files)})
	if len(fs) != 1 || !fs[0].ReplayOnly {
		t.Fatalf("IncludeReplayOnly Detect = %+v", fs)
	}
}

// TestMemberValueDecodesOneMember pins the member-only read (D16): the
// named member is decoded, a sibling holding anything is not needed, and a
// file that is not an object yields nothing.
func TestMemberValueDecodesOneMember(t *testing.T) {
	cases := []struct {
		body   string
		member string
		want   any
	}{
		{`{"auth":{"token":"t"},"hooks":{"enabled":false}}`, "hooks", map[string]any{"enabled": false}},
		{`{"auth":{"token":"t"}}`, "hooks", nil},
		{`[{"hooks":{}}]`, "hooks", nil},
		{"{\n // c\n \"hooks\": {\"enabled\": false},\n}", "hooks", map[string]any{"enabled": false}},
		{bom + `{"hooks":true}`, "hooks", true},
	}
	for _, tc := range cases {
		if got := memberValue([]byte(tc.body), tc.member); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: memberValue = %#v, want %#v", tc.body, got, tc.want)
		}
	}
}

// claudeProjectOnlyReplayHosts are the hosts that run a repository's
// Claude Code hook settings but never the user file, so a user-scope Claude
// Code switch does not silence them (table.go, claudeUserReplayHosts).
var claudeProjectOnlyReplayHosts = map[string]string{
	"copilot-cli": "surface-gap S-8: the Copilot CLI runtime reads only a repository's .claude/settings(.local).json; its Claude replay binding is G2's",
}

// TestReplayHostsCoverTheRegistry pins the Claude replay host lists to the
// registry (W-3): every tool with a hook binding reached through Claude
// Code's settings is silenced by a Claude Code switch in every scope it
// reads (the project scope only, for claudeProjectOnlyReplayHosts).
func TestReplayHostsCoverTheRegistry(t *testing.T) {
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.ReplayedVia != "claude-code" {
				continue
			}
			_, projectOnly := claudeProjectOnlyReplayHosts[c.Tool]
			if (!projectOnly && !slices.Contains(claudeUserReplayHosts, c.Tool)) || !slices.Contains(claudeProjectReplayHosts, c.Tool) {
				t.Errorf("%s replays Claude Code's hooks (%s %s) but is missing from a Claude replay host list", c.Tool, b.Cap, b.NativeEvent)
			}
		}
	}
	for tool := range claudeProjectOnlyReplayHosts {
		if slices.Contains(claudeUserReplayHosts, tool) {
			t.Errorf("%s is listed as project-only but is on the user replay host list", tool)
		}
	}
}

// TestDetectUserFilesResolver pins FU-38: a user row with a catalogue File
// reads the path the caller's resolver returns (its relocation rules
// applied), and falls back to the default home without one.
func TestDetectUserFilesResolver(t *testing.T) {
	moved := filepath.Join("/relocated", "codebuddy", "settings.json")
	def := filepath.Join("/h", ".codebuddy", "settings.json")
	resolve := func(id string) (string, bool) {
		if id == "codebuddy/user-settings" {
			return moved, true
		}
		return "", false
	}
	cases := []struct {
		name    string
		files   map[string]string
		resolve func(string) (string, bool)
		want    []string
	}{
		{"relocated file is read", map[string]string{moved: `{"disableAllHooks":true}`, def: `{}`}, resolve, []string{"codebuddy.disableAllHooks"}},
		{"the default home is not read once relocated", map[string]string{def: `{"disableAllHooks":true}`}, resolve, nil},
		{"no resolver falls back to the home", map[string]string{def: `{"disableAllHooks":true}`}, nil, []string{"codebuddy.disableAllHooks"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ids []string
			for _, f := range Detect(Options{Home: "/h", UserFiles: tc.resolve, ReadFile: reader(tc.files)}) {
				if f.SwitchID == "codebuddy.disableAllHooks" {
					ids = append(ids, f.SwitchID)
				}
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("Detect = %v, want %v", ids, tc.want)
			}
		})
	}
}

// TestTOMLMemberValue pins the TOML member read (W-6): the one table is
// decoded, a malformed file or a missing member yields nothing.
func TestTOMLMemberValue(t *testing.T) {
	cases := []struct {
		body string
		want any
	}{
		{"[provider_overrides.openai]\napi_key = \"k\"\n[workspace]\nuse_root_config = true\n", map[string]any{"use_root_config": true}},
		{"[agent]\nx = 1\n", nil},
		{"[workspace\n", nil},
	}
	for _, tc := range cases {
		if got := tomlMemberValue([]byte(tc.body), "workspace"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %#v, want %#v", tc.body, got, tc.want)
		}
	}
}

// TestEnvTruthy pins the truthy env spellings (CLI-5 qwen rows).
func TestEnvTruthy(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, " Yes ": true, "on": true, "0": false, "false": false, "": false, "2": false} { //nolint:gocritic // " Yes " is the intentional test input: envTruthy must TrimSpace.
		if got := envTruthy(v); got != want {
			t.Errorf("envTruthy(%q) = %v, want %v", v, got, want)
		}
	}
}
