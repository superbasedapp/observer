package hookdisable

import (
	"errors"
	"go/build"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// bom is a UTF-8 byte order mark, spelled as an escape so the source stays BOM-free.
const bom = "\ufeff"

func reader(files map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("absent")
	}
}

func TestDetect(t *testing.T) {
	home := "/h"
	claude := filepath.Join(home, ".claude", "settings.json")
	qwen := filepath.Join(home, ".qwen", "settings.json")
	gemini := filepath.Join(home, ".gemini", "settings.json")
	factory := filepath.Join(home, ".factory", "settings.json")
	managed := "/etc/claude-code/managed-settings.json"
	managedFiles := func(id, goos string) []string {
		if id == claudeManagedSettingsFile && goos == "linux" {
			return []string{managed}
		}
		return nil
	}
	cases := []struct {
		name  string
		files map[string]string
		goos  string
		want  []string
	}{
		{"nothing installed", nil, "linux", nil},
		{"claude off", map[string]string{claude: `{"disableAllHooks":true}`}, "linux", []string{"claude.disableAllHooks"}},
		{"claude explicitly on", map[string]string{claude: `{"disableAllHooks":false}`}, "linux", nil},
		{"claude non-bool is not a finding", map[string]string{claude: `{"disableAllHooks":"yes"}`}, "linux", nil},
		{"claude malformed is not a finding", map[string]string{claude: `{"disableAllHooks":tru`}, "linux", nil},
		{"claude BOM", map[string]string{claude: bom + "{\"disableAllHooks\":true}"}, "linux", []string{"claude.disableAllHooks"}},
		{"managed off", map[string]string{managed: `{"disableAllHooks":true}`}, "linux", []string{"claude.managed.disableAllHooks"}},
		{"managed only", map[string]string{managed: `{"allowManagedHooksOnly":true}`}, "linux", []string{"claude.managed.allowManagedHooksOnly"}},
		{"managed skipped without GOOS", map[string]string{managed: `{"disableAllHooks":true}`}, "", nil},
		{"qwen off", map[string]string{qwen: `{"disableAllHooks":true}`}, "linux", []string{"qwen.disableAllHooks"}},
		{"gemini off", map[string]string{gemini: `{"hooksConfig":{"enabled":false}}`}, "linux", []string{"gemini.hooksConfig.enabled"}},
		{"gemini on", map[string]string{gemini: `{"hooksConfig":{"enabled":true}}`}, "linux", nil},
		{"gemini key absent", map[string]string{gemini: `{"hooksConfig":{}}`}, "linux", nil},
		{"copilot-cli disableAllHooks is not a switch (FU-159)", map[string]string{filepath.Join(home, ".copilot", "settings.json"): `{"disableAllHooks":true}`}, "linux", nil},
		{"factory off", map[string]string{factory: `{"hooksDisabled":true}`}, "linux", []string{"factory.hooksDisabled"}},
		{
			"several",
			map[string]string{claude: `{"disableAllHooks":true}`, factory: `{"hooksDisabled":true}`},
			"linux",
			[]string{"claude.disableAllHooks", "factory.hooksDisabled"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(Options{Home: home, GOOS: tc.goos, ManagedFiles: managedFiles, ReadFile: reader(tc.files)})
			var ids []string
			for _, f := range got {
				ids = append(ids, f.SwitchID)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("Detect = %v, want %v", ids, tc.want)
			}
		})
	}
}

// TestDetectProjectScope pins one case per project-scope row (T-910): the
// switch is found in the project directory, an explicit "on" value or a
// non-boolean is not a finding, and a JSON-with-comments file still counts.
func TestDetectProjectScope(t *testing.T) {
	// The finding carries the root cleaned in the host separator.
	root := filepath.FromSlash("/work/app")
	p := func(rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no project files", nil, nil},
		{"claude project off", map[string]string{p(".claude/settings.json"): `{"disableAllHooks":true}`}, []string{"claude.project.disableAllHooks"}},
		{"claude local off", map[string]string{p(".claude/settings.local.json"): `{"permissions":{"allow":["Bash(ls)"]},"disableAllHooks":true}`}, []string{"claude.local.disableAllHooks"}},
		{"claude local permission grants only", map[string]string{p(".claude/settings.local.json"): `{"permissions":{"allow":["Bash(npm test)"]}}`}, nil},
		{"claude local explicitly on", map[string]string{p(".claude/settings.local.json"): `{"disableAllHooks":false}`}, nil},
		{"claude local string is not a bool", map[string]string{p(".claude/settings.local.json"): `{"disableAllHooks":"true"}`}, nil},
		{"copilot-cli repo disableAllHooks is not a switch (FU-159)", map[string]string{p(".github/copilot/settings.json"): `{"disableAllHooks":true}`}, nil},
		{"copilot-cli local disableAllHooks is not a switch (FU-159)", map[string]string{p(".github/copilot/settings.local.json"): `{"disableAllHooks":true}`}, nil},
		{"codebuddy local off with comments", map[string]string{p(".codebuddy/settings.local.json"): "{\n  // turned off\n  \"disableAllHooks\": true, /* trailing */\n}"}, []string{"codebuddy.local.disableAllHooks"}},
		{"qwen workspace off", map[string]string{p(".qwen/settings.json"): `{"disableAllHooks":true}`}, []string{"qwen.project.disableAllHooks"}},
		{"gemini workspace off", map[string]string{p(".gemini/settings.json"): `{"hooksConfig":{"enabled":false}}`}, []string{"gemini.project.hooksConfig.enabled"}},
		{"gemini workspace on", map[string]string{p(".gemini/settings.json"): `{"hooksConfig":{"enabled":true}}`}, nil},
		{"factory project off", map[string]string{p(".factory/settings.json"): `{"hooksDisabled":true}`}, []string{"factory.project.hooksDisabled"}},
		{"factory local off", map[string]string{p(".factory/settings.local.json"): `{"hooksDisabled":true}`}, []string{"factory.local.hooksDisabled"}},
		{"comment mentioning the key is not a finding", map[string]string{p(".qwen/settings.json"): "{\n // \"disableAllHooks\": true\n \"model\": {}\n}"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(Options{ProjectRoots: []string{root}, ReadFile: reader(tc.files)})
			var ids []string
			for _, f := range got {
				ids = append(ids, f.SwitchID)
				if f.Scope != ScopeProject || f.ProjectRoot != root {
					t.Errorf("%s: scope %q root %q", f.SwitchID, f.Scope, f.ProjectRoot)
				}
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("Detect = %v, want %v", ids, tc.want)
			}
		})
	}
}

// TestDetectUserLocalFactory pins the user-scope settings.local.json row.
func TestDetectUserLocalFactory(t *testing.T) {
	f := filepath.Join("/h", ".factory", "settings.local.json")
	got := Detect(Options{Home: "/h", ReadFile: reader(map[string]string{f: `{"hooksDisabled":true}`})})
	if len(got) != 1 || got[0].SwitchID != "factory.userlocal.hooksDisabled" {
		t.Fatalf("Detect = %+v", got)
	}
}

// TestDetectProjectRootsBounded pins the scan bound: duplicates and empty
// roots are dropped, and only the first MaxProjectRoots distinct roots are
// read.
func TestDetectProjectRootsBounded(t *testing.T) {
	var roots []string
	files := map[string]string{}
	for i := 0; i < MaxProjectRoots+10; i++ {
		r := filepath.Join("/p", strings.Repeat("x", i+1))
		roots = append(roots, r, r, "")
		files[filepath.Join(r, ".claude", "settings.local.json")] = `{"disableAllHooks":true}`
	}
	reads := 0
	read := func(p string) ([]byte, error) {
		reads++
		return reader(files)(p)
	}
	got := Detect(Options{ProjectRoots: roots, ReadFile: read})
	if len(got) != MaxProjectRoots {
		t.Fatalf("findings = %d, want %d", len(got), MaxProjectRoots)
	}
	projectRows := 0
	for _, s := range Switches {
		if s.Scope == ScopeProject {
			projectRows++
		}
	}
	if max := projectRows * MaxProjectRoots; reads > max {
		t.Fatalf("reads = %d, want at most %d", reads, max)
	}
}

// TestDetectProjectSkippedWithoutRoots pins that user and managed callers
// that pass no roots read no project file: every read is a user-scope file
// under the home.
func TestDetectProjectSkippedWithoutRoots(t *testing.T) {
	read := func(p string) ([]byte, error) {
		if !strings.HasPrefix(p, filepath.Clean("/h")+string(filepath.Separator)) {
			t.Errorf("read %s outside the home without roots", p)
		}
		return nil, errors.New("absent")
	}
	Detect(Options{Home: "/h", GOOS: "linux", ReadFile: read})
}

// TestDetectClaudeSilencesTheReplayHosts pins who a Claude Code switch
// silences, per scope (S-8): the user file is not read by Copilot CLI or
// VS Code Copilot, a repository's .claude files are; Cortex Code and Kimchi
// replay both (W-3).
func TestDetectClaudeSilencesTheReplayHosts(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{
			"user file",
			Options{Home: "/h", ReadFile: reader(map[string]string{filepath.Join("/h", ".claude", "settings.json"): `{"disableAllHooks":true}`})},
			[]string{"claude-code", "cortex-code", "cursor", "deepseek", "devin", "grok", "kimchi"},
		},
		{
			"project file",
			Options{ProjectRoots: []string{"/w"}, ReadFile: reader(map[string]string{filepath.Join("/w", ".claude", "settings.local.json"): `{"disableAllHooks":true}`})},
			[]string{"claude-code", "copilot", "copilot-cli", "cortex-code", "cursor", "deepseek", "devin", "grok", "kimchi"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AffectedTools(Detect(tc.o)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("AffectedTools = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectNilReader(t *testing.T) {
	if got := Detect(Options{Home: "/h"}); got != nil {
		t.Fatalf("nil reader: %v", got)
	}
}

func TestTrackerTransitions(t *testing.T) {
	a := Finding{SwitchID: "a", Path: "/p"}
	b := Finding{SwitchID: "b", Path: "/p"}
	var tr Tracker
	steps := []struct {
		in   []Finding
		want []string
	}{
		{[]Finding{a}, []string{"a"}},
		{[]Finding{a}, nil},
		{[]Finding{a, b}, []string{"b"}},
		{nil, nil},
		{[]Finding{a}, []string{"a"}},
	}
	for i, s := range steps {
		var ids []string
		for _, f := range tr.Turned(s.in) {
			ids = append(ids, f.SwitchID)
		}
		if !reflect.DeepEqual(ids, s.want) {
			t.Fatalf("step %d: Turned = %v, want %v", i, ids, s.want)
		}
	}
}

func TestSwitchTableRowsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Switches {
		if seen[s.ID] {
			t.Errorf("duplicate switch id %s", s.ID)
		}
		seen[s.ID] = true
		if len(s.Tools) == 0 || s.Key == "" || s.Effect == "" || s.Grounding == "" {
			t.Errorf("%s: incomplete row", s.ID)
		}
		switch s.Scope {
		case ScopeUser:
			if s.HomeRel == "" {
				t.Errorf("%s: user row without HomeRel", s.ID)
			}
		case ScopeManaged:
			if s.ManagedFile == "" || s.HomeRel != "" || s.ProjectRel != "" {
				t.Errorf("%s: managed row needs ManagedFile only", s.ID)
			}
		case ScopeProject:
			if s.ProjectRel == "" || s.HomeRel != "" || s.ManagedFile != "" {
				t.Errorf("%s: project row needs ProjectRel only", s.ID)
			}
		case ScopeEnv:
			if (s.EnvOff == "") == !s.EnvTruthy || s.HomeRel != "" || s.ProjectRel != "" || s.ManagedFile != "" {
				t.Errorf("%s: env row needs Key and exactly one of EnvOff or EnvTruthy", s.ID)
			}
		default:
			t.Errorf("%s: scope %q", s.ID, s.Scope)
		}
		if s.DenyList != "" && (denyListDialects[s.DenyList] == nil || s.DenyHooksRel == "" || s.Scope != ScopeUser) {
			t.Errorf("%s: deny-list row needs a known dialect, DenyHooksRel and user scope", s.ID)
		}
		if strings.ContainsAny(strings.Split(s.Key, ".")[0], `",`) {
			t.Errorf("%s: the key's first segment must be a plain member name", s.ID)
		}
		if s.Format != "" && s.Format != FormatTOML {
			t.Errorf("%s: unknown format %q", s.ID, s.Format)
		}
		if s.File != "" && s.Scope != ScopeUser {
			t.Errorf("%s: File names a user-scope row's catalogue file", s.ID)
		}
		if len(s.KeyPath) > 0 && strings.Join(s.KeyPath, ".") != s.Key {
			t.Errorf("%s: Key must be the dotted KeyPath", s.ID)
		}
		if s.KeySwitch() == (s.Scope == ScopeEnv || s.Contains != "" || s.DenyList != "" || s.Format != "" || len(s.KeyPath) > 0) {
			t.Errorf("%s: KeySwitch disagrees with the row's shape", s.ID)
		}
	}
}

// TestImportsArePure pins the package free of database, network and file
// watching imports (CLAUDE.md module boundaries).
func TestImportsArePure(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		for _, bad := range []string{"database/sql", "net/http", "fsnotify", "os/exec", "superbased-observer/internal/store"} {
			if strings.Contains(imp, bad) {
				t.Errorf("hookdisable imports %s", imp)
			}
		}
		if imp == "os" {
			t.Errorf("hookdisable imports os: the file read must be injected")
		}
	}
}

// TestClaudeUserReplayHostsIsACopy: the exported host list matches the
// table the user rows use and a caller cannot edit the table through it.
func TestClaudeUserReplayHostsIsACopy(t *testing.T) {
	got := ClaudeUserReplayHosts()
	if !reflect.DeepEqual(got, claudeUserReplayHosts) {
		t.Fatalf("ClaudeUserReplayHosts = %v, want %v", got, claudeUserReplayHosts)
	}
	got[0] = "edited"
	if claudeUserReplayHosts[0] == "edited" {
		t.Fatal("ClaudeUserReplayHosts returned the table itself")
	}
	proj := ClaudeProjectReplayHosts()
	if !reflect.DeepEqual(proj, claudeProjectReplayHosts) {
		t.Fatalf("ClaudeProjectReplayHosts = %v, want %v", proj, claudeProjectReplayHosts)
	}
	proj[0] = "edited"
	if claudeProjectReplayHosts[0] == "edited" {
		t.Fatal("ClaudeProjectReplayHosts returned the table itself")
	}
}

// TestNoCopilotCLIDisableAllHooksSwitch pins FU-159: Copilot CLI 1.0.105 did
// not stop ~/.copilot/hooks (Observer's hook included) with disableAllHooks
// true in ~/.copilot/settings.json or the repo .github/copilot/settings.json
// (Windows rig run 2026-10-29), so no row may claim it silences copilot-cli:
// every such row is write-guard-only (the guard still refuses the write),
// and the three files are all still guarded. Lifting the flag needs a live
// run showing the key does stop hooks.
func TestNoCopilotCLIDisableAllHooksSwitch(t *testing.T) {
	guarded := map[string]bool{}
	for _, s := range Switches {
		if s.Key != "disableAllHooks" {
			continue
		}
		rel := s.HomeRel + s.ProjectRel
		if !strings.Contains(rel, ".copilot/") && !strings.Contains(rel, ".github/copilot/") {
			continue
		}
		if !s.WriteGuardOnly {
			t.Errorf("row %s claims Copilot CLI's disableAllHooks (%s) silences copilot-cli", s.ID, rel)
		}
		if !s.KeySwitch() {
			t.Errorf("row %s is not a key switch, so the guard cannot refuse the write", s.ID)
		}
		guarded[rel] = true
	}
	for _, rel := range []string{".copilot/settings.json", ".github/copilot/settings.json", ".github/copilot/settings.local.json"} {
		if !guarded[rel] {
			t.Errorf("%s has no write-guard row", rel)
		}
	}
}
