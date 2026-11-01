package agentconfig

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// osFixture is one OS's machine for the relocation tests. Every value is
// spelled for that OS, and PathEnv.GOOS is set explicitly, so the tests run
// the same on any host.
type osFixture struct {
	goos       string
	home       string
	abs        string // an absolute directory outside home
	absV2      string // abs + its "v2" segment
	absFile    string // an absolute file
	root       string
	homeParent string
	sep        string
}

var relocFixtures = []osFixture{
	{goos: "linux", home: "/home/u", abs: "/opt/tool", absV2: "/opt/tool/v2", absFile: "/opt/tool/conf.toml", root: "/", homeParent: "/home", sep: "/"},
	{goos: "darwin", home: "/Users/u", abs: "/opt/tool", absV2: "/opt/tool/v2", absFile: "/opt/tool/conf.toml", root: "/", homeParent: "/Users", sep: "/"},
	{goos: "windows", home: `C:\Users\u`, abs: `D:\tool`, absV2: `D:\tool\v2`, absFile: `D:\tool\conf.toml`, root: `C:\`, homeParent: `C:\Users`, sep: `\`},
}

// envOf is a PathEnv whose environment holds exactly vars.
func envOf(fx osFixture, vars map[string]string) PathEnv {
	return PathEnv{GOOS: fx.goos, Home: fx.home, Getenv: func(k string) string { return vars[k] }}
}

// TestRelocationSemanticsPerOS has one block of rows per RelocSemantics
// value, run on linux, darwin and windows.
func TestRelocationSemanticsPerOS(t *testing.T) {
	for _, fx := range relocFixtures {
		e := envOf(fx, nil)
		j := e.Join
		cases := []struct {
			name    string
			rule    Relocation
			raw     string
			value   string
			want    string      // relocated path when applied
			refused RelocIgnore // when not applied
		}{
			// exact_dir
			{"exact_dir moves the anchor", Relocation{Semantics: RelocExactDir, Anchor: "~/.tool"}, "~/.tool/config.toml", fx.abs, j(fx.abs, "config.toml"), ""},
			{"exact_dir on the anchor itself", Relocation{Semantics: RelocExactDir, Anchor: "~/.tool"}, "~/.tool", fx.abs, e.native(fx.abs), ""},
			{"exact_dir refuses a relative value", Relocation{Semantics: RelocExactDir, Anchor: "~/.tool"}, "~/.tool/config.toml", "rel/dir", "", RelocIgnoreRelative},
			{"exact_dir: a sibling file is not under the anchor", Relocation{Semantics: RelocExactDir, Anchor: "~/.tool"}, "~/.tool.json", fx.abs, "", RelocIgnoreAnchorMismatch},
			{"exact_dir: a longer dir name is not under the anchor", Relocation{Semantics: RelocExactDir, Anchor: "~/.tool"}, "~/.toolx/a.json", fx.abs, "", RelocIgnoreAnchorMismatch},
			// absolute_not_home_ancestor
			{"not_home_ancestor accepts an outside dir", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", fx.abs, j(fx.abs, "agents"), ""},
			{"not_home_ancestor refuses home", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", fx.home, "", RelocIgnoreHomeAncestor},
			{"not_home_ancestor refuses root", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", fx.root, "", RelocIgnoreHomeAncestor},
			{"not_home_ancestor refuses an ancestor of home", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", fx.homeParent, "", RelocIgnoreHomeAncestor},
			{"not_home_ancestor accepts a dir inside home", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", j(fx.home, "kh"), j(fx.home, "kh", "agents"), ""},
			{"not_home_ancestor refuses a relative value", Relocation{Semantics: RelocAbsoluteNotHomeAncestor, Anchor: "~/.tool"}, "~/.tool/agents", "kh", "", RelocIgnoreRelative},
			// tilde_expand
			{"tilde_expand expands a leading ~", Relocation{Semantics: RelocTildeExpand, Anchor: "~/.tool"}, "~/.tool/x.json", "~/dh", j(fx.home, "dh", "x.json"), ""},
			{"tilde_expand takes an absolute value as is", Relocation{Semantics: RelocTildeExpand, Anchor: "~/.tool"}, "~/.tool/x.json", fx.abs, j(fx.abs, "x.json"), ""},
			{"tilde_expand refuses a bare relative value", Relocation{Semantics: RelocTildeExpand, Anchor: "~/.tool"}, "~/.tool/x.json", "dh", "", RelocIgnoreRelative},
			// file_not_dir
			{"file_not_dir names the file", Relocation{Semantics: RelocFileNotDir}, "~/.config/tool/tool.toml", fx.absFile, e.native(fx.absFile), ""},
			{"file_not_dir refuses a relative value", Relocation{Semantics: RelocFileNotDir}, "~/.config/tool/tool.toml", "tool.toml", "", RelocIgnoreRelative},
			// append_if_missing
			{"append_if_missing appends the segment", Relocation{Semantics: RelocAppendIfMissing, Anchor: "~/.tool/v2", Sub: "v2"}, "~/.tool/v2/db.sqlite", fx.abs, j(fx.absV2, "db.sqlite"), ""},
			{"append_if_missing keeps a value that already ends in it", Relocation{Semantics: RelocAppendIfMissing, Anchor: "~/.tool/v2", Sub: "v2"}, "~/.tool/v2/db.sqlite", fx.absV2, j(fx.absV2, "db.sqlite"), ""},
			{"append_if_missing ignores a trailing separator", Relocation{Semantics: RelocAppendIfMissing, Anchor: "~/.tool/v2", Sub: "v2"}, "~/.tool/v2/db.sqlite", fx.absV2 + fx.sep, j(fx.absV2, "db.sqlite"), ""},
			{"append_if_missing refuses a relative value", Relocation{Semantics: RelocAppendIfMissing, Anchor: "~/.tool/v2", Sub: "v2"}, "~/.tool/v2/db.sqlite", "dim", "", RelocIgnoreRelative},
			// root_plus_sub
			{"root_plus_sub joins Sub onto the root", Relocation{Semantics: RelocRootPlusSub, Anchor: "~/.config/tool", Sub: "config"}, "~/.config/tool/c.yaml", fx.abs, j(fx.abs, "config", "c.yaml"), ""},
			{"root_plus_sub joins Sub even when the value ends in it", Relocation{Semantics: RelocRootPlusSub, Anchor: "~/.config/tool", Sub: "config"}, "~/.config/tool/c.yaml", j(fx.abs, "config"), j(fx.abs, "config", "config", "c.yaml"), ""},
			{"root_plus_sub refuses a relative value", Relocation{Semantics: RelocRootPlusSub, Anchor: "~/.config/tool", Sub: "config"}, "~/.config/tool/c.yaml", "rel", "", RelocIgnoreRelative},
			// anchor_suffix
			{"anchor_suffix appends to the anchor's last segment", Relocation{Semantics: RelocAnchorSuffix, Anchor: "~/.tool"}, "~/.tool/config.yaml", "-dev", j(fx.home, ".tool-dev", "config.yaml"), ""},
			{"anchor_suffix on a token anchor", Relocation{Semantics: RelocAnchorSuffix, Anchor: "%LOCALAPPDATA%/tool"}, "%LOCALAPPDATA%/tool/config.yaml", "2", j(fx.home, "AppData", "Local", "tool2", "config.yaml"), ""},
			{"anchor_suffix: a sibling is not under the anchor", Relocation{Semantics: RelocAnchorSuffix, Anchor: "~/.tool"}, "~/.toolx/a", "-dev", "", RelocIgnoreAnchorMismatch},
			// does_not_move_artifact
			{"does_not_move refuses every value", Relocation{Semantics: RelocDoesNotMoveArtifact}, "~/.tool/Hooks/", fx.abs, "", RelocIgnoreDoesNotMove},
		}
		for _, tc := range cases {
			t.Run(fx.goos+"/"+tc.name, func(t *testing.T) {
				tc.rule.Env = "TOOL_HOME"
				got := envOf(fx, map[string]string{"TOOL_HOME": tc.value}).relocateWith([]Relocation{tc.rule}, tc.raw)
				if tc.refused != "" {
					want := []string{"TOOL_HOME:" + string(tc.refused)}
					if got.applied || !reflect.DeepEqual(got.ignored, want) {
						t.Errorf("got applied=%v path=%q ignored=%v; want refused %v", got.applied, got.path, got.ignored, want)
					}
					return
				}
				if !got.applied || got.path != tc.want || got.env != "TOOL_HOME" || len(got.ignored) != 0 {
					t.Errorf("got applied=%v path=%q env=%q ignored=%v; want %q", got.applied, got.path, got.env, got.ignored, tc.want)
				}
			})
		}
	}
}

// TestRelocationJudgesTheValueBeforeJoining: a rule that joins onto the value
// (a "~/" expansion, an appended or added Sub) judges absoluteness on the
// value as set, before Join rewrites its separators for the resolve OS. A
// host path resolved for another OS (a Linux temp home under GOOS=windows,
// with the host's own absolute rule injected) must still relocate; before
// the gates-3 fix and this one it read as relative (the joined
// `\home\u\dh` is not absolute to a Linux host).
func TestRelocationJudgesTheValueBeforeJoining(t *testing.T) {
	hostIsAbs := func(v string) bool { return strings.HasPrefix(v, "/") }
	for _, tc := range []struct {
		name  string
		rule  Relocation
		raw   string
		value string
		want  string
	}{
		{"tilde_expand", Relocation{Semantics: RelocTildeExpand, Anchor: "~/.tool"}, "~/.tool/x.json", "~/dh", `\home\u\dh\x.json`},
		{"tilde_expand, bare ~", Relocation{Semantics: RelocTildeExpand, Anchor: "~/.tool"}, "~/.tool/x.json", "~", `\home\u\x.json`},
		{"append_if_missing", Relocation{Semantics: RelocAppendIfMissing, Anchor: "~/.tool/v2", Sub: "v2"}, "~/.tool/v2/db.sqlite", "/opt/tool", `\opt\tool\v2\db.sqlite`},
		{"root_plus_sub", Relocation{Semantics: RelocRootPlusSub, Anchor: "~/.config/tool", Sub: "config"}, "~/.config/tool/c.yaml", "/opt/tool", `\opt\tool\config\c.yaml`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.Env = "TOOL_HOME"
			e := PathEnv{GOOS: "windows", Home: "/home/u", IsAbs: hostIsAbs, Getenv: func(k string) string {
				if k == "TOOL_HOME" {
					return tc.value
				}
				return ""
			}}
			got := e.relocateWith([]Relocation{tc.rule}, tc.raw)
			if !got.applied || got.path != tc.want || len(got.ignored) != 0 {
				t.Errorf("got applied=%v path=%q ignored=%v; want %q", got.applied, got.path, got.ignored, tc.want)
			}
		})
	}
	// A relative home is still refused, and an anchor mismatch still wins.
	e := PathEnv{GOOS: "windows", Home: "rel/home", IsAbs: hostIsAbs, Getenv: func(string) string { return "~/dh" }}
	rule := Relocation{Env: "TOOL_HOME", Semantics: RelocTildeExpand, Anchor: "~/.tool"}
	if got := e.relocateWith([]Relocation{rule}, "~/.tool/x.json"); got.applied || !reflect.DeepEqual(got.ignored, []string{"TOOL_HOME:" + string(RelocIgnoreRelative)}) {
		t.Errorf("relative home: applied=%v ignored=%v; want refused relative", got.applied, got.ignored)
	}
	if got := e.relocateWith([]Relocation{rule}, "~/.other/x.json"); got.applied || !reflect.DeepEqual(got.ignored, []string{"TOOL_HOME:" + string(RelocIgnoreAnchorMismatch)}) {
		t.Errorf("anchor mismatch: applied=%v ignored=%v; want refused anchor_mismatch", got.applied, got.ignored)
	}
}

// TestEveryRelocSemanticsHasAnEntry keeps the semantics table closed.
func TestEveryRelocSemanticsHasAnEntry(t *testing.T) {
	for _, s := range []RelocSemantics{RelocExactDir, RelocAbsoluteNotHomeAncestor, RelocTildeExpand, RelocFileNotDir, RelocAppendIfMissing, RelocDoesNotMoveArtifact, RelocRootPlusSub, RelocAnchorSuffix} {
		if relocSemantics[s] == nil {
			t.Errorf("semantics %q has no entry in relocSemantics", s)
		}
	}
	if len(relocSemantics) != 8 {
		t.Errorf("relocSemantics has %d entries; update this test with the new value", len(relocSemantics))
	}
	fx := relocFixtures[0]
	got := envOf(fx, map[string]string{"X": fx.abs}).relocateWith([]Relocation{{Env: "X", Semantics: "made_up"}}, "~/.x/a")
	if got.applied || !reflect.DeepEqual(got.ignored, []string{"X:unknown_semantics"}) {
		t.Errorf("unknown semantics: got %+v", got)
	}
}

// TestRelocationOrder: rules are walked top-down; an unset variable is
// skipped silently, a refused one is recorded, the first accepted one wins,
// and an OS-limited rule only applies on its OS.
func TestRelocationOrder(t *testing.T) {
	rules := []Relocation{
		{Env: "UNSET", Semantics: RelocExactDir, Anchor: "~/.t"},
		{Env: "RELATIVE", Semantics: RelocExactDir, Anchor: "~/.t", RelativeFallsThrough: true},
		{Env: "WIN_ONLY", Semantics: RelocExactDir, Anchor: "~/.t", GOOS: "windows"},
		{Env: "GOOD", Semantics: RelocExactDir, Anchor: "~/.t"},
		{Env: "LATER", Semantics: RelocExactDir, Anchor: "~/.t"},
	}
	for _, fx := range relocFixtures {
		vars := map[string]string{"RELATIVE": "rel", "WIN_ONLY": fx.abs, "GOOD": fx.abs, "LATER": fx.abs}
		got := envOf(fx, vars).relocateWith(rules, "~/.t/c.json")
		wantEnv := "GOOD"
		if fx.goos == "windows" {
			wantEnv = "WIN_ONLY"
		}
		if !got.applied || got.env != wantEnv || !reflect.DeepEqual(got.ignored, []string{"RELATIVE:relative_value"}) {
			t.Errorf("%s: got %+v; want %s applied after RELATIVE refused", fx.goos, got, wantEnv)
		}
	}
}

// TestRelativeValueStopsTheWalk (FU-31): a relative value the tool itself
// would read against its working directory stops the walk; the row then
// resolves to PathRelocationUnresolved with no path, never to a lower
// location the tool would not read. A rule whose tool ignores a relative
// value (RelativeFallsThrough) still lets the next one apply.
func TestRelativeValueStopsTheWalk(t *testing.T) {
	rules := []Relocation{
		{Env: "FIRST", Semantics: RelocExactDir, Anchor: "~/.t"},
		{Env: "SECOND", Semantics: RelocExactDir, Anchor: "~/.t"},
	}
	for _, fx := range relocFixtures {
		got := envOf(fx, map[string]string{"FIRST": "rel", "SECOND": fx.abs}).relocateWith(rules, "~/.t/c.json")
		if got.applied || got.unresolved != "FIRST" || !reflect.DeepEqual(got.ignored, []string{"FIRST:relative_value"}) {
			t.Errorf("%s: got %+v; want the walk stopped at FIRST", fx.goos, got)
		}
		row := fileByIDForTest(t, "qwen-code/user-settings")
		e := envOf(fx, map[string]string{"QWEN_HOME": "rel/qwen"})
		e.Relocate = true
		res := ResolvePath(row, e)
		if res.Status != PathRelocationUnresolved || res.Path != "" || res.RelocatedBy != "QWEN_HOME" {
			t.Errorf("%s qwen relative QWEN_HOME: got %+v; want relocation_unresolved", fx.goos, res)
		}
		kiro := fileByIDForTest(t, "kiro-cli/user-hooks")
		e = envOf(fx, map[string]string{"KIRO_HOME": "rel/kiro"})
		e.Relocate = true
		res = ResolvePath(kiro, e)
		if res.Status != PathDirectory || res.Path != e.Join(fx.home, ".kiro", "hooks")+fx.sep || res.RelocatedBy != "" {
			t.Errorf("%s kiro relative KIRO_HOME: got %+v; want the default (Kiro ignores it)", fx.goos, res)
		}
	}
}

// TestResolvePathRelocateIsOptIn: the seeded codex row moves only when the
// resolution asks for it, and a relocated path is never re-rooted under
// SystemRoot.
func TestResolvePathRelocateIsOptIn(t *testing.T) {
	row := fileByIDForTest(t, "codex/user-config")
	for _, fx := range relocFixtures {
		vars := map[string]string{"CODEX_HOME": fx.abs}
		off := ResolvePath(row, envOf(fx, vars))
		if off.Path != envOf(fx, nil).Join(fx.home, ".codex", "config.toml") || off.RelocatedBy != "" {
			t.Errorf("%s Relocate off: got %+v; want the default path", fx.goos, off)
		}
		e := envOf(fx, vars)
		e.Relocate, e.SystemRoot = true, e.Join(fx.abs, "sysroot")
		on := ResolvePath(row, e)
		if on.Status != PathResolved || on.Path != e.Join(fx.abs, "config.toml") || on.RelocatedBy != "CODEX_HOME" {
			t.Errorf("%s Relocate on: got %+v; want %s under CODEX_HOME", fx.goos, on, e.Join(fx.abs, "config.toml"))
		}
	}
}

// TestRowsWithoutRulesResolveAsBefore is the regression guard: for every
// catalogued row and OS, setting the seeded relocation variables changes
// nothing unless the row has a rule AND the resolution opts in.
func TestRowsWithoutRulesResolveAsBefore(t *testing.T) {
	for _, fx := range relocFixtures {
		vars := map[string]string{"CLAUDE_CONFIG_DIR": fx.abs, "CODEX_HOME": fx.abs}
		for _, row := range Files() {
			plain := ResolvePath(row, PathEnv{GOOS: fx.goos, Home: fx.home, Project: fx.abs})
			withVars := ResolvePath(row, PathEnv{GOOS: fx.goos, Home: fx.home, Project: fx.abs, Getenv: func(k string) string { return vars[k] }})
			if !reflect.DeepEqual(plain, withVars) {
				t.Errorf("%s %s: relocation variables changed a non-relocating resolution: %+v vs %+v", fx.goos, row.ID, plain, withVars)
			}
			if len(RelocationsFor(row.ID)) != 0 {
				continue
			}
			opted := ResolvePath(row, PathEnv{GOOS: fx.goos, Home: fx.home, Project: fx.abs, Relocate: true, Getenv: func(k string) string { return vars[k] }})
			if !reflect.DeepEqual(plain, opted) {
				t.Errorf("%s %s: a row with no rule moved under Relocate: %+v vs %+v", fx.goos, row.ID, plain, opted)
			}
		}
	}
}

func TestResolveArtifact(t *testing.T) {
	fx := relocFixtures[2] // windows: the managed-config rule is Windows-only
	got, err := ResolveArtifact("codex/managed-config", envOf(fx, map[string]string{"CODEX_HOME": fx.abs}))
	if err != nil || got.Path != envOf(fx, nil).Join(fx.abs, "managed_config.toml") || got.RelocatedBy != "CODEX_HOME" {
		t.Errorf("windows managed-config: got %+v, %v", got, err)
	}
	linux := relocFixtures[0]
	got, err = ResolveArtifact("codex/managed-config", envOf(linux, map[string]string{"CODEX_HOME": linux.abs}))
	if err != nil || got.Path != "/etc/codex/managed_config.toml" || got.RelocatedBy != "" {
		t.Errorf("linux managed-config must stay in /etc/codex: got %+v, %v", got, err)
	}
	if _, err := ResolveArtifact("no/such-artifact", envOf(linux, nil)); !errors.Is(err, ErrUnknownArtifact) {
		t.Errorf("unknown id: err = %v, want ErrUnknownArtifact", err)
	}
}

func TestRelocationsForReturnsACopy(t *testing.T) {
	got := RelocationsFor("codex/user-config")
	if len(got) != 1 {
		t.Fatalf("codex/user-config: %d rules, want 1", len(got))
	}
	got[0].Env = "MUTATED"
	if RelocationsFor("codex/user-config")[0].Env != "CODEX_HOME" {
		t.Errorf("RelocationsFor leaked the table")
	}
	// CC-8, grounded by MAC-4: CLAUDE_CONFIG_DIR moves ~/.claude.json into
	// the relocated directory.
	if r := RelocationsFor("claude-code/global-config"); len(r) != 1 || r[0].Env != "CLAUDE_CONFIG_DIR" || r[0].Anchor != "~" {
		t.Errorf("claude-code/global-config rules = %+v, want the CLAUDE_CONFIG_DIR rule anchored at ~", r)
	}
}

var relocEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// TestRelocationRowsWellFormed checks the real fileRelocations table: every
// key is a catalogued row; every rule is a known semantics with a grounded,
// well-formed variable; and on every OS a rule applies to, the row's path is
// under its Anchor (so an OS-specific path needs a GOOS-limited rule).
func TestRelocationRowsWellFormed(t *testing.T) {
	byID := map[string]FileRow{}
	for _, f := range Files() {
		byID[f.ID] = f
	}
	anchored := map[RelocSemantics]bool{RelocExactDir: true, RelocAbsoluteNotHomeAncestor: true, RelocTildeExpand: true, RelocAppendIfMissing: true, RelocRootPlusSub: true, RelocAnchorSuffix: true}
	for id, rules := range fileRelocations {
		row, ok := byID[id]
		if !ok {
			t.Errorf("fileRelocations[%q] is not a catalogued FileRow", id)
			continue
		}
		for _, r := range rules {
			where := id + "/" + r.Env
			if !relocEnvName.MatchString(r.Env) {
				t.Errorf("%s: malformed variable name", where)
			}
			if relocSemantics[r.Semantics] == nil {
				t.Errorf("%s: unknown semantics %q", where, r.Semantics)
			}
			if r.Grounding.Kind == "" || r.Grounding.Source == "" || r.Grounding.Date == "" {
				t.Errorf("%s: incomplete grounding", where)
			}
			if (r.Semantics == RelocAppendIfMissing || r.Semantics == RelocRootPlusSub) && r.Sub == "" {
				t.Errorf("%s: %s without Sub", where, r.Semantics)
			}
			if r.GOOS != "" && r.GOOS != "linux" && r.GOOS != "darwin" && r.GOOS != "windows" {
				t.Errorf("%s: unknown GOOS %q", where, r.GOOS)
			}
			if !anchored[r.Semantics] {
				continue
			}
			for _, fx := range relocFixtures {
				if r.GOOS != "" && r.GOOS != fx.goos {
					continue
				}
				raw := PathEnv{GOOS: fx.goos}.rawPath(row.Paths)
				if raw == "" {
					continue
				}
				if _, under := underAnchor(raw, r.Anchor); !under {
					t.Errorf("%s on %s: path %q is not under anchor %q (limit the rule with GOOS)", where, fx.goos, raw, r.Anchor)
				}
			}
		}
	}
}

// fileByIDForTest returns one catalogued row or fails the test.
func fileByIDForTest(t *testing.T, id string) FileRow {
	t.Helper()
	for _, f := range Files() {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no FileRow %q", id)
	return FileRow{}
}
