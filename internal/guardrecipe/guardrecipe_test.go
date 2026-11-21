package guardrecipe

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// testCatalog is a synthetic built-in rule catalog: one rule per shape the
// compiler treats differently.
var testCatalog = []CatalogRule{
	{ID: "R-101", Category: "destructive", Observe: "flag", Enforce: "deny"},
	{ID: "R-150", Category: "boundary", Observe: "flag", Enforce: "ask"},
	{ID: "R-160", Category: "boundary", Observe: "flag", Enforce: "deny", Integrity: true},
	{ID: "R-173", Category: "exfil", Observe: "flag", Enforce: "flag"},
	{ID: "R-175", Category: "exfil", Observe: "allow", Enforce: "allow"},
	{ID: "B-601", Category: "budget", Observe: "flag", Enforce: "flag"},
	{ID: "B-626", Category: "budget", Observe: "flag", Enforce: "deny"},
}

// mustSet builds a Set from inline recipe files (name -> body).
func mustSet(t *testing.T, files map[string]string) *Set {
	t.Helper()
	s := &Set{byName: map[string]*Recipe{}}
	for name, body := range files {
		r, err := Parse(name, []byte(body), SourceBuiltin)
		if err != nil {
			t.Fatalf("Parse %s: %v", name, err)
		}
		s.byName[name] = r
	}
	if err := s.checkExtends(); err != nil {
		t.Fatalf("checkExtends: %v", err)
	}
	return s
}

const lvlStrict = `name = "lvl"
kind = "level"
title = "Lvl"
version = 2
order = 40
mode = "enforce"
prompt_mode = "block"

[[override]]
rule = "R-150"
decision = "ask"
enforce = true
note = "reads ask"
`

const packNet = `name = "net"
kind = "pack"
title = "Net"
version = 1

[[override]]
rule = "R-175"
decision = "ask"
enforce = true

[[rule]]
id = "RC-X-01"
category = "posture"
decision = "ask"
[rule.match]
command_regex = '(^|\s)ufw(\s|$)'
`

// TestParse_Rejects is one case per refusal row of Recipe.check.
func TestParse_Rejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, body, want string
	}{
		{"bad name", "Bad", `name = "Bad"` + "\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n", "not a recipe name"},
		{"name mismatch", "a", "name = \"b\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n", "does not match the file name"},
		{"no title", "a", "name = \"a\"\nkind=\"pack\"\nversion=1\n", "missing title"},
		{"no version", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\n", "version must be"},
		{"bad kind", "a", "name = \"a\"\nkind=\"mode\"\ntitle=\"x\"\nversion=1\n", "kind"},
		{"level bad mode", "a", "name = \"a\"\nkind=\"level\"\ntitle=\"x\"\nversion=1\nmode=\"on\"\nprompt_mode=\"off\"\n", "level mode"},
		{"level bad prompt", "a", "name = \"a\"\nkind=\"level\"\ntitle=\"x\"\nversion=1\nmode=\"off\"\nprompt_mode=\"loud\"\n", "prompt_mode"},
		{"pack with mode", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\nmode=\"off\"\n", "rows only"},
		{"self extend", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\nextends=\"a\"\n", "extend itself"},
		{"override no rule", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n[[override]]\ndecision=\"ask\"\n", "missing rule id"},
		{"override bad decision", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n[[override]]\nrule=\"R-1\"\ndecision=\"block\"\n", "decision"},
		{"override empty", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n[[override]]\nrule=\"R-1\"\n", "neither decision nor enforce"},
		{"rule no id", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n[[rule]]\ncategory=\"x\"\n", "missing id"},
		{"rule dup id", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\n[[rule]]\nid=\"X\"\n[[rule]]\nid=\"X\"\n", "duplicate id"},
		{"unknown key", "a", "name = \"a\"\nkind=\"pack\"\ntitle=\"x\"\nversion=1\nmod=\"x\"\n", "unknown keys: mod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(tc.file, []byte(tc.body), SourceUser)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestBuiltinCatalog pins the embedded catalog's shape: every file parses,
// the five levels are in slider order, and the packs are the named set.
func TestBuiltinCatalog(t *testing.T) {
	t.Parallel()
	s, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	var levels []string
	for _, r := range s.Levels() {
		levels = append(levels, r.Name)
	}
	if got := strings.Join(levels, ","); got != "none,loose,balanced,strict,lockdown" {
		t.Errorf("levels = %s", got)
	}
	var packs []string
	for _, r := range s.Packs() {
		packs = append(packs, r.Name)
	}
	want := "backend-database,baseline-guard,data-ml,devops-infra,frontend,networking,regulated,strict-egress"
	if got := strings.Join(packs, ","); got != want {
		t.Errorf("packs = %s, want %s", got, want)
	}
	for _, r := range s.All() {
		if r.Source != SourceBuiltin || strings.TrimSpace(r.Summary) == "" {
			t.Errorf("%s: source %q, summary %q", r.Name, r.Source, r.Summary)
		}
	}
}

// TestAddUser is one case per user-recipe outcome.
func TestAddUser(t *testing.T) {
	t.Parallel()
	base := func(t *testing.T) *Set { return mustSet(t, map[string]string{"lvl": lvlStrict, "net": packNet}) }
	t.Run("added", func(t *testing.T) {
		s := base(t)
		s.AddUser("mine", []byte("name=\"mine\"\nkind=\"pack\"\ntitle=\"Mine\"\nversion=1\nextends=\"net\"\n"))
		if r, ok := s.Get("mine"); !ok || r.Source != SourceUser || len(s.Issues) != 0 {
			t.Fatalf("mine = %v %v, issues %v", r, ok, s.Issues)
		}
	})
	t.Run("built-in name refused", func(t *testing.T) {
		s := base(t)
		s.AddUser("net", []byte(packNet))
		if len(s.Issues) != 1 || !strings.Contains(s.Issues[0], "built-in") {
			t.Fatalf("issues = %v", s.Issues)
		}
	})
	t.Run("bad file skipped", func(t *testing.T) {
		s := base(t)
		s.AddUser("bad", []byte("name = "))
		if _, ok := s.Get("bad"); ok || len(s.Issues) != 1 {
			t.Fatalf("issues = %v", s.Issues)
		}
	})
	t.Run("extends missing skipped", func(t *testing.T) {
		s := base(t)
		s.AddUser("orphan", []byte("name=\"orphan\"\nkind=\"pack\"\ntitle=\"O\"\nversion=1\nextends=\"nope\"\n"))
		if _, ok := s.Get("orphan"); ok || len(s.Issues) != 1 {
			t.Fatalf("issues = %v", s.Issues)
		}
	})
	t.Run("extends other kind skipped", func(t *testing.T) {
		s := base(t)
		s.AddUser("mixed", []byte("name=\"mixed\"\nkind=\"pack\"\ntitle=\"M\"\nversion=1\nextends=\"lvl\"\n"))
		if _, ok := s.Get("mixed"); ok || len(s.Issues) != 1 || !strings.Contains(s.Issues[0], "a level") {
			t.Fatalf("issues = %v", s.Issues)
		}
	})
}

// overrideOf finds the emitted rows for a rule.
func overrideOf(c *Compiled, id string) []EmittedOverride {
	var out []EmittedOverride
	for _, ov := range c.Overrides {
		if ov.Rule == id {
			out = append(out, ov)
		}
	}
	return out
}

// TestCompile is one case per compile path: global writes the mode and
// emits only authored rows; project emulates the mode on the rules the
// selection does not name, never on budget rows or an integrity rule's
// weakening side.
func TestCompile(t *testing.T) {
	t.Parallel()
	set := mustSet(t, map[string]string{
		"lvl": lvlStrict,
		"net": packNet,
		"off": "name=\"off\"\nkind=\"level\"\ntitle=\"Off\"\nversion=1\nmode=\"off\"\nprompt_mode=\"off\"\n",
		"obs": "name=\"obs\"\nkind=\"level\"\ntitle=\"Obs\"\nversion=1\nmode=\"observe\"\nprompt_mode=\"warn\"\n[[override]]\nrule=\"R-101\"\nenforce=true\n",
	})
	t.Run("global level and pack", func(t *testing.T) {
		c, err := Compile(set, Selection{Level: "lvl", Packs: []string{"net"}, Scope: ScopeGlobal}, testCatalog, Meta{AppliedVia: "cli"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Mode != "enforce" || c.PromptMode != "block" {
			t.Errorf("mode = %q / %q", c.Mode, c.PromptMode)
		}
		if len(c.Overrides) != 2 || c.Overrides[0].Rule != "R-150" || c.Overrides[1].Rule != "R-175" {
			t.Errorf("overrides = %+v", c.Overrides)
		}
		if len(c.RuleIDs) != 1 || c.RuleIDs[0] != "RC-X-01" || len(c.Disable) != 0 {
			t.Errorf("rules %v disable %v", c.RuleIDs, c.Disable)
		}
		m, ok := ParseMeta(c.Text)
		if !ok || m.LevelName() != "lvl" || m.Level.Version != 2 || strings.Join(m.PackNames(), ",") != "net" || m.Scope != ScopeGlobal || m.AppliedVia != "cli" {
			t.Errorf("meta = %+v %v", m, ok)
		}
		assertTOML(t, c.Text)
	})
	t.Run("global pack only leaves the mode", func(t *testing.T) {
		c, err := Compile(set, Selection{Packs: []string{"net"}, Scope: ScopeGlobal}, testCatalog, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		if c.Mode != "" || c.PromptMode != "" {
			t.Errorf("pack-only apply set mode %q / %q", c.Mode, c.PromptMode)
		}
	})
	t.Run("project enforce emulation", func(t *testing.T) {
		c, err := Compile(set, Selection{Level: "lvl", Scope: ScopeProject}, testCatalog, Meta{ProjectRoot: "/p"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Mode != "" {
			t.Errorf("project scope set mode %q", c.Mode)
		}
		// R-101 (flag/deny) gets enforce=true; R-150 is named by the level so
		// only its own row; R-160 (integrity, flag/deny) may be escalated;
		// R-173 (flag/flag), R-175 (allow/allow) and the budget rows get none.
		if rows := overrideOf(c, "R-101"); len(rows) != 1 || rows[0].Origin != OriginMode || rows[0].Enforce == nil || !*rows[0].Enforce {
			t.Errorf("R-101 = %+v", rows)
		}
		if rows := overrideOf(c, "R-150"); len(rows) != 1 || rows[0].Origin != OriginLevel {
			t.Errorf("R-150 = %+v", rows)
		}
		if rows := overrideOf(c, "R-160"); len(rows) != 1 {
			t.Errorf("R-160 = %+v", rows)
		}
		for _, id := range []string{"R-173", "R-175", "B-601", "B-626"} {
			if rows := overrideOf(c, id); len(rows) != 0 {
				t.Errorf("%s emulated: %+v", id, rows)
			}
		}
		assertTOML(t, c.Text)
	})
	t.Run("project observe emulation caps", func(t *testing.T) {
		c, err := Compile(set, Selection{Level: "obs", Scope: ScopeProject}, testCatalog, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		if rows := overrideOf(c, "R-150"); len(rows) != 1 || *rows[0].Enforce {
			t.Errorf("R-150 not capped: %+v", rows)
		}
		if rows := overrideOf(c, "R-101"); len(rows) != 1 || rows[0].Origin != OriginLevel {
			t.Errorf("R-101 = %+v (the level's own enforce row, no cap)", rows)
		}
		if rows := overrideOf(c, "R-160"); len(rows) != 0 {
			t.Errorf("integrity rule capped: %+v", rows)
		}
		assertTOML(t, c.Text)
	})
	t.Run("project off disables", func(t *testing.T) {
		c, err := Compile(set, Selection{Level: "off", Scope: ScopeProject}, testCatalog, Meta{})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(c.Disable, ","); got != "R-101,R-150,R-173,R-175" {
			t.Errorf("disable = %s", got)
		}
		if !strings.Contains(string(c.Text), "disable = [") {
			t.Errorf("no disable key in\n%s", c.Text)
		}
		assertTOML(t, c.Text)
	})
	t.Run("refusals", func(t *testing.T) {
		bad := mustSet(t, map[string]string{
			"weak": "name=\"weak\"\nkind=\"pack\"\ntitle=\"W\"\nversion=1\n[[override]]\nrule=\"R-160\"\ndecision=\"flag\"\n",
		})
		cases := []struct {
			name string
			set  *Set
			sel  Selection
			want string
		}{
			{"empty", set, Selection{Scope: ScopeGlobal}, "nothing selected"},
			{"bad scope", set, Selection{Level: "lvl", Scope: "repo"}, "scope"},
			{"unknown level", set, Selection{Level: "nope", Scope: ScopeGlobal}, "not in the catalog"},
			{"pack as level", set, Selection{Level: "net", Scope: ScopeGlobal}, "not a level"},
			{"level as pack", set, Selection{Packs: []string{"lvl"}, Scope: ScopeGlobal}, "not a pack"},
			{"integrity lowering", bad, Selection{Packs: []string{"weak"}, Scope: ScopeGlobal}, "integrity rule"},
		}
		for _, tc := range cases {
			if _, err := Compile(tc.set, tc.sel, testCatalog, Meta{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
			}
		}
	})
}

// TestCompile_ExtendsOrder pins fold order: a recipe's base rows come first
// so its own rows win (last override wins in the engine).
func TestCompile_ExtendsOrder(t *testing.T) {
	t.Parallel()
	set := mustSet(t, map[string]string{
		"base": "name=\"base\"\nkind=\"pack\"\ntitle=\"B\"\nversion=1\n[[override]]\nrule=\"R-150\"\ndecision=\"ask\"\n",
		"top":  "name=\"top\"\nkind=\"pack\"\ntitle=\"T\"\nversion=1\nextends=\"base\"\n[[override]]\nrule=\"R-150\"\ndecision=\"deny\"\n",
	})
	c, err := Compile(set, Selection{Packs: []string{"top"}, Scope: ScopeGlobal}, testCatalog, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	rows := overrideOf(c, "R-150")
	if len(rows) != 2 || rows[0].Decision != "ask" || rows[1].Decision != "deny" || rows[0].Recipe != "base" {
		t.Fatalf("rows = %+v", rows)
	}
}

// TestRender_RoundTrip decodes a compiled file and checks the values that
// matter survived the hand-written TOML emitter (escaping included).
func TestRender_RoundTrip(t *testing.T) {
	t.Parallel()
	set := mustSet(t, map[string]string{
		"esc": "name=\"esc\"\nkind=\"pack\"\ntitle=\"E\"\nversion=1\n" +
			"[[rule]]\nid=\"RC-E-1\"\ncategory=\"boundary\"\ndecision=\"ask\"\nenforce=true\napplies_to=[\"file_access\"]\n" +
			"[rule.match]\ncommand_regex='a\\\\b \"q\"'\npath_glob=[\"**/.env\", \"x\\ty\"]\nrepeat_count_gt=3\nsession_cost_usd_gt=1.5\n",
	})
	c, err := Compile(set, Selection{Packs: []string{"esc"}, Scope: ScopeGlobal}, testCatalog, Meta{})
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Rule []map[string]any `toml:"rule"`
	}
	if _, err := toml.Decode(string(c.Text), &back); err != nil {
		t.Fatalf("decode:\n%s\n%v", c.Text, err)
	}
	if len(back.Rule) != 1 {
		t.Fatalf("rules = %v", back.Rule)
	}
	m := back.Rule[0]["match"].(map[string]any)
	if m["command_regex"] != `a\\b "q"` {
		t.Errorf("command_regex = %q", m["command_regex"])
	}
	globs := m["path_glob"].([]any)
	if globs[1] != "x\ty" || m["repeat_count_gt"] != int64(3) || m["session_cost_usd_gt"] != 1.5 {
		t.Errorf("match = %#v", m)
	}
	if back.Rule[0]["enforce"] != true {
		t.Errorf("enforce = %v", back.Rule[0]["enforce"])
	}
}

// TestParseMeta covers the header reader's refusals.
func TestParseMeta(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, text string
		ok         bool
	}{
		{"none", "[[override]]\nrule=\"R-1\"\n", false},
		{"good", metaPrefix + `{"format":1,"scope":"global"}` + "\n", true},
		{"newer format", metaPrefix + `{"format":9,"scope":"global"}` + "\n", false},
		{"bad scope", metaPrefix + `{"format":1,"scope":"repo"}` + "\n", false},
		{"bad json", metaPrefix + `{` + "\n", false},
		{"crlf", "# x\r\n" + metaPrefix + `{"format":1,"scope":"project"}` + "\r\n", true},
	}
	for _, tc := range cases {
		if _, ok := ParseMeta([]byte(tc.text)); ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
		}
	}
}

func assertTOML(t *testing.T, text []byte) {
	t.Helper()
	var v map[string]any
	if _, err := toml.Decode(string(text), &v); err != nil {
		t.Fatalf("compiled file is not TOML: %v\n%s", err, text)
	}
}
