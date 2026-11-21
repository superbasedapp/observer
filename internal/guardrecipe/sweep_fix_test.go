package guardrecipe

import (
	"strings"
	"testing"
)

// foldState is a rule's stance after the compiled [[override]] rows apply in
// file order, the way the engine applies them (policy applyOverride): a
// decision replaces both observe and enforce, `enforce = true` holds the
// enforce decision in observe mode, `enforce = false` caps at flag.
type foldState struct {
	obs, enf string
	enforced bool
	capped   bool
}

// fold applies c's overrides over cat and returns every touched rule's state.
func fold(cat []CatalogRule, c *Compiled) map[string]foldState {
	out := map[string]foldState{}
	for _, r := range cat {
		out[r.ID] = foldState{obs: r.Observe, enf: r.Enforce}
	}
	for _, ov := range c.Overrides {
		st := out[ov.Rule]
		if ov.Decision != "" {
			st.obs, st.enf = ov.Decision, ov.Decision
		}
		if ov.Enforce != nil {
			if *ov.Enforce {
				st.enforced, st.capped = true, false
			} else {
				st.enforced, st.capped = false, true
			}
		}
		out[ov.Rule] = st
	}
	return out
}

// sweepCatalog adds the shapes the RC-3 cases need to the synthetic catalog.
var sweepCatalog = append(append([]CatalogRule(nil), testCatalog...),
	CatalogRule{ID: "R-124", Category: "destructive", Observe: "flag", Enforce: "flag"},
	CatalogRule{ID: "R-176", Category: "exfil", Observe: "allow", Enforce: "allow"},
	CatalogRule{ID: "T-503", Category: "taint", Observe: "flag", Enforce: "flag"},
)

// TestCompile_PacksTightenOnly is RC-3: a pack row joins the level's row
// tighten-only (the stricter decision, the enforce flags OR-ed), and a pack
// row that could only lower is a problem, never a silent last-wins.
func TestCompile_PacksTightenOnly(t *testing.T) {
	t.Parallel()
	level := `name = "lock"
kind = "level"
title = "Lock"
version = 1
order = 50
mode = "enforce"
prompt_mode = "block"

[[override]]
rule = "R-176"
decision = "deny"
enforce = true

[[override]]
rule = "R-124"
decision = "deny"
enforce = true

[[override]]
rule = "T-503"
decision = "deny"
enforce = true

[[override]]
rule = "R-150"
enforce = true
`
	pack := func(name, rows string) string {
		return "name = \"" + name + "\"\nkind = \"pack\"\ntitle = \"P\"\nversion = 1\n" + rows
	}
	set := mustSet(t, map[string]string{
		"lock": level,
		"net":  pack("net", "[[override]]\nrule = \"R-176\"\ndecision = \"ask\"\nenforce = true\n"),
		"db":   pack("db", "[[override]]\nrule = \"R-124\"\ndecision = \"ask\"\nenforce = true\n"),
		"reg":  pack("reg", "[[override]]\nrule = \"T-503\"\ndecision = \"ask\"\nenforce = true\n"),
		"up":   pack("up", "[[override]]\nrule = \"R-150\"\ndecision = \"deny\"\n"),
		"cap":  pack("cap", "[[override]]\nrule = \"R-101\"\nenforce = false\n"),
		"low":  pack("low", "[[override]]\nrule = \"R-101\"\ndecision = \"ask\"\n"),
		"raw":  pack("raw", "[[override]]\nrule = \"R-176\"\ndecision = \"ask\"\n"),
	})
	cases := []struct {
		name    string
		sel     Selection
		rule    string
		want    foldState
		problem string // "" = no problem expected
	}{
		{"lockdown + networking keeps R-176 deny", Selection{Level: "lock", Packs: []string{"net"}}, "R-176", foldState{obs: "deny", enf: "deny", enforced: true}, ""},
		{"lockdown + backend keeps R-124 deny", Selection{Level: "lock", Packs: []string{"db"}}, "R-124", foldState{obs: "deny", enf: "deny", enforced: true}, ""},
		{"lockdown + regulated keeps T-503 deny", Selection{Level: "lock", Packs: []string{"reg"}}, "T-503", foldState{obs: "deny", enf: "deny", enforced: true}, ""},
		{"a raising pack decision applies and the level's enforce stays", Selection{Level: "lock", Packs: []string{"up"}}, "R-150", foldState{obs: "deny", enf: "deny", enforced: true}, ""},
		{"a pack alone raises a rule", Selection{Packs: []string{"raw"}}, "R-176", foldState{obs: "ask", enf: "ask"}, ""},
		{"a pack cap is a problem and is not written", Selection{Packs: []string{"cap"}}, "R-101", foldState{obs: "flag", enf: "deny"}, "enforce = false"},
		{"a pack decision below the rule's own is a problem and is not written", Selection{Packs: []string{"low"}}, "R-101", foldState{obs: "flag", enf: "deny"}, "below"},
		{"a pack decision below the level's is kept at the level's", Selection{Level: "lock", Packs: []string{"raw"}}, "R-176", foldState{obs: "deny", enf: "deny", enforced: true}, ""},
	}
	for _, tc := range cases {
		for _, scope := range []Scope{ScopeGlobal, ScopeProject} {
			tc, scope := tc, scope
			t.Run(tc.name+"/"+string(scope), func(t *testing.T) {
				tc.sel.Scope = scope
				c, err := Compile(set, tc.sel, sweepCatalog, Meta{})
				if err != nil {
					t.Fatal(err)
				}
				if got := fold(sweepCatalog, c)[tc.rule]; got != tc.want {
					t.Errorf("%s = %+v, want %+v\n%s", tc.rule, got, tc.want, c.Text)
				}
				switch {
				case tc.problem == "" && len(c.Problems) > 0:
					t.Errorf("problems = %v, want none", c.Problems)
				case tc.problem != "" && (len(c.Problems) != 1 || !strings.Contains(c.Problems[0], tc.problem)):
					t.Errorf("problems = %v, want one naming %q", c.Problems, tc.problem)
				}
				assertTOML(t, c.Text)
			})
		}
	}
}

// TestCompile_ProjectFloor is CFG-2: at project scope the level's mode is
// emulated under the organization's mode floor, never below it.
func TestCompile_ProjectFloor(t *testing.T) {
	t.Parallel()
	set := mustSet(t, map[string]string{
		"off": "name=\"off\"\nkind=\"level\"\ntitle=\"Off\"\nversion=1\nmode=\"off\"\nprompt_mode=\"off\"\n",
		"obs": "name=\"obs\"\nkind=\"level\"\ntitle=\"Obs\"\nversion=1\nmode=\"observe\"\nprompt_mode=\"warn\"\n",
		"enf": "name=\"enf\"\nkind=\"level\"\ntitle=\"Enf\"\nversion=1\nmode=\"enforce\"\nprompt_mode=\"block\"\n",
	})
	cases := []struct {
		level, floor string
		disable      int  // emitted disable ids
		caps, holds  bool // any enforce=false / enforce=true mode row
		note         bool
	}{
		{"off", "", 4, false, false, false},
		{"off", "observe", 0, true, false, true},
		{"off", "enforce", 0, false, false, true},
		{"obs", "", 0, true, false, false},
		{"obs", "observe", 0, true, false, false},
		{"obs", "enforce", 0, false, false, true},
		{"enf", "enforce", 0, false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.level+"/floor="+tc.floor, func(t *testing.T) {
			c, err := Compile(set, Selection{Level: tc.level, Scope: ScopeProject, FloorMode: tc.floor}, testCatalog, Meta{})
			if err != nil {
				t.Fatal(err)
			}
			var caps, holds bool
			for _, ov := range c.Overrides {
				if ov.Origin == OriginMode && ov.Enforce != nil {
					caps = caps || !*ov.Enforce
					holds = holds || *ov.Enforce
				}
			}
			if len(c.Disable) != tc.disable || caps != tc.caps || holds != tc.holds {
				t.Errorf("disable %v caps %v holds %v, want %d %v %v", c.Disable, caps, holds, tc.disable, tc.caps, tc.holds)
			}
			if (c.ModeNote != "") != tc.note {
				t.Errorf("mode note = %q, want one: %v", c.ModeNote, tc.note)
			}
		})
	}
}

// TestParse_RejectsControlChars is RC-9: recipe text a surface prints
// cannot carry terminal control sequences.
func TestParse_RejectsControlChars(t *testing.T) {
	t.Parallel()
	base := "name = \"a\"\nkind = \"pack\"\ntitle = \"x\"\nversion = 1\n"
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"title ESC", "name = \"a\"\nkind = \"pack\"\ntitle = \"x\\u001b[2J\"\nversion = 1\n", false},
		{"summary C1 CSI", base + "summary = \"a\\u009b31m\"\n", false},
		{"summary bell", base + "summary = \"a\\u0007\"\n", false},
		{"summary line break", base + "summary = \"line one\\nline two\"\n", true},
		{"advice ESC", base + "advice = [\"ok\", \"\\u001b]0;pwned\\u0007\"]\n", false},
		{"advice line break", base + "advice = [\"one\\ntwo\"]\n", true},
		{"inputs line break", base + "inputs = [\"guard.network\\nallow_hosts\"]\n", false},
		{"note DEL", base + "[[override]]\nrule = \"R-1\"\nenforce = true\nnote = \"a\\u007f\"\n", false},
		{"rule doc ESC", base + "[[rule]]\nid = \"RC-A-1\"\ndoc = \"\\u001b[31mred\"\n", false},
		{"rule advice line break", base + "[[rule]]\nid = \"RC-A-1\"\nadvice = \"one\\ntwo\"\n", true},
		{"rule id ESC", base + "[[rule]]\nid = \"RC-\\u001b\"\n", false},
		{"crlf summary", base + "summary = \"one\\r\\ntwo\"\n", true},
		{"lone CR", base + "summary = \"one\\rtwo\"\n", false},
		{"tab in title", "name = \"a\"\nkind = \"pack\"\ntitle = \"x\\ty\"\nversion = 1\n", false},
		// The raw file is printed too (show --toml): comments count.
		{"raw C1 in a comment", base + "# \u009b31m\n", false},
		{"raw ESC in a comment", base + "# \x1b[2J\n", false},
		{"raw tab and CRLF", "name = \"a\"\r\nkind = \"pack\"\t# t\r\ntitle = \"x\"\r\nversion = 1\r\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse("a", []byte(tc.body), SourceUser)
			if tc.ok && err != nil {
				t.Fatalf("Parse err = %v, want ok", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "control character")) {
				t.Fatalf("Parse err = %v, want a control character refusal", err)
			}
		})
	}
}

// TestParse_RejectsDeepNesting is RC-10: a nesting depth above the bound is
// refused before the decoder runs.
func TestParse_RejectsDeepNesting(t *testing.T) {
	t.Parallel()
	deep := func(open, close string, n int) string {
		return "name = \"a\"\nkind = \"pack\"\ntitle = \"x\"\nversion = 1\nadvice = " + strings.Repeat(open, n) + "\"x\"" + strings.Repeat(close, n) + "\n"
	}
	inline := "name = \"a\"\nkind = \"pack\"\ntitle = \"x\"\nversion = 1\n[[rule]]\nid = \"RC-A-1\"\nm = " + strings.Repeat("{a = ", 2000) + "1" + strings.Repeat("}", 2000) + "\n"
	cases := []struct {
		name, body string
	}{
		{"arrays", deep("[", "]", 2000)},
		{"inline tables", inline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse("a", []byte(tc.body), SourceUser)
			if err == nil || !strings.Contains(err.Error(), "nested") {
				t.Fatalf("Parse err = %v, want a nesting refusal", err)
			}
		})
	}
	// Brackets and braces inside strings and comments do not count.
	ok := "name = \"a\" # [[[[[[[[[[[[\nkind = \"pack\"\ntitle = \"x {{{{{{{{{{{{\"\nversion = 1\nsummary = '''[[[[[[[[[[[[[\n{{{{{{{{{{{'''\n"
	if _, err := Parse("a", []byte(ok), SourceUser); err != nil {
		t.Fatalf("Parse of brackets in strings and comments: %v", err)
	}
}

// TestAddUser_NameRules is UI-4: a user file whose name is not a recipe name,
// or whose recipe names a built-in, never replaces a built-in.
func TestAddUser_NameRules(t *testing.T) {
	t.Parallel()
	strictBody := strings.Replace(lvlStrict, `name = "lvl"`, `name = "strict"`, 1)
	cases := []struct {
		name, file, body string
	}{
		// A file named exactly ".toml": the name is empty after the suffix.
		{"empty file name", "", strictBody},
		{"upper case file name", "Strict", strictBody},
		{"file name of a built-in", "strict", strictBody},
		{"file name with a path", "../strict", strictBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustSet(t, map[string]string{"strict": strictBody, "net": packNet})
			before := s.byName["strict"]
			s.AddUser(tc.file, []byte(tc.body))
			if s.byName["strict"] != before || before.Source != SourceBuiltin {
				t.Fatalf("a user file replaced a built-in")
			}
			if _, ok := s.byName[tc.file]; ok && tc.file != "strict" {
				t.Fatalf("a user file loaded under %q", tc.file)
			}
			if len(s.Issues) != 1 {
				t.Fatalf("issues = %v, want one", s.Issues)
			}
		})
	}
}
