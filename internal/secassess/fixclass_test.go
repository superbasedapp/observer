package secassess

import (
	"strings"
	"testing"
)

// TestFixClassOfSuffix: one row per suffix form a derivation writes, and the
// forms it refuses.
func TestFixClassOfSuffix(t *testing.T) {
	for _, c := range []struct {
		suffix, name string
		question     bool
		ok           bool
	}{
		{"cwe-89", "weakness CWE-89" + fixCWENamedByAgent, false, true},
		{"CWE-639", "weakness CWE-639" + fixCWENamedByAgent, false, true},
		{"cwe-0", "", false, false},
		{"cwe-123456", "", false, false},
		{"cwe-", "", false, false},
		{"cwe-8x", "", false, false},
		{"stride-t", "STRIDE, Tampering", true, true},
		{"stride-E", "STRIDE, Elevation of privilege", true, true},
		{"stride-x", "", false, false},
		{"stride-tt", "", false, false},
		{"linddun-non_repudiation", "LINDDUN, Non-repudiation", true, true},
		{"linddun-nothing", "", false, false},
		{"wstg-athz", "WSTG ATHZ, Authorization", true, true},
		{"wstg-INPV", "WSTG INPV, Input validation", true, true},
		{"wstg-zzzz", "", false, false},
		{"llm01", "OWASP Top 10 for LLM applications, category LLM01", false, true},
		{"asi10", "OWASP Top 10 for agentic applications, category ASI10", false, true},
		{"llm11", "", false, false},
		{"unnamed", "", false, false},
		{"", "", false, false},
		{"my-own-rule", "", false, false},
	} {
		got, ok := FixClassOfSuffix(c.suffix)
		if ok != c.ok || got.Name != c.name || (got.Question != "") != c.question {
			t.Errorf("FixClassOfSuffix(%q) = %+v, %v; want name %q, question %v, ok %v", c.suffix, got, ok, c.name, c.question, c.ok)
		}
	}
}

// TestFixClassOfRule: the rule-id forms of the import, with and without the
// import's own prefix and the run id, and the ids that are not model-derived.
func TestFixClassOfRule(t *testing.T) {
	const run = "3fa9c2d17b0e4a56"
	for _, c := range []struct {
		rule string
		name string
		ok   bool
	}{
		{"other/assess.tm.cwe-89", "weakness CWE-89" + fixCWENamedByAgent, true},
		{"assess.tm.cwe-89", "weakness CWE-89" + fixCWENamedByAgent, true},
		{"other/assess.tm." + run + ".stride-t", "STRIDE, Tampering", true},
		{"other/assess.pt.wstg-athz", "WSTG ATHZ, Authorization", true},
		{"other/assess.pt." + run + ".cwe-639", "weakness CWE-639" + fixCWENamedByAgent, true},
		{"other/assess.rt.wstg-sess", "WSTG SESS, Session management", true},
		// A kind whose results are not derived from a model.
		{"other/assess.cspm.cwe-89", "", false},
		{"other/assess.iast.stride-t", "", false},
		{"other/assess.rasp.cwe-89", "", false},
		// Not an assessment rule id.
		{"G101", "", false},
		{"other/assessx.tm.cwe-89", "", false},
		{"other/assess.tm", "", false},
		{"other/assess.tm.", "", false},
		{"other/assess.tm." + run, "", false},
		{"other/assess.tm." + run + ".", "", false},
		{"other/assess.tm.nothing-known", "", false},
		{"", "", false},
	} {
		got, ok := FixClassOfRule(c.rule)
		if ok != c.ok || got.Name != c.name {
			t.Errorf("FixClassOfRule(%q) = %+v, %v; want %q, %v", c.rule, got, ok, c.name, c.ok)
		}
	}
}

// TestFixClassCoversEverySuffixADerivationWrites ties the class table to the
// derivation: every suffix tmSuffix and ptSuffix can write from Observer's own
// tables resolves, so a new category cannot be derived and then lose its words.
func TestFixClassCoversEverySuffixADerivationWrites(t *testing.T) {
	for _, c := range StrideCategories {
		s := tmSuffix(Threat{Framework: FrameworkSTRIDE, Category: c.ID})
		if _, ok := FixClassOfSuffix(s); !ok {
			t.Errorf("STRIDE %s: the derived suffix %q has no class", c.ID, s)
		}
	}
	for _, c := range LinddunCategories {
		s := tmSuffix(Threat{Framework: FrameworkLINDDUN, Category: c.ID})
		if _, ok := FixClassOfSuffix(s); !ok {
			t.Errorf("LINDDUN %s: the derived suffix %q has no class", c.ID, s)
		}
	}
	for _, c := range WSTGCategories {
		s := ptSuffix(PTFinding{Category: c.ID})
		if _, ok := FixClassOfSuffix(s); !ok {
			t.Errorf("WSTG %s: the derived suffix %q has no class", c.ID, s)
		}
	}
	for _, f := range AIFrameworks {
		for _, n := range []string{"01", "05", "10"} {
			s := tmSuffix(Threat{Framework: f.ID, Category: f.IDPrefix + n})
			if _, ok := FixClassOfSuffix(s); !ok {
				t.Errorf("%s %s: the derived suffix %q has no class", f.ID, n, s)
			}
		}
	}
	// The cleaned form of a derived suffix is the one that reaches a rule id.
	for _, c := range LinddunCategories {
		s := cleanRuleSuffix(tmSuffix(Threat{Framework: FrameworkLINDDUN, Category: c.ID}))
		if _, ok := FixClassOfSuffix(s); !ok {
			t.Errorf("LINDDUN %s: the cleaned suffix %q has no class", c.ID, s)
		}
	}
}

// TestFixHintFor: the sentence fits the fix prompt's hint cap for every class of
// the tables, carries the regression-test rule, holds no clearance word and no
// agent text, and is absent for a rule id the table does not know.
func TestFixHintFor(t *testing.T) {
	banned := rdBannedPattern(t)
	var suffixes []string
	for _, c := range StrideCategories {
		suffixes = append(suffixes, "stride-"+strings.ToLower(c.Letter))
	}
	for _, c := range LinddunCategories {
		suffixes = append(suffixes, "linddun-"+c.ID)
	}
	for _, c := range WSTGCategories {
		suffixes = append(suffixes, "wstg-"+strings.ToLower(c.ID))
	}
	suffixes = append(suffixes, "cwe-89", "cwe-99999", "llm01", "asi10")
	for _, s := range suffixes {
		hint, ok := FixHintFor("other/assess.tm." + s)
		if !ok {
			t.Errorf("no hint for %q", s)
			continue
		}
		if len(hint) > FixHintMaxBytes {
			t.Errorf("hint for %q is %d bytes, over %d", s, len(hint), FixHintMaxBytes)
		}
		if !strings.Contains(hint, "add a regression test that fails before the fix") {
			t.Errorf("hint for %q lacks the regression test rule: %q", s, hint)
		}
		if m := banned.FindString(hint); m != "" {
			t.Errorf("hint for %q uses the word %q: %q", s, m, hint)
		}
		if strings.Contains(hint, "`") || strings.Contains(hint, "\n") {
			t.Errorf("hint for %q is not one plain line: %q", s, hint)
		}
	}
	for _, id := range []string{"G101", "other/assess.cspm.cwe-89", "other/assess.tm.whatever"} {
		if h, ok := FixHintFor(id); ok || h != "" {
			t.Errorf("FixHintFor(%q) = %q, %v; want none", id, h, ok)
		}
	}
}
