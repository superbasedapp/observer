package secassess

import "strings"

// The weakness class of an assessment item, in Observer's own words, for the
// fix task (plan section 4, W6b; decision D24). Two seams share this table:
//
//   - the one-call hook of the Findings tab's "Fix with an agent": an imported
//     finding's rule id names a class (assess.<tag>.<suffix>), and the table
//     turns the suffix into a sentence (FixHintFor);
//   - the fix route's prompt, which names the class of the threat or finding it
//     is built from (BuildFixPrompt).
//
// Only words from Observer's own vocabulary tables reach a prompt through here.
// A suffix or a category the tables do not know is left out: it is never
// printed as the agent wrote it.

// FixClass is a weakness class named from Observer's tables.
type FixClass struct {
	// Name is the plain-words name ("STRIDE, Tampering"); for a bare weakness id
	// it is the id.
	Name string
	// Question is what the class asks, in Observer's words; empty for a weakness
	// id, which has no name in the tables (D29).
	Question string
}

// Words is the class as one phrase: "Tampering (Can data ...?)".
func (c FixClass) Words() string {
	if c.Question == "" {
		return c.Name
	}
	return c.Name + " (" + c.Question + ")"
}

// fixHintHead and fixHintTail frame the hook's sentence. Observer's words; the
// head says the finding came from a model and not from a scanner, the tail is
// the regression-test rule the fix prompt carries too.
const (
	fixHintHead = "Found by a security assessment (an agent's model, not a scanner). Class: "
	fixHintTail = ". Confirm the weakness in the code before changing it, then add a regression test that fails before the fix."
)

// fixCWENamedByAgent follows a weakness id in a class: the id came from the
// agent (Observer checked only its shape), and the fix prompt says so too.
const fixCWENamedByAgent = " (as the agent named it; Observer checked only that it is well formed)"

// FixHintMaxBytes bounds the hook's sentence: the fix prompt's own cleaner cuts
// a hint at 400 bytes, and a cut sentence would lose its tail.
const FixHintMaxBytes = 400

// strideByLetter looks a STRIDE category up by its derived-rule-id letter.
func strideByLetter(letter string) (StrideCategory, bool) {
	for _, c := range StrideCategories {
		if strings.EqualFold(c.Letter, letter) {
			return c, true
		}
	}
	return StrideCategory{}, false
}

// aiClassByCategory names an AI-framework category ("LLM01", "asi04"): the
// framework's name and the bare category id (the published lists are not
// typed in, so the category has no name here).
func aiClassByCategory(cat string) (FixClass, bool) {
	up := strings.ToUpper(cat)
	for _, f := range AIFrameworks {
		if ValidAICategory(f.ID, up) {
			return FixClass{Name: f.Name + ", category " + up}, true
		}
	}
	return FixClass{}, false
}

// fixSuffixRules is the table of the rule-id suffix forms a derivation writes
// (derive.go tmSuffix and ptSuffix), one row per form. A row resolves the part
// after its prefix; the first row whose prefix matches decides.
var fixSuffixRules = []struct {
	prefix  string
	resolve func(rest string) (FixClass, bool)
}{
	{"cwe-", func(rest string) (FixClass, bool) {
		id := "CWE-" + rest
		if !ValidCWE(id) {
			return FixClass{}, false
		}
		return FixClass{Name: "weakness " + id + fixCWENamedByAgent}, true
	}},
	{"stride-", func(rest string) (FixClass, bool) {
		c, ok := strideByLetter(rest)
		if !ok {
			return FixClass{}, false
		}
		return FixClass{Name: "STRIDE, " + c.Name, Question: c.Question}, true
	}},
	{"linddun-", func(rest string) (FixClass, bool) {
		c, ok := LinddunCategoryByID(rest)
		if !ok {
			return FixClass{}, false
		}
		return FixClass{Name: "LINDDUN, " + c.Name, Question: c.Question}, true
	}},
	{"wstg-", func(rest string) (FixClass, bool) {
		c, ok := WSTGCategoryByID(strings.ToUpper(rest))
		if !ok {
			return FixClass{}, false
		}
		return FixClass{Name: "WSTG " + c.ID + ", " + c.Title, Question: c.Intent}, true
	}},
	{"", aiClassByCategory},
}

// FixClassOfSuffix resolves the suffix of a derived rule id (the part after the
// tag and the optional run id) to a class. A suffix no row of the table knows
// is not resolved.
func FixClassOfSuffix(suffix string) (FixClass, bool) {
	s := strings.ToLower(suffix)
	for _, r := range fixSuffixRules {
		if r.prefix == "" {
			return r.resolve(s)
		}
		if rest, ok := strings.CutPrefix(s, r.prefix); ok {
			return r.resolve(rest)
		}
	}
	return FixClass{}, false
}

// ruleSuffixOf splits an imported rule id into its suffix: it strips an
// optional "other/" (the import's own prefix), requires "assess.", then the tag
// of a kind that writes a model, then an optional run id. ok is false for a
// rule id that is not a model-derived assessment rule id.
func ruleSuffixOf(ruleID string) (string, bool) {
	id := strings.TrimPrefix(ruleID, "other/")
	rest, ok := strings.CutPrefix(id, "assess.")
	if !ok {
		return "", false
	}
	tag, rest, ok := strings.Cut(rest, ".")
	if !ok || !modelTag(tag) {
		return "", false
	}
	// With rerun_dedup off the run id is in the rule id: assess.<tag>.<run>.<suffix>.
	if run, after, found := strings.Cut(rest, "."); found && ValidRunID(run) {
		rest = after
	}
	return rest, rest != ""
}

// modelTag reports whether a rule-id tag belongs to a kind whose new runs
// write a model (and so derive their findings from it).
func modelTag(tag string) bool {
	for _, k := range Kinds() {
		if k.Tag == tag && k.ModelContract() {
			return true
		}
	}
	return false
}

// FixClassOfRule resolves an imported finding's rule id to its weakness class.
func FixClassOfRule(ruleID string) (FixClass, bool) {
	suffix, ok := ruleSuffixOf(ruleID)
	if !ok {
		return FixClass{}, false
	}
	return FixClassOfSuffix(suffix)
}

// FixHintFor is the sentence the Findings tab's fix task carries for an
// imported assessment finding: Observer's own words and a class from its tables
// (D24: nothing the agent wrote). The finding's place and band are already in
// the prompt from the finding's own row, so they are not repeated here. ok is
// false for a rule id that is not a model-derived assessment rule id or whose
// suffix no table row knows.
func FixHintFor(ruleID string) (string, bool) {
	c, ok := FixClassOfRule(ruleID)
	if !ok {
		return "", false
	}
	return fixHintHead + c.Words() + fixHintTail, true
}
