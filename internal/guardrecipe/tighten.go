package guardrecipe

import "fmt"

// A pack adds or tightens rules; it never lowers one (docs/guard-recipes.md
// "The packs"). The engine applies [[override]] rows in file order, last
// wins, so a pack row placed after the level's row would replace the
// level's decision with its own, stricter or not (sweep finding RC-3:
// lockdown with the networking pack turned R-176 from deny to ask). The
// compiler therefore joins every pack row to the stance the rows before it
// leave the rule in, tighten-only: the stricter decision, the enforce flags
// OR-ed. A pack row that could only lower the rule (an `enforce = false`
// cap, or a decision below the rule's own decision where no recipe row set
// one) is a problem that refuses the apply, not a row in the file.

// stance is one rule's state as the rows compiled so far leave it, folded
// the way the engine applies override rows (policy applyOverride): a
// decision replaces both the observe and the enforce decision,
// `enforce = true` holds the enforce decision in observe mode.
type stance struct {
	// enf is the enforce decision; "" when the compiler does not know the
	// rule (a rule this binary lacks: the guard drops the row on load).
	enf string
	// pinned reports that a recipe row set the decision, so the rule's own
	// catalog decision no longer applies.
	pinned bool
}

// stances tracks every rule a compiled file touches.
type stances struct {
	m map[string]*stance
}

// newStances seeds the stances from the rule catalog.
func newStances(cat []CatalogRule) *stances {
	s := &stances{m: map[string]*stance{}}
	for _, c := range cat {
		if _, ok := s.m[c.ID]; !ok {
			s.m[c.ID] = &stance{enf: c.Enforce}
		}
	}
	return s
}

// define seeds a rule a recipe [[rule]] row defines, from its own decision
// (first definition wins, as it does in the compiled file).
func (s *stances) define(row map[string]any) {
	id := RuleID(row)
	if id == "" {
		return
	}
	if _, ok := s.m[id]; ok {
		return
	}
	d, _ := row["decision"].(string)
	if !validDecisions[d] || d == "" {
		d = "allow"
	}
	s.m[id] = &stance{enf: d}
}

func (s *stances) get(id string) *stance {
	st, ok := s.m[id]
	if !ok {
		st = &stance{}
		s.m[id] = st
	}
	return st
}

// apply folds a level row in last-wins, as the engine will.
func (s *stances) apply(ov OverrideRow) {
	if ov.Decision != "" {
		st := s.get(ov.Rule)
		st.enf, st.pinned = ov.Decision, true
	}
}

// packOutcome is what the compiler does with one half of a pack row.
type packOutcome int

const (
	// packNone: the row does not set this half.
	packNone packOutcome = iota
	// packEmit: the half tightens (or keeps) the rule; it is written.
	packEmit
	// packKeep: a recipe row before it is stricter; that one stays and the
	// half is recorded as a comment.
	packKeep
	// packRefuse: the half could only lower the rule; it is a problem.
	packRefuse
)

// packDecisionRules decide a pack row's decision against the rule's stance,
// walked top-down, first match wins (CLAUDE.md rule 5).
var packDecisionRules = []struct {
	name string
	when func(st stance, dec string) bool
	then packOutcome
}{
	{"no decision", func(_ stance, dec string) bool { return dec == "" }, packNone},
	{"rule unknown to the compiler (the guard drops the row)", func(st stance, _ string) bool { return st.enf == "" }, packEmit},
	{"raises or keeps the decision", func(st stance, dec string) bool { return decisionRank[dec] >= decisionRank[st.enf] }, packEmit},
	{"below a recipe row's decision", func(st stance, _ string) bool { return st.pinned }, packKeep},
	{"below the rule's own decision", func(stance, string) bool { return true }, packRefuse},
}

// packEnforceRules decide a pack row's enforce flag (OR-ed with the rule's).
var packEnforceRules = []struct {
	name string
	when func(e *bool) bool
	then packOutcome
}{
	{"no enforce key", func(e *bool) bool { return e == nil }, packNone},
	{"enforce = true holds the rule in observe mode too", func(e *bool) bool { return *e }, packEmit},
	{"enforce = false caps the rule at flag", func(*bool) bool { return true }, packRefuse},
}

// tighten joins one pack row to the rule's stance. It returns the row to
// write (Decision and Enforce cleared where they do not tighten), a comment
// naming a decision a stricter recipe row kept, and a problem when the row
// could only lower the rule.
func (s *stances) tighten(recipe string, ov OverrideRow) (row OverrideRow, kept, problem string) {
	st := s.get(ov.Rule)
	row = ov
	switch decide(packDecisionRules, *st, ov.Decision) {
	case packEmit:
		st.enf, st.pinned = ov.Decision, true
	case packKeep:
		kept = fmt.Sprintf("%s: the pack's %q is below the %q a recipe row before it set, which stays (a pack only tightens)", ov.Rule, ov.Decision, st.enf)
		row.Decision = ""
	case packRefuse:
		problem = fmt.Sprintf("pack %s: decision %q on %s is below the rule's own %q: a pack only adds or tightens rules (put a lowering in a level or in your own policy file)", recipe, ov.Decision, ov.Rule, st.enf)
		row.Decision = ""
	}
	switch decideEnforce(ov.Enforce) {
	case packRefuse:
		msg := fmt.Sprintf("pack %s: `enforce = false` on %s would cap the rule at flag: a pack only adds or tightens rules", recipe, ov.Rule)
		if problem == "" {
			problem = msg
		} else {
			problem += "; " + msg
		}
		row.Enforce = nil
	case packNone:
		row.Enforce = nil
	}
	return row, kept, problem
}

func decide(rules []struct {
	name string
	when func(st stance, dec string) bool
	then packOutcome
}, st stance, dec string,
) packOutcome {
	for _, r := range rules {
		if r.when(st, dec) {
			return r.then
		}
	}
	return packNone
}

func decideEnforce(e *bool) packOutcome {
	for _, r := range packEnforceRules {
		if r.when(e) {
			return r.then
		}
	}
	return packNone
}
