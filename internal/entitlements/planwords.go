package entitlements

import "strings"

// planwords.go is the plan-name vocabulary (plan 06 5.8.4 "a plan-name
// lint"; 17.1 rule 4 "no plan-name literals"). This package owns it; the
// structural rule S7 (tools/structcheck) reads it through PlanName and
// internal/entitlements/planlint. A plan name belongs in the catalog and in
// documents, never in code that decides something: code asks Has or Cap.

// PlanWord is one row of the vocabulary.
type PlanWord struct {
	// Word is the name, normalized: lower case, '_' for spaces and hyphens.
	Word string
	// Anywhere: the spelling is distinctive enough to flag as any string
	// literal. Otherwise a literal is flagged only where it is compared
	// with, or switched on, an expression naming a plan or tier ("team"
	// also names the teams feature, "free" a free rate, "self_hosted" a
	// deployment mode).
	Anywhere bool
}

// PlanWords returns the vocabulary: every catalog plan name (pinned by
// TestEveryCatalogPlanIsInTheVocabulary) and the price card's tier names
// (plan 06 8.3) that the catalog does not use as a name.
func PlanWords() []PlanWord {
	return []PlanWord{
		{Word: "free"},
		{Word: "plus_beta", Anywhere: true},
		{Word: "personal_free", Anywhere: true},
		{Word: "personal_pro", Anywhere: true},
		{Word: "team_free", Anywhere: true},
		{Word: "team_lapsed", Anywhere: true},
		{Word: "team"},
		{Word: "business"},
		{Word: "dedicated"},
		{Word: "dedicated_lapsed", Anywhere: true},
		{Word: "self_hosted"},
		{Word: "community"},
	}
}

// PlanName returns the plan name a string literal's value spells and
// whether that spelling is flagged anywhere; "" when it spells none.
func PlanName(v string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(v))
	n = strings.NewReplacer(" ", "_", "-", "_").Replace(n)
	for _, w := range PlanWords() {
		if w.Word == n {
			return n, w.Anywhere
		}
	}
	return "", false
}
