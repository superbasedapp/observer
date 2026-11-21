package reviewcore

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/scorecore"
)

// Rubric bounds.
const (
	MaxRubricCriteria = 20
	MaxCriterionOpts  = 30
)

// RubricCriterion is one rubric line (the org's org_review_queue.rubric_json
// and the machine's obs_review_queues.rubric_json store a list of these).
type RubricCriterion struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	Options  []string `json:"options,omitempty"`
	Required bool     `json:"required,omitempty"`
	About    string   `json:"about,omitempty"`
}

// ValidateRubric checks a rubric: 1-20 criteria, unique valid names, a
// known kind, min ≤ max on numeric, at least two options on categorical.
func ValidateRubric(r []RubricCriterion) error {
	if len(r) == 0 || len(r) > MaxRubricCriteria {
		return fmt.Errorf("a rubric needs 1-%d criteria", MaxRubricCriteria)
	}
	seen := map[string]bool{}
	for i, c := range r {
		name, err := scorecore.NormalizeName(c.Name)
		if err != nil {
			return fmt.Errorf("criterion %d: %s", i, err.Message)
		}
		if seen[name] {
			return fmt.Errorf("criterion %q repeats", name)
		}
		seen[name] = true
		if err := validateKind(name, c); err != nil {
			return err
		}
		if len(c.About) > 500 {
			return fmt.Errorf("criterion %q: about is at most 500 characters", name)
		}
	}
	return nil
}

func validateKind(name string, c RubricCriterion) error {
	switch scorecore.Kind(c.Kind) {
	case scorecore.KindNumeric:
		if c.Min != nil && c.Max != nil && *c.Min > *c.Max {
			return fmt.Errorf("criterion %q: min is above max", name)
		}
	case scorecore.KindBoolean:
	case scorecore.KindCategorical:
		if len(c.Options) < 2 || len(c.Options) > MaxCriterionOpts {
			return fmt.Errorf("criterion %q needs 2-%d options", name, MaxCriterionOpts)
		}
		for _, o := range c.Options {
			if _, err := scorecore.CategoricalText(o); err != nil {
				return fmt.Errorf("criterion %q option: %s", name, err.Message)
			}
		}
	default:
		return fmt.Errorf("criterion %q: kind must be numeric, boolean or categorical", name)
	}
	return nil
}

// ValidateAnswers checks answers (criterion name to a JSON value) against a
// rubric and returns the scores they make: source review, scorer "review",
// with no trace, author or time (the caller stamps those).
func ValidateAnswers(rubric []RubricCriterion, answers map[string]json.RawMessage) ([]scorecore.Score, error) {
	known := map[string]RubricCriterion{}
	for _, c := range rubric {
		n, _ := scorecore.NormalizeName(c.Name)
		known[n] = c
	}
	for k := range answers {
		if _, ok := known[strings.ToLower(strings.TrimSpace(k))]; !ok {
			return nil, fmt.Errorf("%q is not a criterion of this rubric", k)
		}
	}
	var out []scorecore.Score
	for _, c := range rubric {
		name, _ := scorecore.NormalizeName(c.Name)
		raw, ok := answers[name]
		if !ok {
			raw, ok = answers[c.Name]
		}
		if !ok || len(raw) == 0 || string(raw) == "null" {
			if c.Required {
				return nil, fmt.Errorf("%q is required", name)
			}
			continue
		}
		s, err := answerScore(name, c, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("a review needs at least one answer")
	}
	return out, nil
}

func answerScore(name string, c RubricCriterion, raw json.RawMessage) (scorecore.Score, error) {
	kind, text, num, err := scorecore.DecodeValue(raw, scorecore.Kind(c.Kind))
	if err != nil {
		return scorecore.Score{}, fmt.Errorf("%q: %s", name, err.Message)
	}
	if kind == scorecore.KindNumeric && ((c.Min != nil && *num < *c.Min) || (c.Max != nil && *num > *c.Max)) {
		return scorecore.Score{}, fmt.Errorf("%q is out of range", name)
	}
	if kind == scorecore.KindCategorical && !hasOption(c.Options, text) {
		return scorecore.Score{}, fmt.Errorf("%q must be one of the criterion's options", name)
	}
	return scorecore.Score{Key: name, Kind: kind, Value: text, ValueNum: num, Source: scorecore.SourceReview, ScorerName: "review"}, nil
}

func hasOption(list []string, s string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == s {
			return true
		}
	}
	return false
}

// Criteria returns the agreement view of a rubric (normalized names).
func Criteria(r []RubricCriterion) []Criterion {
	out := make([]Criterion, 0, len(r))
	for _, c := range r {
		n, _ := scorecore.NormalizeName(c.Name)
		out = append(out, Criterion{Name: n, Kind: c.Kind})
	}
	return out
}
