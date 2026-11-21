package reviewcore

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/scorecore"
)

// RouteRule sends a matching score's trace into a review queue (the
// negative-feedback route, W5-6). A queue holds up to MaxRouteRules; a score
// routes when any of them matches.
type RouteRule struct {
	// Source is the score source the rule reads: feedback (the default) or
	// sdk.
	Source string `json:"source,omitempty"`
	// Name is the score name; empty matches any name.
	Name string `json:"name,omitempty"`
	// Match is the predicate: negative (the default; the score did not
	// pass, scorecore.Passed), at_most or below (numeric against
	// Threshold), or one_of (the stored value is one of Values).
	Match     string   `json:"match,omitempty"`
	Threshold *float64 `json:"threshold,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// MaxRouteRules bounds a queue's rules.
const MaxRouteRules = 10

// ScoreFacts are the fields of a written score the rules read.
type ScoreFacts struct {
	Source string
	Name   string
	Kind   string
	Value  string
	Num    *float64
}

// matchRow is one row of the predicate table.
type matchRow struct {
	Match         string
	NeedThreshold bool
	NeedValues    bool
	Test          func(r RouteRule, s ScoreFacts) bool
}

var matchTable = []matchRow{
	{"negative", false, false, func(_ RouteRule, s ScoreFacts) bool {
		return !scorecore.Passed(scorecore.Kind(s.Kind), s.Value, s.Num)
	}},
	{"at_most", true, false, func(r RouteRule, s ScoreFacts) bool { return s.Num != nil && *s.Num <= *r.Threshold }},
	{"below", true, false, func(r RouteRule, s ScoreFacts) bool { return s.Num != nil && *s.Num < *r.Threshold }},
	{"one_of", false, true, func(r RouteRule, s ScoreFacts) bool {
		for _, v := range r.Values {
			if strings.EqualFold(strings.TrimSpace(v), s.Value) {
				return true
			}
		}
		return false
	}},
}

// routeSources are the sources a rule may read: the client-written ones.
var routeSources = []string{string(scorecore.SourceFeedback), string(scorecore.SourceSDK)}

func (r RouteRule) norm() RouteRule {
	r.Source = strings.ToLower(strings.TrimSpace(r.Source))
	if r.Source == "" {
		r.Source = string(scorecore.SourceFeedback)
	}
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	r.Match = strings.ToLower(strings.TrimSpace(r.Match))
	if r.Match == "" {
		r.Match = "negative"
	}
	return r
}

func matchOf(m string) (matchRow, bool) {
	for _, row := range matchTable {
		if row.Match == m {
			return row, true
		}
	}
	return matchRow{}, false
}

// NormalizeRouteRules validates rules and returns them with defaults filled.
func NormalizeRouteRules(rules []RouteRule) ([]RouteRule, error) {
	if len(rules) > MaxRouteRules {
		return nil, fmt.Errorf("at most %d route rules", MaxRouteRules)
	}
	out := make([]RouteRule, 0, len(rules))
	for i, r := range rules {
		r = r.norm()
		ok := false
		for _, s := range routeSources {
			ok = ok || r.Source == s
		}
		if !ok {
			return nil, fmt.Errorf("route rule %d: source is feedback or sdk", i)
		}
		if r.Name != "" {
			if _, err := scorecore.NormalizeName(r.Name); err != nil {
				return nil, fmt.Errorf("route rule %d: %s", i, err.Message)
			}
		}
		row, ok := matchOf(r.Match)
		if !ok {
			return nil, fmt.Errorf("route rule %d: match is negative, at_most, below or one_of", i)
		}
		if row.NeedThreshold != (r.Threshold != nil) {
			return nil, fmt.Errorf("route rule %d: threshold is required for at_most and below and refused otherwise", i)
		}
		if row.NeedValues != (len(r.Values) > 0) || len(r.Values) > 30 {
			return nil, fmt.Errorf("route rule %d: values (1-30) are required for one_of and refused otherwise", i)
		}
		out = append(out, r)
	}
	return out, nil
}

// Matches reports whether rule r (normalized) matches score s.
func (r RouteRule) Matches(s ScoreFacts) bool {
	if r.Source != s.Source || (r.Name != "" && r.Name != s.Name) {
		return false
	}
	row, ok := matchOf(r.Match)
	return ok && row.Test(r, s)
}

// Routes reports whether any of rules routes s.
func Routes(rules []RouteRule, s ScoreFacts) bool {
	for _, r := range rules {
		if r.Matches(s) {
			return true
		}
	}
	return false
}
