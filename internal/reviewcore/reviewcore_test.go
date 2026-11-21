package reviewcore

import (
	"math"
	"reflect"
	"testing"
)

func f(v float64) *float64 { return &v }

func TestSettingsValidate(t *testing.T) {
	ok := Settings{RequiredReviews: 1, Mode: ModeOpen}
	cases := []struct {
		name string
		s    Settings
		bad  bool
	}{
		{"single reviewer default", ok, false},
		{"zero reviews", Settings{RequiredReviews: 0, Mode: ModeOpen}, true},
		{"too many reviews", Settings{RequiredReviews: 6, Mode: ModeOpen}, true},
		{"unknown mode", Settings{RequiredReviews: 1, Mode: "rr"}, true},
		{"round robin needs a pool", Settings{RequiredReviews: 2, Mode: ModeRoundRobin}, true},
		{"round robin over a team", Settings{RequiredReviews: 2, Mode: ModeRoundRobin, PoolKind: PoolTeam, PoolID: "t1"}, false},
		{"pool kind without id", Settings{RequiredReviews: 1, Mode: ModeClaim, PoolKind: PoolTeam}, true},
		{"pool id without kind", Settings{RequiredReviews: 1, Mode: ModeClaim, PoolID: "t1"}, true},
		{"unknown pool kind", Settings{RequiredReviews: 1, Mode: ModeClaim, PoolKind: "group", PoolID: "g"}, true},
		{"negative tolerance", Settings{RequiredReviews: 1, Mode: ModeOpen, NumericTolerance: -1}, true},
		{"adjudicator is the only reviewer", Settings{RequiredReviews: 1, Mode: ModeClaim, PoolKind: PoolMember, PoolID: "u1", Adjudicator: "u1"}, true},
	}
	for _, c := range cases {
		if err := c.s.Validate(); (err != nil) != c.bad {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestModeTable(t *testing.T) {
	if NeedsAssignment(ModeOpen) || AutoAssign(ModeOpen) || !NeedsAssignment(ModeClaim) || AutoAssign(ModeClaim) || !AutoAssign(ModeRoundRobin) {
		t.Fatal("mode table rows")
	}
	if len(Modes()) != 3 {
		t.Fatal(Modes())
	}
}

func TestRoundRobin(t *testing.T) {
	pool := []string{"c", "a", "b"}
	cases := []struct {
		name    string
		cursor  int
		n       int
		exclude map[string]bool
		want    []string
		next    int
	}{
		{"first one", 0, 1, nil, []string{"a"}, 1},
		{"wraps", 2, 2, nil, []string{"c", "a"}, 1},
		{"skips excluded", 0, 2, map[string]bool{"a": true}, []string{"b", "c"}, 0},
		{"fewer than asked", 0, 5, map[string]bool{"a": true, "b": true}, []string{"c"}, 0},
		{"cursor past end", 7, 1, nil, []string{"b"}, 2},
	}
	for _, c := range cases {
		got, next := RoundRobin(pool, c.cursor, c.n, c.exclude)
		if !reflect.DeepEqual(got, c.want) || next != c.next {
			t.Errorf("%s: got %v next %d, want %v next %d", c.name, got, next, c.want, c.next)
		}
	}
	if got, next := RoundRobin(nil, 3, 1, nil); got != nil || next != 3 {
		t.Fatal("empty pool picks nobody")
	}
}

func TestNextStatus(t *testing.T) {
	cases := []struct {
		req, done, conflicts int
		want                 string
	}{
		{1, 0, 0, StatusPending},
		{1, 1, 0, StatusDone},
		{2, 1, 0, StatusPending},
		{2, 2, 1, StatusAdjudication},
		{2, 2, 0, StatusDone},
	}
	for _, c := range cases {
		if got := NextStatus(c.req, c.done, c.conflicts); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
	}
}

var crit = []Criterion{{"correct", "boolean"}, {"quality", "numeric"}, {"tone", "categorical"}}

func vd(r string, correct string, q float64, tone string) Verdict {
	return Verdict{Reviewer: r, Answers: map[string]Value{
		"correct": {Kind: "boolean", Text: correct},
		"quality": {Kind: "numeric", Num: f(q)},
		"tone":    {Kind: "categorical", Text: tone},
	}}
}

func TestConflicts(t *testing.T) {
	cases := []struct {
		name string
		vs   []Verdict
		tol  float64
		want []string
	}{
		{"agree", []Verdict{vd("a", "true", 3, "calm"), vd("b", "true", 3, "calm")}, 0, []string{}},
		{"numeric within tolerance", []Verdict{vd("a", "true", 3, "calm"), vd("b", "true", 3.5, "calm")}, 0.5, []string{}},
		{"numeric outside tolerance", []Verdict{vd("a", "true", 3, "calm"), vd("b", "true", 4, "calm")}, 0.5, []string{"quality"}},
		{"two criteria", []Verdict{vd("a", "true", 3, "calm"), vd("b", "false", 3, "rude")}, 0, []string{"correct", "tone"}},
		{"one reviewer", []Verdict{vd("a", "true", 3, "calm")}, 0, []string{}},
		{"missing answer never conflicts", []Verdict{vd("a", "true", 3, "calm"), {Reviewer: "b", Answers: map[string]Value{"correct": {Text: "true"}}}}, 0, []string{}},
	}
	for _, c := range cases {
		if got := Conflicts(crit, c.vs, c.tol); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestAgreement(t *testing.T) {
	items := []ItemVerdicts{
		{"i1", []Verdict{vd("a", "true", 3, "calm"), vd("b", "true", 3, "calm")}},
		{"i2", []Verdict{vd("a", "false", 1, "rude"), vd("b", "true", 2, "rude")}},
		{"i3", []Verdict{vd("a", "true", 5, "calm"), vd("b", "true", 5, "calm"), vd("c", "true", 4, "calm")}},
		{"i4", []Verdict{vd("a", "true", 2, "calm")}}, // one verdict: left out
	}
	got := ComputeAgreement(crit, items, 0)
	if got.Items != 3 || got.FullAgreement != 1 || got.Reviewers != 3 || math.Abs(got.Percent-1.0/3) > 1e-9 {
		t.Fatalf("%+v", got)
	}
	byName := map[string]CriterionAgreement{}
	for _, c := range got.Criteria {
		byName[c.Name] = c
	}
	correct := byName["correct"]
	if correct.Items != 3 || correct.Agreed != 2 || math.Abs(correct.Pairwise-4.0/5) > 1e-9 || correct.Ratings != 7 {
		t.Fatalf("correct %+v", correct)
	}
	// Krippendorff nominal alpha by hand: n=7, values true×6, false×1.
	// D_o = (1/7)·[0 + 2/1 + 0] = 2/7; D_e = (49-37)/(7·6) = 12/42.
	if correct.Alpha == nil || math.Abs(*correct.Alpha-(1-(2.0/7)/(12.0/42))) > 1e-9 {
		t.Fatalf("alpha %v", correct.Alpha)
	}
	if tone := byName["tone"]; tone.Alpha == nil || math.Abs(*tone.Alpha-1) > 1e-9 || tone.Agreed != 3 {
		t.Fatalf("agreement within every item is alpha 1: %+v", tone)
	}
	same := []ItemVerdicts{{"i1", []Verdict{vd("a", "true", 1, "x"), vd("b", "true", 1, "x")}}}
	if c := ComputeAgreement(crit, same, 0).Criteria[0]; c.Alpha != nil || c.Percent != 1 {
		t.Fatalf("one value everywhere: alpha undefined: %+v", c)
	}
	if q := byName["quality"]; q.Alpha == nil || *q.Alpha >= 1 || q.Agreed != 1 {
		t.Fatalf("quality %+v", q)
	}
	if empty := ComputeAgreement(crit, nil, 0); empty.Items != 0 || len(empty.Criteria) != 3 || empty.Criteria[0].Alpha != nil {
		t.Fatalf("%+v", empty)
	}
}

func TestPerfectNumericAlphaIsOne(t *testing.T) {
	items := []ItemVerdicts{
		{"i1", []Verdict{vd("a", "true", 1, "x"), vd("b", "true", 1, "x")}},
		{"i2", []Verdict{vd("a", "true", 4, "x"), vd("b", "true", 4, "x")}},
	}
	q := ComputeAgreement(crit, items, 0).Criteria[1]
	if q.Alpha == nil || math.Abs(*q.Alpha-1) > 1e-9 {
		t.Fatalf("%+v", q)
	}
}

func TestRouteRules(t *testing.T) {
	if _, err := NormalizeRouteRules(make([]RouteRule, 11)); err == nil {
		t.Fatal("cap")
	}
	bad := []RouteRule{
		{Source: "eval"},
		{Match: "worse"},
		{Match: "at_most"},
		{Match: "negative", Threshold: f(1)},
		{Match: "one_of"},
		{Match: "below", Threshold: f(1), Values: []string{"x"}},
		{Name: "Bad Name!"},
	}
	for i, r := range bad {
		if _, err := NormalizeRouteRules([]RouteRule{r}); err == nil {
			t.Errorf("bad rule %d accepted: %+v", i, r)
		}
	}
	rules, err := NormalizeRouteRules([]RouteRule{
		{}, // negative feedback, any name
		{Source: "SDK", Name: "Helpfulness", Match: "below", Threshold: f(0.3)},
		{Name: "rating", Match: "one_of", Values: []string{"Bad"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Source != "feedback" || rules[0].Match != "negative" || rules[1].Source != "sdk" || rules[1].Name != "helpfulness" {
		t.Fatalf("%+v", rules)
	}
	cases := []struct {
		name string
		s    ScoreFacts
		want bool
	}{
		{"thumbs down", ScoreFacts{Source: "feedback", Name: "thumbs", Kind: "boolean", Value: "false", Num: f(0)}, true},
		{"thumbs up", ScoreFacts{Source: "feedback", Name: "thumbs", Kind: "boolean", Value: "true", Num: f(1)}, false},
		{"low numeric feedback", ScoreFacts{Source: "feedback", Name: "stars", Kind: "numeric", Value: "0.2", Num: f(0.2)}, true},
		{"sdk below threshold", ScoreFacts{Source: "sdk", Name: "helpfulness", Kind: "numeric", Value: "0.2", Num: f(0.2)}, true},
		{"sdk above threshold", ScoreFacts{Source: "sdk", Name: "helpfulness", Kind: "numeric", Value: "0.5", Num: f(0.5)}, false},
		{"sdk other name", ScoreFacts{Source: "sdk", Name: "other", Kind: "numeric", Value: "0", Num: f(0)}, false},
		{"eval source never routes", ScoreFacts{Source: "eval", Name: "x", Kind: "boolean", Value: "false", Num: f(0)}, false},
		{"categorical one_of", ScoreFacts{Source: "feedback", Name: "rating", Kind: "categorical", Value: "bad"}, true},
	}
	for _, c := range cases {
		if got := Routes(rules, c.s); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
