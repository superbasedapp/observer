package codequality

import (
	"reflect"
	"testing"
	"time"
)

// One case per row of the complexity state table, in table order.
func TestComplexityStateRows(t *testing.T) {
	measuredIndex := ComplexityFacts{Enabled: true, CodeIntelOn: true, IndexedFiles: 4, CounterFiles: 4, CountedFiles: 4, Functions: 9}
	cases := []struct {
		f    ComplexityFacts
		want State
	}{
		{ComplexityFacts{Enabled: false, CodeIntelOn: true, IndexedFiles: 4, CounterFiles: 4, CountedFiles: 4, Functions: 9}, StateOff},
		{ComplexityFacts{Enabled: true, NotInBuild: true}, StateNotInBuild},
		{ComplexityFacts{Enabled: true, Archived: true}, StateArchived},
		{ComplexityFacts{Enabled: true, CodeIntelOn: false}, StateCodeIntelOff},
		{ComplexityFacts{Enabled: true, CodeIntelOn: true}, StateNotIndexed},
		{ComplexityFacts{Enabled: true, CodeIntelOn: true, IndexedFiles: 4}, StateNoSupportedFiles},
		{ComplexityFacts{Enabled: true, CodeIntelOn: false, IndexedFiles: 4, CounterFiles: 4}, StateCodeIntelOff},
		{ComplexityFacts{Enabled: true, CodeIntelOn: true, IndexedFiles: 4, CounterFiles: 4}, StateCountPending},
		{ComplexityFacts{Enabled: true, CodeIntelOn: true, IndexedFiles: 4, CounterFiles: 4, CountedFiles: 2}, StateNoFunctions},
		{measuredIndex, StateMeasured},
	}
	if len(cases) != len(complexityRules) {
		t.Fatalf("one case per rule: %d cases, %d rules", len(cases), len(complexityRules))
	}
	for i, c := range cases {
		got, reason := ComplexityState(c.f)
		if got != c.want || reason == "" || reason != complexityRules[i].Reason {
			t.Errorf("row %d: got %q (%q), want %q (%q)", i, got, reason, c.want, complexityRules[i].Reason)
		}
	}
}

func cxInput(values ...FuncValue) ComplexityInput {
	return ComplexityInput{
		Index: IndexFacts{Key: "/r", IndexedFiles: 6},
		Files: []ComplexityFiles{
			{Lang: "go", Counter: true, Current: true, Files: 3},
			{Lang: "python", Counter: true, Current: false, Files: 1},
			{Lang: "elixir", Counter: false, Current: true, Files: 1},
			{Lang: "go", Counter: false, Current: false, Files: 1}, // a heuristic Go file
		},
		Values: values,
	}
}

func TestMeasureComplexityRollUp(t *testing.T) {
	var values []FuncValue
	for _, c := range []int{1, 1, 2, 3, 4, 5, 8, 11, 12, 30} {
		values = append(values, FuncValue{Lang: "go", Complexity: c})
	}
	values = append(values, FuncValue{Lang: "python", Complexity: 2}, FuncValue{Lang: "python", Complexity: 0})
	in := cxInput(values...)
	in.Top = []ComplexFunction{
		{Name: "b", File: "b.go", StartLine: 1, Complexity: 12},
		{Name: "a", File: "a.go", StartLine: 9, Complexity: 30},
		{Name: "c", File: "a.go", StartLine: 2, Complexity: 12},
	}
	r := MeasureComplexity(true, true, in)
	if r.State != StateMeasured || r.Stale {
		t.Fatalf("state %s stale %v", r.State, r.Stale)
	}
	// 11 counted (the 0 is not a figure): 1,1,2,2,3,4,5,8,11,12,30.
	if r.Functions != 11 || r.Over != 3 || r.Sum != 79 || r.Max != 30 || r.P50 != 4 || r.P90 != 12 {
		t.Errorf("figure %+v", r.ComplexityFigure)
	}
	if r.OverShare == nil || *r.OverShare < 27.27 || *r.OverShare > 27.28 {
		t.Errorf("over share %v", r.OverShare)
	}
	if r.Mean == nil || *r.Mean < 7.18 || *r.Mean > 7.19 {
		t.Errorf("mean %v", r.Mean)
	}
	wantLangs := []LangComplexity{{Lang: "go", Functions: 10, Over: 3, P90: 12, Max: 30}, {Lang: "python", Functions: 1, P90: 2, Max: 2}}
	if !reflect.DeepEqual(r.PerLanguage, wantLangs) {
		t.Errorf("per language %+v", r.PerLanguage)
	}
	if r.CountedFiles != 3 || r.PendingFiles != 1 || r.UncountedFiles != 2 || !reflect.DeepEqual(r.UncountedLangs, []string{"elixir", "go"}) {
		t.Errorf("files counted %d pending %d uncounted %d %v", r.CountedFiles, r.PendingFiles, r.UncountedFiles, r.UncountedLangs)
	}
	if got := []string{r.Top[0].Name, r.Top[1].Name, r.Top[2].Name}; !reflect.DeepEqual(got, []string{"a", "c", "b"}) {
		t.Errorf("top order %v", got)
	}
}

func TestMeasureComplexityHidesNumbersWhenNotMeasured(t *testing.T) {
	in := cxInput(FuncValue{Lang: "go", Complexity: 20})
	off := MeasureComplexity(false, true, in)
	if off.State != StateOff || off.Functions != 0 || off.OverShare != nil || off.Max != 0 {
		t.Errorf("off %+v", off)
	}
	nib := MeasureComplexity(true, true, ComplexityInput{Index: IndexFacts{NotInBuild: true}})
	if nib.State != StateNotInBuild {
		t.Errorf("not in build: %s", nib.State)
	}
	pending := cxInput()
	pending.Files = []ComplexityFiles{{Lang: "go", Counter: true, Current: false, Files: 3}}
	p := MeasureComplexity(true, true, pending)
	if p.State != StateCountPending || p.PendingFiles != 3 || p.Functions != 0 {
		t.Errorf("pending %+v", p)
	}
	stale := MeasureComplexity(true, false, cxInput(FuncValue{Lang: "go", Complexity: 3}))
	if stale.State != StateMeasured || !stale.Stale {
		t.Errorf("stale %+v", stale)
	}
}

func TestPercentile(t *testing.T) {
	cases := []struct {
		vals []int
		p    float64
		want int
	}{
		{[]int{7}, 50, 7},
		{[]int{7}, 90, 7},
		{[]int{1, 2, 3, 4}, 50, 2},
		{[]int{1, 2, 3, 4}, 90, 4},
		{[]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 90, 9},
	}
	for _, c := range cases {
		if got := percentile(c.vals, c.p); got != c.want {
			t.Errorf("percentile(%v, %v) = %d, want %d", c.vals, c.p, got, c.want)
		}
	}
}

func TestComplexityPointAndChange(t *testing.T) {
	m := Measurement{
		MeasuredAt: time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC),
		Complexity: MeasureComplexity(true, true, cxInput(FuncValue{Lang: "go", Complexity: 2}, FuncValue{Lang: "go", Complexity: 20})),
	}
	p := PointFrom(m)
	if p.ComplexityState != StateMeasured || p.ComplexityFunctions != 2 || p.ComplexityOver != 1 || p.ComplexitySum != 22 || p.ComplexityP90 != 20 || p.ComplexityMax != 20 {
		t.Fatalf("point %+v", p)
	}
	if s := p.ComplexityOverShare(); s == nil || *s != 50 {
		t.Errorf("share %v", s)
	}
	old := DayPoint{Day: "2026-11-01", ComplexityState: StateMeasured, ComplexityFunctions: 4, ComplexityOver: 1}
	unrecorded := DayPoint{Day: "2026-11-02"} // a row from before migration 221
	pending := DayPoint{Day: "2026-11-03", ComplexityState: StateCountPending}
	c := ComplexityChange([]DayPoint{p, unrecorded, pending, old})
	if c.Days != 2 || c.FromDay != "2026-11-01" || c.ToDay != "2026-11-04" || c.Delta == nil || *c.Delta != 25 {
		t.Errorf("change %+v", c)
	}
	if unrecorded.ComplexityOverShare() != nil {
		t.Error("an unrecorded state is not measured")
	}
	notMeasured := PointFrom(Measurement{MeasuredAt: m.MeasuredAt, Complexity: ComplexityResult{State: StateCountPending}})
	if notMeasured.ComplexityFunctions != 0 || notMeasured.ComplexityState != StateCountPending {
		t.Errorf("not measured point %+v", notMeasured)
	}
}
