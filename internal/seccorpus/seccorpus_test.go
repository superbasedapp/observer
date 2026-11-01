package seccorpus

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestWilsonLowerKnownValues(t *testing.T) {
	// Reference values of the Wilson 95 percent lower bound (z = 1.96).
	cases := []struct {
		k, n int
		want float64
	}{
		{0, 10, 0},
		{8, 10, 0.4902},
		{10, 10, 0.7225},
		{27, 30, 0.7438},
		{30, 30, 0.8865},
		{50, 100, 0.4038},
		{95, 100, 0.8883},
		{0, 0, 0},
		{5, 4, 0},
	}
	for _, c := range cases {
		if got := WilsonLower(c.k, c.n); math.Abs(got-c.want) > 0.0005 {
			t.Errorf("WilsonLower(%d, %d) = %.4f, want %.4f", c.k, c.n, got, c.want)
		}
	}
	// Sixteen of sixteen is the smallest all-true sample to clear 0.8.
	if WilsonLower(15, 15) >= 0.8 || WilsonLower(16, 16) < 0.8 {
		t.Errorf("the 0.8 bar moved: 15/15 = %.4f, 16/16 = %.4f", WilsonLower(15, 15), WilsonLower(16, 16))
	}
}

func TestKappa(t *testing.T) {
	cases := []struct {
		name    string
		a       Agreement
		want    float64
		defined bool
	}{
		// The textbook table: po 0.7, pe 0.5.
		{"textbook", Agreement{BothTrue: 20, OnlyA: 5, OnlyB: 10, BothFalse: 15}, 0.4, true},
		{"perfect, mixed", Agreement{BothTrue: 7, BothFalse: 3}, 1, true},
		{"no agreement beyond chance", Agreement{BothTrue: 1, OnlyA: 1, OnlyB: 1, BothFalse: 1}, 0, true},
		{"all one verdict", Agreement{BothTrue: 9}, 0, false},
		{"empty", Agreement{}, 0, false},
	}
	for _, c := range cases {
		got, def := c.a.Kappa()
		if def != c.defined || math.Abs(got-c.want) > 1e-9 {
			t.Errorf("%s: Kappa = %.4f %v, want %.4f %v", c.name, got, def, c.want, c.defined)
		}
	}
}

func f(path string, line int, rule string) Finding {
	return Finding{Repo: "https://github.com/o/r", Commit: strings.Repeat("a", 40), Path: path, Line: line, Rule: rule}
}

func lab(fd Finding, rev string, v Verdict) LabelRecord {
	r := Reason("input_reaches_sink")
	if v == FalsePositive {
		r = "constant_or_internal"
	}
	return LabelRecord{Finding: fd, Reviewer: rev, Verdict: v, Reason: r}
}

func TestMeasure(t *testing.T) {
	x1, x2, x3 := f("a.py", 1, "python.x"), f("a.py", 2, "python.x"), f("a.py", 3, "python.x")
	y1 := f("b.go", 9, "go.y")
	cands := []Finding{x1, x2, x3, y1}
	labels := []LabelRecord{
		lab(x1, ReviewerA, TruePositive), lab(x1, ReviewerB, TruePositive),
		lab(x2, ReviewerA, TruePositive), lab(x2, ReviewerB, FalsePositive), // a disagreement counts against
		lab(x3, ReviewerA, FalsePositive), lab(x3, ReviewerB, FalsePositive),
		lab(y1, ReviewerA, TruePositive), lab(y1, ReviewerB, TruePositive),
	}
	m, err := Measure(cands, labels)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Rules) != 2 || m.Rules[0].Rule != "go.y" || m.Rules[1].Rule != "python.x" {
		t.Fatalf("rules %+v", m.Rules)
	}
	x := m.Rules[1]
	if x.Labelled != 3 || x.TruePositives != 1 || x.Agreement.Disagreements() != 1 || math.Abs(x.Figure-1.0/3) > 1e-9 {
		t.Fatalf("python.x %+v", x)
	}
	if x.WilsonLower != WilsonLower(1, 3) {
		t.Fatalf("lower %v", x.WilsonLower)
	}
	if m.Overall.N() != 4 || m.Overall.Disagreements() != 1 {
		t.Fatalf("overall %+v", m.Overall)
	}

	bad := []struct {
		name   string
		labels []LabelRecord
		want   string
	}{
		{"missing label", labels[:7], "no label"},
		{"duplicate", append(append([]LabelRecord(nil), labels...), lab(y1, ReviewerA, TruePositive)), "twice"},
		{"unknown finding", append(append([]LabelRecord(nil), labels...), lab(f("c.py", 1, "python.x"), ReviewerA, TruePositive)), "names no candidate"},
		{"reason of the other verdict", append(append([]LabelRecord(nil), labels[:7]...), LabelRecord{Finding: y1, Reviewer: ReviewerB, Verdict: TruePositive, Reason: "wrong_match"}), "belongs to"},
		{"third reviewer", append(append([]LabelRecord(nil), labels[:7]...), LabelRecord{Finding: y1, Reviewer: "c", Verdict: TruePositive, Reason: "unsafe_setting"}), "reviewer"},
	}
	for _, c := range bad {
		_, err := Measure(cands, c.labels)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := Measure(cands, labels[:7]); !errors.Is(err, ErrIncomplete) {
		t.Errorf("missing label is not ErrIncomplete: %v", err)
	}
}

func TestFindingValidate(t *testing.T) {
	good := f("src/a.py", 3, "python.x")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Finding){
		"http":         func(x *Finding) { x.Repo = "http://github.com/o/r" },
		"short commit": func(x *Finding) { x.Commit = "abc" },
		"upper commit": func(x *Finding) { x.Commit = strings.Repeat("A", 40) },
		"absolute":     func(x *Finding) { x.Path = "/etc/passwd" },
		"dotdot":       func(x *Finding) { x.Path = "../x" },
		"unclean":      func(x *Finding) { x.Path = "a/./b" },
		"backslash":    func(x *Finding) { x.Path = `a\b` },
		"line":         func(x *Finding) { x.Line = 0 },
		"rule":         func(x *Finding) { x.Rule = "Python.X" },
	} {
		x := good
		mut(&x)
		if x.Validate() == nil {
			t.Errorf("%s validated", name)
		}
	}
}

func TestExclusions(t *testing.T) {
	cases := map[string]string{
		"web/node_modules/x/index.js":                    "deps.node_modules",
		"vendor/github.com/a/b.go":                       "deps.vendor",
		"src/third_party/lib.py":                         "deps.third_party",
		"assets/app.min.js":                              "build.min-js",
		"api/v1/svc.pb.go":                               "gen.pb-go",
		"Forms/Main.Designer.cs":                         "gen.designer-cs",
		"lib/.venv/x.py":                                 "deps.venv",
		"tests/test_db.py":                               "",
		"src/vendor.go":                                  "",
		"node_modules.js":                                "",
		"pkg/server_test.go":                             "",
		"internal/secrulepack/testdata/fixtures/go.x.go": "self.rule-fixtures",
	}
	for p, want := range cases {
		e, ok := Excluded(p)
		if (want == "") == ok || e.ID != want {
			t.Errorf("Excluded(%q) = %q %v, want %q", p, e.ID, ok, want)
		}
	}
	kept, ex := Partition([]Finding{f("a.js", 1, "js.x"), f("node_modules/a.js", 1, "js.x"), f("x.min.js", 1, "js.x")})
	if len(kept) != 1 || ex["deps.node_modules"] != 1 || ex["build.min-js"] != 1 {
		t.Fatalf("Partition = %v %v", kept, ex)
	}
	ids := map[string]bool{}
	for _, e := range Exclusions {
		set := 0
		for _, s := range []string{e.Segment, e.Suffix, e.Prefix} {
			if s != "" {
				set++
			}
		}
		if ids[e.ID] || set != 1 || e.Why == "" {
			t.Errorf("exclusion row %+v: a unique id, exactly one of segment, suffix and prefix, and a reason", e)
		}
		ids[e.ID] = true
	}
}

func rows() []SampleRow {
	var out []SampleRow
	for _, rule := range []string{"go.a", "go.b", "js.c"} {
		for i := 1; i <= 12; i++ {
			out = append(out, SampleRow{Finding: f("x.go", i, rule), ReviewerA: TruePositive, ReviewerB: TruePositive, Joint: TruePositive})
		}
	}
	return out
}

func TestDrawSampleIsSeededAndStratified(t *testing.T) {
	a, err := DrawSample(rows(), []string{"go.a", "js.c"}, 20261021, 5, 150)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DrawSample(rows(), []string{"js.c", "go.a"}, 20261021, 5, 150)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the same seed drew different rows")
	}
	per := map[string]int{}
	for _, r := range a {
		per[r.Rule]++
	}
	// Every row is both-true: half of 12 is 6, and the minimum a rule may
	// block on is 10, which lifts the per-rule 5.
	if len(a) != 20 || per["go.a"] != 10 || per["js.c"] != 10 || per["go.b"] != 0 {
		t.Fatalf("sample %v", per)
	}
	c, _ := DrawSample(rows(), []string{"go.a", "js.c"}, 7, 5, 150)
	if reflect.DeepEqual(a, c) {
		t.Fatal("another seed drew the same rows")
	}
	// Adding a rule leaves the other rules' rows unchanged.
	d, _ := DrawSample(rows(), []string{"go.a", "go.b", "js.c"}, 20261021, 5, 150)
	var dGoA, aGoA []SampleRow
	for _, r := range d {
		if r.Rule == "go.a" {
			dGoA = append(dGoA, r)
		}
	}
	for _, r := range a {
		if r.Rule == "go.a" {
			aGoA = append(aGoA, r)
		}
	}
	if !reflect.DeepEqual(aGoA, dGoA) {
		t.Fatal("adding a rule changed another rule's draw")
	}
	// The total cap lowers the per-rule fill but never the required rows.
	e, _ := DrawSample(rows(), []string{"go.a", "go.b", "js.c"}, 1, 5, 7)
	if len(e) != 30 {
		t.Fatalf("capped sample of %d rows", len(e))
	}
	if _, err := DrawSample(rows(), []string{"py.none"}, 1, 5, 150); err == nil {
		t.Fatal("a rule with no rows drew")
	}
	// A recorded draw: a fixed seed draws these rows on every Go version
	// (rows are ordered by key, so line 10 sorts before line 2). The first
	// five of the shuffle (10, 2, 3, 5, 6) were the unstratified draw.
	want := []int{10, 12, 1, 2, 3, 4, 5, 6, 8, 9}
	var got []int
	for _, r := range a {
		if r.Rule == "go.a" {
			got = append(got, r.Line)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("seed 20261021 drew lines %v for go.a, recorded %v", got, want)
	}
}

// TestDrawSampleKeepsTheEvidence is audit finding 4: the sample always holds
// every reviewer disagreement and at least half the both-true findings,
// whatever the per-rule count, and at least min(10, both-true) rows.
func TestDrawSampleKeepsTheEvidence(t *testing.T) {
	var rs []SampleRow
	for i := 1; i <= 40; i++ {
		r := SampleRow{Finding: f("m.go", i, "go.mixed"), ReviewerA: FalsePositive, ReviewerB: FalsePositive}
		switch {
		case i <= 3:
			r.ReviewerB = TruePositive // a disagreement
		case i <= 9:
			r.ReviewerA, r.ReviewerB = TruePositive, TruePositive
		}
		r.Joint = Joint(r.ReviewerA, r.ReviewerB)
		rs = append(rs, r)
	}
	for i := 1; i <= 30; i++ {
		rs = append(rs, SampleRow{Finding: f("t.go", i, "go.true"), ReviewerA: TruePositive, ReviewerB: TruePositive, Joint: TruePositive})
	}
	for _, seed := range []uint64{1, 20261022, 99} {
		for _, per := range []int{1, 5} {
			s, err := DrawSample(rs, []string{"go.mixed", "go.true"}, seed, per, 150)
			if err != nil {
				t.Fatal(err)
			}
			dis, bt := map[string]int{}, map[string]int{}
			n := map[string]int{}
			for _, r := range s {
				n[r.Rule]++
				if r.ReviewerA != r.ReviewerB {
					dis[r.Rule]++
				}
				if r.Joint == TruePositive {
					bt[r.Rule]++
				}
			}
			// go.mixed: 3 disagreements, 3 of its 6 both-true, then up to
			// max(per, min(10, 6)) = 6 rows.
			if dis["go.mixed"] != 3 || bt["go.mixed"] < 3 || n["go.mixed"] != 6 {
				t.Errorf("seed %d per %d: go.mixed %d rows, %d disagreements, %d both-true", seed, per, n["go.mixed"], dis["go.mixed"], bt["go.mixed"])
			}
			// go.true: half of 30 is 15, above the minimum of 10.
			if n["go.true"] != 15 {
				t.Errorf("seed %d per %d: go.true %d rows (want 15)", seed, per, n["go.true"])
			}
		}
	}
}

func TestPerRule(t *testing.T) {
	for _, c := range []struct{ rules, per, max, want int }{{10, 5, 150, 5}, {40, 5, 150, 3}, {200, 5, 150, 1}, {0, 5, 150, 0}} {
		if got := PerRule(c.rules, c.per, c.max); got != c.want {
			t.Errorf("PerRule(%d, %d, %d) = %d, want %d", c.rules, c.per, c.max, got, c.want)
		}
	}
}

func TestTallySample(t *testing.T) {
	rs := []SampleRow{
		{Finding: f("a", 1, "go.a"), ReviewerA: TruePositive, ReviewerB: TruePositive, Joint: TruePositive, Operator: OperatorAgree},
		{Finding: f("a", 2, "go.a"), ReviewerA: TruePositive, ReviewerB: TruePositive, Joint: TruePositive, Operator: OperatorOverturn},
		{Finding: f("a", 3, "go.a"), ReviewerA: TruePositive, ReviewerB: FalsePositive, Joint: FalsePositive, Operator: OperatorOverturn},
		{Finding: f("a", 1, "js.b"), ReviewerA: TruePositive, ReviewerB: TruePositive, Joint: TruePositive, Operator: OperatorAgree},
	}
	got, err := TallySample(rs)
	if err != nil {
		t.Fatal(err)
	}
	want := []Tally{{Rule: "go.a", SampleSize: 3, Disagreements: 2, OverturnedTrue: 1}, {Rule: "js.b", SampleSize: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TallySample = %+v", got)
	}
	unanswered := append([]SampleRow(nil), rs...)
	unanswered[0].Operator = ""
	if _, err := TallySample(unanswered); err == nil {
		t.Fatal("an unanswered row tallied")
	}
	forged := append([]SampleRow(nil), rs...)
	forged[2].Joint = TruePositive
	if _, err := TallySample(forged); err == nil {
		t.Fatal("an edited joint verdict tallied")
	}
}

func TestSelectForLabelling(t *testing.T) {
	var cands []Finding
	for i := 1; i <= 100; i++ {
		cands = append(cands, f("a.go", i, "go.many"))
	}
	for i := 1; i <= 7; i++ {
		cands = append(cands, f("b.go", i, "go.few"))
	}
	a := SelectForLabelling(cands, 42, 60, nil)
	b := SelectForLabelling(append([]Finding(nil), cands...), 42, 60, nil)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the same seed selected different findings")
	}
	per := map[string]int{}
	for _, x := range a {
		per[x.Rule]++
	}
	if per["go.many"] != 60 || per["go.few"] != 7 {
		t.Fatalf("selected %v (want 60 of 100 and all 7)", per)
	}
	if reflect.DeepEqual(a, SelectForLabelling(cands, 43, 60, nil)) {
		t.Fatal("another seed selected the same findings")
	}
	// A rule named in full is labelled in full (P-077); the others keep the
	// cap and the same draw.
	full := SelectForLabelling(cands, 42, 60, []string{"go.many", "go.absent"})
	per = map[string]int{}
	for _, x := range full {
		per[x.Rule]++
	}
	if per["go.many"] != 100 || per["go.few"] != 7 || len(full) != 107 {
		t.Fatalf("with go.many in full selected %v (want all 100 and all 7)", per)
	}
}

// TestMeasureCountsPassAgreement: Measure counts verdict and reason-code
// agreement over every labelled finding (lane SEC-G4 audit finding 1).
func TestMeasureCountsPassAgreement(t *testing.T) {
	var cands []Finding
	var labels []LabelRecord
	for i := 1; i <= 4; i++ {
		f := Finding{Repo: "https://github.com/o/r", Commit: strings.Repeat("a", 40), Path: "p.go", Line: i, Rule: "go.x"}
		cands = append(cands, f)
		labels = append(labels, LabelRecord{Finding: f, Reviewer: ReviewerA, Verdict: FalsePositive, Reason: "wrong_match"})
		vb, rb := FalsePositive, Reason("wrong_match")
		switch i {
		case 2:
			rb = "constant_or_internal" // same verdict, another reason
		case 3:
			vb, rb = TruePositive, "input_reaches_sink"
		}
		labels = append(labels, LabelRecord{Finding: f, Reviewer: ReviewerB, Verdict: vb, Reason: rb})
	}
	m, err := Measure(cands, labels)
	if err != nil {
		t.Fatal(err)
	}
	if want := (PassAgreement{Results: 4, VerdictAgreements: 3, ReasonAgreements: 2}); m.Passes != want {
		t.Fatalf("Passes = %+v, want %+v", m.Passes, want)
	}
}

// TestMeasureSecondPassPending: without the option a side-a-only finding is
// incomplete; with it, the finding counts on side a's verdict, outside the
// two-pass agreement, and the pending count is recorded.
func TestMeasureSecondPassPending(t *testing.T) {
	a1, a2, b1 := f("a.py", 1, "py.x"), f("a.py", 2, "py.x"), f("b.py", 1, "py.y")
	cands := []Finding{a1, a2, b1}
	labels := []LabelRecord{
		lab(a1, ReviewerA, TruePositive), lab(a2, ReviewerA, FalsePositive),
		lab(b1, ReviewerA, TruePositive), lab(b1, ReviewerB, TruePositive),
	}
	if _, err := Measure(cands, labels); err == nil {
		t.Fatal("a side-a-only finding measured without the option")
	}
	m, err := MeasureWith(cands, labels, MeasureOptions{SecondPassPending: true})
	if err != nil {
		t.Fatal(err)
	}
	if m.Passes.SecondPassPending != 2 || m.Passes.Results != 1 || m.Passes.VerdictAgreements != 1 {
		t.Fatalf("passes %+v", m.Passes)
	}
	for _, r := range m.Rules {
		switch r.Rule {
		case "py.x":
			if r.Labelled != 2 || r.TruePositives != 1 || r.SecondPassPending != 2 || r.Agreement.BothTrue != 0 {
				t.Errorf("py.x %+v", r)
			}
		case "py.y":
			if r.Labelled != 1 || r.TruePositives != 1 || r.SecondPassPending != 0 {
				t.Errorf("py.y %+v", r)
			}
		}
	}
	if _, err := MeasureWith(cands, labels[1:], MeasureOptions{SecondPassPending: true}); err == nil {
		t.Fatal("a finding with no side-a label measured")
	}
}
