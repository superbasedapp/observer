package cvss4

import (
	"math"
	"strings"
	"testing"
)

func mustScore(t *testing.T, vector string) Result {
	t.Helper()
	r, err := Compute(vector)
	if err != nil {
		t.Fatalf("Compute(%q): %v", vector, err)
	}
	return r
}

func TestComputeKnownVectors(t *testing.T) {
	// Expected scores written by the authors of other implementations from the
	// specification (pandatix/go-cvss's own tests, MIT) and the extremes.
	cases := []struct {
		name, vector string
		score        string
		rating       Rating
	}{
		{"every impact High", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "10.0", RatingCritical},
		{"no impact at all", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "0.0", RatingNone},
		{"full system, no subsequent system", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "9.3", RatingCritical},
		{"no system, full subsequent system", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", "7.9", RatingHigh},
		{"lowest nonzero corner", "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "1.0", RatingLow},
		{"mixed", "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L", "5.2", RatingMedium},
	}
	for _, c := range cases {
		r := mustScore(t, c.vector)
		if FormatScore(r.Score) != c.score || r.Rating != c.rating {
			t.Errorf("%s: %s = %s %s, want %s %s", c.name, c.vector, FormatScore(r.Score), r.Rating, c.score, c.rating)
		}
		if r.Vector != c.vector {
			t.Errorf("%s: canonical vector %q", c.name, r.Vector)
		}
	}
}

func TestAllZeroImpactRule(t *testing.T) {
	// A vector with no impact on the vulnerable or the subsequent system scores
	// 0.0 whatever its exploitability says. The rule is the only reason: the
	// MacroVector such a vector falls in has a positive score.
	zero, positiveMacro := 0, 0
	walkBase(func(v string) {
		b, err := Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		allNone := true
		for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
			if x, _ := b.Value(k); x != "N" {
				allNone = false
			}
		}
		if !allNone {
			return
		}
		zero++
		score, err := b.Score()
		if err != nil || score != 0 {
			t.Errorf("%s: score %v, err %v; want 0", v, score, err)
		}
		if macroScores[b.MacroVector()] > 0 {
			positiveMacro++
		}
	})
	// 4 x 2 x 2 x 3 x 3 combinations of exploitability metrics.
	if zero != 144 {
		t.Errorf("%d zero-impact base vectors, want 144", zero)
	}
	if positiveMacro != zero {
		t.Errorf("only %d of %d zero-impact vectors sit in a MacroVector that scores above 0: the rule would not be what makes them 0", positiveMacro, zero)
	}
}

func TestBaseOnlyDefaults(t *testing.T) {
	// A base vector leaves E, CR, IR and AR undefined. The specification
	// counts them as Attacked and High. Spelling those values out must give
	// the same score, and any milder value must lower it.
	base := "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
	b, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	want, err := b.Score()
	if err != nil {
		t.Fatal(err)
	}
	scoreWith := func(extra map[string]string) float64 {
		s := b.selection()
		for k, v := range extra {
			s[k] = v
		}
		got, _, err := scoreSelection(s)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, spelled := range []map[string]string{
		{"E": "A"},
		{"CR": "H"},
		{"IR": "H"},
		{"AR": "H"},
		{"E": "A", "CR": "H", "IR": "H", "AR": "H"},
		{"E": "X", "CR": "X", "IR": "X", "AR": "X"},
	} {
		if got := scoreWith(spelled); got != want {
			t.Errorf("%v scores %v, want the base score %v", spelled, got, want)
		}
	}
	for _, milder := range []map[string]string{{"E": "P"}, {"E": "U"}, {"CR": "L"}, {"IR": "L"}} {
		if got := scoreWith(milder); got >= want {
			t.Errorf("%v scores %v, not below the base score %v", milder, got, want)
		}
	}
	// Each default is applied where cvss_score.js applies it: through the
	// modified-metric-aware effective value.
	s := b.selection()
	for metric, def := range notDefinedDefaults {
		if got := s.effective(metric); got != def {
			t.Errorf("an undefined %s counts as %q, want %q", metric, got, def)
		}
	}
}

func TestSeverityDistanceLowersTheScoreInsideAMacroVector(t *testing.T) {
	// The first vector is the maximal vector of its MacroVector and scores the
	// table value; the second sits in the same MacroVector with a milder
	// attack requirement and scores less.
	top := mustScore(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if macroScores[top.MacroVector] != top.Score {
		t.Fatalf("the maximal vector scores %v, the table says %v", top.Score, macroScores[top.MacroVector])
	}
	// PR:L leaves EQ1 level 0, so the MacroVector, and with it the ceiling, is lower.
	lower := mustScore(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if lower.MacroVector == top.MacroVector || !(lower.Score < top.Score) {
		t.Fatalf("PR:L scores %v in %s, want a lower MacroVector than %s (%v)", lower.Score, lower.MacroVector, top.MacroVector, top.Score)
	}
	inside := mustScore(t, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N")
	if inside.MacroVector != top.MacroVector {
		t.Fatalf("SA:N moved the MacroVector: %s vs %s", inside.MacroVector, top.MacroVector)
	}
	if !(inside.Score < top.Score) {
		t.Errorf("a vector one step below the maximal one scores %v, not below %v", inside.Score, top.Score)
	}
}

func TestEveryBaseVectorScoresAndFindsAReferenceVector(t *testing.T) {
	n := 0
	walkBase(func(v string) {
		n++
		b, err := Parse(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		sel := b.selection()
		s, _, err := scoreSelection(sel)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if s < 0 || s > 10 {
			t.Fatalf("%s: score %v", v, s)
		}
		if tenths := s * 10; math.Abs(tenths-math.Round(tenths)) > 1e-9 {
			t.Fatalf("%s: score %v has more than one decimal", v, s)
		}
		// cvss_score.js falls back to the last candidate when no maximal
		// vector qualifies. No base vector may rely on that.
		if _, qualified, err := sel.referenceDistances(sel.macroLevels()); err != nil || !qualified {
			t.Fatalf("%s: no maximal vector qualifies (err %v)", v, err)
		}
		// The 36 MacroVectors a base vector can reach all exist.
		if _, ok := macroScore(sel.macroLevels()); !ok {
			t.Fatalf("%s: MacroVector %s is not in the table", v, macroKey(sel.macroLevels()))
		}
	})
	if n != 104976 {
		t.Fatalf("walked %d base vectors, want 104,976", n)
	}
}

func TestBaseVectorsReachExactlyThirtySixMacroVectors(t *testing.T) {
	// With E = Attacked, the requirements High and no modified metric, EQ4 is
	// 1 or 2, EQ5 is 0, and (EQ3, EQ6) is (0,0), (1,0) or (2,1).
	seen := map[string]bool{}
	walkBase(func(v string) {
		b, err := Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		seen[b.MacroVector()] = true
	})
	if len(seen) != 36 {
		t.Errorf("base vectors reach %d MacroVectors, want 36", len(seen))
	}
	for k := range seen {
		if k[3] == '0' || k[4] != '0' {
			t.Errorf("a base vector reached %s: EQ4 must be 1 or 2 and EQ5 0", k)
		}
	}
}

func TestJSRoundMatchesMathRound(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{0, 0},
		{0.4, 0},
		{0.5, 1},
		{0.6, 1},
		{1.5, 2},
		{2.5, 3},
		{49.5, 50},
		{49.499999999999993, 49}, // the 4.95 tie: float64 holds it below .5
		{0.49999999999999994, 0}, // floor(x+0.5) would answer 1
		{87.5, 88},
		{99.99999999999999, 100},
		{100, 100},
	}
	for _, c := range cases {
		if got := jsRound(c.in); got != c.want {
			t.Errorf("jsRound(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRoundingTieFollowsFirstsCalculator(t *testing.T) {
	// The unrounded score is 4.95. FIRST's calculator holds it as
	// 4.9499999999999993 and rounds down to 4.9; exact decimal arithmetic
	// (and go-cvss) answer 5.0. The package follows FIRST's calculator: this
	// is the one place the two disagree for a base vector (72 of 104,976, all
	// this same value, never across a rating boundary; testdata/README.md).
	const tie = "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"
	b, err := Parse(tie)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := unroundedScore(b.selection())
	if err != nil {
		t.Fatal(err)
	}
	if raw != 4.9499999999999993 {
		t.Fatalf("unrounded score = %.17g, want 4.9499999999999993", raw)
	}
	r := mustScore(t, tie)
	if FormatScore(r.Score) != "4.9" || r.Rating != RatingMedium {
		t.Errorf("tie scores %s %s, want 4.9 medium", FormatScore(r.Score), r.Rating)
	}
}

func TestRatingBands(t *testing.T) {
	cases := []struct {
		score float64
		want  Rating
	}{
		{0, RatingNone},
		{-1, RatingNone},
		{math.NaN(), RatingNone},
		{0.1, RatingLow},
		{3.9, RatingLow},
		{4.0, RatingMedium},
		{6.9, RatingMedium},
		{7.0, RatingHigh},
		{8.9, RatingHigh},
		{9.0, RatingCritical},
		{10.0, RatingCritical},
	}
	for _, c := range cases {
		if got := RatingOf(c.score); got != c.want {
			t.Errorf("RatingOf(%v) = %q, want %q", c.score, got, c.want)
		}
	}
	// No score a base vector can take straddles a boundary wrongly: every
	// score is a multiple of 0.1 and lands in exactly one band.
	for tenths := 0; tenths <= 100; tenths++ {
		score := float64(tenths) / 10
		got := RatingOf(score)
		switch {
		case tenths == 0 && got != RatingNone,
			tenths >= 1 && tenths <= 39 && got != RatingLow,
			tenths >= 40 && tenths <= 69 && got != RatingMedium,
			tenths >= 70 && tenths <= 89 && got != RatingHigh,
			tenths >= 90 && got != RatingCritical:
			t.Errorf("RatingOf(%s) = %q", FormatScore(score), got)
		}
	}
}

func TestClampScore(t *testing.T) {
	for in, want := range map[float64]float64{-0.4: 0, 0: 0, 5.5: 5.5, 10: 10, 10.2: 10} {
		if got := clampScore(in); got != want {
			t.Errorf("clampScore(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestUnroundedScoreNeverNeedsTheClamp(t *testing.T) {
	// The calculator clamps after taking the mean distance off; for a base
	// vector the result is always inside 0..10 already, so the clamp is a
	// guard, never a correction. A table change that made it one would show
	// here before it showed in a score.
	lo, hi := math.Inf(1), math.Inf(-1)
	walkBase(func(v string) {
		b, err := Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		raw, _, err := unroundedScore(b.selection())
		if err != nil {
			t.Fatal(err)
		}
		lo, hi = math.Min(lo, raw), math.Max(hi, raw)
	})
	if lo < 0 || hi > 10 {
		t.Errorf("unrounded scores range %v to %v, outside 0..10", lo, hi)
	}
}

func TestFormatScore(t *testing.T) {
	for in, want := range map[float64]string{0: "0.0", 10: "10.0", 9.3: "9.3", 0.1: "0.1", 4.9: "4.9"} {
		if got := FormatScore(in); got != want {
			t.Errorf("FormatScore(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestComputeReportsTheCanonicalVectorAndMacroVector(t *testing.T) {
	r := mustScore(t, goodVector)
	if r.Vector != goodVector || len(r.MacroVector) != 6 || strings.Trim(r.MacroVector, "012") != "" {
		t.Errorf("Compute = %+v", r)
	}
}

// walkBase visits every base vector in the canonical nested order, AV
// outermost, each metric's values in baseMetricDefs order.
func walkBase(visit func(vector string)) {
	var walk func(i int, cur string)
	walk = func(i int, cur string) {
		if i == len(baseMetricDefs) {
			visit(cur)
			return
		}
		d := baseMetricDefs[i]
		for _, v := range d.Values {
			walk(i+1, cur+"/"+d.Key+":"+v)
		}
	}
	walk(0, "CVSS:4.0")
}
