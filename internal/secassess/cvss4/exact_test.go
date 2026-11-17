package cvss4

import (
	"math"
	"math/big"
	"strconv"
	"testing"
)

// exactScore is the same algorithm in exact rational arithmetic, rounded half
// up to one decimal. It is test code: a reference for what the score would be
// if float64 had no noise, used to classify every disagreement between FIRST's
// calculator (which is float64) and other implementations. It reuses the
// scorer's table lookups and reference-vector choice, which do not depend on
// float noise (a severity distance is a difference of two tenths, so it is
// zero or at least a tenth), and redoes only the arithmetic.
func exactScore(t *testing.T, s selection) *big.Rat {
	t.Helper()
	eq := s.macroLevels()
	allNone := true
	for _, m := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if !s.is(m, "N") {
			allNone = false
		}
	}
	if allNone {
		return new(big.Rat)
	}
	rat := func(f float64) *big.Rat {
		r, ok := new(big.Rat).SetString(strconv.FormatFloat(f, 'f', -1, 64))
		if !ok {
			t.Fatalf("not a decimal: %v", f)
		}
		return r
	}
	tenths := func(f float64) *big.Rat { return big.NewRat(int64(math.Round(f*10)), 10) }

	value := rat(macroScores[macroKey(eq)])
	lower, exists := lowerScores(eq)
	d, _, err := s.referenceDistances(eq)
	if err != nil {
		t.Fatal(err)
	}
	sum := func(keys ...string) *big.Rat {
		total := new(big.Rat)
		for _, k := range keys {
			total.Add(total, tenths(d[k]))
		}
		return total
	}
	current := [slots]*big.Rat{
		slotEQ1:    sum("AV", "PR", "UI"),
		slotEQ2:    sum("AC", "AT"),
		slotEQ3EQ6: sum("VC", "VI", "VA", "CR", "IR", "AR"),
		slotEQ4:    sum("SC", "SI", "SA"),
		slotEQ5:    new(big.Rat),
	}
	maxSev := [slots]int{
		slotEQ1:    maxSeverityEQ1[eq[0]],
		slotEQ2:    maxSeverityEQ2[eq[1]],
		slotEQ3EQ6: maxSeverityEQ3EQ6[[2]int{eq[2], eq[5]}],
		slotEQ4:    maxSeverityEQ4[eq[3]],
	}
	total, existing := new(big.Rat), 0
	for i := 0; i < slots; i++ {
		if !exists[i] {
			continue
		}
		existing++
		if i == slotEQ5 {
			continue
		}
		available := new(big.Rat).Sub(value, rat(lower[i]))
		percent := new(big.Rat).Quo(current[i], big.NewRat(int64(maxSev[i]), 10))
		total.Add(total, available.Mul(available, percent))
	}
	result := new(big.Rat).Set(value)
	if existing > 0 {
		result.Sub(result, total.Quo(total, big.NewRat(int64(existing), 1)))
	}
	if result.Sign() < 0 {
		result.SetInt64(0)
	}
	if result.Cmp(big.NewRat(10, 1)) > 0 {
		result.SetInt64(10)
	}
	// round half up to one decimal: floor(result*10 + 1/2) / 10
	x := new(big.Rat).Mul(result, big.NewRat(10, 1))
	x.Add(x, big.NewRat(1, 2))
	fl := new(big.Int).Div(x.Num(), x.Denom())
	return new(big.Rat).SetFrac(fl, big.NewInt(10))
}

func exactFloat(r *big.Rat) float64 {
	f, _ := r.Float64()
	return f
}

// TestScoreMatchesExactArithmeticExceptFloatTies classifies every difference
// between the float64 scorer and exact arithmetic over the whole base space
// and the full-vector oracle. Each one must be a vector whose unrounded score
// is an exact tie (x.x5) that float64 holds on the other side of the half,
// the two scores one tenth apart, in the same rating. Nothing else may
// differ. The classes are pinned: they are what testdata/README.md reports.
func TestScoreMatchesExactArithmeticExceptFloatTies(t *testing.T) {
	if testing.Short() {
		t.Skip("exact arithmetic over 104,976 vectors")
	}
	classes := map[string]int{}
	check := func(label string, sel selection) string {
		got, _, err := scoreSelection(sel)
		if err != nil {
			t.Fatal(err)
		}
		want := exactFloat(exactScore(t, sel))
		if got == want {
			return ""
		}
		raw, _, _ := unroundedScore(sel)
		if !isRoundingTie(raw) || math.Abs(math.Round((got-want)*10)) != 1 {
			t.Errorf("%s: float scorer %v, exact %v, unrounded %.17g: not a rounding tie", label, got, want, raw)
			return ""
		}
		if RatingOf(got) != RatingOf(want) {
			t.Errorf("%s: the tie crosses a rating boundary (%v vs %v)", label, got, want)
		}
		return FormatScore(got) + " (float) vs " + FormatScore(want) + " (exact)"
	}
	walkBase(func(v string) {
		b, err := Parse(v)
		if err != nil {
			t.Fatal(err)
		}
		if class := check(v, b.selection()); class != "" {
			classes[class]++
		}
	})
	wantClasses := map[string]int{
		"4.9 (float) vs 5.0 (exact)": 72,
		"5.6 (float) vs 5.7 (exact)": 432,
		"8.5 (float) vs 8.6 (exact)": 18,
	}
	for c, n := range wantClasses {
		if classes[c] != n {
			t.Errorf("base ties %q = %d, want %d", c, classes[c], n)
		}
	}
	if len(classes) != len(wantClasses) {
		t.Errorf("base tie classes = %v, want %v", classes, wantClasses)
	}
	full := 0
	for _, r := range readTSV(t, "oracle_gocvss_full.tsv") {
		if check(r[0], selectionOf(t, r[0])) != "" {
			full++
		}
	}
	t.Logf("base ties by class: %v; full-vector ties: %d", classes, full)
}
