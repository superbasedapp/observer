package cvss4

import (
	"errors"
	"fmt"
	"math"
	"strconv"
)

// step is the unit severity distances are measured in (cvss_score.js
// `step = 0.1`): a maximal severity of n is n steps.
const step = 0.1

// ErrInternal reports that the generated tables do not cover a vector the
// parser accepted. It cannot happen for a table set that passes the package's
// tests (every one of the 104,976 base vectors is scored in them); it is an
// error rather than a zero so that a damaged table can never read as a score.
var ErrInternal = errors.New("cvss4: scoring tables do not cover the vector")

// Rating is the qualitative severity rating of a score, from the CVSS 4.0
// specification: none for 0.0, low for 0.1 to 3.9, medium for 4.0 to 6.9,
// high for 7.0 to 8.9 and critical for 9.0 to 10.0.
type Rating string

// The five ratings, in ascending order.
const (
	RatingNone     Rating = "none"
	RatingLow      Rating = "low"
	RatingMedium   Rating = "medium"
	RatingHigh     Rating = "high"
	RatingCritical Rating = "critical"
)

// RatingOf returns the rating of a score.
func RatingOf(score float64) Rating {
	switch {
	case !(score > 0): // zero, negative or NaN
		return RatingNone
	case score < 4.0:
		return RatingLow
	case score < 7.0:
		return RatingMedium
	case score < 9.0:
		return RatingHigh
	default:
		return RatingCritical
	}
}

// FormatScore renders a score with one decimal ("9.3", "0.0", "10.0").
func FormatScore(score float64) string { return strconv.FormatFloat(score, 'f', 1, 64) }

// Result is a vector scored: the canonical vector, its base score, the rating
// of that score and the MacroVector the score was derived from.
type Result struct {
	Vector      string
	Score       float64
	Rating      Rating
	MacroVector string
}

// Compute parses a base vector and scores it.
func Compute(vector string) (Result, error) {
	b, err := Parse(vector)
	if err != nil {
		return Result{}, err
	}
	score, macro, err := b.score()
	if err != nil {
		return Result{}, err
	}
	return Result{Vector: b.Vector(), Score: score, Rating: RatingOf(score), MacroVector: macro}, nil
}

// Score returns the CVSS 4.0 base score of the vector, 0.0 to 10.0 with one
// decimal. It scores the base metrics alone: Exploit Maturity is taken as
// Attacked and the three requirements as High (notDefinedDefaults).
func (b Base) Score() (float64, error) {
	score, _, err := b.score()
	return score, err
}

// MacroVector returns the six-digit EQ1..EQ6 key of the vector's MacroVector.
func (b Base) MacroVector() string {
	return macroKey(b.selection().macroLevels())
}

func (b Base) score() (float64, string, error) {
	return scoreSelection(b.selection())
}

// selection is a vector as the calculator holds it: every metric by key, a
// metric that is not defined being "X". A base vector leaves the threat and
// requirement metrics at "X", which is how the specification's defaults apply.
type selection map[string]string

func (b Base) selection() selection {
	s := selection{}
	for i, d := range baseMetricDefs {
		s[d.Key] = b.v[i]
	}
	for metric := range notDefinedDefaults {
		s[metric] = "X"
	}
	return s
}

// effective is cvss_score.js m(): the value a metric counts as. A metric left
// at "X" takes its default; otherwise a modified metric (M<key>), when set,
// overrides the base value.
func (s selection) effective(metric string) string {
	selected := s[metric]
	if selected == "X" {
		if d, ok := notDefinedDefaults[metric]; ok {
			return d
		}
	}
	if mod, ok := s["M"+metric]; ok && mod != "X" {
		return mod
	}
	return selected
}

func (s selection) is(metric, value string) bool { return s.effective(metric) == value }

// macroLevels derives the six equivalence-class levels (EQ1..EQ6) of a
// vector, as cvss_score.js macroVector() does.
func (s selection) macroLevels() [6]int {
	var eq [6]int

	// EQ1: 0 AV:N and PR:N and UI:N; 1 one of them is N but not AV:P;
	// 2 AV:P or none is N.
	anyN := s.is("AV", "N") || s.is("PR", "N") || s.is("UI", "N")
	switch {
	case s.is("AV", "N") && s.is("PR", "N") && s.is("UI", "N"):
		eq[0] = 0
	case anyN && !s.is("AV", "P"):
		eq[0] = 1
	default:
		eq[0] = 2
	}

	// EQ2: 0 AC:L and AT:N; 1 otherwise.
	if s.is("AC", "L") && s.is("AT", "N") {
		eq[1] = 0
	} else {
		eq[1] = 1
	}

	// EQ3: 0 VC:H and VI:H; 1 one of VC, VI, VA is H; 2 none is.
	switch {
	case s.is("VC", "H") && s.is("VI", "H"):
		eq[2] = 0
	case s.is("VC", "H") || s.is("VI", "H") || s.is("VA", "H"):
		eq[2] = 1
	default:
		eq[2] = 2
	}

	// EQ4: 0 safety (MSI:S or MSA:S, which a base vector never has); 1 one of
	// SC, SI, SA is H; 2 none is.
	switch {
	case s.is("MSI", "S") || s.is("MSA", "S"):
		eq[3] = 0
	case s.is("SC", "H") || s.is("SI", "H") || s.is("SA", "H"):
		eq[3] = 1
	default:
		eq[3] = 2
	}

	// EQ5: exploit maturity, A 0, P 1, U 2.
	switch {
	case s.is("E", "A"):
		eq[4] = 0
	case s.is("E", "P"):
		eq[4] = 1
	case s.is("E", "U"):
		eq[4] = 2
	}

	// EQ6: 0 a High requirement meets a High impact on the same property;
	// 1 otherwise.
	if (s.is("CR", "H") && s.is("VC", "H")) || (s.is("IR", "H") && s.is("VI", "H")) || (s.is("AR", "H") && s.is("VA", "H")) {
		eq[5] = 0
	} else {
		eq[5] = 1
	}
	return eq
}

func macroKey(eq [6]int) string {
	var b [6]byte
	for i, l := range eq {
		b[i] = byte('0' + l)
	}
	return string(b[:])
}

// macroScore returns the score of a MacroVector, and whether it exists.
func macroScore(eq [6]int) (float64, bool) {
	v, ok := macroScores[macroKey(eq)]
	return v, ok
}

// lowerEQ3EQ6 lists, per (EQ3, EQ6) pair, the pairs one step less severe
// (cvss_score.js): 00 has two, and the higher-scoring one counts; 21 has none
// that exists, so its entry names the pair the calculator looks up and misses.
var lowerEQ3EQ6 = map[[2]int][][2]int{
	{0, 0}: {{0, 1}, {1, 0}},
	{0, 1}: {{1, 1}},
	{1, 0}: {{1, 1}},
	{1, 1}: {{2, 1}},
	{2, 1}: {{3, 2}},
}

// The five slots of the per-EQ arrays below: EQ1, EQ2, the joined (EQ3, EQ6)
// pair, EQ4 and EQ5.
const (
	slotEQ1 = iota
	slotEQ2
	slotEQ3EQ6
	slotEQ4
	slotEQ5
	slots
)

// lowerScores returns, per slot, the score of the next less severe
// MacroVector and whether one exists.
func lowerScores(eq [6]int) (scores [slots]float64, exists [slots]bool) {
	for _, one := range []struct{ slot, eq int }{{slotEQ1, 0}, {slotEQ2, 1}, {slotEQ4, 3}, {slotEQ5, 4}} {
		next := eq
		next[one.eq]++
		scores[one.slot], exists[one.slot] = macroScore(next)
	}

	type neighbour struct {
		score float64
		ok    bool
	}
	var near []neighbour
	for _, p := range lowerEQ3EQ6[[2]int{eq[2], eq[5]}] {
		next := eq
		next[2], next[5] = p[0], p[1]
		s, ok := macroScore(next)
		near = append(near, neighbour{s, ok})
	}
	switch len(near) {
	case 1:
		scores[slotEQ3EQ6], exists[slotEQ3EQ6] = near[0].score, near[0].ok
	case 2:
		// 00 --> 01 or 10: when both exist the higher score counts. As in
		// cvss_score.js the test is a strict `>`, and anything else falls to
		// the right-hand pair.
		left, right := near[0], near[1]
		if left.ok && right.ok && left.score > right.score {
			scores[slotEQ3EQ6], exists[slotEQ3EQ6] = left.score, true
		} else {
			scores[slotEQ3EQ6], exists[slotEQ3EQ6] = right.score, right.ok
		}
	}
	return scores, exists
}

// distanceMetrics are the metrics whose severity distance from a maximal
// vector is measured, in the order cvss_score.js lists them.
var distanceMetrics = []string{"AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"}

// severityDistances measures the vector against one maximal vector: for each
// metric, its severity level minus the maximal vector's. ok reports that no
// distance is negative, which is what makes a maximal vector a valid
// reference for this vector.
func (s selection) severityDistances(max map[string]string) (d map[string]float64, ok bool, err error) {
	d = make(map[string]float64, len(distanceMetrics))
	ok = true
	for _, metric := range distanceMetrics {
		have, found1 := severityLevels[metric][s.effective(metric)]
		top, found2 := severityLevels[metric][max[metric]]
		if !found1 || !found2 {
			return nil, false, fmt.Errorf("%w: metric %s", ErrInternal, metric)
		}
		d[metric] = have - top
		if d[metric] < 0 {
			ok = false
		}
	}
	return d, ok, nil
}

// referenceDistances finds the maximal vector to measure against and returns
// the vector's severity distances from it. The candidates are the
// combinations of each EQ's maximal fragments, nested EQ1 outermost to EQ5
// innermost; the first one the vector is no worse than in every metric wins.
// As in cvss_score.js, when none qualifies the distances of the last
// candidate stand and qualified is false (the tests prove no base vector, and
// none of the oracle's full vectors, reaches that case).
func (s selection) referenceDistances(eq [6]int) (distances map[string]float64, qualified bool, err error) {
	groups := [][]fragment{
		maxComposedEQ1[eq[0]],
		maxComposedEQ2[eq[1]],
		maxComposedEQ3EQ6[[2]int{eq[2], eq[5]}],
		maxComposedEQ4[eq[3]],
		maxComposedEQ5[eq[4]],
	}
	for _, g := range groups {
		if len(g) == 0 {
			return nil, false, fmt.Errorf("%w: no maximal vectors for %s", ErrInternal, macroKey(eq))
		}
	}
	var last map[string]float64
	var failure error
	picked := make([]fragment, len(groups))
	var walk func(depth int) bool
	walk = func(depth int) bool {
		if depth == len(groups) {
			max := map[string]string{}
			for _, f := range picked {
				for _, mv := range f {
					max[mv.Metric] = mv.Value
				}
			}
			d, ok, err := s.severityDistances(max)
			if err != nil {
				failure = err
				return true
			}
			last = d
			return ok
		}
		for _, f := range groups[depth] {
			picked[depth] = f
			if walk(depth + 1) {
				return true
			}
		}
		return false
	}
	qualified = walk(0)
	if failure != nil {
		return nil, false, failure
	}
	return last, qualified, nil
}

// jsRound is JavaScript's Math.round: the nearest integer, ties toward
// positive infinity.
func jsRound(x float64) float64 {
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}

// scoreSelection is cvss_score.js cvss_score(): the score of the vector and
// the key of its MacroVector.
//
// The arithmetic follows the calculator operation for operation, in float64,
// because the published score depends on its rounding: every product is
// wrapped in float64() so a compiler that fuses multiply-add (arm64) cannot
// change a result, and sums keep upstream's left-to-right order.
func scoreSelection(s selection) (float64, string, error) {
	value, key, err := unroundedScore(s)
	if err != nil {
		return 0, key, err
	}
	return jsRound(float64(value*10)) / 10, key, nil
}

// unroundedScore is scoreSelection before the final rounding to one decimal:
// the MacroVector score less the mean severity distance, clamped to 0..10.
// It is separate so the tests can look at the rounding step on its own.
func unroundedScore(s selection) (float64, string, error) {
	eq := s.macroLevels()
	key := macroKey(eq)

	// The all-zero impact shortcut: no impact on the vulnerable or the
	// subsequent system scores 0.0 whatever the rest says.
	allNone := true
	for _, m := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if !s.is(m, "N") {
			allNone = false
		}
	}
	if allNone {
		return 0, key, nil
	}

	value, ok := macroScore(eq)
	if !ok {
		return 0, key, fmt.Errorf("%w: macro vector %s", ErrInternal, key)
	}
	lowerScore, lowerExists := lowerScores(eq)

	// A vector no maximal vector qualifies for keeps the last candidate's
	// distances, as upstream does; the tests prove no base vector is in that
	// case, so the flag is not consulted here.
	d, _, err := s.referenceDistances(eq)
	if err != nil {
		return 0, key, err
	}
	current := [slots]float64{
		slotEQ1:    d["AV"] + d["PR"] + d["UI"],
		slotEQ2:    d["AC"] + d["AT"],
		slotEQ3EQ6: d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"],
		slotEQ4:    d["SC"] + d["SI"] + d["SA"],
		slotEQ5:    0, // EQ5 never moves the score
	}
	maxSev := [slots]int{
		slotEQ1:    maxSeverityEQ1[eq[0]],
		slotEQ2:    maxSeverityEQ2[eq[1]],
		slotEQ3EQ6: maxSeverityEQ3EQ6[[2]int{eq[2], eq[5]}],
		slotEQ4:    maxSeverityEQ4[eq[3]],
	}

	var normalized [slots]float64
	existing := 0
	for i := range normalized {
		if !lowerExists[i] {
			continue
		}
		existing++
		available := value - lowerScore[i]
		percent := 0.0 // EQ5: always zero
		if i != slotEQ5 {
			if maxSev[i] < 1 {
				return 0, key, fmt.Errorf("%w: maximal severity for %s", ErrInternal, key)
			}
			percent = current[i] / float64(float64(maxSev[i])*step)
		}
		normalized[i] = float64(available * percent)
	}
	mean := 0.0
	if existing > 0 {
		mean = (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4]) / float64(existing)
	}
	return clampScore(value - mean), key, nil
}

// clampScore keeps a score inside 0..10, as cvss_score.js does after taking
// the mean distance off the MacroVector score. No base vector reaches either
// edge (the tests bound the unrounded score over all 104,976); the clamp is
// kept because the calculator has it and a damaged table must not produce a
// score outside the range.
func clampScore(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 10 {
		return 10
	}
	return v
}
