package cvss4

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The generated tables are checked against facts of the CVSS 4.0
// specification that are stated here independently of the generator (which
// checks the same shapes while generating): the level grid, the metric value
// sets, and the property that makes a maximal vector maximal.

func TestMacroScoresAreExactlyTheValidGrid(t *testing.T) {
	// EQ1..EQ6 have 3, 2, 3, 3, 3 and 2 levels: 324 combinations. EQ3 = 2
	// (no High vulnerable-system impact) cannot go with EQ6 = 0 (a High
	// requirement meeting a High impact), which removes 3 x 2 x 3 x 3 = 54.
	want := map[string]bool{}
	impossible := 0
	for e1 := 0; e1 < 3; e1++ {
		for e2 := 0; e2 < 2; e2++ {
			for e3 := 0; e3 < 3; e3++ {
				for e4 := 0; e4 < 3; e4++ {
					for e5 := 0; e5 < 3; e5++ {
						for e6 := 0; e6 < 2; e6++ {
							if e3 == 2 && e6 == 0 {
								impossible++
								continue
							}
							want[fmt.Sprintf("%d%d%d%d%d%d", e1, e2, e3, e4, e5, e6)] = true
						}
					}
				}
			}
		}
	}
	if impossible != 54 || len(want) != 270 {
		t.Fatalf("grid arithmetic: %d impossible, %d valid; want 54 and 270", impossible, len(want))
	}
	if len(macroScores) != 270 {
		t.Fatalf("macroScores has %d rows, want 270", len(macroScores))
	}
	for k, v := range macroScores {
		if !want[k] {
			t.Errorf("macroScores has %q, which is not a valid MacroVector", k)
		}
		if v < 0 || v > 10 {
			t.Errorf("macroScores[%s] = %v is outside 0..10", k, v)
		}
	}
	for k := range want {
		if _, ok := macroScores[k]; !ok {
			t.Errorf("macroScores lacks the valid MacroVector %s", k)
		}
	}
	if got := macroScores["000000"]; got != 10 {
		t.Errorf("the most severe MacroVector scores %v, want 10", got)
	}
}

func TestMacroScoresNeverRiseTowardLessSevere(t *testing.T) {
	// Moving one EQ to its next, less severe level must not raise the score.
	// (EQ3 and EQ6 are checked as the joined pair, through lowerEQ3EQ6.)
	for key, score := range macroScores {
		var eq [6]int
		for i := range eq {
			eq[i] = int(key[i] - '0')
		}
		scores, exists := lowerScores(eq)
		for slot := range scores {
			if exists[slot] && scores[slot] > score {
				t.Errorf("%s scores %v but its lower neighbour in slot %d scores %v", key, score, slot, scores[slot])
			}
		}
	}
}

func TestLowerNeighboursOfTheJoinedPair(t *testing.T) {
	cases := []struct {
		pair   [2]int
		wantTo [][2]int
	}{
		{[2]int{0, 0}, [][2]int{{0, 1}, {1, 0}}},
		{[2]int{0, 1}, [][2]int{{1, 1}}},
		{[2]int{1, 0}, [][2]int{{1, 1}}},
		{[2]int{1, 1}, [][2]int{{2, 1}}},
		{[2]int{2, 1}, [][2]int{{3, 2}}}, // none exists: EQ3 has no level 3
	}
	if len(lowerEQ3EQ6) != len(cases) {
		t.Fatalf("lowerEQ3EQ6 has %d pairs, the test covers %d", len(lowerEQ3EQ6), len(cases))
	}
	for _, c := range cases {
		got := lowerEQ3EQ6[c.pair]
		if fmt.Sprint(got) != fmt.Sprint(c.wantTo) {
			t.Errorf("lower neighbours of %v = %v, want %v", c.pair, got, c.wantTo)
		}
	}
	// The pair (0, 0) takes the higher of its two lower MacroVectors, and the
	// right-hand one (1, 0) when they tie or compare unevenly.
	for key := range macroScores {
		if key[2] != '0' || key[5] != '0' {
			continue
		}
		var eq [6]int
		for i := range eq {
			eq[i] = int(key[i] - '0')
		}
		left, right := eq, eq
		left[5] = 1
		right[2] = 1
		ls, lok := macroScore(left)
		rs, rok := macroScore(right)
		if !lok || !rok {
			t.Fatalf("%s: a lower neighbour of (0,0) is missing", key)
		}
		want := rs
		if ls > rs {
			want = ls
		}
		scores, exists := lowerScores(eq)
		if !exists[slotEQ3EQ6] || scores[slotEQ3EQ6] != want {
			t.Errorf("%s: joined lower score %v (exists %v), want %v", key, scores[slotEQ3EQ6], exists[slotEQ3EQ6], want)
		}
	}
}

func TestBaseMetricDefsMatchTheSpecification(t *testing.T) {
	want := []struct {
		key    string
		values string
	}{
		{"AV", "NALP"},
		{"AC", "LH"},
		{"AT", "NP"},
		{"PR", "NLH"},
		{"UI", "NPA"},
		{"VC", "HLN"},
		{"VI", "HLN"},
		{"VA", "HLN"},
		{"SC", "HLN"},
		{"SI", "HLN"},
		{"SA", "HLN"},
	}
	if len(baseMetricDefs) != len(want) {
		t.Fatalf("%d base metrics, want %d", len(baseMetricDefs), len(want))
	}
	for i, w := range want {
		got := baseMetricDefs[i]
		if got.Key != w.key || strings.Join(got.Values, "") != w.values {
			t.Errorf("base metric %d = %s %v, want %s %s", i, got.Key, got.Values, w.key, w.values)
		}
	}
	if keys := BaseMetricKeys(); len(keys) != 11 || keys[0] != "AV" || keys[10] != "SA" {
		t.Errorf("BaseMetricKeys = %v", keys)
	}
}

func TestKnownMetricKeysAreTheThirtyTwoMetrics(t *testing.T) {
	// 11 base, 1 threat, 14 environmental, 6 supplemental.
	if len(knownMetricKeys) != 32 {
		t.Fatalf("%d metric keys, want 32: %v", len(knownMetricKeys), knownMetricKeys)
	}
	seen := map[string]bool{}
	for _, k := range knownMetricKeys {
		if seen[k] {
			t.Errorf("metric %s listed twice", k)
		}
		seen[k] = true
	}
	for _, d := range baseMetricDefs {
		if !seen[d.Key] {
			t.Errorf("base metric %s is not in knownMetricKeys", d.Key)
		}
	}
	for _, k := range []string{"E", "CR", "IR", "AR", "MAV", "MSA", "S", "AU", "R", "V", "RE", "U"} {
		if !seen[k] {
			t.Errorf("metric %s is missing from knownMetricKeys", k)
		}
	}
}

func TestSeverityLevelsRunFromMostToLeastSevere(t *testing.T) {
	// Each base metric lists its values most severe first, so the level must
	// rise strictly along that list.
	for _, d := range baseMetricDefs {
		levels := severityLevels[d.Key]
		prev := -1.0
		for _, v := range d.Values {
			l, ok := levels[v]
			if !ok {
				t.Errorf("%s has no severity level for %s", d.Key, v)
				continue
			}
			if l <= prev {
				t.Errorf("%s level of %s is %v, not above the previous %v", d.Key, v, l, prev)
			}
			prev = l
		}
	}
	// The safety value of SI and SA is more severe than any base value, and
	// the requirements and exploit maturity are ordered the same way.
	for _, k := range []string{"SI", "SA"} {
		if severityLevels[k]["S"] != 0 || severityLevels[k]["S"] >= severityLevels[k]["H"] {
			t.Errorf("%s: S must be the most severe level, got %v", k, severityLevels[k])
		}
	}
	for _, k := range []string{"CR", "IR", "AR"} {
		l := severityLevels[k]
		if !(l["H"] < l["M"] && l["M"] < l["L"]) {
			t.Errorf("%s levels are not H < M < L: %v", k, l)
		}
	}
	e := severityLevels["E"]
	if !(e["A"] < e["P"] && e["P"] < e["U"]) {
		t.Errorf("E levels are not A < P < U: %v", e)
	}
	if len(severityLevels) != 15 {
		t.Errorf("%d level tables, want 15", len(severityLevels))
	}
}

func TestNotDefinedDefaults(t *testing.T) {
	// The values a base-only vector relies on, from the specification:
	// Exploit Maturity not defined is Attacked, and each requirement not
	// defined is High.
	want := map[string]string{"E": "A", "CR": "H", "IR": "H", "AR": "H"}
	if len(notDefinedDefaults) != len(want) {
		t.Fatalf("notDefinedDefaults = %v, want %v", notDefinedDefaults, want)
	}
	for k, v := range want {
		if notDefinedDefaults[k] != v {
			t.Errorf("notDefinedDefaults[%s] = %q, want %q", k, notDefinedDefaults[k], v)
		}
	}
}

func TestMaxSeverityTables(t *testing.T) {
	check := func(name string, got map[int]int, want map[int]int) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	// Every value is a positive divisor: the maximal severity distance of an
	// EQ level, in steps of 0.1, plus one.
	check("maxSeverityEQ1", maxSeverityEQ1, map[int]int{0: 1, 1: 4, 2: 5})
	check("maxSeverityEQ2", maxSeverityEQ2, map[int]int{0: 1, 1: 2})
	check("maxSeverityEQ4", maxSeverityEQ4, map[int]int{0: 6, 1: 5, 2: 4})
	check("maxSeverityEQ5", maxSeverityEQ5, map[int]int{0: 1, 1: 1, 2: 1})
	wantPair := map[[2]int]int{{0, 0}: 7, {0, 1}: 6, {1, 0}: 8, {1, 1}: 8, {2, 1}: 10}
	if fmt.Sprint(maxSeverityEQ3EQ6) != fmt.Sprint(wantPair) {
		t.Errorf("maxSeverityEQ3EQ6 = %v, want %v", maxSeverityEQ3EQ6, wantPair)
	}
}

func TestMaxComposedSetsPerEQ(t *testing.T) {
	counts := func(m map[int][]fragment) string {
		keys := make([]int, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%d:%d", k, len(m[k])))
		}
		return strings.Join(parts, " ")
	}
	for name, c := range map[string]struct{ got, want string }{
		"EQ1": {counts(maxComposedEQ1), "0:1 1:3 2:2"},
		"EQ2": {counts(maxComposedEQ2), "0:1 1:2"},
		"EQ4": {counts(maxComposedEQ4), "0:1 1:1 2:1"},
		"EQ5": {counts(maxComposedEQ5), "0:1 1:1 2:1"},
	} {
		if c.got != c.want {
			t.Errorf("%s maximal fragments per level = %q, want %q", name, c.got, c.want)
		}
	}
	pairs := map[[2]int]int{{0, 0}: 1, {0, 1}: 2, {1, 0}: 2, {1, 1}: 5, {2, 1}: 1}
	if len(maxComposedEQ3EQ6) != len(pairs) {
		t.Errorf("maxComposedEQ3EQ6 has %d pairs, want %d", len(maxComposedEQ3EQ6), len(pairs))
	}
	for p, n := range pairs {
		if len(maxComposedEQ3EQ6[p]) != n {
			t.Errorf("maxComposedEQ3EQ6[%v] has %d fragments, want %d", p, len(maxComposedEQ3EQ6[p]), n)
		}
	}
}

// maximalVectors lists every full maximal vector of a MacroVector: the
// combinations of its EQs' fragments, as selections the scorer can read.
func maximalVectors(eq [6]int) []selection {
	groups := [][]fragment{
		maxComposedEQ1[eq[0]],
		maxComposedEQ2[eq[1]],
		maxComposedEQ3EQ6[[2]int{eq[2], eq[5]}],
		maxComposedEQ4[eq[3]],
		maxComposedEQ5[eq[4]],
	}
	out := []selection{{}}
	for _, g := range groups {
		var next []selection
		for _, base := range out {
			for _, f := range g {
				s := selection{}
				for k, v := range base {
					s[k] = v
				}
				for _, mv := range f {
					if mv.Value == "S" {
						// Safety is a value of the modified SI and SA only.
						s["M"+mv.Metric] = "S"
						s[mv.Metric] = "H"
						continue
					}
					s[mv.Metric] = mv.Value
				}
				next = append(next, s)
			}
		}
		out = next
	}
	return out
}

func eqOf(key string) [6]int {
	var eq [6]int
	for i := range eq {
		eq[i] = int(key[i] - '0')
	}
	return eq
}

func TestMaximalVectorsBelongToTheirMacroVectorAndScoreIt(t *testing.T) {
	vectors := 0
	for key, want := range macroScores {
		for _, s := range maximalVectors(eqOf(key)) {
			vectors++
			if got := macroKey(s.macroLevels()); got != key {
				t.Fatalf("a maximal vector of %s derives MacroVector %s: %v", key, got, s)
			}
			score, _, err := scoreSelection(s)
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			if score != want {
				t.Errorf("a maximal vector of %s scores %v, want the MacroVector's %v: %v", key, score, want, s)
			}
		}
	}
	if vectors < 270 {
		t.Fatalf("only %d maximal vectors were checked", vectors)
	}
}
