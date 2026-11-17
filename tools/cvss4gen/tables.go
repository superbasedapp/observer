package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The shapes of every EQ (equivalence class) in CVSS 4.0, from the
// specification: how many levels each has, and which (EQ3, EQ6) pairs can
// exist at all. The generator checks the upstream files against these, so
// "270 valid MacroVectors" is verified, not assumed.
var (
	eqLevels      = [6]int{3, 2, 3, 3, 3, 2} // EQ1..EQ6
	validEQ3EQ6   = [][2]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}, {2, 1}}
	macroVectorsN = 270
)

// levelMetrics are the metrics whose severity-level table cvss_score.js
// defines, in the order the generated file lists them.
var levelMetrics = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR", "E"}

// baseMetricKeys are the base metrics, in vector order.
var baseMetricKeys = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

// notDefinedDefaults are the values a metric takes when a vector leaves it
// out (or says X). A base-only vector relies on all of them: it carries no
// Exploit Maturity (E, taken as Attacked) and no Confidentiality, Integrity
// or Availability Requirement (CR, IR, AR, each taken as High). They live in
// cvss_score.js's m() function as code, not as a data literal, so the
// generator carries them here and proves upstream still says the same thing
// (see anchors).
var notDefinedDefaults = []struct{ Metric, Value string }{
	{"E", "A"},
	{"CR", "H"},
	{"IR", "H"},
	{"AR", "H"},
}

// anchors are the fragments of cvss_score.js's algorithm that the Go scorer
// reproduces by hand. Each must appear (after collapsing whitespace) in the
// pinned file; if upstream changes one, generation stops and a human reads
// the diff. The fragments are the rules the plan calls out: the all-zero
// impact shortcut, the severity-distance step, rounding and clamping, the
// EQ5 contribution, and the (EQ3, EQ6) lower-neighbour rules.
var anchors = []struct{ Name, Text string }{
	{"all-zero impact shortcut", `if (["VC", "VI", "VA", "SC", "SI", "SA"].every((metric) => m(cvssSelected, metric) == "N")) { return 0.0 }`},
	{"severity distance step", `step = 0.1`},
	{"maximal severity scaled by the step", `maxSeverity_eq1 = maxSeverityData["eq1"][eq1] * step`},
	{"EQ3/EQ6 maximal severity", `maxSeverity_eq3eq6 = maxSeverityData["eq3eq6"][eq3][eq6] * step`},
	{"EQ5 distance is zero", `current_severity_distance_eq5 = 0`},
	{"EQ5 percent is zero", `percent_to_next_eq5_severity = 0`},
	{"mean over the existing lower MacroVectors", `mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower`},
	{"no lower MacroVector means no distance", `if (n_existing_lower == 0) { mean_distance = 0 }`},
	{"subtract the mean distance", `value -= mean_distance;`},
	{"clamp low", `if (value < 0) { value = 0.0 }`},
	{"clamp high", `if (value > 10) { value = 10.0 }`},
	{"rounding", `return Math.round(value * 10) / 10`},
	{"lower neighbour of 11", `if (eq3 == 1 && eq6 == 1) { // 11 --> 21 eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6) }`},
	{"lower neighbour of 01", `else if (eq3 == 0 && eq6 == 1) { // 01 --> 11 eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6) }`},
	{"lower neighbour of 10", `else if (eq3 == 1 && eq6 == 0) { // 10 --> 11 eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3, eq4, eq5, eq6 + 1) }`},
	{"lower neighbours of 00", `else if (eq3 == 0 && eq6 == 0) { // 00 --> 01 // 00 --> 10 eq3eq6_next_lower_macro_left = "".concat(eq1, eq2, eq3, eq4, eq5, eq6 + 1) eq3eq6_next_lower_macro_right = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6) }`},
	{"lower neighbour of 21", `else { // 21 --> 32 (do not exist) eq3eq6_next_lower_macro = "".concat(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1) }`},
	{"00 takes the higher of its two lower neighbours", `if (score_eq3eq6_next_lower_macro_left > score_eq3eq6_next_lower_macro_right) { score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left } else { score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right }`},
	{"first max vector no worse in every metric wins", `if ([severity_distance_AV, severity_distance_PR, severity_distance_UI, severity_distance_AC, severity_distance_AT, severity_distance_VC, severity_distance_VI, severity_distance_VA, severity_distance_SC, severity_distance_SI, severity_distance_SA, severity_distance_CR, severity_distance_IR, severity_distance_AR].some((met) => met < 0)) { continue }`},
	{"EQ1 distance", `current_severity_distance_eq1 = severity_distance_AV + severity_distance_PR + severity_distance_UI`},
	{"EQ2 distance", `current_severity_distance_eq2 = severity_distance_AC + severity_distance_AT`},
	{"EQ3/EQ6 distance", `current_severity_distance_eq3eq6 = severity_distance_VC + severity_distance_VI + severity_distance_VA + severity_distance_CR + severity_distance_IR + severity_distance_AR`},
	{"EQ4 distance", `current_severity_distance_eq4 = severity_distance_SC + severity_distance_SI + severity_distance_SA`},
	{"E not defined is Attacked", `if (metric == "E" && selected == "X") { return "A" }`},
	{"CR not defined is High", `if (metric == "CR" && selected == "X") { return "H"; }`},
	{"IR not defined is High", `if (metric == "IR" && selected == "X") { return "H" }`},
	{"AR not defined is High", `if (metric == "AR" && selected == "X") { return "H" }`},
	{"macro vector digit order", `return eq1 + eq2 + eq3 + eq4 + eq5 + eq6`},
	{"EQ1 level 0", `if (m(cvssSelected, "AV") == "N" && m(cvssSelected, "PR") == "N" && m(cvssSelected, "UI") == "N") { eq1 = "0" }`},
	{"EQ2 level 0", `if (m(cvssSelected, "AC") == "L" && m(cvssSelected, "AT") == "N") { eq2 = "0" }`},
	{"EQ3 level 0", `if (m(cvssSelected, "VC") == "H" && m(cvssSelected, "VI") == "H") { eq3 = 0 }`},
	{"EQ6 level 0", `if ((m(cvssSelected, "CR") == "H" && m(cvssSelected, "VC") == "H") || (m(cvssSelected, "IR") == "H" && m(cvssSelected, "VI") == "H") || (m(cvssSelected, "AR") == "H" && m(cvssSelected, "VA") == "H")) { eq6 = 0 }`},
}

// tables is everything the generated file carries, in a form ready to emit.
type tables struct {
	BaseMetrics []baseMetric
	AllMetrics  []string // every metric key cvss_config.js defines, in its order
	Levels      []levelTable
	Macro       []macroRow
	MaxSeverity maxSeverityTables
	Composed    composedTables
}

type baseMetric struct {
	Key    string
	Values []string // valid values, in upstream order
}

type levelTable struct {
	Metric string
	Rows   []levelRow // upstream order
}

type levelRow struct{ Value, Number string }

type macroRow struct{ Key, Number string }

type maxSeverityTables struct {
	EQ1, EQ2, EQ4, EQ5 []intRow
	EQ3EQ6             []pairRow
}

type intRow struct {
	Key   int
	Value int
}

type pairRow struct {
	EQ3, EQ6 int
	Value    int
}

type fragmentRow struct{ Metric, Value string }

type composedGroup struct {
	Key       string // "0", "1" or for EQ3/EQ6 "0,1"
	Fragments [][]fragmentRow
	Source    []string // the upstream spelling of each fragment, for comments
}

type composedTables struct {
	EQ1, EQ2, EQ4, EQ5 []composedGroup
	EQ3EQ6             []composedGroup
}

var wsRe = regexp.MustCompile(`\s+`)

func collapse(s string) string { return strings.TrimSpace(wsRe.ReplaceAllString(s, " ")) }

func checkAnchors(score string) error {
	flat := collapse(score)
	for _, a := range anchors {
		if !strings.Contains(flat, collapse(a.Text)) {
			return fmt.Errorf("cvss4gen: cvss_score.js no longer contains the %s rule the Go scorer reproduces:\n  %s\nread the upstream change and update the scorer and this anchor together", a.Name, a.Text)
		}
	}
	return nil
}

func buildTables(files map[string]string) (*tables, error) {
	if err := checkAnchors(files["cvss_score.js"]); err != nil {
		return nil, err
	}
	cfg, err := parseAssigned("cvss_config.js", files["cvss_config.js"], "cvssConfig")
	if err != nil {
		return nil, err
	}
	base, options, all, err := metricOptions(cfg)
	if err != nil {
		return nil, err
	}
	t := &tables{BaseMetrics: base, AllMetrics: all}
	if t.Levels, err = buildLevels(files["cvss_score.js"], options); err != nil {
		return nil, err
	}
	if err = checkNotDefined(options); err != nil {
		return nil, err
	}
	if t.Macro, err = buildMacro(files["cvss_lookup.js"]); err != nil {
		return nil, err
	}
	if t.MaxSeverity, err = buildMaxSeverity(files["max_severity.js"]); err != nil {
		return nil, err
	}
	if t.Composed, err = buildComposed(files["max_composed.js"], t.Levels); err != nil {
		return nil, err
	}
	return t, nil
}

// metricOptions walks cvssConfig and returns the base metrics in vector order
// plus, for every metric the config defines, its option values (X, the "not
// defined" option, is dropped).
func metricOptions(cfg *node) ([]baseMetric, map[string][]string, []string, error) {
	options := map[string][]string{}
	var all []string
	for i, groupName := range cfg.keys {
		groups, ok := cfg.vals[i].lookup("metric_groups")
		if !ok {
			return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js %q has no metric_groups", groupName)
		}
		for j := range groups.keys {
			metrics := groups.vals[j]
			for k := range metrics.keys {
				short, ok1 := metrics.vals[k].lookup("short")
				opts, ok2 := metrics.vals[k].lookup("options")
				if !ok1 || !ok2 || short.kind != kindString || opts.kind != kindObject {
					return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js metric %q lacks short/options", metrics.keys[k])
				}
				if _, dup := options[short.str]; dup {
					return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js defines %s twice", short.str)
				}
				var vals []string
				for oi, o := range opts.vals {
					if opts.keys[oi] == "" && o.kind == kindObject && len(o.keys) == 0 {
						// The calculator's dropdowns carry an empty separator
						// option ("": {}) between "not defined" and the values.
						continue
					}
					v, ok := o.lookup("value")
					if !ok || v.kind != kindString {
						return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js option of %s has no value", short.str)
					}
					if v.str == "X" {
						continue
					}
					if contains(vals, v.str) {
						return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js lists %s=%s twice", short.str, v.str)
					}
					vals = append(vals, v.str)
				}
				options[short.str] = vals
				all = append(all, short.str)
			}
		}
	}
	var base []baseMetric
	for _, k := range baseMetricKeys {
		vals, ok := options[k]
		if !ok {
			return nil, nil, nil, fmt.Errorf("cvss4gen: cvss_config.js has no base metric %s", k)
		}
		base = append(base, baseMetric{Key: k, Values: vals})
	}
	return base, options, all, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func buildLevels(score string, options map[string][]string) ([]levelTable, error) {
	var out []levelTable
	for _, m := range levelMetrics {
		n, err := parseAssigned("cvss_score.js", score, m+"_levels")
		if err != nil {
			return nil, err
		}
		lt := levelTable{Metric: m}
		for i, k := range n.keys {
			v := n.vals[i]
			if v.kind != kindNumber {
				return nil, fmt.Errorf("cvss4gen: %s_levels[%s] is not a number", m, k)
			}
			lt.Rows = append(lt.Rows, levelRow{Value: k, Number: v.str})
		}
		// The table must cover exactly the values the metric can take: its own
		// options and, where a modified metric exists, that one's (which add S
		// to SI and SA).
		own, ok := options[m]
		if !ok {
			return nil, fmt.Errorf("cvss4gen: cvss_config.js has no metric %s for %s_levels", m, m)
		}
		want := append([]string(nil), own...)
		for _, v := range options["M"+m] {
			if !contains(want, v) {
				want = append(want, v)
			}
		}
		var have []string
		for _, r := range lt.Rows {
			have = append(have, r.Value)
		}
		if !sameSet(have, want) {
			return nil, fmt.Errorf("cvss4gen: %s_levels covers %v but cvss_config.js says %s takes %v", m, have, m, want)
		}
		out = append(out, lt)
	}
	return out, nil
}

func checkNotDefined(options map[string][]string) error {
	for _, d := range notDefinedDefaults {
		found := false
		for _, v := range options[d.Metric] {
			if v == d.Value {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("cvss4gen: the default %s=%s is not a value cvss_config.js defines for %s", d.Metric, d.Value, d.Metric)
		}
	}
	return nil
}

func buildMacro(src string) ([]macroRow, error) {
	n, err := parseAssigned("cvss_lookup.js", src, "cvssLookup_global")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for e1 := 0; e1 < eqLevels[0]; e1++ {
		for e2 := 0; e2 < eqLevels[1]; e2++ {
			for _, p := range validEQ3EQ6 {
				for e4 := 0; e4 < eqLevels[3]; e4++ {
					for e5 := 0; e5 < eqLevels[4]; e5++ {
						want[fmt.Sprintf("%d%d%d%d%d%d", e1, e2, p[0], e4, e5, p[1])] = true
					}
				}
			}
		}
	}
	if len(want) != macroVectorsN {
		return nil, fmt.Errorf("cvss4gen: internal: expected %d valid MacroVectors, built %d", macroVectorsN, len(want))
	}
	var rows []macroRow
	for i, k := range n.keys {
		if !want[k] {
			return nil, fmt.Errorf("cvss4gen: cvss_lookup.js has %q, which is not a valid MacroVector", k)
		}
		v := n.vals[i]
		if v.kind != kindNumber {
			return nil, fmt.Errorf("cvss4gen: cvss_lookup.js[%s] is not a number", k)
		}
		f, err := strconv.ParseFloat(v.str, 64)
		if err != nil || f < 0 || f > 10 {
			return nil, fmt.Errorf("cvss4gen: cvss_lookup.js[%s]=%s is not a score from 0 to 10", k, v.str)
		}
		rows = append(rows, macroRow{Key: k, Number: v.str})
	}
	if len(rows) != macroVectorsN {
		return nil, fmt.Errorf("cvss4gen: cvss_lookup.js has %d MacroVectors, want %d", len(rows), macroVectorsN)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows, nil
}

func intOf(n *node, what string) (int, error) {
	if n.kind != kindNumber {
		return 0, fmt.Errorf("cvss4gen: %s is not a number", what)
	}
	v, err := strconv.Atoi(n.str)
	if err != nil {
		return 0, fmt.Errorf("cvss4gen: %s=%q is not an integer", what, n.str)
	}
	return v, nil
}

func intTable(n *node, name string, levels int) ([]intRow, error) {
	if n == nil || n.kind != kindObject || len(n.keys) != levels {
		return nil, fmt.Errorf("cvss4gen: max_severity.js %s must be an object with %d levels", name, levels)
	}
	var rows []intRow
	for i, k := range n.keys {
		key, err := strconv.Atoi(k)
		if err != nil || key != i {
			return nil, fmt.Errorf("cvss4gen: max_severity.js %s has key %q, want %d", name, k, i)
		}
		v, err := intOf(n.vals[i], name+"["+k+"]")
		if err != nil {
			return nil, err
		}
		if v < 1 {
			return nil, fmt.Errorf("cvss4gen: max_severity.js %s[%s]=%d must be positive (it is a divisor)", name, k, v)
		}
		rows = append(rows, intRow{Key: key, Value: v})
	}
	return rows, nil
}

func buildMaxSeverity(src string) (maxSeverityTables, error) {
	var out maxSeverityTables
	n, err := parseAssigned("max_severity.js", src, "maxSeverity")
	if err != nil {
		return out, err
	}
	for _, name := range []string{"eq1", "eq2", "eq3eq6", "eq4", "eq5"} {
		if _, ok := n.lookup(name); !ok {
			return out, fmt.Errorf("cvss4gen: max_severity.js lacks %s", name)
		}
	}
	if len(n.keys) != 5 {
		return out, fmt.Errorf("cvss4gen: max_severity.js has %d tables, want 5", len(n.keys))
	}
	get := func(name string) *node { v, _ := n.lookup(name); return v }
	if out.EQ1, err = intTable(get("eq1"), "eq1", eqLevels[0]); err != nil {
		return out, err
	}
	if out.EQ2, err = intTable(get("eq2"), "eq2", eqLevels[1]); err != nil {
		return out, err
	}
	if out.EQ4, err = intTable(get("eq4"), "eq4", eqLevels[3]); err != nil {
		return out, err
	}
	if out.EQ5, err = intTable(get("eq5"), "eq5", eqLevels[4]); err != nil {
		return out, err
	}
	pairs := get("eq3eq6")
	for _, p := range validEQ3EQ6 {
		row, ok := pairs.lookup(strconv.Itoa(p[0]))
		if !ok {
			return out, fmt.Errorf("cvss4gen: max_severity.js eq3eq6 lacks EQ3=%d", p[0])
		}
		cell, ok := row.lookup(strconv.Itoa(p[1]))
		if !ok {
			return out, fmt.Errorf("cvss4gen: max_severity.js eq3eq6[%d] lacks EQ6=%d", p[0], p[1])
		}
		v, err := intOf(cell, fmt.Sprintf("eq3eq6[%d][%d]", p[0], p[1]))
		if err != nil {
			return out, err
		}
		if v < 1 {
			return out, fmt.Errorf("cvss4gen: max_severity.js eq3eq6[%d][%d]=%d must be positive", p[0], p[1], v)
		}
		out.EQ3EQ6 = append(out.EQ3EQ6, pairRow{EQ3: p[0], EQ6: p[1], Value: v})
	}
	cells := 0
	for _, row := range pairs.vals {
		cells += len(row.keys)
	}
	if len(pairs.keys) != 3 || cells != len(validEQ3EQ6) {
		return out, fmt.Errorf("cvss4gen: max_severity.js eq3eq6 has %d cells, want exactly the %d valid (EQ3, EQ6) pairs", cells, len(validEQ3EQ6))
	}
	return out, nil
}

// composedMetrics are the metrics each EQ's maximal vectors fix, in the order
// the upstream fragments list them.
var composedMetrics = map[string][]string{
	"eq1": {"AV", "PR", "UI"},
	"eq2": {"AC", "AT"},
	"eq3": {"VC", "VI", "VA", "CR", "IR", "AR"},
	"eq4": {"SC", "SI", "SA"},
	"eq5": {"E"},
}

func parseFragment(text string, metrics []string, levels map[string]map[string]bool) ([]fragmentRow, error) {
	if !strings.HasSuffix(text, "/") {
		return nil, fmt.Errorf("fragment %q does not end in '/'", text)
	}
	parts := strings.Split(strings.TrimSuffix(text, "/"), "/")
	if len(parts) != len(metrics) {
		return nil, fmt.Errorf("fragment %q has %d metrics, want %d", text, len(parts), len(metrics))
	}
	var out []fragmentRow
	for i, p := range parts {
		k, v, ok := strings.Cut(p, ":")
		if !ok || k != metrics[i] {
			return nil, fmt.Errorf("fragment %q: part %d is %q, want metric %s", text, i+1, p, metrics[i])
		}
		if !levels[k][v] {
			return nil, fmt.Errorf("fragment %q: %s has no level %q", text, k, v)
		}
		out = append(out, fragmentRow{Metric: k, Value: v})
	}
	return out, nil
}

func fragmentList(n *node, eq string, levels map[string]map[string]bool) ([][]fragmentRow, []string, error) {
	if n.kind != kindArray || len(n.vals) == 0 {
		return nil, nil, fmt.Errorf("cvss4gen: max_composed.js %s entry is not a non-empty array", eq)
	}
	var frags [][]fragmentRow
	var src []string
	seen := map[string]bool{}
	for _, v := range n.vals {
		if v.kind != kindString {
			return nil, nil, fmt.Errorf("cvss4gen: max_composed.js %s fragment is not a string", eq)
		}
		if seen[v.str] {
			return nil, nil, fmt.Errorf("cvss4gen: max_composed.js %s repeats fragment %q", eq, v.str)
		}
		seen[v.str] = true
		f, err := parseFragment(v.str, composedMetrics[eq], levels)
		if err != nil {
			return nil, nil, fmt.Errorf("cvss4gen: max_composed.js %s: %w", eq, err)
		}
		frags = append(frags, f)
		src = append(src, v.str)
	}
	return frags, src, nil
}

func buildComposed(src string, lt []levelTable) (composedTables, error) {
	var out composedTables
	levels := map[string]map[string]bool{}
	for _, t := range lt {
		levels[t.Metric] = map[string]bool{}
		for _, r := range t.Rows {
			levels[t.Metric][r.Value] = true
		}
	}
	n, err := parseAssigned("max_composed.js", src, "maxComposed")
	if err != nil {
		return out, err
	}
	if len(n.keys) != 5 {
		return out, fmt.Errorf("cvss4gen: max_composed.js has %d tables, want 5", len(n.keys))
	}
	simple := func(eq string, levelCount int) ([]composedGroup, error) {
		t, ok := n.lookup(eq)
		if !ok || t.kind != kindObject || len(t.keys) != levelCount {
			return nil, fmt.Errorf("cvss4gen: max_composed.js %s must be an object with %d levels", eq, levelCount)
		}
		var groups []composedGroup
		for i, k := range t.keys {
			if k != strconv.Itoa(i) {
				return nil, fmt.Errorf("cvss4gen: max_composed.js %s has key %q, want %d", eq, k, i)
			}
			f, s, err := fragmentList(t.vals[i], eq, levels)
			if err != nil {
				return nil, err
			}
			groups = append(groups, composedGroup{Key: k, Fragments: f, Source: s})
		}
		return groups, nil
	}
	if out.EQ1, err = simple("eq1", eqLevels[0]); err != nil {
		return out, err
	}
	if out.EQ2, err = simple("eq2", eqLevels[1]); err != nil {
		return out, err
	}
	if out.EQ4, err = simple("eq4", eqLevels[3]); err != nil {
		return out, err
	}
	if out.EQ5, err = simple("eq5", eqLevels[4]); err != nil {
		return out, err
	}
	t3, ok := n.lookup("eq3")
	if !ok || t3.kind != kindObject {
		return out, fmt.Errorf("cvss4gen: max_composed.js lacks eq3")
	}
	cells := 0
	for _, row := range t3.vals {
		cells += len(row.keys)
	}
	if len(t3.keys) != 3 || cells != len(validEQ3EQ6) {
		return out, fmt.Errorf("cvss4gen: max_composed.js eq3 has %d cells, want exactly the %d valid (EQ3, EQ6) pairs", cells, len(validEQ3EQ6))
	}
	for _, p := range validEQ3EQ6 {
		row, ok := t3.lookup(strconv.Itoa(p[0]))
		if !ok {
			return out, fmt.Errorf("cvss4gen: max_composed.js eq3 lacks EQ3=%d", p[0])
		}
		cell, ok := row.lookup(strconv.Itoa(p[1]))
		if !ok {
			return out, fmt.Errorf("cvss4gen: max_composed.js eq3[%d] lacks EQ6=%d", p[0], p[1])
		}
		f, s, err := fragmentList(cell, "eq3", levels)
		if err != nil {
			return out, err
		}
		out.EQ3EQ6 = append(out.EQ3EQ6, composedGroup{Key: fmt.Sprintf("%d,%d", p[0], p[1]), Fragments: f, Source: s})
	}
	return out, nil
}
