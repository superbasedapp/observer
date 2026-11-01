package seccorpus

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// SampleRow is one row of the operator's spot-check sample: a finding, both
// reviewers' verdicts, the joint verdict (true only when both said true)
// and the operator's column, empty until they answer.
type SampleRow struct {
	Finding
	ReviewerA Verdict `json:"reviewer_a"`
	ReviewerB Verdict `json:"reviewer_b"`
	Joint     Verdict `json:"joint"`
	// Operator is "", OperatorAgree or OperatorOverturn.
	Operator string `json:"operator"`
}

// The operator's answers.
const (
	OperatorAgree    = "agree"
	OperatorOverturn = "overturn"
)

// Joint is the joint verdict of two reviewers' verdicts.
func Joint(a, b Verdict) Verdict {
	if a == TruePositive && b == TruePositive {
		return TruePositive
	}
	return FalsePositive
}

// splitmix64 is the sample's generator: fixed here, so a recorded seed
// draws the same rows on every Go version.
type splitmix64 struct{ s uint64 }

func (g *splitmix64) next() uint64 {
	g.s += 0x9e3779b97f4a7c15
	z := g.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// intn returns a value in [0, n) (n > 0) by rejection, without bias.
func (g *splitmix64) intn(n int) int {
	max := ^uint64(0) - ^uint64(0)%uint64(n)
	for {
		v := g.next()
		if v < max {
			return int(v % uint64(n))
		}
	}
}

// PerRule is how many rows each rule gets: perRule, lowered so the total
// stays within maxTotal, and never under one.
func PerRule(rules, perRule, maxTotal int) int {
	if rules <= 0 {
		return 0
	}
	if rules*perRule > maxTotal {
		perRule = maxTotal / rules
	}
	if perRule < 1 {
		perRule = 1
	}
	return perRule
}

// MinSpotcheckSample is the smallest spot-check a rule may block on: this
// many answered rows, or every row both reviewers called true when the rule
// has fewer (secrulepack.Precision.MinSpotcheck). DrawSample always draws
// at least that many rows for a rule.
const MinSpotcheckSample = 10

// DrawSample draws the spot-check sample, stratified per rule. For each
// rule in rules it takes, in the order of a seeded shuffle of the rule's
// rows sorted by key: every row the two reviewers labelled differently,
// at least half (rounded up) of the rows both called true, and then further
// rows until the rule has PerRule(len(rules), perRule, maxTotal) rows and
// at least min(MinSpotcheckSample, both-true rows). The cap lowers only
// the per-rule fill, never the required rows. Each rule's generator is
// the seed mixed with the rule id, so adding or removing a rule leaves
// every other rule's draw unchanged. The result is sorted by rule, then
// key.
func DrawSample(rows []SampleRow, rules []string, seed uint64, perRule, maxTotal int) ([]SampleRow, error) {
	want := map[string]bool{}
	for _, r := range rules {
		want[r] = true
	}
	groups := map[string][]SampleRow{}
	for _, r := range rows {
		if want[r.Rule] {
			groups[r.Rule] = append(groups[r.Rule], r)
		}
	}
	k := PerRule(len(rules), perRule, maxTotal)
	var out []SampleRow
	sorted := append([]string(nil), rules...)
	sort.Strings(sorted)
	for _, rule := range sorted {
		g := groups[rule]
		if len(g) == 0 {
			return nil, fmt.Errorf("seccorpus.DrawSample: rule %s has no rows", rule)
		}
		out = append(out, stratified(g, rule, seed, k)...)
	}
	return out, nil
}

// stratified is one rule's DrawSample draw.
func stratified(g []SampleRow, rule string, seed uint64, k int) []SampleRow {
	g = shuffled(g, rule, seed, func(r SampleRow) string { return r.Key() })
	take := make([]bool, len(g))
	n, bothTrue := 0, 0
	for _, r := range g {
		if r.ReviewerA == TruePositive && r.ReviewerB == TruePositive {
			bothTrue++
		}
	}
	half, seenTrue := (bothTrue+1)/2, 0
	for i, r := range g {
		switch {
		case r.ReviewerA != r.ReviewerB:
			take[i] = true
		case r.ReviewerA == TruePositive && seenTrue < half:
			seenTrue++
			take[i] = true
		}
		if take[i] {
			n++
		}
	}
	need := max(k, min(MinSpotcheckSample, bothTrue))
	for i := range g {
		if n >= need {
			break
		}
		if !take[i] {
			take[i] = true
			n++
		}
	}
	var out []SampleRow
	for i, r := range g {
		if take[i] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// shuffled returns the rows sorted by key and then shuffled with the seed
// mixed with the rule id.
func shuffled[T any](g []T, rule string, seed uint64, key func(T) string) []T {
	g = append([]T(nil), g...)
	sort.Slice(g, func(i, j int) bool { return key(g[i]) < key(g[j]) })
	h := fnv.New64a()
	_, _ = h.Write([]byte(rule))
	gen := splitmix64{s: seed ^ h.Sum64()}
	for i := len(g) - 1; i > 0; i-- {
		j := gen.intn(i + 1)
		g[i], g[j] = g[j], g[i]
	}
	return g
}

// pick sorts rows by key, shuffles them with the seed mixed with the rule
// id, keeps k and returns them sorted by key again.
func pick[T any](g []T, rule string, seed uint64, k int, key func(T) string) []T {
	g = shuffled(g, rule, seed, key)
	if len(g) > k {
		g = g[:k]
	}
	sort.Slice(g, func(i, j int) bool { return key(g[i]) < key(g[j]) })
	return g
}

// SelectForLabelling is JSP-8 step 3: every result of a rule with at most
// limit results, otherwise a seeded random sample of limit of them, and
// every result of a rule named in full whatever its count (a rule proposed
// for blocking is labelled in full, P-077). The result is sorted by key;
// the same seed always selects the same findings.
func SelectForLabelling(cands []Finding, seed uint64, limit int, full []string) []Finding {
	inFull := map[string]bool{}
	for _, r := range full {
		inFull[r] = true
	}
	groups := map[string][]Finding{}
	for _, f := range cands {
		groups[f.Rule] = append(groups[f.Rule], f)
	}
	var out []Finding
	for rule, g := range groups {
		if inFull[rule] {
			out = append(out, g...)
			continue
		}
		out = append(out, pick(g, rule, seed, limit, Finding.Key)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Tally is one rule's spot-check result.
type Tally struct {
	Rule       string `json:"rule"`
	SampleSize int    `json:"sample_size"`
	// Disagreements counts rows the operator overturned.
	Disagreements int `json:"disagreements"`
	// OverturnedTrue counts overturned rows whose joint verdict was true:
	// the operator found a finding the reviewers accepted to be false.
	OverturnedTrue int `json:"overturned_true"`
}

// TallySample counts the operator's answers per rule. Every row needs an
// answer; a joint verdict that does not follow from the two reviewers'
// verdicts is refused (the sample file was edited).
func TallySample(rows []SampleRow) ([]Tally, error) {
	per := map[string]*Tally{}
	for _, r := range rows {
		if r.Joint != Joint(r.ReviewerA, r.ReviewerB) {
			return nil, fmt.Errorf("seccorpus.TallySample: %s: the joint verdict does not follow from the reviewers'", r.Key())
		}
		if r.Operator != OperatorAgree && r.Operator != OperatorOverturn {
			return nil, fmt.Errorf("seccorpus.TallySample: %s: operator answer %q (want agree or overturn)", r.Key(), r.Operator)
		}
		t := per[r.Rule]
		if t == nil {
			t = &Tally{Rule: r.Rule}
			per[r.Rule] = t
		}
		t.SampleSize++
		if r.Operator == OperatorOverturn {
			t.Disagreements++
			if r.Joint == TruePositive {
				t.OverturnedTrue++
			}
		}
	}
	out := make([]Tally, 0, len(per))
	for _, t := range per {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}
