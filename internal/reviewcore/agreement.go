package reviewcore

import (
	"math"
	"sort"
)

// Value is one reviewer's answer on one criterion, as a score stores it.
type Value struct {
	Kind string // numeric | boolean | categorical
	Text string
	Num  *float64
}

// Criterion is the part of a rubric line the agreement rules read.
type Criterion struct {
	Name string
	Kind string
}

// Verdict is one reviewer's answers on one item, by criterion name.
type Verdict struct {
	Reviewer string
	Answers  map[string]Value
}

// numeric reports whether a criterion compares by distance.
func numeric(kind string) bool { return kind == "numeric" }

// same reports whether two answers agree: numeric within tolerance, any
// other kind by its stored text.
func same(kind string, a, b Value, tol float64) bool {
	if numeric(kind) {
		if a.Num == nil || b.Num == nil {
			return a.Num == nil && b.Num == nil
		}
		return math.Abs(*a.Num-*b.Num) <= tol+1e-12
	}
	return a.Text == b.Text
}

// answers returns the values given on one criterion, in reviewer order.
func answers(c Criterion, vs []Verdict) []Value {
	sorted := append([]Verdict(nil), vs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Reviewer < sorted[j].Reviewer })
	var out []Value
	for _, v := range sorted {
		if a, ok := v.Answers[c.Name]; ok {
			out = append(out, a)
		}
	}
	return out
}

// Conflicts returns the criteria on which the verdicts disagree. A criterion
// answered by fewer than two reviewers never conflicts.
func Conflicts(criteria []Criterion, vs []Verdict, tol float64) []string {
	out := []string{}
	for _, c := range criteria {
		vals := answers(c, vs)
		for i := 1; i < len(vals); i++ {
			if !same(c.Kind, vals[0], vals[i], tol) {
				out = append(out, c.Name)
				break
			}
		}
	}
	return out
}

// ItemVerdicts is one item's reviewer verdicts.
type ItemVerdicts struct {
	ItemID   string
	Verdicts []Verdict
}

// CriterionAgreement is the agreement on one rubric criterion.
type CriterionAgreement struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Items is the number of items with at least two answers on it.
	Items int `json:"items"`
	// Agreed is the number of those items on which every answer agreed.
	Agreed int `json:"agreed"`
	// Percent is Agreed / Items (0 when Items is 0).
	Percent float64 `json:"percent_agreement"`
	// Pairwise is the share of reviewer pairs that agreed.
	Pairwise float64 `json:"pairwise_agreement"`
	// Alpha is Krippendorff's alpha (nominal for boolean and categorical,
	// interval for numeric); nil when undefined (fewer than two pairable
	// answers, or every answer identical so no disagreement is possible).
	Alpha *float64 `json:"alpha"`
	// Ratings is the number of pairable answers alpha is computed over.
	Ratings int `json:"ratings"`
}

// Agreement is a queue's inter-reviewer agreement.
type Agreement struct {
	// Items is the number of items with at least two verdicts.
	Items int `json:"items"`
	// FullAgreement counts those items with no conflicting criterion.
	FullAgreement int `json:"full_agreement"`
	// Percent is FullAgreement / Items.
	Percent   float64              `json:"percent_agreement"`
	Reviewers int                  `json:"reviewers"`
	Criteria  []CriterionAgreement `json:"criteria"`
}

// ComputeAgreement computes agreement per criterion and for the queue.
func ComputeAgreement(criteria []Criterion, items []ItemVerdicts, tol float64) Agreement {
	out := Agreement{Criteria: []CriterionAgreement{}}
	reviewers := map[string]bool{}
	for _, it := range items {
		if len(it.Verdicts) < 2 {
			continue
		}
		out.Items++
		for _, v := range it.Verdicts {
			reviewers[v.Reviewer] = true
		}
		if len(Conflicts(criteria, it.Verdicts, tol)) == 0 {
			out.FullAgreement++
		}
	}
	out.Reviewers = len(reviewers)
	if out.Items > 0 {
		out.Percent = float64(out.FullAgreement) / float64(out.Items)
	}
	for _, c := range criteria {
		out.Criteria = append(out.Criteria, criterionAgreement(c, items, tol))
	}
	return out
}

func criterionAgreement(c Criterion, items []ItemVerdicts, tol float64) CriterionAgreement {
	ca := CriterionAgreement{Name: c.Name, Kind: c.Kind}
	var units [][]Value
	pairs, agreeing := 0, 0
	for _, it := range items {
		vals := answers(c, it.Verdicts)
		if len(vals) < 2 {
			continue
		}
		units = append(units, vals)
		ca.Items++
		all := true
		for i := 0; i < len(vals); i++ {
			for j := i + 1; j < len(vals); j++ {
				pairs++
				if same(c.Kind, vals[i], vals[j], tol) {
					agreeing++
				} else {
					all = false
				}
			}
		}
		if all {
			ca.Agreed++
		}
	}
	if ca.Items > 0 {
		ca.Percent = float64(ca.Agreed) / float64(ca.Items)
	}
	if pairs > 0 {
		ca.Pairwise = float64(agreeing) / float64(pairs)
	}
	ca.Alpha, ca.Ratings = alpha(c.Kind, units)
	return ca
}

// alpha is Krippendorff's alpha over units of at least two values each:
// 1 - D_o / D_e, with D_o the within-unit and D_e the overall disagreement.
// Nominal distance is 0/1; interval distance is the squared difference.
// Both sums run in linear time from counts (nominal) or moments (interval).
func alpha(kind string, units [][]Value) (*float64, int) {
	n := 0
	for _, u := range units {
		n += len(u)
	}
	if n < 2 {
		return nil, n
	}
	pairSum := pairDistanceNominal
	if numeric(kind) {
		pairSum = pairDistanceInterval
	}
	do := 0.0
	for _, u := range units {
		do += pairSum(u) / float64(len(u)-1)
	}
	do /= float64(n)
	var all []Value
	for _, u := range units {
		all = append(all, u...)
	}
	de := pairSum(all) / (float64(n) * float64(n-1))
	if de == 0 {
		return nil, n
	}
	a := 1 - do/de
	return &a, n
}

// pairDistanceNominal is the sum over ordered pairs i≠j of [v_i ≠ v_j]:
// m² - Σ count².
func pairDistanceNominal(vs []Value) float64 {
	counts := map[string]int{}
	for _, v := range vs {
		counts[v.Text]++
	}
	sq := 0
	for _, c := range counts {
		sq += c * c
	}
	return float64(len(vs)*len(vs) - sq)
}

// pairDistanceInterval is the sum over ordered pairs i≠j of (v_i - v_j)²:
// 2(mΣv² - (Σv)²). A value with no number counts as 0.
func pairDistanceInterval(vs []Value) float64 {
	s, s2 := 0.0, 0.0
	for _, v := range vs {
		x := 0.0
		if v.Num != nil {
			x = *v.Num
		}
		s += x
		s2 += x * x
	}
	d := 2 * (float64(len(vs))*s2 - s*s)
	if d < 0 {
		return 0
	}
	return d
}
