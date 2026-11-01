package seccorpus

import (
	"fmt"
	"sort"
)

// RuleFigures is one rule's measurement.
type RuleFigures struct {
	Rule string `json:"rule"`
	// Labelled is how many of the rule's findings were labelled: every
	// result when the rule has at most the labelling cap, else the seeded
	// sample of SelectForLabelling. It is the precision's denominator.
	Labelled  int       `json:"labelled"`
	Agreement Agreement `json:"agreement"`
	// TruePositives counts findings both reviewers called true.
	TruePositives int `json:"true_positives"`
	// Figure is TruePositives over Labelled; WilsonLower its 95 percent
	// lower bound.
	Figure      float64 `json:"figure"`
	WilsonLower float64 `json:"wilson_lower"`
	// Kappa is Cohen's kappa of the rule's labels; KappaDefined is false
	// when it has no value (see Agreement.Kappa).
	Kappa        float64 `json:"kappa"`
	KappaDefined bool    `json:"kappa_defined"`
	// SecondPassPending counts the rule's findings labelled on side a only
	// (MeasureOptions.SecondPassPending); each is a true positive when side
	// a says so, so the figure is one pass and may never block.
	SecondPassPending int `json:"second_pass_pending,omitempty"`
}

// Measurement is the whole corpus's figures.
type Measurement struct {
	Rules []RuleFigures `json:"rules"`
	// Overall is the agreement over every finding of every rule.
	Overall      Agreement `json:"overall"`
	Kappa        float64   `json:"kappa"`
	KappaDefined bool      `json:"kappa_defined"`
	// Passes is how the two passes agreed over every labelled finding, on
	// the verdict and on the reason code.
	Passes PassAgreement `json:"passes"`
	// OneEffectivePass is set by the measure step when the passes agree on
	// every verdict and reason code over enough results and the second pass
	// is not attested isolated (secrulepack.Passes.OneEffectivePass): the
	// kappa figures here are then not inter-rater agreement.
	OneEffectivePass bool `json:"one_effective_pass,omitempty"`
}

// Measure computes each rule's figures from the kept candidates and the two
// reviewers' labels. Every candidate needs exactly one label from each
// reviewer (ErrIncomplete otherwise); a label for a finding that is not a
// candidate, a duplicate label or an invalid record is an error. A finding
// is a true positive only when both reviewers say so (P-047).
func Measure(cands []Finding, labels []LabelRecord) (Measurement, error) {
	return MeasureWith(cands, labels, MeasureOptions{})
}

// MeasureOptions select how Measure treats missing labels.
type MeasureOptions struct {
	// SecondPassPending accepts a finding labelled by side a only, while
	// the side-b batches are prepared and await their (attested) relabel:
	// such a finding is counted on side a's verdict, in
	// PassAgreement.SecondPassPending and RuleFigures.SecondPassPending,
	// and never in the two-pass agreement. A finding with no side-a label
	// is still ErrIncomplete.
	SecondPassPending bool
}

// MeasureWith is Measure with options.
func MeasureWith(cands []Finding, labels []LabelRecord, o MeasureOptions) (Measurement, error) {
	type pair struct {
		a, b   Verdict
		ra, rb Reason
	}
	byKey := map[string]*pair{}
	for _, f := range cands {
		if err := f.Validate(); err != nil {
			return Measurement{}, fmt.Errorf("seccorpus.Measure: candidate %s: %w", f.Key(), err)
		}
		if byKey[f.Key()] != nil {
			return Measurement{}, fmt.Errorf("seccorpus.Measure: candidate %s listed twice", f.Key())
		}
		byKey[f.Key()] = &pair{}
	}
	for _, l := range labels {
		if err := l.Validate(); err != nil {
			return Measurement{}, fmt.Errorf("seccorpus.Measure: label %s: %w", l.Key(), err)
		}
		p := byKey[l.Key()]
		if p == nil {
			return Measurement{}, fmt.Errorf("seccorpus.Measure: label %s names no candidate", l.Key())
		}
		slot, reason := &p.a, &p.ra
		if l.Reviewer == ReviewerB {
			slot, reason = &p.b, &p.rb
		}
		if *slot != "" {
			return Measurement{}, fmt.Errorf("seccorpus.Measure: reviewer %s labelled %s twice", l.Reviewer, l.Key())
		}
		*slot, *reason = l.Verdict, l.Reason
	}
	per := map[string]*RuleFigures{}
	var m Measurement
	for _, f := range cands {
		p := byKey[f.Key()]
		pending := o.SecondPassPending && p.a != "" && p.b == ""
		if !pending && (p.a == "" || p.b == "") {
			return Measurement{}, fmt.Errorf("%w: %s", ErrIncomplete, f.Key())
		}
		r := per[f.Rule]
		if r == nil {
			r = &RuleFigures{Rule: f.Rule}
			per[f.Rule] = r
		}
		r.Labelled++
		if pending {
			r.SecondPassPending++
			m.Passes.SecondPassPending++
			if p.a == TruePositive {
				r.TruePositives++
			}
			continue
		}
		r.Agreement.Add(p.a, p.b)
		m.Overall.Add(p.a, p.b)
		m.Passes.Results++
		if p.a == p.b {
			m.Passes.VerdictAgreements++
		}
		if p.a == p.b && p.ra == p.rb {
			m.Passes.ReasonAgreements++
		}
	}
	for _, r := range per {
		r.TruePositives += r.Agreement.BothTrue
		r.Figure = float64(r.TruePositives) / float64(r.Labelled)
		r.WilsonLower = WilsonLower(r.TruePositives, r.Labelled)
		r.Kappa, r.KappaDefined = r.Agreement.Kappa()
		m.Rules = append(m.Rules, *r)
	}
	sort.Slice(m.Rules, func(i, j int) bool { return m.Rules[i].Rule < m.Rules[j].Rule })
	m.Kappa, m.KappaDefined = m.Overall.Kappa()
	return m, nil
}
