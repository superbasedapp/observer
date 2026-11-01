package seccorpus

import "math"

// z95 is the two-sided 95 percent normal quantile.
const z95 = 1.959963984540054

// WilsonLower is the lower bound of the Wilson score interval at 95
// percent for k successes in n trials (0 when n is not positive or k is out
// of range).
func WilsonLower(k, n int) float64 {
	if n <= 0 || k < 0 || k > n {
		return 0
	}
	nf, ph := float64(n), float64(k)/float64(n)
	den := 1 + z95*z95/nf
	centre := ph + z95*z95/(2*nf)
	margin := z95 * math.Sqrt(ph*(1-ph)/nf+z95*z95/(4*nf*nf))
	return math.Max(0, (centre-margin)/den)
}

// PassAgreement is how two labelling passes agreed over a set of findings:
// on the verdict and on the reason code (a reason code belongs to one
// verdict, so ReasonAgreements is at most VerdictAgreements).
type PassAgreement struct {
	Results           int `json:"results"`
	VerdictAgreements int `json:"verdict_agreements"`
	ReasonAgreements  int `json:"reason_agreements"`
	// SecondPassPending counts labelled findings with no side-b label yet
	// (MeasureOptions.SecondPassPending, lane SEC-G5): they are counted on
	// side a alone and are not in Results.
	SecondPassPending int `json:"second_pass_pending,omitempty"`
}

// Agreement is the two-reviewer table of one set of findings.
type Agreement struct {
	BothTrue  int `json:"both_true"`
	BothFalse int `json:"both_false"`
	// OnlyA and OnlyB count findings only that reviewer called true.
	OnlyA int `json:"only_a"`
	OnlyB int `json:"only_b"`
}

// Add counts one finding's pair of verdicts.
func (a *Agreement) Add(va, vb Verdict) {
	switch {
	case va == TruePositive && vb == TruePositive:
		a.BothTrue++
	case va == TruePositive:
		a.OnlyA++
	case vb == TruePositive:
		a.OnlyB++
	default:
		a.BothFalse++
	}
}

// N is how many findings were counted.
func (a Agreement) N() int { return a.BothTrue + a.BothFalse + a.OnlyA + a.OnlyB }

// Disagreements is how many findings the reviewers labelled differently.
func (a Agreement) Disagreements() int { return a.OnlyA + a.OnlyB }

// Kappa is Cohen's kappa of the two reviewers. defined is false when the
// expected agreement is 1 (both reviewers gave one verdict to every
// finding), where kappa has no value; the observed agreement is then 1.
func (a Agreement) Kappa() (kappa float64, defined bool) {
	n := float64(a.N())
	if n == 0 {
		return 0, false
	}
	po := float64(a.BothTrue+a.BothFalse) / n
	pa := float64(a.BothTrue+a.OnlyA) / n
	pb := float64(a.BothTrue+a.OnlyB) / n
	pe := pa*pb + (1-pa)*(1-pb)
	if pe >= 1 {
		return 0, false
	}
	return (po - pe) / (1 - pe), true
}
