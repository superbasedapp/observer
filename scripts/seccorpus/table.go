package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// The generated block of docs/code-rules-precision.md.
const (
	tableBegin = "<!-- BEGIN seccorpus table (generated: go run ./scripts/seccorpus table) -->"
	tableEnd   = "<!-- END seccorpus table -->"
)

// docPath is the precision doc, relative to the repository root.
var docPath = filepath.Join("docs", "code-rules-precision.md")

// counts reads corpus/counts.tsv: rule to results kept, excluded and
// repositories.
func counts(p paths) (map[string][3]int, error) {
	b, err := os.ReadFile(p.file("counts.tsv"))
	if err != nil {
		return nil, err
	}
	out := map[string][3]int{}
	for i, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if i == 0 {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("counts.tsv:%d: %d columns", i+1, len(f))
		}
		var n [3]int
		for j := range n {
			if n[j], err = strconv.Atoi(f[j+1]); err != nil {
				return nil, fmt.Errorf("counts.tsv:%d: %w", i+1, err)
			}
		}
		out[f[0]] = n
	}
	return out, nil
}

// renderTable is the generated block: one row per rule of the pack.
func renderTable(man secrulepack.Manifest, c map[string][3]int) string {
	rules := append([]secrulepack.Rule(nil), man.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	var b strings.Builder
	b.WriteString(tableBegin + "\n\n")
	fmt.Fprintf(&b, "Pack `observer-code` %s, %d rules.\n\n", man.Version, len(rules))
	for _, r := range rules {
		if p := r.Precision; p != nil && p.Passes != nil && p.Passes.SecondPassPending > 0 {
			fmt.Fprintf(&b, "These figures come from ONE labelling pass: side a labelled all %d results and the side-b batches are prepared but not yet labelled, so \"True (both)\" counts side a's verdict alone, no disagreement or kappa can exist yet, and no rule may block on them.\n\n", p.Passes.SecondPassPending+p.Passes.Results)
			break
		}
		if p := r.Precision; p != nil && p.OneEffectivePass() {
			fmt.Fprintf(&b, "These figures come from ONE effective labelling pass: the two passes agree on every verdict and reason code (%d of %d) and the second pass is not attested isolated, so no kappa is given and no rule may block on them.\n\n", p.Passes.ReasonAgreements, p.Passes.Results)
			break
		}
	}
	b.WriteString("| Rule | Severity | Results | Excluded | Repos | True (both) | Disagreements | Kappa | Precision | Wilson lower | Status |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rules {
		n := c[r.ID]
		prec, lower, tp, dis, kappa := "none", "none", "-", "-", "-"
		if p := r.Precision; p != nil {
			prec, lower = fmt.Sprintf("%.3f", p.Figure), fmt.Sprintf("%.3f", p.WilsonLower)
			tp = strconv.Itoa(int(p.Figure*float64(p.Denominator) + 0.5))
			dis = strconv.Itoa(p.ReviewerDisagreements)
			switch {
			case p.OneEffectivePass():
				kappa = "not shown (one pass)"
			case p.Kappa != nil:
				kappa = fmt.Sprintf("%.2f", *p.Kappa)
			default:
				kappa = "n/a"
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d | %d | %d | %s | %s | %s | %s | %s | %s |\n",
			r.ID, r.Severity, n[0], n[1], n[2], tp, dis, kappa, prec, lower, status(r, n[0]))
	}
	b.WriteString("\n" + tableEnd)
	return b.String()
}

// status is a rule's standing against the bar, in words, with the
// rule's test-path exclusion named (lane SEC-G5).
func status(r secrulepack.Rule, results int) string {
	s := standing(r, results)
	if r.ExcludeTests {
		s += "; test paths excluded"
	}
	return s
}

// standing is a rule's standing against the bar, in words.
func standing(r secrulepack.Rule, results int) string {
	switch p := r.Precision; {
	case r.BlockingEligible():
		return "blocks (spot-checked " + r.OperatorSpotcheck.Date + ")"
	case p == nil && results > 0:
		return "flag only, unmeasured: not yet labelled"
	case p == nil:
		return "flag only, unmeasured: no results on the corpus"
	case r.Noisy():
		return "flag only, noisy: rewrite or retire at the next pack revision"
	case p.RecomputedLower() >= secrulepack.BlockingLowerBound && !p.FullyLabelled():
		return "flag only: cleared 0.8 on a capped figure, label every result to block"
	case r.MayBlock():
		return "cleared, spot-checked, blocking off"
	case p.RecomputedLower() >= secrulepack.BlockingLowerBound && r.OperatorSpotcheck != nil:
		return "flag only: the spot-check does not clear the bar"
	case p.RecomputedLower() >= secrulepack.BlockingLowerBound:
		return "cleared 0.8: awaits the independent spot-check"
	}
	return "flag only: under the 0.8 bar"
}

// writeTable replaces the generated block of the precision doc.
func writeTable(p paths) error {
	var man secrulepack.Manifest
	if err := readJSON(filepath.Join(p.pack, secrulepack.ManifestFile), &man); err != nil {
		return err
	}
	c, err := counts(p)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(docPath)
	if err != nil {
		return err
	}
	s := string(b)
	i, j := strings.Index(s, tableBegin), strings.Index(s, tableEnd)
	if i < 0 || j < i {
		return fmt.Errorf("%s has no generated block", docPath)
	}
	s = s[:i] + renderTable(man, c) + s[j+len(tableEnd):]
	return os.WriteFile(docPath, []byte(s), 0o644)
}
