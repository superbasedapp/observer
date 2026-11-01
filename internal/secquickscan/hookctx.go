package secquickscan

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// QuickScanner adapts the engine to the hook context seam's provider
// (hookctx.QuickScanner): the daemon serves the host's request with it,
// and the relay path calls it in process (security plan section 4.8
// "Relay path"). The seam's budget, when set, caps the engine's.
//
// The seam keeps the commit form and directory: only a plain `git commit`
// (with its -a, pathspec and --amend shapes) and a push are scanned. Any
// other form (merge, cherry-pick, rebase, am, revert, update-ref,
// commit-tree, `gh pr merge`, `gh api`, an MCP write) and any `git -C` or
// `--git-dir` directory answer unknown with no DirtyCovered: the index of
// the project root is not what those record, so a clean answer over it
// would be vacuous and would clear the dirty state for changes nobody
// scanned.
func (e *Engine) QuickScanner() hookctx.QuickScanner { return e.QuickScannerObserved(nil) }

// QuickScannerObserved is QuickScanner that also hands every completed
// scan's full result to observe (the daemon records the CI rule hits and
// the diff observations the seam's verdict does not carry; lane
// SEC-GATEFIX milestone 2i). observe runs after the scan, before the
// answer returns; nil observes nothing.
func (e *Engine) QuickScannerObserved(observe func(root string, r Result)) hookctx.QuickScanner {
	return func(ctx context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
		if !seamScannable(req.Form) {
			return hookctx.QuickScanResult{Verdict: hookctx.QuickScanUnknown}, nil
		}
		r := e.Scan(ctx, Request{
			Root: req.ProjectRoot,
			Form: Form{
				Push: req.Form.Push, All: req.Form.All, Amend: req.Form.Amend,
				Pathspecs:    append([]string(nil), req.Form.Pathspecs...),
				PushOperands: append([]string(nil), req.Form.PushOperands...),
				PushOpaque:   req.Form.PushOpaque,
			},
			DirtySeen: req.DirtySeen,
		})
		if observe != nil {
			observe(req.ProjectRoot, r)
		}
		out := hookctx.QuickScanResult{Verdict: SeamVerdict(r.Verdict), DirtyCovered: r.CoveredDirty}
		for _, f := range r.Findings {
			out.Findings = append(out.Findings, SecurityHit(f))
		}
		return out, nil
	}
}

// SecurityHit maps a quick-scan finding onto the contract's hit (a secret
// finding; never the matched value). A hit in a fixture or test-data path
// is low severity: reported, never blocking (S-721 asks there).
func SecurityHit(f Finding) policy.SecurityHit {
	conf := policy.FindingConfidenceLow
	if f.Confidence == secdetect.ConfidenceHigh {
		conf = policy.FindingConfidenceHigh
	}
	sev := policy.FindingSeverityHigh
	if f.Fixture {
		sev = policy.FindingSeverityLow
	}
	p := f.Path
	if len(p) > policy.SecurityHitPathMax {
		p = p[:policy.SecurityHitPathMax]
	}
	return policy.SecurityHit{
		Category: policy.FindingSecret, Severity: sev, Confidence: conf,
		Baseline: policy.FindingBaselineNew, RuleID: "secret." + f.Type, Path: p, Line: f.Line,
	}
}

// SeamVerdict maps a verdict onto the seam's vocabulary.
func SeamVerdict(v Verdict) hookctx.QuickScanVerdict {
	switch v {
	case VerdictClean:
		return hookctx.QuickScanClean
	case VerdictBlocking:
		return hookctx.QuickScanBlocking
	default:
		return hookctx.QuickScanUnknown
	}
}

// seamScannable reports a form the quick scan reads exactly: a plain commit
// or a push, in the project root itself.
func seamScannable(f hookctx.CommitForm) bool {
	if f.Dir != "" || f.FlagOnly {
		return false
	}
	switch {
	case f.Form == policy.GitWriteCommit && !f.Push:
		return true
	case f.Form == "" && f.Push:
		return true
	}
	return false
}
