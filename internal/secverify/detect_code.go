package secverify

import (
	"context"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
)

// The two security Phase C detectors (lane SEC-C2): the native GitHub
// Actions workflow rules (internal/secciwf, S-771 to S-778) and the
// test-tampering and disabled-verification observations
// (internal/secdiffobs, S-761 and S-767 to S-769). Both read only what the
// cmd layer handed in: the parsed diff and, for a workflow, the file at the
// head commit through Input.ReadHead.

// ciWorkflowRuleID maps a secciwf rule onto its verify rule id; the guard
// id rides in the message's rule table, never as a finding rule id.
func ciWorkflowRuleID(id string) string { return "ci/" + strings.ToLower(id) }

// detectCIWorkflow checks every added or modified workflow file whole, as
// it is at the head commit. A workflow it cannot read whole (no reader, a
// read error, a file over secciwf.MaxWorkflowBytes, YAML that does not
// parse) is skipped and makes the coverage partial: a dangerous job past
// the cap is never "clean".
func detectCIWorkflow(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "ci_workflow", Status: CoverageComplete}
	var out []Finding
	skip := func(reason string) {
		cov.Skipped++
		cov.SkipReason = reason
		if cov.Status == CoverageComplete {
			cov.Status = CoveragePartial
			cov.Note = "a changed workflow could not be read whole and was not checked"
		}
	}
	for _, f := range in.Files {
		if ctx.Err() != nil {
			cov.Status, cov.Note = CoverageFailed, "cancelled before every file was read"
			break
		}
		if f.Status == StatusDeleted || !secciwf.IsWorkflowPath(f.Path) {
			continue
		}
		if f.Binary {
			skip("binary files are not read")
			continue
		}
		content, ok := workflowContent(in, f)
		if !ok {
			skip("the workflow could not be read at the head commit")
			continue
		}
		rep := secciwf.Check(content)
		switch rep.Status {
		case secciwf.StatusOverCap:
			skip("the workflow is over the size cap")
			continue
		case secciwf.StatusUnparsed:
			skip("the workflow does not parse as YAML")
			continue
		}
		cov.Files++
		occ := map[string]int{}
		for _, h := range rep.Findings {
			rule := ciWorkflowRuleID(h.RuleID)
			n := occ[rule]
			occ[rule]++
			sev, act := SeverityHigh, ActionDeny
			switch {
			case h.FlagOnly:
				sev, act = SeverityLow, ActionFlag
			case h.Severity == secciwf.SeverityMedium:
				sev, act = SeverityMedium, ActionFlag
			}
			out = append(out, Finding{
				RuleID: rule, Detector: "ci_workflow", Category: CategoryCIConfig,
				Severity: sev, Confidence: ConfidenceHigh, Path: f.Path, Line: h.Line,
				Message: h.RuleID + ": " + h.Message, Fingerprint: fingerprint(rule, f.Path, n), DefaultAction: act,
			})
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// workflowContent returns the workflow as it is at the head commit: through
// the reader, or, for a new file whose added lines are complete, those
// lines (they are the whole file).
func workflowContent(in Input, f ChangedFile) ([]byte, bool) {
	if in.ReadHead != nil {
		b, over, err := in.ReadHead(f.Path)
		if err != nil {
			return nil, false
		}
		if over {
			// One byte past the cap: Check reports it over_cap.
			return make([]byte, secciwf.MaxWorkflowBytes+1), true
		}
		return b, true
	}
	if f.Status != StatusAdded || f.Partial {
		return nil, false
	}
	var b strings.Builder
	for _, l := range f.Added {
		b.WriteString(l.Text)
		b.WriteByte('\n')
	}
	return []byte(b.String()), true
}

// detectTestTampering runs the diff observations over the change. They
// are flag only: a weakened test or a switched-off verification is for a
// reviewer to judge, never a deny.
func detectTestTampering(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "test_tampering", Status: CoverageComplete}
	diffs := make([]secdiffobs.FileDiff, 0, len(in.Files))
	for _, f := range in.Files {
		if ctx.Err() != nil {
			return Result{Coverage: Coverage{Status: CoverageFailed, Note: "cancelled before every file was read"}}
		}
		if f.Binary {
			cov.Skipped++
			cov.SkipReason = "binary files are not read"
			continue
		}
		cov.Files++
		if f.Partial && cov.Status == CoverageComplete {
			cov.Status = CoveragePartial
			cov.Note = "a file's changed text was over the cap and was read only in part"
		}
		d := secdiffobs.FileDiff{Path: f.Path, Deleted: f.Status == StatusDeleted}
		for _, l := range f.Added {
			d.Added = append(d.Added, secdiffobs.Line{N: l.N, Text: l.Text})
		}
		for _, l := range f.Removed {
			d.Removed = append(d.Removed, secdiffobs.Line{N: l.N, Text: l.Text})
		}
		diffs = append(diffs, d)
	}
	var out []Finding
	occ := map[string]int{}
	for _, o := range secdiffobs.Observe(diffs) {
		rule := "code/" + strings.ToLower(o.RuleID)
		key := rule + "\x00" + o.Path
		n := occ[key]
		occ[key]++
		out = append(out, Finding{
			RuleID: rule, Detector: "test_tampering", Category: CategoryTestTampering,
			Severity: SeverityMedium, Confidence: ConfidenceMedium, Path: o.Path, Line: o.Line,
			Message: o.RuleID + ": " + o.Message, Fingerprint: fingerprint(rule, o.Path, n), DefaultAction: ActionFlag,
		})
	}
	return Result{Findings: out, Coverage: cov}
}
