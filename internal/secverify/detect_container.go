package secverify

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secdockerfile"
)

// The container_config detector (OS and CI vulnerability scanning plan
// section 4.2, phase OS-1): the native Dockerfile and base-image rules
// (internal/secdockerfile, S-750 to S-755) over every added or modified
// Dockerfile, read whole as it is at the head commit through
// Input.ReadHead, like the ci_workflow detector reads a workflow.

// containerNow is the clock S-752's end-of-life judgement reads; a test
// sets it.
var containerNow = time.Now

// containerRuleID maps a secdockerfile rule onto its verify rule id.
func containerRuleID(id string) string { return "container/" + strings.ToLower(id) }

// containerSeverities maps a rule hit's severity onto verify's scale.
var containerSeverities = map[secdockerfile.Severity]Severity{
	secdockerfile.SeverityHigh:   SeverityHigh,
	secdockerfile.SeverityMedium: SeverityMedium,
	secdockerfile.SeverityLow:    SeverityLow,
}

// detectContainerConfig checks every added or modified Dockerfile whole. A
// Dockerfile it cannot read whole (no reader, a read error, binary, a file
// over secdockerfile.MaxDockerfileBytes, a RUN script past the shell
// classifier's cap) makes the coverage partial: what is past the cap is
// never "clean". A FROM line whose image names a build argument with no
// literal default is not checked and is said in the note; it is not a
// partial read. Every rule is flag only: a base image or an unpinned
// install is for a reviewer to judge, never a deny.
func detectContainerConfig(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "container_config", Status: CoverageComplete}
	var out []Finding
	partial := func(note string) {
		if cov.Status == CoverageComplete {
			cov.Status = CoveragePartial
			cov.Note = note
		}
	}
	skip := func(reason string) {
		cov.Skipped++
		cov.SkipReason = reason
		partial("a changed Dockerfile could not be read whole and was not checked")
	}
	unchecked := 0
	now := containerNow()
	for _, f := range in.Files {
		if ctx.Err() != nil {
			cov.Status, cov.Note = CoverageFailed, "cancelled before every file was read"
			break
		}
		if f.Status == StatusDeleted || !secdockerfile.IsDockerfilePath(f.Path) {
			continue
		}
		if f.Binary {
			skip("binary files are not read")
			continue
		}
		content, ok := containerContent(in, f)
		if !ok {
			skip("the Dockerfile could not be read at the head commit")
			continue
		}
		rep := secdockerfile.CheckAt(content, now)
		if rep.Status == secdockerfile.StatusOverCap {
			skip("the Dockerfile is over the size cap")
			continue
		}
		cov.Files++
		unchecked += rep.UncheckedFrom
		if rep.TruncatedRuns > 0 {
			partial("a RUN script was longer than the shell classifier reads and was checked only in part")
		}
		occ := map[string]int{}
		for _, h := range rep.Findings {
			rule := containerRuleID(h.RuleID)
			n := occ[rule]
			occ[rule]++
			sev, ok := containerSeverities[h.Severity]
			if !ok {
				sev = SeverityMedium
			}
			msg := h.RuleID + ": " + h.Message
			if h.Detail != "" {
				msg += " (" + h.Detail + ")"
			}
			out = append(out, Finding{
				RuleID: rule, Detector: "container_config", Category: CategoryIaC,
				Severity: sev, Confidence: ConfidenceHigh, Path: f.Path, Line: h.Line,
				Message: msg, Fingerprint: fingerprint(rule, f.Path, n), DefaultAction: ActionFlag,
			})
		}
	}
	if unchecked > 0 && cov.Status != CoverageFailed {
		sentence := uncheckedFromNote(unchecked)
		if cov.Note == "" {
			cov.Note = sentence
		} else {
			cov.Note += "; " + sentence
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// uncheckedFromNote is the fixed sentence for FROM lines a build argument
// decides.
func uncheckedFromNote(n int) string {
	if n == 1 {
		return "1 FROM line names a build argument and was not checked"
	}
	return strconv.Itoa(n) + " FROM lines name a build argument and were not checked"
}

// containerContent returns the Dockerfile as it is at the head commit:
// through the reader, or, for a new file whose added lines are complete,
// those lines (they are the whole file).
func containerContent(in Input, f ChangedFile) ([]byte, bool) {
	if in.ReadHead != nil {
		b, over, err := in.ReadHead(f.Path)
		if err != nil {
			return nil, false
		}
		if over {
			// One byte past the cap: CheckAt reports it over_cap.
			return make([]byte, secdockerfile.MaxDockerfileBytes+1), true
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
