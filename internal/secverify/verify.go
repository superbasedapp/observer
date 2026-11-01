package secverify

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// Verdict is the check's outcome.
type Verdict string

// The closed verdict vocabulary.
const (
	VerdictPass    Verdict = "pass"
	VerdictFail    Verdict = "fail"
	VerdictUnknown Verdict = "unknown"
)

// The exit codes, one per verdict. 3 is taken by the component gate
// (componentstate.RefusalExitCode): `observer security verify` on a binary
// whose security module is not active refuses before it runs.
const (
	ExitPass    = 0
	ExitFail    = 1
	ExitUnknown = 2
)

// ExitCode returns the process exit code for a verdict; anything but pass
// and fail is unknown (fail closed).
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictPass:
		return ExitPass
	case VerdictFail:
		return ExitFail
	}
	return ExitUnknown
}

// Request is one verify run's input, read by the caller and passed in as
// bytes: the package does no I/O.
type Request struct {
	Policy Policy
	// Base and Head are the commits compared, recorded in the report.
	Base, Head string
	// NameStatus and Patch are the outputs of `git diff --name-status -z
	// --no-renames` and `git diff -U0 --no-renames` over base...head.
	NameStatus, Patch []byte
	// Truncated is true when either output hit the reader's byte cap.
	Truncated bool
	// ReadErr is a failure reading the diff; the verdict is then unknown.
	ReadErr error
	// ReadHead, when set, reads one changed file at Head (Input.ReadHead).
	ReadHead func(path string) (content []byte, over bool, err error)
	// Dependencies is the verified install index for the install_index
	// detector; nil when the caller supplied none.
	Dependencies DependencyCheck
	// Provenance is the AI change record step's input (provenance.go); nil
	// when the caller named no keys file, and the report says so.
	Provenance *ProvenanceInput
}

// Report is one verify run's outcome.
type Report struct {
	Verdict Verdict
	// Rule names the verdict table row that decided, Reason its sentence.
	Rule, Reason string
	Base, Head   string
	Policy       Policy
	Files        int
	Findings     []Finding
	Coverage     []Coverage
	// Error is set when the diff could not be read or parsed; it holds the
	// error text with any repository path already quoted.
	Error string
	// Provenance is the change record step's outcome (Checked false when
	// it did not run).
	Provenance ProvenanceReport
}

// facts are what the verdict table reads.
type facts struct {
	err             bool
	truncated       bool
	requiredMissing []string
	denies          int
	mode            Mode
	// unknownProvenance counts the commits with no verified change record
	// under a provenance floor of "fail".
	unknownProvenance int
	// failedProvenance counts the commits whose change record is present
	// and fails verification, under any floor (decision log P-059).
	failedProvenance int
}

// verdictRule is one row of the verdict table.
type verdictRule struct {
	name    string
	when    func(f facts) bool
	verdict Verdict
	reason  func(f facts) string
}

// verdictTable is walked top-down; the first row that matches decides. An
// error and an incomplete read come before any finding, so a run that could
// not see the whole change is never a pass, and a run that saw a deny is a
// fail only when it also saw everything it was required to see (a partial
// read with a deny is unknown, which exits non-zero all the same).
var verdictTable = []verdictRule{
	{
		name: "read_error", verdict: VerdictUnknown,
		when:   func(f facts) bool { return f.err },
		reason: func(facts) string { return "the change could not be read, so it was not checked" },
	},
	{
		name: "diff_truncated", verdict: VerdictUnknown,
		when:   func(f facts) bool { return f.truncated },
		reason: func(facts) string { return "the change is larger than verify reads, so it was checked only in part" },
	},
	{
		name: "required_incomplete", verdict: VerdictUnknown,
		when: func(f facts) bool { return len(f.requiredMissing) > 0 },
		reason: func(f facts) string {
			return fmt.Sprintf("%d required detector(s) did not finish: %s", len(f.requiredMissing), joinIDs(f.requiredMissing))
		},
	},
	{
		// A forged, revoked, expired or replayed change record (decision log
		// P-059): a failure whatever the provenance floor and the mode, so a
		// tampered record never passes as a review label.
		name: "provenance_failed", verdict: VerdictFail,
		when: func(f facts) bool { return f.failedProvenance > 0 },
		reason: func(f facts) string {
			return fmt.Sprintf("%d commit(s) carry an AI change record that fails verification", f.failedProvenance)
		},
	},
	{
		name: "deny_finding", verdict: VerdictFail,
		when: func(f facts) bool { return f.mode == ModeEnforce && f.denies > 0 },
		reason: func(f facts) string {
			return fmt.Sprintf("%d finding(s) the policy denies", f.denies)
		},
	},
	{
		name: "provenance_floor", verdict: VerdictFail,
		when: func(f facts) bool { return f.mode == ModeEnforce && f.unknownProvenance > 0 },
		reason: func(f facts) string {
			return fmt.Sprintf("%d commit(s) with no verified AI change record, and the policy's provenance floor is fail", f.unknownProvenance)
		},
	},
	{
		name: "clean", verdict: VerdictPass,
		when:   func(facts) bool { return true },
		reason: func(facts) string { return "every required detector finished and nothing the policy denies was found" },
	},
}

// Verify judges one change. detectors nil means the built-in table.
func Verify(ctx context.Context, req Request, detectors []Detector) Report {
	if detectors == nil {
		detectors = Detectors()
	}
	rep := Report{Base: req.Base, Head: req.Head, Policy: req.Policy}
	var ff facts
	ff.mode = req.Policy.Mode
	ff.truncated = req.Truncated

	var files []ChangedFile
	err := req.ReadErr
	if err == nil {
		err = req.Policy.Validate()
	}
	if err == nil {
		files, err = ParseDiff(req.NameStatus, req.Patch, req.Policy.limits())
	}
	if err != nil {
		ff.err = true
		rep.Error = clipSafe(err.Error(), 400)
	}
	rep.Files = len(files)

	required := map[string]bool{}
	for _, id := range req.Policy.Require {
		required[id] = true
	}
	for _, d := range detectors {
		var res Result
		switch {
		case req.Policy.Detectors[d.ID] == ActionOff:
			res.Coverage = Coverage{Detector: d.ID, Status: CoverageOff, Note: "switched off by the policy"}
		case d.Run == nil:
			res.Coverage = Coverage{Detector: d.ID, Status: CoverageNotInBuild, Note: "not in this build (security plan phase " + d.Phase + ")"}
		case ff.err:
			res.Coverage = Coverage{Detector: d.ID, Status: CoverageFailed, Note: "not run: the change could not be read"}
		default:
			res = runDetector(ctx, d, Input{Files: files, ReadHead: req.ReadHead, Dependencies: req.Dependencies})
		}
		if required[d.ID] && res.Coverage.Status != CoverageComplete {
			ff.requiredMissing = append(ff.requiredMissing, d.ID)
		}
		for _, f := range res.Findings {
			f = applyPolicy(req.Policy, f)
			if f.Action == ActionOff {
				continue
			}
			if f.Action == ActionDeny {
				ff.denies++
			}
			rep.Findings = append(rep.Findings, f)
		}
		rep.Coverage = append(rep.Coverage, res.Coverage)
	}
	sortFindings(rep.Findings)

	if req.Provenance != nil {
		rep.Provenance = checkProvenance(req.Provenance, req.Policy.Provenance)
		ff.failedProvenance = rep.Provenance.Failed
		if req.Policy.Provenance == secchange.FloorFail {
			ff.unknownProvenance = rep.Provenance.Unknown
		}
	}

	for _, row := range verdictTable {
		if row.when(ff) {
			rep.Verdict, rep.Rule, rep.Reason = row.verdict, row.name, row.reason(ff)
			break
		}
	}
	return rep
}

// runDetector runs one detector and turns a panic into a failed coverage,
// never a pass.
func runDetector(ctx context.Context, d Detector, in Input) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{Coverage: Coverage{Detector: d.ID, Status: CoverageFailed, Note: "the detector stopped with an internal error"}}
		}
	}()
	res = d.Run(ctx, in)
	res.Coverage.Detector = d.ID
	if res.Coverage.Status == "" {
		res.Coverage.Status = CoverageFailed
		res.Coverage.Note = "the detector reported no coverage"
	}
	return res
}

// applyPolicy sets a finding's Action: the policy's override for its
// detector, else the detector's default; then a deny on a fixture path is
// lowered to a flag for secrets.
func applyPolicy(p Policy, f Finding) Finding {
	f.Action = f.DefaultAction
	if a, ok := p.Detectors[f.Detector]; ok {
		f.Action = a
	}
	if f.Action == ActionDeny && f.Category == CategorySecret && p.isFixture(f.Path) {
		f.Action, f.Lowered = ActionFlag, "fixture_path"
	}
	return f
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += clipSafe(id, 32)
	}
	return out
}
