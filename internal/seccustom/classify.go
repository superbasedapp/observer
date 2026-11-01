package seccustom

import (
	"bytes"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// RunFacts are what one finished run showed, resolved at the boundary from
// the runner's record and the adapter's answer.
type RunFacts struct {
	Runner extrun.Outcome
	Refuse extrun.RefuseReason
	Exit   extrun.ExitMeaning
	// NoSARIF: the SARIF is missing or does not decode.
	NoSARIF bool
	// Findings is how many findings the strict adapter kept; Refused how
	// many results it refused; Truncated whether a cap cut the results.
	Findings  int
	Refused   int
	Truncated bool
	// UnknownMarker: a manifest unknown_stderr pattern appeared.
	UnknownMarker bool
	// SelfTestCurrent: the self-test passed for the current digests and
	// companion versions.
	SelfTestCurrent bool
	// ToolchainSkew: the executable is a Go program built with an older Go
	// release than its go companion (CheckToolchainSkew).
	ToolchainSkew bool
}

// Verdict is a run's coverage outcome and its closed reason code.
type Verdict struct {
	Outcome secscan.Outcome
	Reason  string
}

// verdictRow is one row of the run outcome table.
type verdictRow struct {
	when func(RunFacts) bool
	v    Verdict
}

// verdictTable is walked top-down; the first row that holds is the verdict.
// "Scanned" is not "clean" (revision 2.4 [JSP-12]): a run is clean only
// when it exited with a result status, wrote a SARIF that decoded, reported
// nothing, refused nothing, showed no unknown-marking stderr pattern, and
// its self-test passed for its current digests and versions. gosec with no
// go companion exits 0 with an empty SARIF: that row is unknown.
var verdictTable = []verdictRow{
	{func(f RunFacts) bool {
		return f.Runner == extrun.OutcomeRefused && f.Refuse == extrun.RefuseDigestMismatch
	}, Verdict{secscan.OutcomeFailed, "driver_unverified"}},
	{func(f RunFacts) bool { return f.Runner == extrun.OutcomeRefused }, Verdict{secscan.OutcomeFailed, "refused"}},
	{func(f RunFacts) bool { return f.Runner == extrun.OutcomeStartFailed }, Verdict{secscan.OutcomeFailed, "start_failed"}},
	{func(f RunFacts) bool { return f.Runner == extrun.OutcomeSignaled }, Verdict{secscan.OutcomeFailed, "engine_crashed"}},
	{func(f RunFacts) bool { return f.Runner == extrun.OutcomeCanceled }, Verdict{secscan.OutcomeUnknown, "canceled"}},
	{func(f RunFacts) bool {
		return f.Runner == extrun.OutcomeTimeout || f.Runner == extrun.OutcomeOutputCap || f.Runner == extrun.OutcomeChildrenCap
	}, Verdict{secscan.OutcomeUnknown, "budget_exceeded"}},
	{func(f RunFacts) bool { return f.Exit == extrun.ExitFailure }, Verdict{secscan.OutcomeFailed, "engine_failure"}},
	{func(f RunFacts) bool { return f.Exit == extrun.ExitNoInput }, Verdict{secscan.OutcomeNotScanned, "nothing_to_scan"}},
	{func(f RunFacts) bool { return f.NoSARIF }, Verdict{secscan.OutcomeFailed, "no_sarif"}},
	// Findings are real even from an incomplete run, but such a run says
	// so (and closes nothing, CanCloseMissing).
	{func(f RunFacts) bool {
		return f.Findings > 0 && (f.UnknownMarker || f.Refused > 0 || f.Truncated || !f.SelfTestCurrent || f.ToolchainSkew)
	}, Verdict{secscan.OutcomeFindings, "incomplete"}},
	{func(f RunFacts) bool { return f.Findings > 0 }, Verdict{secscan.OutcomeFindings, ""}},
	{func(f RunFacts) bool { return f.Exit == extrun.ExitFindings }, Verdict{secscan.OutcomeUnknown, "exit_says_findings"}},
	{func(f RunFacts) bool { return f.UnknownMarker }, Verdict{secscan.OutcomeUnknown, "unknown_marker"}},
	{func(f RunFacts) bool { return f.ToolchainSkew }, Verdict{secscan.OutcomeUnknown, "toolchain_skew"}},
	{func(f RunFacts) bool { return f.Refused > 0 || f.Truncated }, Verdict{secscan.OutcomeUnknown, "results_refused"}},
	{func(f RunFacts) bool { return !f.SelfTestCurrent }, Verdict{secscan.OutcomeUnknown, "no_self_test"}},
	{func(RunFacts) bool { return true }, Verdict{secscan.OutcomeClean, ""}},
}

// Classify names a finished run's coverage outcome.
func Classify(f RunFacts) Verdict {
	for _, r := range verdictTable {
		if r.when(f) {
			return r.v
		}
	}
	return Verdict{secscan.OutcomeUnknown, "unclassified"}
}

// StderrMarksUnknown reports whether stderr carries one of the manifest's
// unknown_stderr patterns (literal substrings, never regular expressions).
func StderrMarksUnknown(m Manifest, stderr []byte) bool {
	for _, p := range m.UnknownStderr {
		if p != "" && bytes.Contains(stderr, []byte(p)) {
			return true
		}
	}
	return false
}

// CanCloseMissing reports whether a run is complete enough for this driver
// to close its own earlier findings that the run did not report again: a
// clean or findings verdict, a current self-test, no unknown marker and
// nothing refused or cut. A custom driver never closes another driver's
// findings (the caller filters by Record.Driver).
func CanCloseMissing(f RunFacts, v Verdict) bool {
	if v.Outcome != secscan.OutcomeClean && v.Outcome != secscan.OutcomeFindings {
		return false
	}
	return f.SelfTestCurrent && !f.UnknownMarker && !f.ToolchainSkew && f.Refused == 0 && !f.Truncated
}
