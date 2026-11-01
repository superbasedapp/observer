package secposture

import (
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture/gatetable"
)

// gate.go re-exports the section 4.8 decision table, which lives in the
// pure package internal/secposture/gatetable since lane SEC-P4 (so the
// rule tables in internal/secrules, which import pure packages only, read
// its managed-floor column; one table, one owner).

// GateColumn is gatetable.GateColumn.
type GateColumn = gatetable.GateColumn

// GateOutcome is gatetable.GateOutcome.
type GateOutcome = gatetable.GateOutcome

// The GateColumn values.
const (
	GateIndividualObserve = gatetable.GateIndividualObserve
	GateIndividualNoAsk   = gatetable.GateIndividualNoAsk
	GateIndividualEnforce = gatetable.GateIndividualEnforce
	GateManaged           = gatetable.GateManaged
	GateManagedFloor      = gatetable.GateManagedFloor
)

// The GateOutcome values.
const (
	GateAllow         = gatetable.GateAllow
	GateAsk           = gatetable.GateAsk
	GateDeny          = gatetable.GateDeny
	GateQuickScanAsk  = gatetable.GateQuickScanAsk
	GateQuickScanDeny = gatetable.GateQuickScanDeny
	GateWaitScanDeny  = gatetable.GateWaitScanDeny
	GateRefuseMissing = gatetable.GateRefuseMissing
)

// IndividualQuickScan is gatetable.IndividualQuickScan.
const IndividualQuickScan = gatetable.IndividualQuickScan

// QuickScanBudgetsS are the quick-scan budgets above the built-in 2 s a
// posture file may carry (the [security.scanning] picker and the floor's
// vocabulary, lane LEFT-SEC).
var QuickScanBudgetsS = []int{5, 10, 30}

// MaxScanStalenessMin bounds File.MaxScanStalenessMin (a week, the floor's
// own bound).
const MaxScanStalenessMin = 7 * 24 * 60

// QuickScanBudgetOf is the quick-scan budget a current, verified file
// carries; IndividualQuickScan when it carries none or there is no file.
func QuickScanBudgetOf(f *File) time.Duration {
	if f != nil && slices.Contains(QuickScanBudgetsS, f.QuickScanBudgetS) {
		return time.Duration(f.QuickScanBudgetS) * time.Second
	}
	return IndividualQuickScan
}

// The launch trust floor values (gatetable).
const (
	PrelaunchTrustAsk    = gatetable.PrelaunchTrustAsk
	PrelaunchTrustRefuse = gatetable.PrelaunchTrustRefuse
)

// GateColumns is gatetable.GateColumns.
func GateColumns() []GateColumn { return gatetable.GateColumns() }

// Gate is gatetable.Gate.
func Gate(state policy.SecurityPosture, col GateColumn) GateOutcome {
	return gatetable.Gate(state, col)
}

// AfterQuickScan is gatetable.AfterQuickScan.
func AfterQuickScan(o GateOutcome, v policy.QuickScanVerdict) GateOutcome {
	return gatetable.AfterQuickScan(o, v)
}

// FloorDecision is gatetable.FloorDecision.
func FloorDecision(o GateOutcome) (policy.Decision, bool) { return gatetable.FloorDecision(o) }

// QuickScanHostMarginMax caps the margin ClampQuickScanBudget keeps on
// each side of the quick scan inside a host's hook timeout.
const QuickScanHostMarginMax = 2 * time.Second

// ClampQuickScanBudget fits the commit gate's quick-scan budget inside the
// vendor's own hook timeout (lane LEFT2-SEC item R-039): a host that kills
// its hook first would turn a scan that is still running into the host's
// own failure policy instead of Observer's answer. The scan gets the host
// timeout less two margins (one for the scan's own wind-down, one for the
// gate's reply before the watchdog), each at most QuickScanHostMarginMax
// and a quarter of the timeout on a short one. clamped reports a budget
// that did not fit; a zero timeout (unknown) changes nothing.
func ClampQuickScanBudget(budget, hostTimeout time.Duration) (limit time.Duration, clamped bool) {
	return ClampQuickScanBudgetAfter(budget, hostTimeout, 0)
}

// ClampQuickScanBudgetAfter is ClampQuickScanBudget for a hook that already
// spent elapsed of the host's timeout before the scan starts (LEFT2 audit
// E4): the scan gets what is left less the two margins. With nothing left
// the limit is zero and clamped is true (the hook then answers the scan as
// unknown rather than start one the host would cut off).
func ClampQuickScanBudgetAfter(budget, hostTimeout, elapsed time.Duration) (limit time.Duration, clamped bool) {
	if hostTimeout <= 0 || budget <= 0 {
		return budget, false
	}
	margin := min(QuickScanHostMarginMax, hostTimeout/4)
	fit := hostTimeout - max(elapsed, 0) - 2*margin
	if budget > fit {
		return max(fit, 0), true
	}
	return budget, false
}

// EffectiveQuickScanBudget is the quick-scan budget a project's reading
// gives the commit gate: the signed per-project value of a current,
// verified posture file, else the built-in default. The hook and doctor
// both read it here, so doctor's clamp lines judge the budget the hook
// uses (LEFT2 audit E4).
func EffectiveQuickScanBudget(r Reading) time.Duration {
	if r.File == nil || r.State.Posture == policy.SecurityPostureUnknown {
		return IndividualQuickScan
	}
	return QuickScanBudgetOf(r.File)
}
