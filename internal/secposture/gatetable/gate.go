package gatetable

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// GateColumn is one column of the section 4.8 decision table at the
// agent's git_commit and git_push sinks.
type GateColumn string

// The GateColumn values (section 4.8; the second column is revision 2.5,
// D-791 Q27 "Mixed").
const (
	// GateIndividualObserve: an individual node in observe mode on a
	// channel that can ask with a terminal attached (the default).
	GateIndividualObserve GateColumn = "individual_observe"
	// GateIndividualNoAsk: an individual node in observe mode on a host
	// that cannot ask, or in a headless run.
	GateIndividualNoAsk GateColumn = "individual_no_ask"
	// GateIndividualEnforce: an individual node in enforce mode.
	GateIndividualEnforce GateColumn = "individual_enforce"
	// GateManaged: a managed node without the org commit-gate floor.
	GateManaged GateColumn = "managed"
	// GateManagedFloor: a managed node holding the org security.scanning
	// floor require.commit_gate = "quick_scan".
	GateManagedFloor GateColumn = "managed_floor"
)

// GateColumns returns the columns in table order.
func GateColumns() []GateColumn {
	return []GateColumn{GateIndividualObserve, GateIndividualNoAsk, GateIndividualEnforce, GateManaged, GateManagedFloor}
}

// GateOutcome is one decision table cell.
type GateOutcome string

// The GateOutcome values.
const (
	// GateAllow lets the commit proceed.
	GateAllow GateOutcome = "allow"
	// GateAsk asks before the commit (a native ask; on a channel that
	// cannot ask the caller uses the GateIndividualNoAsk column instead).
	GateAsk GateOutcome = "ask"
	// GateDeny denies, naming `observer guard approve`.
	GateDeny GateOutcome = "deny"
	// GateQuickScanAsk runs the quick scan for up to IndividualQuickScan:
	// clean allows with no prompt, anything else asks (D-764 Q21).
	GateQuickScanAsk GateOutcome = "quick_scan_then_ask"
	// GateQuickScanDeny runs the quick scan for up to IndividualQuickScan:
	// clean allows with no prompt, anything else denies (D-791 Q27).
	GateQuickScanDeny GateOutcome = "quick_scan_then_deny"
	// GateWaitScanDeny waits for the quick scan within the floor's budget:
	// clean allows, a blocking finding or unknown denies (D-041).
	GateWaitScanDeny GateOutcome = "wait_quick_scan_then_deny"
	// GateRefuseMissing refuses: the floor names the missing component
	// (D-753).
	GateRefuseMissing GateOutcome = "refuse_missing_component"
)

// IndividualQuickScan is the individual node's quick-scan budget (D-764
// Q21).
const IndividualQuickScan = 2 * time.Second

// gateTable is the section 4.8 decision table, one row per state and one
// cell per column in GateColumns order.
var gateTable = map[policy.SecurityPosture][5]GateOutcome{
	policy.SecurityPostureAbsent:   {GateAllow, GateAllow, GateAllow, GateAllow, GateRefuseMissing},
	policy.SecurityPostureClean:    {GateAllow, GateAllow, GateAllow, GateAllow, GateAllow},
	policy.SecurityPostureBlocking: {GateAsk, GateDeny, GateDeny, GateAsk, GateDeny},
	policy.SecurityPostureDirty:    {GateQuickScanAsk, GateQuickScanDeny, GateQuickScanAsk, GateAsk, GateWaitScanDeny},
	policy.SecurityPostureUnknown:  {GateAsk, GateDeny, GateAsk, GateAsk, GateDeny},
}

// Gate returns the decision table cell for a state and a column. A state
// or column outside the vocabulary reads as unknown in that column, and an
// unknown column as the strictest (the floor), never looser (PR14).
func Gate(state policy.SecurityPosture, col GateColumn) GateOutcome {
	row, ok := gateTable[state]
	if !ok {
		row = gateTable[policy.SecurityPostureUnknown]
	}
	for i, c := range GateColumns() {
		if c == col {
			return row[i]
		}
	}
	return row[len(row)-1]
}

// AfterQuickScan resolves a quick-scan cell once the scan answered: clean
// allows; anything else (blocking, unknown, no answer) asks or denies as
// the cell says. A cell that is not a quick-scan cell is returned as is.
func AfterQuickScan(o GateOutcome, v policy.QuickScanVerdict) GateOutcome {
	switch o {
	case GateQuickScanAsk:
		if v == policy.QuickScanClean {
			return GateAllow
		}
		return GateAsk
	case GateQuickScanDeny, GateWaitScanDeny:
		if v == policy.QuickScanClean {
			return GateAllow
		}
		return GateDeny
	}
	return o
}

// The launch trust floor values that raise the launch step (lane SEC-P4
// decision 9; the axis require.prelaunch_trust, warn being the guard
// mode's own step).
const (
	PrelaunchTrustAsk    = "ask"
	PrelaunchTrustRefuse = "refuse"
)

// FloorDecision maps a managed-floor cell onto the rule decision S-791 to
// S-794 take under the commit gate floor (lane SEC-P4 decision 9): allow
// matches nothing; an ask cell asks; every deny cell (deny, the quick scan
// waited for then deny, a refused missing component) denies. A quick-scan
// cell is resolved by AfterQuickScan first.
func FloorDecision(o GateOutcome) (policy.Decision, bool) {
	switch o {
	case GateAllow:
		return 0, false
	case GateAsk, GateQuickScanAsk:
		return policy.DecisionAsk, true
	}
	return policy.DecisionDeny, true
}
