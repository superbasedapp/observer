package sandboxcred

// sweep.go closes tracker F-055: a run's injection record
// (sandbox-cred/runs/<run>.json) and its kept fresh session ids
// (sandbox-cred/fresh/<run>.json) were removed only by the run's own host
// helper at its clean end. A helper killed before a daemon restart, or a
// run ended in a way that skipped that end, left them for good, and a
// later reader could take a stale record as a new run's. The daemon's
// relay sweep (at start and on every tick) now asks SweepRecord about
// each file, and removes it only when no rule keeps it. A run the
// re-adoption dead-run hold still holds is kept until the re-adoption
// table decides it, through that same hold (never a second one).

// SweepFacts are what the sweep knows about one run's credential file.
// HeldByDeadRunHold is asked only when no earlier row kept the file (the
// hold may log its own decision), so it is a func; nil reads false.
type SweepFacts struct {
	// Young: the file was written within the sweep's grace, so its run may
	// still be starting (its helper writes the file before its lock and
	// relay record are visible to the sweep).
	Young bool
	// HelperLive: the run's host helper holds its liveness lock.
	HelperLive bool
	// RelayRecord: the run's relay record exists: the run is live, offered
	// for re-adoption, or held by the dead-run hold until the re-adoption
	// table decides it.
	RelayRecord bool
	// HostedRecord: a hosted run's teardown record exists, so a hosted
	// re-adoption may still read the injection record.
	HostedRecord bool
	// HeldByDeadRunHold asks the relay's dead-run hold about the run.
	HeldByDeadRunHold func() bool
}

// SweepRow names the row that decided one file.
type SweepRow string

// The sweep's rows. Every row but SweepRowDead keeps the file.
const (
	SweepRowYoung        SweepRow = "young"
	SweepRowHelperLive   SweepRow = "helper-live"
	SweepRowRelayRecord  SweepRow = "relay-record"
	SweepRowHostedRecord SweepRow = "hosted-record"
	SweepRowDeadRunHold  SweepRow = "dead-run-hold"
	SweepRowDead         SweepRow = "dead"
)

// sweepRules are walked top-down; the first that matches keeps the file.
// The dead-run hold is last, so it is asked only about a file every other
// row would let go.
var sweepRules = []struct {
	row   SweepRow
	match func(SweepFacts) bool
}{
	{SweepRowYoung, func(f SweepFacts) bool { return f.Young }},
	{SweepRowHelperLive, func(f SweepFacts) bool { return f.HelperLive }},
	{SweepRowRelayRecord, func(f SweepFacts) bool { return f.RelayRecord }},
	{SweepRowHostedRecord, func(f SweepFacts) bool { return f.HostedRecord }},
	{SweepRowDeadRunHold, func(f SweepFacts) bool { return f.HeldByDeadRunHold != nil && f.HeldByDeadRunHold() }},
}

// SweepRecord decides one run's credential file: remove reports whether
// the sweep removes it, and row names the rule that decided.
func SweepRecord(f SweepFacts) (remove bool, row SweepRow) {
	for _, r := range sweepRules {
		if r.match(f) {
			return false, r.row
		}
	}
	return true, SweepRowDead
}
