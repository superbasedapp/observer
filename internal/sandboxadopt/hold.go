package sandboxadopt

// hold.go closes tracker F-045: every sweep that prunes the records of dead
// host helpers (the relay's start prune and its own sweep, the oci and VM
// start sweeps, the worktree and Apple container sweeps) used to remove a
// re-adoptable run's record and lock file before the oci reaper's
// re-adoption step had read them. The step then saw a run with no lock and
// no offer and decided nothing, and the orphan rule removed the container:
// no Decide row ever fired. HoldDeadRecord is the one rule those prunes now
// ask first: a run the re-adoption step will decide keeps its record until
// that step has decided it (offered, held, or reaped as before).

// HoldFacts are what a prune knows about one run whose helper is gone.
type HoldFacts struct {
	// Active: the re-adoption component is selected on this node.
	Active bool
	// Kept: the run's kept record and plan were read (the run is one the
	// re-adoption step decides).
	Kept bool
	// CLIRun: a sandboxed CLI launch owns the run; it is reaped as before
	// and its stored row must be ended at once (process_gone).
	CLIRun bool
}

// RowNotKept is the hold table's row for a run with no kept record and plan
// (the decision table has no such row: the sweep never sees that run).
const RowNotKept = "not-kept"

// holdRules are walked top-down; the first that matches lets the prune
// remove the record, and its decision says why, with the same row ids and
// codes as the decision table, so a run a prune ends can be logged and
// logged like one the sweep ends (lane FU10 fix round 1, audit FU10-A4).
// None matching holds the record for the re-adoption step. not-kept comes
// first: it needs no other fact, so a caller that reads the settings only
// for a kept run still gets the true row (fix round 2, FU10-R2).
var holdRules = []struct {
	match func(HoldFacts) bool
	d     Decision
}{
	{func(f HoldFacts) bool { return !f.Kept }, reapOn(RowNotKept, CodePlanMissing,
		"the run's plan was not kept when it started, so it ends as before")},
	{func(f HoldFacts) bool { return !f.Active }, reapOn("component", CodeComponentInactive,
		"re-adoption is off on this node (terminals.sandbox.oci.readopt), so the run ends as before")},
	{func(f HoldFacts) bool { return f.CLIRun }, reapOn("cli-run", CodeCLIRun,
		"a sandboxed CLI launch owns its terminal; it ends as before and its tool's own resume applies")},
}

// reapOn is a let-go decision with a fixed line.
func reapOn(row string, code Code, line string) Decision {
	return Decision{Action: ActionReap, Code: code, Row: row, Reason: line, Summary: line}
}

// HoldDeadRecord decides one dead helper's record: hold reports whether the
// prune leaves it for the re-adoption step; otherwise d is the reap
// decision that lets the prune go on (its row, code and fact-free line).
func HoldDeadRecord(f HoldFacts) (hold bool, d Decision) {
	for _, r := range holdRules {
		if r.match(f) {
			return false, r.d
		}
	}
	return true, Decision{}
}
