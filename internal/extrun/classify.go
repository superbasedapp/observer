package extrun

// classifyRule is one row of the outcome table: the first row whose when
// returns true names the outcome.
type classifyRule struct {
	when    func(ExecFacts) bool
	outcome Outcome
}

// classifyTable is walked top-down. A kill the runner caused outranks the
// exit status it produced (a group kill shows as a signal), and a start
// failure outranks everything.
var classifyTable = []classifyRule{
	{func(f ExecFacts) bool { return f.StartErr != "" }, OutcomeStartFailed},
	{func(f ExecFacts) bool { return f.KillReason == KillCanceled }, OutcomeCanceled},
	{func(f ExecFacts) bool { return f.KillReason == KillTimeout }, OutcomeTimeout},
	{func(f ExecFacts) bool { return f.KillReason == KillOutputCap }, OutcomeOutputCap},
	{func(f ExecFacts) bool { return f.KillReason == KillChildrenCap }, OutcomeChildrenCap},
	{func(f ExecFacts) bool { return f.Signaled }, OutcomeSignaled},
	{func(f ExecFacts) bool { return f.ExitCode == 0 }, OutcomeOK},
	{func(ExecFacts) bool { return true }, OutcomeExitNonZero},
}

// Classify names the outcome of an executed run.
func Classify(f ExecFacts) Outcome {
	for _, r := range classifyTable {
		if r.when(f) {
			return r.outcome
		}
	}
	return OutcomeExitNonZero
}
