package scoring

// Test-only bridges for the external scoring_test package: its tests seed
// through internal/store, which imports scoring, so they cannot live in
// package scoring without an import cycle.
var (
	EvictedBetween = evictedBetween
	ContinuityFrom = continuityFrom
)

// Opts exposes the resolved options (defaults applied) to the external tests.
func (a *AutoScorer) Opts() *AutoOptions { return &a.opts }
