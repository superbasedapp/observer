package personalmig

// Stage is a personal_migrations ledger stage (cloud 0134).
type Stage string

// The ledger stages. StageNone is "no ledger row yet".
const (
	StageNone     Stage = ""
	StagePlanned  Stage = "planned"
	StageOrgReady Stage = "org_ready"
	StageRekeyed  Stage = "rekeyed"
	StageExported Stage = "exported"
	StageVerified Stage = "verified"
	StageSkipped  Stage = "skipped"
)

// KnownStages returns the stages a ledger row may hold, in lifecycle order
// (skipped last). The 0134 CHECK constraint lists exactly these.
func KnownStages() []Stage {
	return []Stage{StagePlanned, StageOrgReady, StageRekeyed, StageExported, StageVerified, StageSkipped}
}

// Valid reports whether s is a stage a ledger row may hold.
func (s Stage) Valid() bool {
	for _, k := range KnownStages() {
		if s == k {
			return true
		}
	}
	return false
}

// stageMoves is the ledger's stage machine: the stages a row in a given
// stage may move to. A move to the same stage rewrites the row's counts and
// is not a stage change (no audit row). verified is NOT terminal (FR-13): the
// personal plane keeps serving after a verify, so a later run re-reads the
// account and, when it grew something after verification (see DriftReasons),
// reopens it to planned; exported can only be re-exported (a --replace) or
// verified; skipped restarts from planned, and every step is idempotent, so
// a restart redoes nothing.
var stageMoves = map[Stage][]Stage{
	StageNone:     {StagePlanned, StageSkipped},
	StageSkipped:  {StageSkipped, StagePlanned},
	StagePlanned:  {StagePlanned, StageOrgReady, StageSkipped},
	StageOrgReady: {StageOrgReady, StageRekeyed, StageSkipped},
	StageRekeyed:  {StageRekeyed, StageExported, StageVerified, StageSkipped},
	StageExported: {StageExported, StageVerified},
	StageVerified: {StageVerified, StagePlanned},
}

// CanMove reports whether a ledger row in from may be written as to.
func CanMove(from, to Stage) bool {
	for _, s := range stageMoves[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Step is the next thing `run` does for an account.
type Step string

// The steps.
const (
	// StepSkip records the account as skipped (Decision.Skip).
	StepSkip Step = "skip"
	// StepPlan records the ledger row as planned.
	StepPlan Step = "plan"
	// StepEnsureOrg finds or creates the personal org (org_ready).
	StepEnsureOrg Step = "ensure_org"
	// StepRekey re-keys the live subscription, or records that there is
	// none (rekeyed).
	StepRekey Step = "rekey"
	// StepExport writes the bundle (exported).
	StepExport Step = "export"
	// StepFinish records an account with no results to carry as verified.
	StepFinish Step = "finish"
	// StepReopen moves a verified account that drifted back to planned (FR-13).
	StepReopen Step = "reopen"
	// StepAwaitReceipt waits for the tenant's receipt (`verify`).
	StepAwaitReceipt Step = "await_receipt"
	// StepDone: nothing left.
	StepDone Step = "done"
)

// stepRule is one row of the step table: at stage, the step is step when
// match holds for the decision. The first matching row of the stage wins.
type stepRule struct {
	stage Stage
	match func(Decision) bool
	step  Step
}

func always(Decision) bool        { return true }
func skipped(d Decision) bool     { return d.Skip != "" }
func needsExport(d Decision) bool { return d.Has(NeedExport) }
func drifted(d Decision) bool     { return len(d.Drift) > 0 }

// stepRules is walked top-down. A skip applies before the bundle is out
// (exported and verified are past the point where skipping means anything).
var stepRules = []stepRule{
	{StageNone, skipped, StepSkip},
	{StageNone, always, StepPlan},
	{StageSkipped, skipped, StepSkip},
	{StageSkipped, always, StepPlan},
	{StagePlanned, skipped, StepSkip},
	{StagePlanned, always, StepEnsureOrg},
	{StageOrgReady, skipped, StepSkip},
	{StageOrgReady, always, StepRekey},
	{StageRekeyed, skipped, StepSkip},
	{StageRekeyed, needsExport, StepExport},
	{StageRekeyed, always, StepFinish},
	{StageExported, always, StepAwaitReceipt},
	{StageVerified, drifted, StepReopen},
	{StageVerified, always, StepDone},
}

// NextStep returns what `run` does next for an account at stage cur with
// decision d. An unknown stage yields StepDone (nothing is guessed).
func NextStep(cur Stage, d Decision) Step {
	for _, r := range stepRules {
		if r.stage == cur && r.match(d) {
			return r.step
		}
	}
	return StepDone
}

// stepStage is the stage a step's success records.
var stepStage = map[Step]Stage{
	StepSkip:      StageSkipped,
	StepPlan:      StagePlanned,
	StepEnsureOrg: StageOrgReady,
	StepRekey:     StageRekeyed,
	StepExport:    StageExported,
	StepFinish:    StageVerified,
	StepReopen:    StagePlanned,
}

// StageAfter returns the stage step records on success, and false for a step
// that records nothing (await_receipt, done).
func StageAfter(step Step) (Stage, bool) {
	s, ok := stepStage[step]
	return s, ok
}
