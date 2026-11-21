package codequality

// State is the honest state of one metric for one project. Only
// StateMeasured carries numbers; every other state is "not measured" with
// its cause, never a zero.
type State string

// The closed State vocabulary. Each metric uses the subset its rule table
// can reach.
const (
	StateMeasured State = "measured"
	// StateOff: [projects].quality_metrics = false.
	StateOff State = "off"
	// StateRootMissing: the project folder is not on this machine.
	StateRootMissing State = "root_missing"

	// Coverage.
	StateNoReport   State = "no_report"  // no report at any probed location
	StateUnreadable State = "unreadable" // reports exist, none could be used
	StateNoLines    State = "no_lines"   // reports read, no instrumented line

	// Duplication.
	StateNotInBuild   State = "not_in_build"  // the binary has no codeintel component
	StateArchived     State = "archived"      // the index moved to the cold archive
	StateCodeIntelOff State = "codeintel_off" // code intelligence is off (D-307), no index
	StateNotIndexed   State = "not_indexed"   // code intelligence on, this project not indexed
	StateNoSymbols    State = "no_symbols"    // indexed, no function or method of MinSymbolLines

	// Complexity (it shares off, not_in_build, archived, codeintel_off and
	// not_indexed with duplication).
	StateNoSupportedFiles State = "no_supported_files" // no indexed file has a counter (heuristic parser, or no rule table for the language)
	StateCountPending     State = "count_pending"      // the index predates complexity counting; the next index pass counts it
	StateNoFunctions      State = "no_functions"       // counted files, no function or method in them
)

// CoverageFacts are the inputs of the coverage state rules.
type CoverageFacts struct {
	Enabled     bool
	RootMissing bool
	Found       int // reports read and parsed with at least one line
	Problems    int // reports that exist but could not be used
	Lines       int // instrumented lines across counted reports
}

// stateRule is one row of an ordered state table: the first row whose When
// holds decides the state and its reason.
type stateRule[F any] struct {
	State  State
	When   func(F) bool
	Reason string
}

// coverageRules is walked top-down; the last row always matches.
var coverageRules = []stateRule[CoverageFacts]{
	{StateOff, func(f CoverageFacts) bool { return !f.Enabled }, "Quality metrics are off ([projects].quality_metrics = false)."},
	{StateRootMissing, func(f CoverageFacts) bool { return f.RootMissing }, "The project folder is not on this machine, so no report could be read."},
	{StateNoReport, func(f CoverageFacts) bool { return f.Found == 0 && f.Problems == 0 }, "No coverage report found at the default locations. Observer never runs your tests; run them with coverage and the next measurement reads the report."},
	{StateUnreadable, func(f CoverageFacts) bool { return f.Found == 0 }, "A coverage report exists but could not be used (see the reports below)."},
	{StateNoLines, func(f CoverageFacts) bool { return f.Lines == 0 }, "The coverage reports hold no instrumented lines."},
	{StateMeasured, func(CoverageFacts) bool { return true }, "Line coverage from the project's own report files."},
}

// CoverageState decides the coverage state and its reason.
func CoverageState(f CoverageFacts) (State, string) { return walk(coverageRules, f) }

// DuplicationFacts are the inputs of the duplication state rules.
type DuplicationFacts struct {
	Enabled         bool
	CodeIntelOn     bool
	NotInBuild      bool
	Archived        bool
	IndexedFiles    int
	EligibleSymbols int
}

// duplicationRules is walked top-down; the last row always matches. An
// index that exists is read even when code intelligence is now off (the
// figure is then flagged stale), so CodeIntelOn only decides between
// codeintel_off and not_indexed when there is no index.
var duplicationRules = []stateRule[DuplicationFacts]{
	{StateOff, func(f DuplicationFacts) bool { return !f.Enabled }, "Quality metrics are off ([projects].quality_metrics = false)."},
	{StateNotInBuild, func(f DuplicationFacts) bool { return f.NotInBuild }, "This build of Observer has no code intelligence, which duplication needs."},
	{StateArchived, func(f DuplicationFacts) bool { return f.Archived && f.IndexedFiles == 0 }, "The project's code intelligence index was moved to the archive; rehydrate it to measure duplication."},
	{StateCodeIntelOff, func(f DuplicationFacts) bool { return f.IndexedFiles == 0 && !f.CodeIntelOn }, "Not measured: code intelligence is off. Turn it on in Settings > Intelligence > Code intelligence to measure duplication."},
	{StateNotIndexed, func(f DuplicationFacts) bool { return f.IndexedFiles == 0 }, "Not measured yet: code intelligence has not indexed this project."},
	{StateNoSymbols, func(f DuplicationFacts) bool { return f.EligibleSymbols == 0 }, "The index holds no function or method long enough to compare."},
	{StateMeasured, func(DuplicationFacts) bool { return true }, "Near-clone functions and methods from the code intelligence index (MinHash, approximate)."},
}

// DuplicationState decides the duplication state and its reason.
func DuplicationState(f DuplicationFacts) (State, string) { return walk(duplicationRules, f) }

func walk[F any](rules []stateRule[F], f F) (State, string) {
	for _, r := range rules {
		if r.When(f) {
			return r.State, r.Reason
		}
	}
	return "", ""
}
