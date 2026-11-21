package proccapture

import "time"

// RunFacts is the plain, SQL-free view of one process run the decision table
// reasons over. The live Observer fills it from its in-memory tree; a replay
// fills it from stored rows (store.LoadCaptureHistory). Fields the caller
// cannot know are left zero; the rules treat zero as "not observed".
//
// The tree-derived fields (ServiceRootKey, SeedRoot, ToolCallRoot,
// ToolCallKey, AnchorKey) are filled by Policy.Derive from the parent's
// Lineage, so the live and replay paths share one owner of that rule.
type RunFacts struct {
	// ProcessKey is the run's stable key; ParentKey its parent's ("" = none).
	ProcessKey string
	ParentKey  string
	// ExeBasename and ParentExeBasename are the run's and its parent's
	// executable basenames, as captured (NormalizeExe folds them).
	ExeBasename       string
	ParentExeBasename string
	// Argv is the scrubbed argv preview; CWD the scrubbed working directory.
	Argv string
	CWD  string
	// SessionID is the attributed session ("" = unattributed) and
	// AttributionSource how it was attributed (procmodel.AttributionSource
	// values: "bridge", "env_token", "adapter_pid", "inherited", ...).
	SessionID         string
	AttributionSource string
	// ActionID is the tool call (actions.id) the run is linked to; 0 = none.
	// At capture time it is usually 0: the link is made by the deferred
	// correlation pass. A replay of stored rows carries it.
	ActionID int64
	// SeedRoot marks a run whose session comes from a direct identity
	// (pid seed, pid bridge, env token) and whose parent is not in the same
	// session: the AI tool's own root process. Set by Derive.
	SeedRoot bool
	// ToolCallRoot marks a direct child of a SeedRoot: the process the agent
	// started for one tool call (its shell). ToolCallKey is the process key of
	// the run's tool-call root ("" when it is not under one). Set by Derive.
	ToolCallRoot bool
	ToolCallKey  string
	// ServiceRootKey is the process key of the service root the run is under,
	// or the run's own key when it IS a service root. Set by Derive (and by
	// the live Attributor, which owns the propagation down the tree).
	ServiceRootKey string
	// DetachHeuristic is set by the caller when Policy.ShouldDetach fired for
	// this run (it outlived its tool call and keeps spawning).
	DetachHeuristic bool
	// AnchorKey is the nearest KEPT ancestor's process key, the parent a
	// rollup or fold is grouped under. Set by Derive.
	AnchorKey string
	// HeldForCorrelation marks an unattributed run a capture path chose to
	// store so a deferred correlation pass can join it later (the cross-OS
	// bridge, AI subtrees, the active-project cwd). R11 keeps it; the
	// retention pass applies the unattributed policy after pending_hours.
	HeldForCorrelation bool
	// Failed is a non-zero exit code or a signal. Ended is true once the run
	// exited. AliveFor is how long it has run (its duration once ended).
	Failed   bool
	Ended    bool
	AliveFor time.Duration
	// FindingsFired counts guard/process findings on the run; SideEffects
	// marks a network or file side effect seen for it. Either keeps it (R1).
	FindingsFired int
	SideEffects   bool
	// Time is when the run started (the rollup bucket and the per-minute
	// budget key off it).
	Time time.Time
	// SessionLastActivity is the session's last agent activity (the latest
	// non-service run start the caller has seen). Zero = unknown, which never
	// stops a service's tracking.
	SessionLastActivity time.Time

	// Resource totals, carried into a rollup when the run is not kept.
	DurationMs   int64
	CPUMs        int64
	PeakRSSBytes int64
	// StoredBytes is the measured stored size of the row's variable columns
	// (exe path, cwd, argv preview, metric ring) when the caller knows it
	// (a replay of stored rows); 0 = derive from field lengths. MetricBytes is
	// the metric-ring share of it, dropped for a run younger than the ring
	// threshold. Used by Estimate only.
	StoredBytes int
	MetricBytes int
}

// Attributed reports whether the run belongs to a session.
func (f RunFacts) Attributed() bool { return f.SessionID != "" }

// underService reports whether the run is inside a service subtree (and is
// not the service root itself).
func (f RunFacts) underService() bool {
	return f.ServiceRootKey != "" && f.ServiceRootKey != f.ProcessKey
}

// Action is what the capture path does with one run (plan §4.1).
type Action string

// Actions.
const (
	// ActionKeep persists the run as its own row (an exemplar).
	ActionKeep Action = "keep"
	// ActionFold stores no row; the nearest kept ancestor's fold count is
	// incremented and the run is counted in a fold rollup.
	ActionFold Action = "fold"
	// ActionDetach persists the run once as a service root; its later
	// subtree is the service's (R5).
	ActionDetach Action = "detach"
	// ActionRollup stores no row; the run is added to a rollup group.
	ActionRollup Action = "rollup"
	// ActionDrop stores no row and no rollup; the run is only counted.
	ActionDrop Action = "drop"
)

// Persists reports whether the action writes a process_runs row.
func (a Action) Persists() bool { return a == ActionKeep || a == ActionDetach }

// GroupKind is a rollup row's group_kind (plan §9.2).
type GroupKind string

// Group kinds.
const (
	GroupBudget       GroupKind = "budget"
	GroupFold         GroupKind = "fold"
	GroupService      GroupKind = "service"
	GroupUnattributed GroupKind = "unattributed"
)

// CaptureClass is process_runs.capture_class (plan §9.2).
type CaptureClass string

// Capture classes. Legacy rows (written before the budget) are NULL.
const (
	ClassExemplar    CaptureClass = "exemplar"
	ClassServiceRoot CaptureClass = "service_root"
	ClassService     CaptureClass = "service"
)

// Counter names one process_capture_stats counter (plan §9.2). The count
// invariant: kept + folded + rolled_up + service_kept + service_rolled_up +
// dropped == observed.
type Counter string

// Counters.
const (
	CounterKept            Counter = "kept"
	CounterFolded          Counter = "folded"
	CounterRolledUp        Counter = "rolled_up"
	CounterServiceKept     Counter = "service_kept"
	CounterServiceRolledUp Counter = "service_rolled_up"
	CounterDropped         Counter = "dropped"
)

// GroupKey identifies one rollup row (the UNIQUE key of process_rollups).
type GroupKey struct {
	// SessionID is "" for the machine-level (unattributed) rollup, stored as
	// NULL.
	SessionID        string
	BucketStart      time.Time
	Kind             GroupKind
	ParentProcessKey string
	ServiceRootKey   string
	ExeBasename      string
	ArgvTemplateHash string
}

// Decision is Classify's answer for one run.
type Decision struct {
	// Action is what to do with the run.
	Action Action
	// Rule is the matching rule's id ("R1".."R11", or "disabled").
	Rule string
	// Reason is the matching rule's one-line explanation.
	Reason string
	// Class is the capture_class a persisted run is stored with.
	Class CaptureClass
	// Counter is the stats counter the run is counted under once final.
	Counter Counter
	// Group is the rollup group for ActionFold and ActionRollup (zero
	// otherwise).
	Group GroupKey
	// FoldAnchor is the kept ancestor a folded run's fold_count is added to
	// (ActionFold only). The fold group itself carries no parent, so a
	// minute of console hosts is one rollup row, not one per parent.
	FoldAnchor string
	// BudgetHit is true when an exemplar budget was full (R9).
	BudgetHit bool
	// ConsumesBudget is true when the run takes a slot of the session's
	// exemplar budgets (R7, R8) and ConsumesService when it takes one of its
	// service's exemplar slots (R5); Ledger.Record reads them.
	ConsumesBudget  bool
	ConsumesService bool
}
