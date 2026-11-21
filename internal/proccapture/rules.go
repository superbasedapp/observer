package proccapture

import "time"

// LongLived is R7's threshold: a run alive this long is kept as an exemplar
// (plan §4.1). It is deliberately a constant rather than a setting: it is the
// line between "a burst of short children" and "a process worth seeing", and
// the per-minute and per-session budgets already bound how many it can keep.
const LongLived = 30 * time.Second

// Policy is a compiled Config: the decision table plus its service and fold
// tables. Build one with NewPolicy and reuse it; it is immutable and safe for
// concurrent use.
type Policy struct {
	cfg    Config
	tables tables
}

// NewPolicy compiles cfg.
func NewPolicy(cfg Config) *Policy {
	return &Policy{cfg: cfg, tables: compileTables(cfg)}
}

// Config returns the policy's configuration.
func (p *Policy) Config() Config { return p.cfg }

// Enabled reports whether the decision table applies.
func (p *Policy) Enabled() bool { return p.cfg.Enabled }

// IsService reports whether exe is in the service table (built-in plus
// services.extra_basenames). The live Attributor uses it to mark service
// roots as it builds the tree.
func (p *Policy) IsService(exe string) bool { return p.tables.isService(exe) }

// Classify is the package-level convenience over NewPolicy(cfg).Classify.
// A loop over many runs should build one Policy instead.
func Classify(cfg Config, f RunFacts, b BudgetState) Decision {
	return NewPolicy(cfg).Classify(f, b)
}

// rule is one row of the decision table. match returns the action and the
// rollup group kind (for fold/rollup) when the row fires.
type rule struct {
	id     string
	reason string
	match  func(p *Policy, f RunFacts, b BudgetState) (Action, GroupKind, bool)
}

// rules is THE decision table (plan §4.1, with R5 per the operator ruling in
// §4.2 and R11 per ruling 3), walked top-down, first match wins. One test case
// per row in rules_test.go.
var rules = []rule{
	{
		id:     "R1",
		reason: "a finding fired or a network/file side effect was seen",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionKeep, "", f.FindingsFired > 0 || f.SideEffects
		},
	},
	{
		id:     "R2",
		reason: "the run failed (non-zero exit or signal)",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionKeep, "", f.Failed
		},
	},
	{
		id:     "R3",
		reason: "linked to a tool call, or the AI tool's root, or a tool call's root",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionKeep, "", f.ActionID > 0 || f.SeedRoot || f.ToolCallRoot
		},
	},
	{
		id:     "R4",
		reason: "starts a service (service table or the detach heuristic)",
		match: func(p *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			if !f.Attributed() || f.underService() {
				return "", "", false
			}
			return ActionDetach, "", f.DetachHeuristic || p.tables.isService(f.ExeBasename)
		},
	},
	{
		id:     "R5",
		reason: "under a service root: kept up to the service cap, then rolled up; dropped after the session's tail",
		match: func(p *Policy, f RunFacts, b BudgetState) (Action, GroupKind, bool) {
			if !f.Attributed() || !f.underService() {
				return "", "", false
			}
			if !p.cfg.TrackServices {
				return ActionDrop, "", true
			}
			if p.cfg.ServiceTail > 0 && !f.SessionLastActivity.IsZero() &&
				f.Time.After(f.SessionLastActivity.Add(p.cfg.ServiceTail)) {
				return ActionDrop, "", true
			}
			// A fold-table run never takes an exemplar slot: the cap is for
			// the service's meaningful children, not its console hosts.
			if _, folds := p.tables.foldMatch(f.ExeBasename, f.Argv, f.ParentExeBasename); !folds &&
				b.Service < p.cfg.ExemplarsPerService {
				return ActionKeep, "", true
			}
			return ActionRollup, GroupService, true
		},
	},
	{
		id:     "R6",
		reason: "matches the fold table",
		match: func(p *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			if !f.Attributed() || !p.cfg.FoldEnabled {
				return "", "", false
			}
			_, ok := p.tables.foldMatch(f.ExeBasename, f.Argv, f.ParentExeBasename)
			return ActionFold, GroupFold, ok
		},
	},
	{
		id:     "R7",
		reason: "alive at least 30 s",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionKeep, "", f.Attributed() && f.AliveFor >= LongLived
		},
	},
	{
		id:     "R8",
		reason: "the tool call's and session's exemplar budgets have room",
		match: func(p *Policy, f RunFacts, b BudgetState) (Action, GroupKind, bool) {
			if !f.Attributed() {
				return "", "", false
			}
			return ActionKeep, "", p.budgetRoom(f, b)
		},
	},
	{
		id:     "R9",
		reason: "attributed, exemplar budget full",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionRollup, GroupBudget, f.Attributed()
		},
	},
	{
		id:     "R10",
		reason: "unattributed and not held for correlation",
		match: func(_ *Policy, f RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionDrop, "", !f.HeldForCorrelation
		},
	},
	{
		id:     "R11",
		reason: "unattributed, held for correlation (the unattributed policy applies after pending_hours)",
		match: func(_ *Policy, _ RunFacts, _ BudgetState) (Action, GroupKind, bool) {
			return ActionKeep, "", true
		},
	},
}

// budgetRoom reports whether every applicable exemplar budget has room. A
// budget <= 0 is uncapped.
func (p *Policy) budgetRoom(f RunFacts, b BudgetState) bool {
	under := func(n, limit int) bool { return limit <= 0 || n < limit }
	if f.ToolCallKey != "" && !under(b.ToolCall, p.cfg.PerToolCall) {
		return false
	}
	return under(b.Session, p.cfg.PerSession) && under(b.Minute, p.cfg.PerMinute)
}

// Classify walks the decision table for one run. It is pure: the caller owns
// the BudgetState and records the decision (Ledger.Record) once it is final.
func (p *Policy) Classify(f RunFacts, b BudgetState) Decision {
	if !p.cfg.Enabled {
		return Decision{Action: ActionKeep, Rule: "disabled", Reason: "capture budget disabled", Counter: CounterKept}
	}
	for _, r := range rules {
		action, kind, ok := r.match(p, f, b)
		if !ok {
			continue
		}
		d := Decision{Action: action, Rule: r.id, Reason: r.reason}
		d.Class = classOf(f, action)
		d.Counter = counterOf(f, action, kind)
		switch r.id {
		case "R5":
			d.ConsumesService = action == ActionKeep
		case "R7", "R8":
			d.ConsumesBudget = true
		case "R9":
			d.BudgetHit = true
		}
		if action == ActionFold || action == ActionRollup {
			d.Group = p.groupOf(f, kind)
		}
		if action == ActionFold {
			d.FoldAnchor = d.Group.ParentProcessKey
			d.Group.ParentProcessKey = ""
		}
		return d
	}
	// Unreachable: R11 always matches.
	return Decision{Action: ActionKeep, Rule: "R11", Counter: CounterKept}
}

// classOf is the capture_class a persisted run is stored with.
func classOf(f RunFacts, a Action) CaptureClass {
	switch {
	case a == ActionDetach || (f.ServiceRootKey != "" && f.ServiceRootKey == f.ProcessKey):
		return ClassServiceRoot
	case f.underService():
		return ClassService
	default:
		return ClassExemplar
	}
}

// counterOf maps a final decision onto its stats counter.
func counterOf(f RunFacts, a Action, kind GroupKind) Counter {
	service := f.ServiceRootKey != "" || a == ActionDetach
	switch a {
	case ActionKeep, ActionDetach:
		if service {
			return CounterServiceKept
		}
		return CounterKept
	case ActionFold:
		return CounterFolded
	case ActionRollup:
		if kind == GroupService {
			return CounterServiceRolledUp
		}
		return CounterRolledUp
	default:
		return CounterDropped
	}
}

// groupOf builds the rollup group key for a folded or rolled-up run.
func (p *Policy) groupOf(f RunFacts, kind GroupKind) GroupKey {
	parent := f.AnchorKey
	if parent == "" {
		parent = f.ParentKey
	}
	return GroupKey{
		SessionID:        f.SessionID,
		BucketStart:      BucketStart(f.Time, p.cfg.bucket()),
		Kind:             kind,
		ParentProcessKey: parent,
		ServiceRootKey:   serviceRootOf(f),
		ExeBasename:      f.ExeBasename,
		ArgvTemplateHash: TemplateHash(f.ExeBasename, f.Argv),
	}
}

func serviceRootOf(f RunFacts) string {
	if f.underService() {
		return f.ServiceRootKey
	}
	return ""
}

// BucketStart aligns t (in UTC) to the start of its bucket.
func BucketStart(t time.Time, width time.Duration) time.Time {
	if width <= 0 {
		width = time.Minute
	}
	return t.UTC().Truncate(width)
}

// Lineage is the per-run tree state a child derives its facts from. The
// caller keeps one per tracked run (keyed by process key) and replaces it
// after each final decision with LineageOf.
type Lineage struct {
	ProcessKey     string
	SessionID      string
	ServiceRootKey string
	ToolCallKey    string
	// AnchorKey is the nearest kept ancestor (the run's own key when it was
	// kept).
	AnchorKey string
	SeedRoot  bool
}

// directIdentity are the attribution sources that name a session directly
// rather than by inheritance (procmodel.AttrBridge / AttrAdapterPID /
// AttrEnvToken / AttrCrossOSCorrelation). The cross-OS pass matches the
// Windows AI tool's own root (its exe is in the session's tool set, and its
// env-token children must name the same session), so it is that tool's root
// the way a bridge hit is on Linux: its tool-call shells are tool-call roots
// on both OSes. Data, not a ladder.
var directIdentity = map[string]bool{"bridge": true, "adapter_pid": true, "env_token": true, "cross_os_correlation": true}

// Derive fills f's tree-derived facts from its parent's lineage (nil = the
// parent is not tracked). It is the ONE owner of the rule, shared by the live
// Observer and Replay:
//
//   - service: a child of a service (root or member) is in that service; a
//     run whose executable is in the service table starts one. A
//     ServiceRootKey the caller already set (the live Attributor) is kept.
//   - seed root: a direct identity whose parent is not in the same session,
//     and not a service.
//   - tool call: a direct child of a seed root is a tool-call root; every
//     other run inherits its parent's tool-call key within the session.
//   - anchor: the parent's anchor (its own key when it was kept).
func (p *Policy) Derive(f *RunFacts, parent *Lineage) {
	sameSession := parent != nil && f.SessionID != "" && parent.SessionID == f.SessionID
	if f.ServiceRootKey == "" {
		switch {
		case parent != nil && parent.ServiceRootKey != "":
			f.ServiceRootKey = parent.ServiceRootKey
		case f.SessionID != "" && p.tables.isService(f.ExeBasename):
			f.ServiceRootKey = f.ProcessKey
		}
	}
	// A fold-table run (a console host, a WSL relay) is never the AI tool's
	// root or a tool call's root: it is the helper that sits beside one. On
	// Windows every child inherits the session token, so without this a
	// console host under a shell whose parent carries another session's
	// attribution would be taken for a tool call and kept.
	_, helper := p.tables.foldMatch(f.ExeBasename, f.Argv, f.ParentExeBasename)
	f.SeedRoot = directIdentity[f.AttributionSource] && f.ServiceRootKey == "" && !sameSession && !helper
	f.ToolCallRoot = sameSession && parent.SeedRoot && f.ServiceRootKey == "" && !helper
	switch {
	case f.ToolCallRoot:
		f.ToolCallKey = f.ProcessKey
	case sameSession:
		f.ToolCallKey = parent.ToolCallKey
	default:
		f.ToolCallKey = ""
	}
	switch {
	case parent != nil && parent.AnchorKey != "":
		f.AnchorKey = parent.AnchorKey
	default:
		f.AnchorKey = f.ParentKey
	}
}

// LineageOf is the lineage a run leaves for its children once its decision is
// known: kept and detached runs anchor their own children.
func LineageOf(f RunFacts, d Decision) Lineage {
	l := Lineage{
		ProcessKey:     f.ProcessKey,
		SessionID:      f.SessionID,
		ServiceRootKey: f.ServiceRootKey,
		ToolCallKey:    f.ToolCallKey,
		AnchorKey:      f.AnchorKey,
		SeedRoot:       f.SeedRoot,
	}
	if d.Action == ActionDetach && l.ServiceRootKey == "" {
		l.ServiceRootKey = f.ProcessKey
	}
	if d.Action.Persists() {
		l.AnchorKey = f.ProcessKey
	}
	return l
}

// ShouldDetach is the detach heuristic (plan §4.2): a run that is not a seed
// or tool-call root, is not already in a service, and starts a child at
// spawnAt, more than services.detach_after_minutes after its tool call's root
// ended at toolCallEndedAt, becomes a service root at that point. A zero
// toolCallEndedAt (the call has not ended) never detaches.
func (p *Policy) ShouldDetach(parent Lineage, toolCallEndedAt, spawnAt time.Time) bool {
	if !p.cfg.Enabled || p.cfg.DetachAfter <= 0 || toolCallEndedAt.IsZero() {
		return false
	}
	if parent.SessionID == "" || parent.SeedRoot || parent.ServiceRootKey != "" ||
		parent.ToolCallKey == "" || parent.ToolCallKey == parent.ProcessKey {
		return false
	}
	return spawnAt.Sub(toolCallEndedAt) >= p.cfg.DetachAfter
}
