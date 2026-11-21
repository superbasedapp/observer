package processobs

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// CaptureSink is the OPTIONAL sink capability the capture budget writes
// through (docs/process-observability.md §11 "Capture budget"): the exemplar
// runs AND the rollup / stats / fold delta of one flush, in ONE transaction,
// so a transient failure retries both together and nothing is counted twice.
// The store implements it (store.PersistCapture). A sink without it still
// receives the exemplar runs through PersistRuns; only the delta is lost.
type CaptureSink interface {
	PersistCapture(ctx context.Context, runs []ProcessRun, delta proccapture.Delta) (int, error)
}

// Capture-state bounds. They keep the drain-owned maps small on a box that
// runs for weeks; none of them changes a decision.
const (
	// captureLineageGrace is how long an exited run's lineage is kept for a
	// child that execs after its parent exited (fork, parent exit, exec).
	captureLineageGrace = 10 * time.Minute
	// captureToolCallMemory is how long a tool call's end time (and its
	// budget counter) is remembered for the detach heuristic.
	captureToolCallMemory = 24 * time.Hour
	// captureMinuteMemory is how long a per-minute budget counter is kept.
	captureMinuteMemory = 5 * time.Minute
)

// capRun is the capture budget's state for one run: its facts and lineage,
// its decision, and whether that decision is final. A decision taken at exec
// that does not persist (fold, rollup, drop) is PROVISIONAL: the run may
// still fail (R2), live past 30 s (R7) or fire a side effect (R1), so it is
// re-classified on every later snapshot and finalized at exit.
type capRun struct {
	facts    proccapture.RunFacts
	lin      proccapture.Lineage
	decision proccapture.Decision
	final    bool
	exitedAt time.Time
	// run is the tracked run itself, so a run the Attributor evicts while
	// provisional can still be finalized from its last state.
	run *ProcessRun
}

// captureState is the drain-owned half of the capture budget: the compiled
// policy, the budget ledger and the per-run state. It is touched ONLY on the
// drain goroutine (like the Attributor), so it needs no locking; the flusher
// reads nothing but the CaptureTag on each snapshot.
type captureState struct {
	policy        *proccapture.Policy
	ringMin       time.Duration
	ledger        *proccapture.Ledger
	runs          map[string]*capRun
	toolCallEnded map[string]time.Time
	lastActivity  map[string]time.Time
	sideEffects   map[string]bool
}

func newCaptureState(cfg proccapture.Config) *captureState {
	if !cfg.Enabled {
		return nil
	}
	return &captureState{
		policy:        proccapture.NewPolicy(cfg),
		ringMin:       cfg.RingMinLifetime,
		ledger:        proccapture.NewLedger(),
		runs:          make(map[string]*capRun),
		toolCallEnded: make(map[string]time.Time),
		lastActivity:  make(map[string]time.Time),
		sideEffects:   make(map[string]bool),
	}
}

// appendRun is THE capture seam (CLAUDE.md rule 2): every run snapshot bound
// for the sink passes here. With the budget off it is exactly the pre-budget
// append; with it on, the run goes through proccapture.Classify and the
// snapshot carries a CaptureTag the flusher splits on.
func (o *Observer) appendRun(batch []ProcessRun, run *ProcessRun, change Change) []ProcessRun {
	if o.capture == nil {
		return append(batch, o.attr.SnapshotForPersist(run))
	}
	return append(batch, o.capture.gate(o, run, change)...)
}

// markSideEffect records a network side effect for a run (R1 keeps it).
func (o *Observer) markSideEffect(key string) {
	if o.capture != nil && key != "" {
		o.capture.sideEffects[key] = true
	}
}

// aliveFor is how long a run has been observed alive (its duration once it
// exited).
func aliveFor(run *ProcessRun) time.Duration {
	if run.Exited && run.DurationMs > 0 {
		return time.Duration(run.DurationMs) * time.Millisecond
	}
	if run.StartedAt.IsZero() || run.LastSeenAt.Before(run.StartedAt) {
		return 0
	}
	return run.LastSeenAt.Sub(run.StartedAt)
}

// refreshFacts copies a run's CURRENT dynamic state onto its facts (the
// tree-derived fields are kept).
func (cs *captureState) refreshFacts(o *Observer, f *proccapture.RunFacts, run *ProcessRun) {
	f.ExeBasename = run.ExeBasename
	f.Argv = run.ArgvPreview
	f.CWD = run.CWD
	f.SessionID = run.Attribution.SessionID
	f.AttributionSource = string(run.Attribution.Source)
	f.HeldForCorrelation = !run.Attributed()
	if run.Attribution.ActionID != nil {
		f.ActionID = *run.Attribution.ActionID
	}
	f.Ended = run.Exited
	f.Failed = run.Exited && (run.ExitCode != 0 || run.ExitSignal != 0)
	f.AliveFor = aliveFor(run)
	f.FindingsFired = len(procmodel.DeriveFindings([]procmodel.RunFacts{{
		ProcessKey: run.ProcessKey, SessionID: run.Attribution.SessionID, Attributed: run.Attributed(),
		ExePath: run.ExePath, ExeBasename: run.ExeBasename, UID: run.UID, EUID: run.EUID,
	}}))
	f.SideEffects = cs.sideEffects[run.ProcessKey]
	f.Time = firstTime(run.StartedAt, run.LastSeenAt, o.now())
	f.SessionLastActivity = cs.lastActivity[f.SessionID]
	f.DurationMs = f.AliveFor.Milliseconds()
	f.CPUMs = run.CPUUserMs + run.CPUSystemMs
	f.PeakRSSBytes = max(run.MaxRSSBytes, run.WorkingSetBytes)
}

// gate classifies one run snapshot and returns what goes into the batch: zero
// snapshots (a provisional decision, nothing to write yet), the run's own
// snapshot (tagged), and possibly its parent's (a detach).
func (cs *captureState) gate(o *Observer, run *ProcessRun, change Change) []ProcessRun {
	cr := cs.runs[run.ProcessKey]
	var out []ProcessRun
	if cr == nil {
		cr = &capRun{}
		f := proccapture.RunFacts{ProcessKey: run.ProcessKey, ParentKey: run.ParentProcessKey}
		cs.refreshFacts(o, &f, run)
		var parent *proccapture.Lineage
		if pr := cs.runs[run.ParentProcessKey]; pr != nil {
			parent = &pr.lin
			f.ParentExeBasename = pr.facts.ExeBasename
			// The detach heuristic: the parent keeps spawning after its tool
			// call ended. Only a KEPT parent detaches (the same rule Replay
			// applies); rows recorded before the detach stay as they are.
			if pr.final && pr.decision.Action == proccapture.ActionKeep &&
				cs.policy.ShouldDetach(pr.lin, cs.toolCallEnded[pr.lin.ToolCallKey], f.Time) {
				out = append(out, cs.detach(o, run.ParentProcessKey, pr)...)
				if run.ServiceRootKey == "" {
					run.ServiceRootKey = run.ParentProcessKey
				}
			}
		}
		f.ServiceRootKey = run.ServiceRootKey
		cs.policy.Derive(&f, parent)
		run.ServiceRootKey = f.ServiceRootKey
		cr.facts = f
		cr.run = run
		cs.runs[run.ProcessKey] = cr
		if f.Attributed() && f.ServiceRootKey == "" && f.Time.After(cs.lastActivity[f.SessionID]) {
			cs.lastActivity[f.SessionID] = f.Time
		}
	} else {
		cr.run = run
		cs.refreshFacts(o, &cr.facts, run)
		cr.facts.ServiceRootKey = firstNonEmpty(cr.facts.ServiceRootKey, run.ServiceRootKey)
	}

	if run.Exited && cr.exitedAt.IsZero() {
		cr.exitedAt = firstTime(run.ExitedAt, o.now())
		if cr.facts.ToolCallRoot {
			cs.toolCallEnded[run.ProcessKey] = cr.exitedAt
		}
	}

	if cr.final {
		if !cr.decision.Action.Persists() {
			return out
		}
		// An already-counted exemplar: re-persist its new snapshot.
		snap := cs.snapshot(o, run)
		snap.Capture = &procmodel.CaptureTag{Persist: true}
		return append(out, snap)
	}

	d := cs.policy.Classify(cr.facts, cs.ledger.State(cr.facts))
	cr.decision = d
	cr.lin = proccapture.LineageOf(cr.facts, d)
	if !d.Action.Persists() && !run.Exited {
		return out // provisional: re-classified on the next snapshot
	}
	return append(out, cs.finalize(o, run, cr))
}

// finalize makes cr's current decision final: it takes the budget slots,
// sets the run's capture class, and returns the tagged snapshot.
func (cs *captureState) finalize(o *Observer, run *ProcessRun, cr *capRun) ProcessRun {
	d := cr.decision
	cr.final = true
	cs.ledger.Record(cr.facts, d)
	tag := &procmodel.CaptureTag{Count: string(d.Counter), BudgetHit: d.BudgetHit}
	var snap ProcessRun
	switch d.Action {
	case proccapture.ActionKeep, proccapture.ActionDetach:
		run.CaptureClass = string(d.Class)
		snap = cs.snapshot(o, run)
		tag.Persist = true
	default:
		// No row: the snapshot only carries the run's totals to the
		// flusher's rollup, so the ring is not copied.
		snap = *run
		snap.MetricSamples = nil
		tag.GroupKind = string(d.Group.Kind)
		tag.BucketStart = d.Group.BucketStart
		tag.AnchorKey = d.Group.ParentProcessKey
		tag.ServiceRootKey = d.Group.ServiceRootKey
		tag.ArgvTemplateHash = d.Group.ArgvTemplateHash
		if d.Action == proccapture.ActionFold {
			tag.FoldInto = d.FoldAnchor
		}
		// Rollup durations are what the run lived, measured or not.
		snap.DurationMs = cr.facts.DurationMs
	}
	snap.Capture = tag
	return snap
}

// detach turns a kept parent into a service root (the detach heuristic) and
// returns its re-counted snapshot.
func (cs *captureState) detach(o *Observer, key string, pr *capRun) []ProcessRun {
	from := pr.decision.Counter
	pr.facts.ServiceRootKey = key
	pr.facts.DetachHeuristic = true
	pr.lin.ServiceRootKey = key
	pr.decision.Action = proccapture.ActionDetach
	pr.decision.Class = proccapture.ClassServiceRoot
	pr.decision.Counter = proccapture.CounterServiceKept
	tag := &procmodel.CaptureTag{Count: string(proccapture.CounterServiceKept), MoveFrom: string(from)}
	if prun := o.attr.runs[key]; prun != nil {
		prun.ServiceRootKey = key
		prun.CaptureClass = string(proccapture.ClassServiceRoot)
		snap := cs.snapshot(o, prun)
		tag.Persist = true
		snap.Capture = tag
		return []ProcessRun{snap}
	}
	return []ProcessRun{{ProcessKey: key, Attribution: Attribution{SessionID: pr.facts.SessionID}, Capture: tag}}
}

// snapshot is the persist copy of a kept run, without the metric ring while
// the run is younger than ring_min_lifetime_seconds (it keeps its totals).
func (cs *captureState) snapshot(o *Observer, run *ProcessRun) ProcessRun {
	snap := o.attr.SnapshotForPersist(run)
	if cs.ringMin > 0 && aliveFor(run) < cs.ringMin {
		snap.MetricSamples = nil
	}
	return snap
}

// prune bounds the capture maps and finalizes runs the Attributor evicted
// while their decision was still provisional (so their counts stay exact).
// Returns the snapshots to append. Drain goroutine only.
func (cs *captureState) prune(o *Observer, now time.Time) []ProcessRun {
	var out []ProcessRun
	for key, cr := range cs.runs {
		tracked := o.attr.runs[key] != nil
		switch {
		case !cr.final && !tracked && cr.exitedAt.IsZero():
			// Evicted (never-exiting, over the live-tree cap) while provisional:
			// finalize on what was last seen.
			cr.facts.Ended = true
			cr.decision = cs.policy.Classify(cr.facts, cs.ledger.State(cr.facts))
			out = append(out, cs.finalize(o, cr.run, cr))
			delete(cs.runs, key)
		case !cr.exitedAt.IsZero() && now.Sub(cr.exitedAt) > captureLineageGrace:
			delete(cs.runs, key)
		case cr.exitedAt.IsZero() && !tracked:
			delete(cs.runs, key)
		}
	}
	for key, at := range cs.toolCallEnded {
		if now.Sub(at) > captureToolCallMemory {
			delete(cs.toolCallEnded, key)
			cs.ledger.ForgetToolCall(key)
		}
	}
	for sess, at := range cs.lastActivity {
		if now.Sub(at) > captureToolCallMemory {
			delete(cs.lastActivity, sess)
		}
	}
	for key := range cs.sideEffects {
		if cs.runs[key] == nil && o.attr.runs[key] == nil {
			delete(cs.sideEffects, key)
		}
	}
	cs.ledger.PruneMinutes(now.Add(-captureMinuteMemory))
	return out
}

// splitCapture is the flusher half of the seam: it keeps the snapshots that
// write a row and folds every tag into one Delta (stats, rollups, folds).
// Pure over the snapshots; it reads no Observer state.
func splitCapture(pending []ProcessRun) ([]ProcessRun, proccapture.Delta) {
	rows := make([]ProcessRun, 0, len(pending))
	acc := proccapture.NewAccumulator()
	for i := range pending {
		r := &pending[i]
		tag := r.Capture
		if tag == nil {
			rows = append(rows, *r)
			continue
		}
		if tag.Persist {
			rows = append(rows, *r)
		}
		session := r.Attribution.SessionID
		switch {
		case tag.MoveFrom != "" && tag.Count != "":
			acc.Move(session, proccapture.Counter(tag.MoveFrom), proccapture.Counter(tag.Count))
		case tag.Count != "":
			acc.Count(session, proccapture.Decision{Counter: proccapture.Counter(tag.Count), BudgetHit: tag.BudgetHit})
		}
		if tag.GroupKind != "" {
			key := proccapture.GroupKey{
				SessionID:        session,
				BucketStart:      tag.BucketStart,
				Kind:             proccapture.GroupKind(tag.GroupKind),
				ParentProcessKey: tag.AnchorKey,
				ServiceRootKey:   tag.ServiceRootKey,
				ExeBasename:      r.ExeBasename,
				ArgvTemplateHash: tag.ArgvTemplateHash,
			}
			f := proccapture.RunFacts{
				ProcessKey:   r.ProcessKey,
				Argv:         r.ArgvPreview,
				Failed:       r.Exited && (r.ExitCode != 0 || r.ExitSignal != 0),
				Time:         r.StartedAt,
				DurationMs:   r.DurationMs,
				CPUMs:        r.CPUUserMs + r.CPUSystemMs,
				PeakRSSBytes: max(r.MaxRSSBytes, r.WorkingSetBytes),
			}
			if r.Attribution.ActionID != nil {
				f.ActionID = *r.Attribution.ActionID
			}
			acc.AddRollup(key, f)
		}
		if tag.FoldInto != "" {
			acc.Fold(tag.FoldInto)
		}
	}
	return rows, acc.Delta()
}

// persistBatch hands one flush to the sink: unchanged with the budget off;
// with it on, the exemplar rows and the delta in one CaptureSink transaction.
func (o *Observer) persistBatch(ctx context.Context, pending []ProcessRun) error {
	if !o.captureOn {
		_, err := o.sink.PersistRuns(ctx, pending)
		return err
	}
	rows, delta := splitCapture(pending)
	if cs, ok := o.sink.(CaptureSink); ok {
		_, err := cs.PersistCapture(ctx, rows, delta)
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	_, err := o.sink.PersistRuns(ctx, rows)
	return err
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
