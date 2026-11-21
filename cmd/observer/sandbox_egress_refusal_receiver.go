//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_egress_refusal_receiver.go is the daemon's side of the egress
// refusal audit (lane N1): the relay handler hands it each validated
// KindEgressRefusal report with the run the channel names, and it writes
// one row through the one store seam (internal/store/sandboxegress.go),
// off the link's goroutine. It applies the flood bound again (one per run
// and host per minute, a per-run cap), and the store's unique key on the
// minute is the last line. It also owns the table's retention: at most
// once an hour it prunes rows past store.SandboxEgressRefusalRetention.
// A refusal it or a feed dropped is counted per run beside the rows (lane
// OC, audit findings O3-W2 and OC-A2): its queue full, a feed past its own
// bound, or its flood bound dropping a distinct refusal (past the per-run
// cap of hosts in a minute, from a minute earlier than the run's, or with
// its run table full). A run whose rows look complete is then not silently
// incomplete. Only a repeat of a host the run's minute already passed is
// not counted: nothing new was lost.

// egressRefusalStore is the store seam the receiver writes through.
type egressRefusalStore interface {
	InsertSandboxEgressRefusal(ctx context.Context, r store.SandboxEgressRefusal) (bool, error)
	AddSandboxEgressRefusalDrops(ctx context.Context, runID string, dropped, uncertain int, at time.Time) error
	AddSandboxEgressRefusalLinkLoss(ctx context.Context, runID string, lost, closed int, at time.Time) error
	PruneSandboxEgressRefusals(ctx context.Context, cutoff time.Time) (int64, error)
}

// Receiver bounds.
const (
	// egressRefusalWriteQueue bounds the rows waiting to be written.
	egressRefusalWriteQueue = 256
	// egressRefusalDropRuns bounds the runs whose dropped counts wait to be
	// written; the counts of one run add together while they wait, so a
	// flood of drops costs one entry per run, never one per drop.
	egressRefusalDropRuns = 4096
	// egressRefusalPruneInterval is how often the receiver prunes.
	egressRefusalPruneInterval = time.Hour
	// egressRefusalClockSkew is how far a report's time may sit from the
	// daemon's clock before the daemon's own time is used instead.
	egressRefusalClockSkew = 5 * time.Minute
)

// egressRefusalDropCount is the dropped-refusal counts of one run a feed
// or the receiver hands on: Dropped are the run's own, Uncertain may be
// the run's (refusals of a box whose id was not recorded yet, dropped
// while the box they claimed was not remembered; audit finding OC-A1).
// LinkLost and Closed are what the run's host helper could not report
// (tracker F-012, audit findings N4-A4 and FU5-A4): refusals it could not
// send, the link down or the daemon busy (written to dropped too), and new
// requests it refused while the link was down under require_refusal_audit.
type egressRefusalDropCount struct {
	Dropped, Uncertain int
	LinkLost, Closed   int
}

// positive reports whether any count is positive and none negative.
func (n egressRefusalDropCount) positive() bool {
	if n.Dropped < 0 || n.Uncertain < 0 || n.LinkLost < 0 || n.Closed < 0 {
		return false
	}
	return n.Dropped+n.Uncertain+n.LinkLost+n.Closed > 0
}

// egressRefusalReceiver is the daemon's one writer of refusal rows.
type egressRefusalReceiver struct {
	st  egressRefusalStore
	lim *sandboxnet.RefusalLimiter
	ch  chan store.SandboxEgressRefusal
	// dropMu guards drops, the dropped counts waiting for the writer by
	// run (audit findings O3-W2 and OC-A2); dropKick wakes the writer.
	dropMu   sync.Mutex
	drops    map[string]egressRefusalDropCount
	dropKick chan struct{}
	now      func() time.Time
	logger   *slog.Logger
}

// newEgressRefusalReceiver starts the writer goroutine, which ends with
// ctx; nil when there is no store.
func newEgressRefusalReceiver(ctx context.Context, st egressRefusalStore, logger *slog.Logger) *egressRefusalReceiver {
	return newEgressRefusalReceiverAt(ctx, st, logger, time.Now)
}

// newEgressRefusalReceiverAt is newEgressRefusalReceiver with its clock
// given before the writer goroutine starts (a test that set the clock
// after the start raced the first prune).
func newEgressRefusalReceiverAt(ctx context.Context, st egressRefusalStore, logger *slog.Logger, now func() time.Time) *egressRefusalReceiver {
	if st == nil {
		return nil
	}
	r := &egressRefusalReceiver{
		st: st, lim: sandboxnet.NewRefusalLimiter(0), ch: make(chan store.SandboxEgressRefusal, egressRefusalWriteQueue),
		drops: map[string]egressRefusalDropCount{}, dropKick: make(chan struct{}, 1),
		now: now, logger: logger,
	}
	go r.loop(ctx)
	return r
}

// OnEgressRefusal is the relay handler's hook (sandboxrelayd.Daemon). It
// never blocks: a row the flood bound drops while it carries something new
// (sandboxnet.RefusalVerdict.Lost), or that does not fit the queue, is
// counted against its run (audit finding OC-A2).
func (r *egressRefusalReceiver) OnEgressRefusal(run sandboxrelayd.RunRecord, rep sandboxrelay.EgressRefusalReport) {
	// The counts a report carries are applied before the row is checked
	// (tracker F-038): the daemon answers every validated report OK, so the
	// helper subtracts them, and a row this daemon rejects (a rule outside
	// its vocabulary, a version skew) must not take them with it.
	if runID := egressRefusalRunID(run); runID != "" && (rep.Lost > 0 || rep.Closed > 0) {
		// The helper's link was lost and is back: what it could not report
		// is counted beside the run's rows, and the daemon says why.
		r.dropped(runID, egressRefusalDropCount{LinkLost: rep.Lost, Closed: rep.Closed})
		if r.logger != nil {
			r.logger.Warn("sandbox egress refusal: a run's link to the daemon was lost and is back; what it could not report is counted with the run",
				"run", runID, "lost_refusals", rep.Lost, "egress_closed", rep.Closed, "refusal_audit_required", run.RefusalAuditRequired)
		}
	}
	row, ok := r.row(run, rep)
	if !ok {
		return
	}
	if v := r.lim.Check(row.RunID, row.Host, row.At); v != sandboxnet.RefusalPass {
		if v.Lost() {
			r.dropped(row.RunID, egressRefusalDropCount{Dropped: 1})
		}
		return
	}
	select {
	case r.ch <- row:
	default:
		r.dropped(row.RunID, egressRefusalDropCount{Dropped: 1})
	}
}

// row turns a report into its stored row: the run and its project from
// the channel's run record (the stored terminal run when bound, else the
// relay run), the rule checked against the closed vocabulary. Backend and
// tier are left for the store to stamp from the run's terminal_run row.
func (r *egressRefusalReceiver) row(run sandboxrelayd.RunRecord, rep sandboxrelay.EgressRefusalReport) (store.SandboxEgressRefusal, bool) {
	rule := sandboxnet.RefusalRule(rep.Rule)
	if !rule.Valid() {
		return store.SandboxEgressRefusal{}, false
	}
	runID := egressRefusalRunID(run)
	if runID == "" {
		return store.SandboxEgressRefusal{}, false
	}
	now := r.now().UTC()
	at := time.UnixMilli(rep.AtMS).UTC()
	if at.Before(now.Add(-egressRefusalClockSkew)) || at.After(now.Add(egressRefusalClockSkew)) {
		at = now
	}
	return store.SandboxEgressRefusal{
		RunID: runID, ProjectRoot: run.ProjectRoot,
		Host: rep.Host, Port: rep.Port, Rule: string(rule), Key: rep.Key, At: at,
	}, true
}

func (r *egressRefusalReceiver) loop(ctx context.Context) {
	r.prune(ctx)
	t := time.NewTicker(egressRefusalPruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.prune(ctx)
		case <-r.dropKick:
			r.writeDrops(ctx)
		case row := <-r.ch:
			if _, err := r.st.InsertSandboxEgressRefusal(ctx, row); err != nil && r.logger != nil {
				r.logger.Warn("sandbox egress refusal: write", "run", row.RunID, "err", err)
			}
		}
	}
}

// writeDrops writes the dropped counts waiting, one add per run.
func (r *egressRefusalReceiver) writeDrops(ctx context.Context) {
	r.dropMu.Lock()
	drops := r.drops
	r.drops = map[string]egressRefusalDropCount{}
	r.dropMu.Unlock()
	for run, d := range drops {
		if d.Dropped+d.Uncertain > 0 {
			if err := r.st.AddSandboxEgressRefusalDrops(ctx, run, d.Dropped, d.Uncertain, r.now()); err != nil && r.logger != nil {
				r.logger.Warn("sandbox egress refusal: write dropped count", "run", run, "err", err)
			}
		}
		if d.LinkLost+d.Closed > 0 {
			if err := r.st.AddSandboxEgressRefusalLinkLoss(ctx, run, d.LinkLost, d.Closed, r.now()); err != nil && r.logger != nil {
				r.logger.Warn("sandbox egress refusal: write link loss count", "run", run, "err", err)
			}
		}
	}
}

func (r *egressRefusalReceiver) prune(ctx context.Context) {
	if _, err := r.st.PruneSandboxEgressRefusals(ctx, r.now().Add(-store.SandboxEgressRefusalRetention)); err != nil && r.logger != nil {
		r.logger.Warn("sandbox egress refusal: prune", "err", err)
	}
}

// onEgressRefusal is r's hook for the relay handler, nil when r is nil.
func (r *egressRefusalReceiver) onEgressRefusal() func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport) {
	if r == nil {
		return nil
	}
	return r.OnEgressRefusal
}

// dropped adds a run's dropped counts to those waiting for the writer and
// wakes it, never blocking. The counts of one run add together while they
// wait, so a burst of drops is never lost to a full queue; only a run new
// to a table already holding egressRefusalDropRuns runs loses its count
// (logged).
func (r *egressRefusalReceiver) dropped(runID string, n egressRefusalDropCount) {
	if runID == "" || !n.positive() {
		return
	}
	r.dropMu.Lock()
	d, ok := r.drops[runID]
	if !ok && len(r.drops) >= egressRefusalDropRuns {
		r.dropMu.Unlock()
		if r.logger != nil {
			r.logger.Warn("sandbox egress refusal: a dropped count was lost (too many runs waiting to be written)", "run", runID, "dropped", n.Dropped, "uncertain", n.Uncertain, "link_lost", n.LinkLost, "egress_closed", n.Closed)
		}
		return
	}
	d.Dropped += n.Dropped
	d.Uncertain += n.Uncertain
	d.LinkLost += n.LinkLost
	d.Closed += n.Closed
	r.drops[runID] = d
	r.dropMu.Unlock()
	select {
	case r.dropKick <- struct{}{}:
	default:
	}
}

// OnDropped is a refusal feed's dropped-count hook (audit finding O3-W2):
// refusals of the channel's run that the feed dropped past its own bound
// are added to the run's counts, kept beside its rows under the same run
// id the rows carry.
func (r *egressRefusalReceiver) OnDropped(run sandboxrelayd.RunRecord, n egressRefusalDropCount) {
	r.dropped(egressRefusalRunID(run), n)
}

// egressRefusalRunID is the run id a run's refusal rows and counts are kept
// under: the stored terminal run when the relay run is bound to one, else
// the relay run.
func egressRefusalRunID(run sandboxrelayd.RunRecord) string {
	if run.TerminalRunID != "" {
		return run.TerminalRunID
	}
	return run.RunID
}

// onDropped is r's dropped-count hook, nil when r is nil.
func (r *egressRefusalReceiver) onDropped() func(sandboxrelayd.RunRecord, egressRefusalDropCount) {
	if r == nil {
		return nil
	}
	return r.OnDropped
}
