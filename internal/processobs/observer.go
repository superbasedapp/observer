package processobs

import (
	"context"
	"maps"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Backend is the OS event source. Implementations (linuxebpf / etw /
// endpointsec / poll) live in their own packages and own all privileged
// code; this package only consumes the channel.
type Backend interface {
	// Name identifies the backend for health/doctor (e.g. "linux_ebpf").
	Name() string
	// Start begins capture and returns the event channel, which the backend
	// closes when capture ends. An error means the backend is unavailable
	// (missing privileges, unsupported kernel, …) — the Observer reports
	// degraded health and the daemon continues (fail-open, spec §15).
	Start(ctx context.Context) (<-chan RawEvent, error)
	// Close releases backend resources. Safe to call after a Start error.
	Close() error
}

// UnattributedCapturer is an OPTIONAL Backend capability. A backend that
// implements it and returns true produces events that cannot be attributed at
// capture time — the cross-OS bridge (§5.5) is the case: the pidbridge holds
// WSL-side pids, so a Windows bridge event never gets a direct hit and arrives
// AttrNone. The daemon must then capture unattributed runs (so they persist)
// and rely on the deferred CorrelateCrossOS pass to join them to a session.
// Branching on this capability — not on the backend's name — keeps the wiring
// rule-compliant (CLAUDE.md: branch on capabilities, never source identity).
type UnattributedCapturer interface {
	RequiresUnattributedCapture() bool
}

// NetworkSampler is an OPTIONAL Backend capability: a backend that maintains
// live per-process CUMULATIVE socket byte counters (today: the Linux eBPF
// backend's TCP fentry/fexit probes). The daemon feeds NetworkBytes into the
// metric-sampling backend so the live chart's network series comes from the
// same MetricSample stream as CPU/RSS/disk.
//
// It is a CAPABILITY, not a backend name (CLAUDE.md rule 3): a future ETW or
// eBPF-socket implementation just implements it. A backend that cannot measure
// bytes simply does not implement the interface, and the samples then carry
// NetMeasured=false — "unmeasured", never a fabricated zero.
type NetworkSampler interface {
	// NetworkBytes reports cumulative bytes for one pid. ok=false means
	// accounting is not live (unmeasured); ok=true with (0,0) means measured
	// and idle.
	NetworkBytes(pid int) (in, out int64, ok bool)
}

// Enricher fills OS-specific envelope fields on a RawEvent in place (e.g.
// the Linux backend reads /proc/<pid>/...) and returns the process
// environment for posture capture. Optional: a nil Enricher means events
// arrive already enriched and no env is captured.
type Enricher interface {
	Enrich(ev *RawEvent) (env map[string]string, err error)
}

// DeepEnricher performs a targeted, per-NEW-process enrichment AFTER
// attribution has decided a run will be persisted. It reads the sensitive or
// expensive data the cheap whole-table enrichment deliberately skips — the
// process environment for posture (spec §8.1) and the executable content for
// hashing (§8 Executable / §19 Q6) — exactly ONCE per persisted run, never
// across the whole process table every poll. The OS-specific implementation
// (Linux reads /proc/<pid>/environ + hashes /proc/<pid>/exe) lives outside
// this pure package and is injected; a nil DeepEnricher means no deep
// enrichment. It mutates the run in place and MUST be best-effort and
// fail-open: a process that already exited or a file it cannot read simply
// leaves the field empty. Distinct from Enricher, which runs per-event and
// pre-attribution over every observed process.
type DeepEnricher interface {
	DeepEnrich(run *ProcessRun)
}

// Sink persists finished runs. The store implements it and translates
// ProcessRun into its own SQL row type at the boundary; process_key is
// UNIQUE, so PersistRuns upserts (insert at exec, update at exit).
type Sink interface {
	PersistRuns(ctx context.Context, runs []ProcessRun) (int, error)
}

// Options configures an Observer.
type Options struct {
	Backend             Backend
	Enricher            Enricher     // optional
	DeepEnricher        DeepEnricher // optional, post-attribution per-new-run
	Attributor          *Attributor  // required
	Sink                Sink         // required
	EventSink           EventSink    // optional high-signal event sink
	CaptureUnattributed bool         // §9.2.7 / D5
	// CaptureUnattributedAISubtree persists an unattributed run when it (or a
	// live ancestor) is a distinctive AI-tool launcher — codex/cursor/… on a
	// native host where no pid-seed/env-token resolves — so the deferred
	// CorrelateCrossOS cwd pass can join them to a session. Bounded to AI
	// subtrees, unlike CaptureUnattributed (whole table). A no-op when
	// CaptureUnattributed is already true.
	CaptureUnattributedAISubtree bool
	// ExcludeOwnBasenames are executable basenames the Observer never captures
	// as an unattributed run — the observer daemon's own binary and its
	// short-lived subcommands (`observer hook`, the cross-OS `observer.exe`
	// bridge). When an AI session is active in the same directory the daemon
	// runs from, those share its cwd, so without this the cwd-anchored and
	// AI-subtree capture paths would persist the observer's own processes and
	// the deferred cwd pass would mis-join them to that session (observed:
	// `observer ×18` attributed to a Codex session in the observer repo).
	// observer is never an AI-tool worker, so excluding it is unambiguous.
	// Empty = exclude nothing.
	ExcludeOwnBasenames []string
	BatchSize           int // store batch (spec §15: 100–500); default 250
	MaxTracked          int // live-tree cap for never-exiting procs; 0 = unbounded
	// MaxRetainedRuns bounds how many runs may be HELD BACK across flush ticks
	// after the sink failed transiently (see runFlusher). It is
	// the memory ceiling on retention, not a retry count: the observer keeps
	// re-offering the held rows every flush tick for as long as they fit, and
	// releases the OLDEST beyond this cap as DropSinkRetryExhausted.
	//
	// Default DefaultMaxRetainedRuns. A NEGATIVE value disables retention
	// entirely and restores the pre-2026-08-27 behaviour (any sink error drops
	// the whole batch at once) — it exists so that behaviour can be tested and
	// mutation-proven, not because any install should want it. Zero means
	// "default", matching every other size knob on this struct.
	MaxRetainedRuns int
	FlushInterval   time.Duration
	// ShutdownFlushTimeout bounds the flushes that run AFTER Run's context has
	// been cancelled — the buffered hand-off drain plus the final flush.
	//
	// It exists because those flushes must NOT use the cancelled context. The
	// sink is a real database: a cancelled context makes every PersistRuns fail
	// instantly with context.Canceled, so on the ordinary shutdown path
	// (SIGINT, `observer stop`, a daemon restart) the last batch of process
	// capture was never written at all — it was counted as sink_shutdown and
	// discarded. The counter was honest; the loss was avoidable. Shutdown
	// therefore flushes on a context DETACHED from the cancellation, and this
	// value is what keeps "detached" from meaning "unbounded": the deadline
	// starts at the first post-cancel flush and covers the whole drain, so the
	// shutdown barrier in Run stays bounded even against a wedged sink.
	//
	// Default DefaultShutdownFlushTimeout. ≤ 0 applies the default; there is no
	// "unlimited" sentinel, because an unbounded shutdown is the failure mode
	// the bound exists to prevent.
	ShutdownFlushTimeout time.Duration
	// Now is the clock. It is called from BOTH the drain and the flusher
	// goroutine (the flush duration is measured on the latter), so an injected
	// clock must be safe for concurrent use — a plain closure over a constant,
	// or an atomically-read value, never an unguarded mutable field.
	Now func() time.Time
	// LateSeed governs the late-seed re-resolution pass (lateseed.go): the
	// deferred re-probe that upgrades a live run whose pidbridge seed arrived
	// AFTER exec — the 30–266s `discovered` correlation lag that exec-time
	// resolution always loses. The zero value means "all defaults" (the pass
	// is ON); a negative LateSeed.Interval turns it off.
	LateSeed LateSeedPolicy
	// NetworkAccounting is the shared status handle written by whichever
	// backend owns the per-process byte probes; the Observer only READS it, to
	// republish in the health snapshot so doctor/dashboard can distinguish
	// "measured zero" from "not measured". Optional (nil = off).
	NetworkAccounting *NetworkAccounting
	// TransportUnavailableReason is the reason a REQUESTED dial-in capture
	// transport could not be created — a bind conflict on the listen address,
	// an unwritable token file, the feature's config block left disabled. It
	// is the "requested but not running" half of the TransportState tri-state
	// (see HealthSnapshot.TransportState), and empty is the normal case.
	//
	// It is a PLAIN VALUE on Options, deliberately, rather than something the
	// daemon attaches to the Backend. The obvious alternative — wrapping the
	// assembled backend in a small decorator that answers
	// TransportUnavailableSource — silently DESTROYS every other optional
	// capability the wrapped backend implements: embedding an interface
	// promotes only that interface's method set, so a type assertion for
	// UnattributedCapturer (or NetworkSampler, or any capability added later)
	// fails on the wrapper. That is not a hypothetical: the daemon probes
	// UnattributedCapturer to decide whether cross-OS process rows are
	// persisted at all, so a wrapper over a bridge-bearing baseline turned
	// cross-OS capture off, silently, on exactly the path that exists to
	// report a failure loudly. A decorator that must be revisited whenever a
	// capability is added is a standing trap (CLAUDE.md rule 6); a field that
	// never touches the backend cannot lose one.
	//
	// A backend that genuinely OWNS a failed transport may still report it
	// through TransportUnavailableSource; that capability is unchanged and
	// takes precedence. This field is for the case where the transport never
	// became a backend at all.
	TransportUnavailableReason string
}

// Observer is the orchestrator: it drains the backend, enriches, attributes,
// applies the capture policy, batches to the sink, and tracks health.
//
// It runs on exactly TWO goroutines, split at one seam. The DRAIN loop (Run)
// owns the backend channel, the Attributor and the current batch, and is
// single-goroutine, so the Attributor still needs no locking. The FLUSHER
// (runFlusher) owns the sink, the retained slice and the retention decision,
// and never touches the Attributor. They meet only at a buffered channel of
// completed batches — see Run for why the flush cannot live on the drain.
type Observer struct {
	backend             Backend
	enricher            Enricher
	deepEnricher        DeepEnricher
	attr                *Attributor
	sink                Sink
	eventSink           EventSink
	captureUnattributed bool
	captureAISubtree    bool
	excludeOwn          map[string]bool
	batchSize           int
	maxTracked          int
	maxRetainedRuns     int
	// handoffBatches is the capacity, in BATCHES, of the drain→flusher
	// hand-off channel, and maxBacklogRuns bounds the rows the DRAIN side may
	// hold when that channel is full. Both are derived from maxRetainedRuns in
	// NewObserver so the whole pipeline stays inside one memory budget — see
	// handoffCapacity.
	handoffBatches       int
	maxBacklogRuns       int
	flushInterval        time.Duration
	shutdownFlushTimeout time.Duration
	lateSeed             LateSeedPolicy
	now                  func() time.Time
	health               *Health

	// activeRoots is the set of NORMALIZED project roots of currently-active
	// sessions, refreshed out-of-band by the daemon (SetActiveSessionRoots).
	// An unattributed process whose cwd is in this set is captured even when it
	// has no distinctive AI-tool launcher — the generic-interpreter tools
	// (hermes-as-python, pi, roo-code, in-IDE Copilot/Cline) run their workers
	// in the project dir, so this is what extends process attribution to EVERY
	// adapter. Read on the single Run goroutine; written by the refresher.
	activeRoots atomic.Pointer[map[string]struct{}]
}

// DefaultMaxRetainedRuns is the default ceiling on runs held back across
// flush ticks while the sink is failing transiently (Options.MaxRetainedRuns).
//
// It is sized as a MULTIPLE of the default batch — 20 × 250 — so the default
// retention covers roughly 40 s of a busy box at the 2 s flush interval, which
// comfortably outlasts SQLite's 30 s busy_timeout and therefore the entire
// window in which a competing writer can hold the lock. A ProcessRun snapshot
// is small (the metric ring is downsampled at the persist boundary), so the
// whole ceiling is single-digit MB — bounded, and cheap next to losing the
// capture history it protects.
const DefaultMaxRetainedRuns = 5000

// DefaultShutdownFlushTimeout bounds the post-cancellation flushes
// (Options.ShutdownFlushTimeout).
//
// Sized against the thing it has to outlast: SQLite's busy_timeout is 30 s, and
// the worst flush ever measured on the live node was 31,179 ms under lock
// contention (2026-08-26). A shorter budget would reintroduce the very loss
// this deadline exists to prevent — the batch would be abandoned mid-write
// exactly when the database is contended. It is a CEILING on a path that
// normally completes in milliseconds, not a delay anyone pays on a healthy
// shutdown: the flusher returns as soon as the sink does.
const DefaultShutdownFlushTimeout = 45 * time.Second

// minHandoffBatches / maxHandoffBatches clamp the drain→flusher hand-off
// channel. The FLOOR matters more than it looks: a deployment that shrinks
// MaxRetainedRuns must still leave the drain somewhere to put a batch while
// the flusher is inside a slow PersistRuns, or the decoupling buys nothing.
// With a small BatchSize the floor is a handful of rows, so it costs nothing.
const (
	minHandoffBatches = 8
	maxHandoffBatches = 64
)

// handoffCapacity derives the drain→flusher channel depth (in batches) and the
// bound on rows the DRAIN may hold while that channel is full, from the single
// memory knob the operator actually sets (Options.MaxRetainedRuns).
//
// The budget is deliberately SPLIT rather than duplicated: the hand-off buffer
// and the drain-side backlog together get one MaxRetainedRuns, so the whole
// pipeline holds at most ~2× that ceiling (the flusher's own retention, plus
// everything still upstream of it) instead of multiplying the bound by the
// number of places a run can sit. A negative MaxRetainedRuns disables the
// SINK RETENTION (see the field doc), not the hand-off — those are different
// decisions — so it falls back to the default for this sizing.
func handoffCapacity(maxRetainedRuns, batchSize int) (batches, backlogRuns int) {
	budget := maxRetainedRuns
	if budget < 0 {
		budget = DefaultMaxRetainedRuns
	}
	batches = budget / (2 * batchSize)
	batches = max(min(batches, maxHandoffBatches), minHandoffBatches)
	// At least one whole batch, or a tiny cap would truncate the very first
	// overflow down to nothing.
	backlogRuns = max(budget/2, batchSize)
	return batches, backlogRuns
}

// NewObserver builds an Observer from Options, applying defaults.
func NewObserver(opts Options) *Observer {
	if opts.BatchSize <= 0 {
		opts.BatchSize = 250
	}
	if opts.MaxRetainedRuns == 0 {
		opts.MaxRetainedRuns = DefaultMaxRetainedRuns
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}
	if opts.ShutdownFlushTimeout <= 0 {
		opts.ShutdownFlushTimeout = DefaultShutdownFlushTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	name := ""
	// transport is the capability probe (never a backend-name check, CLAUDE.md
	// rule 3): a backend that owns a dial-in capture transport reports its
	// connection health through it, and every other backend leaves it nil so
	// the surfaces stay silent about a transport that does not exist.
	var transport func() (TransportStats, bool)
	// transportUnavailable is the SECOND half of the same probe: "you asked
	// for the cross-OS feed and it is not running" must be a reportable state
	// instead of silence. It has TWO sources, resolved here once and in this
	// order — a backend that OWNS a failed transport reports it through the
	// TransportUnavailableSource capability, and otherwise the plain
	// Options.TransportUnavailableReason carries a transport that never
	// became a backend at all. The backend is never wrapped to carry it (see
	// Options.TransportUnavailableReason for what wrapping destroys).
	var transportUnavailable func() string
	var backendUnavailable func() string
	if opts.Backend != nil {
		name = opts.Backend.Name()
		if src, ok := opts.Backend.(TransportStatsSource); ok {
			transport = src.TransportStats
		}
		if src, ok := opts.Backend.(TransportUnavailableSource); ok {
			backendUnavailable = src.TransportUnavailableReason
		}
	}
	if backendUnavailable != nil || opts.TransportUnavailableReason != "" {
		staticReason := opts.TransportUnavailableReason
		transportUnavailable = func() string {
			if backendUnavailable != nil {
				if r := backendUnavailable(); r != "" {
					return r
				}
			}
			return staticReason
		}
	}
	var excludeOwn map[string]bool
	if len(opts.ExcludeOwnBasenames) > 0 {
		excludeOwn = make(map[string]bool, len(opts.ExcludeOwnBasenames))
		for _, b := range opts.ExcludeOwnBasenames {
			if b != "" {
				excludeOwn[b] = true
			}
		}
	}
	handoffBatches, maxBacklogRuns := handoffCapacity(opts.MaxRetainedRuns, opts.BatchSize)
	return &Observer{
		backend:              opts.Backend,
		enricher:             opts.Enricher,
		deepEnricher:         opts.DeepEnricher,
		attr:                 opts.Attributor,
		sink:                 opts.Sink,
		eventSink:            opts.EventSink,
		captureUnattributed:  opts.CaptureUnattributed,
		captureAISubtree:     opts.CaptureUnattributedAISubtree,
		excludeOwn:           excludeOwn,
		batchSize:            opts.BatchSize,
		maxTracked:           opts.MaxTracked,
		maxRetainedRuns:      opts.MaxRetainedRuns,
		handoffBatches:       handoffBatches,
		maxBacklogRuns:       maxBacklogRuns,
		flushInterval:        opts.FlushInterval,
		shutdownFlushTimeout: opts.ShutdownFlushTimeout,
		lateSeed:             opts.LateSeed.withDefaults(),
		now:                  opts.Now,
		health:               newHealth(name, opts.NetworkAccounting, transport, transportUnavailable),
	}
}

// Health exposes the live counters for metrics/doctor.
func (o *Observer) Health() *Health { return o.health }

// SetActiveSessionRoots installs the set of active-session project roots used
// by the cwd-anchored capture (see the activeRoots field). Roots are
// normalized with the same folding CorrelateCrossOS uses, so a Windows-shaped
// session root and a WSL-shaped process cwd that name the same directory match.
// Safe to call concurrently with Run; an empty/nil slice disables the signal.
func (o *Observer) SetActiveSessionRoots(roots []string) {
	m := make(map[string]struct{}, len(roots))
	for _, r := range roots {
		if n := normalizePath(r); n != "" {
			m[n] = struct{}{}
		}
	}
	o.activeRoots.Store(&m)
}

// cwdInActiveRoot reports whether a process cwd falls inside an active
// session's project root. Normalizes the cwd the same way as the root set.
// False for an empty cwd or an unset/empty set.
func (o *Observer) cwdInActiveRoot(cwd string) bool {
	m := o.activeRoots.Load()
	if m == nil || len(*m) == 0 {
		return false
	}
	n := normalizePath(cwd)
	if n == "" {
		return false
	}
	_, ok := (*m)[n]
	return ok
}

// Run drains the backend until the channel closes or ctx is cancelled,
// handing completed batches to the flusher goroutine as it goes. A backend
// Start error is returned after recording degraded health; callers log it and
// keep the daemon running.
//
// Run OWNS the drain half only. Persistence runs on a SEPARATE goroutine
// (runFlusher) because the flush used to be synchronous here, and its duration
// was therefore also the length of a capture BLACKOUT: a 31,179 ms flush was
// measured on the live node (SQLite busy_timeout contention, 2026-08-26), and
// for those 31 s nothing read the backend channel — a snapshot-diff backend
// that blocks on send stops ENUMERATING, so processes born and gone inside the
// window were never observed at all. No drop counter can see that loss, which
// is why the coupling had to go rather than be measured better.
//
// Run does not return until the flusher has exited (the shutdown barrier), so
// a caller that sees Run return knows the final batch has been offered to the
// sink and every drop has been counted.
func (o *Observer) Run(ctx context.Context) error {
	ch, err := o.backend.Start(ctx)
	if err != nil {
		o.health.setBackendUp(false)
		o.health.setError(err.Error())
		return err
	}
	o.health.setBackendUp(true)
	defer func() {
		o.health.setBackendUp(false)
		_ = o.backend.Close()
	}()

	// handoff carries completed batches to the single flusher goroutine. ONE
	// flusher, FIFO channel: process_runs upserts on process_key, so a later
	// snapshot of a run must be applied after the earlier one, and a second
	// flusher would race two snapshots of the same key into the sink.
	handoff := make(chan []ProcessRun, o.handoffBatches)
	flusherDone := make(chan struct{})
	go o.runFlusher(ctx, handoff, flusherDone)
	// The shutdown BARRIER. Registered after the backend-close defer so it runs
	// FIRST (LIFO): closing the hand-off is what tells the flusher to perform
	// its final flush, and Run must not return before that has finished — a
	// leaked flusher would keep writing after the daemon believed it stopped.
	defer func() {
		close(handoff)
		<-flusherDone
	}()

	ticker := time.NewTicker(o.flushInterval)
	defer ticker.Stop()

	// Late-seed re-resolution ticker. It runs on THIS goroutine — the same one
	// that drives the Attributor — so the pass needs no locking, exactly like
	// exec-time resolution. A nil channel (policy disabled) blocks forever, so
	// the select arm is simply never taken.
	var lateSeedC <-chan time.Time
	if o.lateSeed.Enabled() {
		lateSeedTicker := time.NewTicker(o.lateSeed.Interval)
		defer lateSeedTicker.Stop()
		lateSeedC = lateSeedTicker.C
	}

	batch := make([]ProcessRun, 0, o.batchSize)

	// handOff offers the current batch to the flusher WITHOUT blocking. That
	// non-blocking property is the entire point of this task: whatever the
	// sink is doing, the next line of this goroutine runs now and the backend
	// keeps being drained.
	//
	// A full hand-off buffer does NOT discard the batch — it keeps it and
	// retries on the next append or tick, so a brief flusher stall costs
	// nothing at all. Only when the drain-side backlog exceeds maxBacklogRuns
	// does anything go, and then the OLDEST rows go under a named counter
	// (DropFlushBacklog): the newest snapshot of a run carries its exit status
	// and can still land a usable row, so dropping the newest would leave the
	// row looking permanently live — the same reasoning as the sink retention.
	handOff := func() {
		if len(batch) == 0 {
			return
		}
		select {
		case handoff <- batch:
			// A FRESH slice, never batch[:0]: the flusher now owns the array
			// that was just sent, and reusing it would rewrite rows it has not
			// persisted yet.
			batch = make([]ProcessRun, 0, o.batchSize)
			o.health.observeHandoffDepth(int64(len(handoff)))
		default:
			o.health.incFlushBacklog()
			o.health.observeHandoffDepth(int64(cap(handoff)))
			if over := len(batch) - o.maxBacklogRuns; over > 0 {
				o.health.addDropped(DropFlushBacklog, int64(over))
				// Copy rather than reslice, so a repeatedly-overflowing
				// backlog cannot pin an ever-growing backing array.
				kept := make([]ProcessRun, len(batch)-over, max(len(batch)-over, o.batchSize))
				copy(kept, batch[over:])
				batch = kept
			}
		}
		// The live-tree cap stays on THIS goroutine: the Attributor is
		// drain-owned and single-threaded by construction, and touching it
		// from the flusher would need locking the whole design avoids. It runs
		// on every hand-off attempt (and every tick) rather than only on a
		// successful flush; it is a no-op below the cap, so running it more
		// often can only bound memory sooner.
		o.attr.EvictOldestLive(o.maxTracked)
	}
	// handOffFinal is the shutdown path, and here the send DOES block — on
	// purpose. There is no next tick to retry on, so the last batch must reach
	// the flusher; the flusher only ever receives from this channel and Run
	// closes it only after this returns, so the send always completes.
	handOffFinal := func() {
		if len(batch) == 0 {
			return
		}
		handoff <- batch
		batch = nil
	}

	for {
		select {
		case <-ctx.Done():
			handOffFinal()
			return ctx.Err()
		case ev, ok := <-ch:
			if !ok {
				handOffFinal()
				return nil
			}
			if ev.Type == EventNetworkConnect {
				o.handleNetworkConnect(ctx, &ev)
				continue
			}
			o.health.setQueueDepth(int64(len(ch)))
			if run, change := o.handle(&ev); change != ChangeNone && run != nil {
				// SnapshotForPersist (not *run) is the persist boundary: it
				// downsamples the live-chart ring into a FRESH slice, so the
				// stored JSON stays small and the batched copy can never be
				// mutated by subsequent in-place ring refreshes.
				batch = append(batch, o.attr.SnapshotForPersist(run))
				if len(batch) >= o.batchSize {
					handOff()
				}
			}
		case <-lateSeedC:
			// Re-probe the seed source for live runs whose pidbridge row landed
			// after exec, and re-inherit down their subtrees. Every changed run
			// is persisted through the same SnapshotForPersist boundary the
			// lifecycle path uses, so the upgrade reaches the DB (and the
			// dashboard's resource chart) on the very next flush.
			for _, run := range o.lateSeedPass() {
				batch = append(batch, o.attr.SnapshotForPersist(run))
				if len(batch) >= o.batchSize {
					handOff()
				}
			}
		case <-ticker.C:
			if len(batch) == 0 {
				// handOff would no-op, but the live-tree cap must not become
				// contingent on capture volume — an idle box with a huge tree
				// of never-exiting processes is exactly when it matters.
				o.attr.EvictOldestLive(o.maxTracked)
				continue
			}
			handOff()
		}
	}
}

// runFlusher is the SINGLE owner of persistence: it drains the hand-off
// channel, calls the sink, and owns the retained slice and the
// retainAfterSinkFailure decision (CLAUDE.md rule 4 — the retention decision
// must not split across goroutines). Nothing else may call PersistRuns.
//
// It is deliberately a plain FIFO consumer with no concurrency inside: the
// sink upserts on process_key, so ordering is a correctness property, not a
// performance nicety. When the channel closes it performs ONE final flush with
// final=true, releasing whatever is still retained under DropSinkShutdown, and
// only then closes done — that is the barrier Run waits on.
//
// Every sink call goes through shutdownAwareContext, which is what makes the
// shutdown path actually WRITE instead of merely counting its losses honestly
// (task 9g follow-up). See that function for why the cancelled context must
// not reach PersistRuns.
func (o *Observer) runFlusher(ctx context.Context, in <-chan []ProcessRun, done chan<- struct{}) {
	defer close(done)
	flushCtx, cancel := o.shutdownAwareContext(ctx)
	defer cancel()
	// retained holds the runs a TRANSIENT sink failure could not persist. They
	// are re-offered, oldest first, on every subsequent flush — the fix for the
	// drop class where one momentary `database is locked` silently destroyed a
	// whole 250-row batch of process history (task 9c). Bounded by
	// o.maxRetainedRuns; see retainAfterSinkFailure.
	var retained []ProcessRun
	for pending := range in {
		retained = o.flushPending(flushCtx(), retained, pending, false)
	}
	o.flushPending(flushCtx(), retained, nil, true)
}

// shutdownAwareContext returns the context every flush should use, plus one
// cleanup func. While ctx is live it hands back ctx unchanged — normal
// operation is untouched. Once ctx is cancelled it hands back a DETACHED
// context carrying a fresh o.shutdownFlushTimeout deadline, created lazily on
// the first post-cancel call and reused for every flush after it.
//
// The bug this closes: Run's context is also the flusher's, so on the ordinary
// shutdown path (SIGINT, `observer stop`, a restart) the buffered hand-off
// drain and the final flush all called PersistRuns with an ALREADY-CANCELLED
// context. Against a real store that fails immediately — database/sql checks
// ctx before it touches the driver — so the last batch of process capture was
// never attempted, and everything landed in the DropSinkShutdown counter. The
// counter was accurate and the loss was entirely avoidable: nothing about a
// cancelled shutdown makes a 250-row upsert impossible, it just made it
// forbidden.
//
// Detaching is therefore the fix, and the deadline is what keeps detaching
// safe. The deadline is created ONCE and shared, not per flush, so a wedged
// sink cannot extend the shutdown one batch at a time: the whole post-cancel
// drain fits inside a single budget, and Run's barrier stays bounded.
//
// The returned cancel is always safe to call and releases the timer.
func (o *Observer) shutdownAwareContext(ctx context.Context) (func() context.Context, context.CancelFunc) {
	var (
		shutdown       context.Context
		cancelShutdown context.CancelFunc
	)
	next := func() context.Context {
		if ctx.Err() == nil {
			return ctx
		}
		if shutdown == nil {
			shutdown, cancelShutdown = context.WithTimeout(
				context.WithoutCancel(ctx), o.shutdownFlushTimeout,
			)
		}
		return shutdown
	}
	cleanup := func() {
		if cancelShutdown != nil {
			cancelShutdown()
		}
	}
	return next, cleanup
}

// flushPending offers retained-then-incoming to the sink and returns what is
// still held. Best-effort: a sink failure is never fatal (fail-open) — the
// drain keeps running either way, and the only question is whether the rows
// get another chance.
//
// The flush DURATION is still measured here even though it no longer stalls
// capture, because it remains the signal that the database is contended (and
// the number the bounded-flush-deadline decision will be taken against).
func (o *Observer) flushPending(ctx context.Context, retained, incoming []ProcessRun, final bool) []ProcessRun {
	if len(retained) == 0 && len(incoming) == 0 {
		return nil
	}
	// Oldest first: the sink upserts on process_key, so a later snapshot of
	// the same run must be applied after the earlier one.
	pending := retained
	retained = nil
	pending = append(pending, incoming...)

	flushStart := o.now()
	if _, err := o.sink.PersistRuns(ctx, pending); err != nil {
		retained = o.retainAfterSinkFailure(pending, err, final)
	}
	o.health.observeFlush(o.now().Sub(flushStart))
	o.health.setSinkRetained(int64(len(retained)))
	return retained
}

// retainAfterSinkFailure decides what survives a failed PersistRuns, and is
// the single owner of that decision (CLAUDE.md rule 4). It returns the runs to
// re-offer on the next flush and COUNTS everything it releases, so no run ever
// disappears without a named reason in the health snapshot — the property that
// made the original drop anomaly undiagnosable from outside the daemon.
//
// Three outcomes, in the order they are tested:
//
//   - final flush — there is no next tick to retry on, so anything still
//     unpersisted is a real loss: DropSinkShutdown (transient/unknown) or
//     DropSinkError (permanent, which names the actual cause).
//   - permanent failure — no retry can change the outcome, and holding the
//     rows would only occupy the retention against runs that could still
//     land: DropSinkError, released immediately. This preserves the
//     pre-existing behaviour for the failures that genuinely deserve it.
//   - transient or unknown failure — RETAIN, oldest released first if the
//     batch exceeds the cap (DropSinkRetryExhausted).
//
// Releasing the OLDEST rather than the newest is deliberate: process_runs is
// upserted on process_key with COALESCE-style column merging, so the newest
// snapshot of a run carries its exit status and final metrics and can still
// land a usable row on its own. Dropping the newest would leave the row
// looking permanently live.
func (o *Observer) retainAfterSinkFailure(pending []ProcessRun, err error, final bool) []ProcessRun {
	class := o.classifySinkError(err)
	switch {
	case final:
		reason := DropSinkShutdown
		if class == SinkErrorPermanent {
			reason = DropSinkError
		}
		o.health.addDropped(reason, int64(len(pending)))
		return nil
	case !class.Retain():
		o.health.addDropped(DropSinkError, int64(len(pending)))
		return nil
	case o.maxRetainedRuns < 0:
		// Retention explicitly disabled (see Options.MaxRetainedRuns): the
		// rows are lost now, and counted as the plain sink error they are.
		o.health.addDropped(DropSinkError, int64(len(pending)))
		return nil
	case len(pending) > o.maxRetainedRuns:
		over := len(pending) - o.maxRetainedRuns
		o.health.addDropped(DropSinkRetryExhausted, int64(over))
		// Copy rather than reslice: pending[over:] would pin the whole
		// backing array, so a repeatedly-overflowing retention would keep
		// growing the very memory this cap exists to bound.
		kept := make([]ProcessRun, o.maxRetainedRuns)
		copy(kept, pending[over:])
		return kept
	default:
		return pending
	}
}

// lateSeedPass runs one late-seed re-resolution and returns the runs whose
// attribution changed. Split out of Run so tests can drive it deterministically
// without a real ticker.
//
// Note what it deliberately does NOT re-apply: the ExcludeOwnBasenames drop and
// the unattributed-capture policy in handle() are both gated on
// `!run.Attributed()`, so an upgraded run bypasses them — which is exactly what
// the exec path does for a run that had a seed at exec time. That is the point
// for the daemon-launched terminals: `observer <tool>` is the PTY child whose
// pid gets seeded, and self-exclusion must not survive a direct identity. It
// can only resurrect runs that were dropped for being UNATTRIBUTED (or
// self-excluded while unattributed) — the other drop reasons (no_start_time,
// enrich_failed) reject the event before it ever enters the tree, so there is
// nothing there for this pass to reach.
func (o *Observer) lateSeedPass() []*ProcessRun {
	res := o.attr.ReconcileLateSeeds(o.now(), o.lateSeed)
	if len(res.Upgraded) == 0 {
		return nil
	}
	o.health.addLateSeedUpgrades(int64(res.Roots), int64(res.Reinherited))
	for _, run := range res.Upgraded {
		o.health.incAttributed(run.Attribution.Tool)
	}
	return res.Upgraded
}

func (o *Observer) handleNetworkConnect(ctx context.Context, ev *RawEvent) {
	o.health.incEvent(ev.Type)
	if o.eventSink == nil {
		return
	}
	run := o.attr.RunForEvent(*ev)
	if run == nil || !run.Attributed() {
		o.health.addDropped(DropUnattributed, 1)
		return
	}
	target := networkTarget(*ev)
	if target == "" {
		target = "unknown"
	}
	details := map[string]any{
		"capture_source":            "process_backend",
		"protocol":                  ev.NetworkProtocol,
		"family":                    ev.NetworkFamily,
		"remote_addr":               ev.RemoteAddr,
		"remote_port":               ev.RemotePort,
		"local_addr":                ev.LocalAddr,
		"local_port":                ev.LocalPort,
		"status":                    ev.NetworkStatus,
		"bytes_in":                  ev.NetworkBytesIn,
		"bytes_out":                 ev.NetworkBytesOut,
		"body_unavailable_reason":   "metadata_only_non_plaintext",
		"payload_capture_supported": false,
	}
	event := ProcessEvent{
		ProcessRunID: 0,
		ProcessKey:   run.ProcessKey,
		Timestamp:    firstTime(ev.Timestamp, o.now()),
		Type:         EventNetworkConnect,
		Attribution:  run.Attribution,
		TargetKind:   "network_endpoint",
		Target:       target,
		Severity:     "info",
		Details:      details,
	}
	if _, err := o.eventSink.PersistProcessEvents(ctx, []ProcessEvent{event}); err != nil {
		o.health.addDropped(DropEventSinkError, 1)
	}
}

func networkTarget(ev RawEvent) string {
	host := ev.RemoteHost
	if host == "" {
		host = ev.RemoteAddr
	}
	if host == "" {
		return ""
	}
	if ev.RemotePort > 0 {
		return net.JoinHostPort(host, strconv.Itoa(ev.RemotePort))
	}
	return host
}

func firstTime(vals ...time.Time) time.Time {
	for _, v := range vals {
		if !v.IsZero() {
			return v
		}
	}
	return time.Time{}
}

// handle folds one event through enrich → attribute → capture policy and
// returns the run to persist (or ChangeNone to skip). Exposed-ish via Run;
// kept separate so tests can drive it deterministically.
func (o *Observer) handle(ev *RawEvent) (*ProcessRun, Change) {
	o.health.incEvent(ev.Type)

	// fork/exec need a start time for a stable key (§9.3); exit can fall
	// back to the live-pid map, so it is not dropped here.
	if (ev.Type == EventFork || ev.Type == EventExec) && !ev.HasStartTime {
		o.health.addDropped(DropNoStartTime, 1)
		return nil, ChangeNone
	}

	var env map[string]string
	if o.enricher != nil {
		e, err := o.enricher.Enrich(ev)
		if err != nil {
			o.health.addDropped(DropEnrichFailed, 1)
			return nil, ChangeNone
		}
		env = e
	}

	run, change := o.attr.Observe(*ev, env)
	if change == ChangeNone || run == nil {
		return nil, ChangeNone
	}
	if !run.Attributed() {
		// The observer daemon's own binary is never an AI-tool worker: drop it
		// before any capture path so its processes don't get persisted and then
		// mis-joined to a session that happens to share the daemon's cwd (§3.1).
		if o.excludeOwn[run.ExeBasename] {
			o.health.addDropped(DropSelfExcluded, 1)
			return nil, ChangeNone
		}
		// Capture an unattributed run when any of: (a) the backend forces
		// whole-table unattributed capture (the cross-OS bridge); (b) it
		// belongs to a distinctive AI-tool subtree — codex/cursor/… with a
		// branded launcher; (c) its cwd is an active session's project root —
		// the generic-interpreter tools (hermes-as-python, pi, roo-code,
		// in-IDE Copilot/Cline) that present no branded launcher but run their
		// workers in the project dir. The deferred CorrelateCrossOS pass then
		// joins it. Everything else is dropped so the table stays bounded to
		// AI activity.
		capture := o.captureUnattributed ||
			(o.captureAISubtree && o.attr.InAISubtree(run)) ||
			o.cwdInActiveRoot(run.CWD)
		if !capture {
			o.health.addDropped(DropUnattributed, 1)
			return nil, ChangeNone
		}
	}
	if run.Attributed() {
		o.health.incAttributed(run.Attribution.Tool)
	} else {
		o.health.incUnattributed()
	}
	// Deep enrichment runs ONCE per persisted run, at the create (exec) point
	// only — the process is freshly observed and still alive, so /proc reads
	// succeed; the exit update reuses the same tracked pointer and inherits
	// these fields. Fail-open: a nil enricher or an unreadable process is a
	// no-op (spec §8.1 env posture, §8 executable hashing, §19 Q6).
	if change == ChangeCreated && o.deepEnricher != nil {
		o.deepEnricher.DeepEnrich(run)
	}
	return run, change
}

// Health holds the live process-observability counters that back the spec
// §15 metrics and the doctor health check. Guarded by a mutex: the Run loop
// writes from one goroutine, metrics/doctor read from another.
type Health struct {
	mu               sync.Mutex
	backendName      string
	backendUp        bool
	lastError        string
	queueDepth       int64
	unattributed     int64
	eventsTotal      map[EventType]int64
	dropped          map[DropReason]int64
	attributedByTool map[string]int64
	// lateSeedRoots / lateSeedReinherited count what the late-seed
	// re-resolution pass recovered: runs upgraded by a seed that arrived after
	// exec, and descendants re-inherited from them. Zero on a box where every
	// seed lands before its process is observed; non-zero is the measure of the
	// `discovered`-lag gap this pass closes.
	lateSeedRoots       int64
	lateSeedReinherited int64
	// sinkRetained is a GAUGE, not a counter: the number of runs currently
	// held back after a transient sink failure. Non-zero means the sink is
	// refusing writes right now and capture is being buffered rather than
	// lost; a value pinned at Options.MaxRetainedRuns alongside a rising
	// DropSinkRetryExhausted means the retention has been overrun.
	sinkRetained int64
	// sinkFlushMaxMs is the LONGEST single sink flush observed, and
	// queueDepthMax the high-water mark of the backend queue. Both are
	// WATERMARKS, not samples: the health record is republished every 30 s and
	// the queue gauge is only re-read when an event arrives, so a stall that
	// begins and ends between two publishes is invisible to a sampled value —
	// which is precisely the shape of the starvation this pair exists to
	// measure (see the flush closure in Run).
	sinkFlushMaxMs int64
	queueDepthMax  int64
	// handoffDepthMax is the high-water mark of the drain→flusher hand-off
	// buffer (in BATCHES) and flushBacklogHits counts how often the drain
	// found it full. Together they say how close the decoupling came to its
	// bound: a hand-off that never fills means the flusher kept up, while hits
	// climbing without any DropFlushBacklog means the drain absorbed a slow
	// sink exactly as intended — capture delayed, none lost.
	handoffDepthMax  int64
	flushBacklogHits int64
	// net is the READ-ONLY handle onto the capture backend's network-accounting
	// status (the backend is its only writer). Nil = off.
	net *NetworkAccounting
	// transport is the READ-ONLY probe onto the backend's dial-in transport
	// stats, resolved ONCE from the TransportStatsSource capability at
	// construction. Nil (or an ok=false result) means this backend has no such
	// transport, which the surfaces render as silence — never as a transport
	// with zero connections.
	transport func() (TransportStats, bool)
	// transportUnavailable is the READ-ONLY probe onto the reason a REQUESTED
	// dial-in transport could not be created, resolved once from the
	// TransportUnavailableSource capability. Health is the SINGLE resolver of
	// the resulting tri-state (CLAUDE.md rule 4): every consumer reads
	// HealthSnapshot.TransportState and none re-derives it from config.
	transportUnavailable func() string
}

func newHealth(backendName string, net *NetworkAccounting, transport func() (TransportStats, bool), transportUnavailable func() string) *Health {
	return &Health{
		net:                  net,
		transport:            transport,
		transportUnavailable: transportUnavailable,
		backendName:          backendName,
		eventsTotal:          make(map[EventType]int64),
		dropped:              make(map[DropReason]int64),
		attributedByTool:     make(map[string]int64),
	}
}

func (h *Health) setBackendUp(up bool) { h.mu.Lock(); h.backendUp = up; h.mu.Unlock() }
func (h *Health) setError(e string)    { h.mu.Lock(); h.lastError = e; h.mu.Unlock() }
func (h *Health) setQueueDepth(d int64) {
	h.mu.Lock()
	h.queueDepth = d
	if d > h.queueDepthMax {
		h.queueDepthMax = d
	}
	h.mu.Unlock()
}

// observeFlush records one sink-flush duration, keeping the maximum. A
// negative duration (a clock that went backwards, or an injected test clock)
// is ignored rather than recorded as a wild watermark.
func (h *Health) observeFlush(d time.Duration) {
	if d < 0 {
		return
	}
	ms := d.Milliseconds()
	h.mu.Lock()
	if ms > h.sinkFlushMaxMs {
		h.sinkFlushMaxMs = ms
	}
	h.mu.Unlock()
}

// observeHandoffDepth records the drain→flusher hand-off occupancy, keeping
// the maximum. A watermark for the same reason observeFlush is one: the health
// record is republished every 30 s, so a buffer that filled and drained between
// two publishes would be invisible to a sampled gauge.
func (h *Health) observeHandoffDepth(d int64) {
	h.mu.Lock()
	if d > h.handoffDepthMax {
		h.handoffDepthMax = d
	}
	h.mu.Unlock()
}

// incFlushBacklog records one hand-off that found the buffer full. Not a loss
// on its own — the drain keeps the batch and retries — so it is counted apart
// from DropFlushBacklog, which is the loss.
func (h *Health) incFlushBacklog() { h.mu.Lock(); h.flushBacklogHits++; h.mu.Unlock() }

func (h *Health) incEvent(t EventType) { h.mu.Lock(); h.eventsTotal[t]++; h.mu.Unlock() }
func (h *Health) incUnattributed()     { h.mu.Lock(); h.unattributed++; h.mu.Unlock() }
func (h *Health) incAttributed(tool string) {
	h.mu.Lock()
	if tool == "" {
		tool = "unknown"
	}
	h.attributedByTool[tool]++
	h.mu.Unlock()
}

// addLateSeedUpgrades records one late-seed pass's yield.
func (h *Health) addLateSeedUpgrades(roots, reinherited int64) {
	h.mu.Lock()
	h.lateSeedRoots += roots
	h.lateSeedReinherited += reinherited
	h.mu.Unlock()
}

// setSinkRetained records the CURRENT retained-run depth (a gauge — the flush
// path assigns it, never accumulates into it).
func (h *Health) setSinkRetained(n int64) { h.mu.Lock(); h.sinkRetained = n; h.mu.Unlock() }

func (h *Health) addDropped(reason DropReason, n int64) {
	h.mu.Lock()
	h.dropped[reason] += n
	h.mu.Unlock()
}

// HealthSnapshot is an immutable copy of the counters for metrics/doctor.
type HealthSnapshot struct {
	BackendName      string
	BackendUp        bool
	LastError        string
	QueueDepth       int64
	Unattributed     int64
	EventsTotal      map[EventType]int64
	Dropped          map[DropReason]int64
	AttributedByTool map[string]int64
	// LateSeedRoots / LateSeedReinherited report what the late-seed
	// re-resolution pass recovered (see Health.lateSeedRoots).
	LateSeedRoots       int64
	LateSeedReinherited int64
	// SinkRetained is the CURRENT number of runs held back after a transient
	// sink failure (see Health.sinkRetained). Zero is the healthy steady
	// state; non-zero says capture is being buffered, not lost.
	SinkRetained int64
	// SinkFlushMaxMs / QueueDepthMax are the sink-contention watermarks (see
	// Health.sinkFlushMaxMs). A large SinkFlushMaxMs was the evidence for the
	// capture-STARVATION half of the 2026-08-26 anomaly, when the flush ran on
	// the only goroutine draining the backend. Since task 9g it no longer
	// does, so a long flush now means "the database was contended", NOT "the
	// backend went unread" — read it beside FlushBacklogHits, which is what
	// says the stall reached the drain at all.
	SinkFlushMaxMs int64
	QueueDepthMax  int64
	// HandoffDepthMax / FlushBacklogHits report how the drain→flusher hand-off
	// coped (see Health.handoffDepthMax). Hits > 0 with no
	// Dropped[flush_backlog] means a slow sink was absorbed with nothing lost.
	HandoffDepthMax  int64
	FlushBacklogHits int64
	// NetworkAccountingMode is one of the NetworkAccounting* constants and
	// NetworkAccountingReason explains a non-live mode ("missing CAP_BPF", …).
	// This is the honest-degradation surface: "unavailable" means per-process
	// byte counts are NOT measured, so a consumer must not render them as zero.
	NetworkAccountingMode   string
	NetworkAccountingReason string
	// TransportState is one of the TransportState* constants and is the
	// honesty gate on the Transport field below. It is a TRI-state, not a
	// bool, because three different facts have to stay distinguishable:
	//
	//   none        — no dial-in transport was requested; the consumer shows
	//                 NOTHING (the 99% install).
	//   unavailable — one was requested and could not be created; the
	//                 consumer must say so, with TransportUnavailableReason.
	//                 Rendering this as silence is indistinguishable from a
	//                 feature that was never enabled.
	//   configured  — the counters in Transport are real, INCLUDING when they
	//                 are all zero (the never-connected waiting state).
	//
	// Same trap as MetricSample.NetMeasured: absent and zero are different
	// facts, and so are absent and broken.
	TransportState string
	// TransportUnavailableReason explains a TransportStateUnavailable, and is
	// empty in every other state. A state with no reason is not actionable,
	// so the resolver refuses to claim the state without one.
	TransportUnavailableReason string
	// Transport carries the transport's connection counters when
	// TransportState is configured, and is the zero value otherwise.
	Transport TransportStats
}

// TransportConfigured reports whether the snapshot's Transport counters are
// real. It is a convenience over TransportState — the state itself is the
// carried fact, so no consumer stores a second boolean.
func (h HealthSnapshot) TransportConfigured() bool {
	return h.TransportState == TransportStateConfigured
}

// Snapshot returns a deep copy of the current counters.
func (h *Health) Snapshot() HealthSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	mode, reason := h.net.Status()
	s := HealthSnapshot{
		NetworkAccountingMode:   mode,
		NetworkAccountingReason: reason,
		BackendName:             h.backendName,
		BackendUp:               h.backendUp,
		LastError:               h.lastError,
		QueueDepth:              h.queueDepth,
		Unattributed:            h.unattributed,
		LateSeedRoots:           h.lateSeedRoots,
		LateSeedReinherited:     h.lateSeedReinherited,
		SinkRetained:            h.sinkRetained,
		SinkFlushMaxMs:          h.sinkFlushMaxMs,
		QueueDepthMax:           h.queueDepthMax,
		HandoffDepthMax:         h.handoffDepthMax,
		FlushBacklogHits:        h.flushBacklogHits,
		EventsTotal:             make(map[EventType]int64, len(h.eventsTotal)),
		Dropped:                 make(map[DropReason]int64, len(h.dropped)),
		AttributedByTool:        make(map[string]int64, len(h.attributedByTool)),
	}
	// Resolve the transport tri-state HERE and nowhere else. An existing
	// transport wins over a recorded failure: if one is actually up, its
	// counters are the live truth and a stale "could not start" alongside
	// them would be the contradiction the whole surface exists to avoid.
	s.TransportState = TransportStateNone
	if h.transport != nil {
		if ts, ok := h.transport(); ok {
			s.Transport, s.TransportState = ts, TransportStateConfigured
		}
	}
	if s.TransportState == TransportStateNone && h.transportUnavailable != nil {
		if reason := h.transportUnavailable(); reason != "" {
			s.TransportState = TransportStateUnavailable
			s.TransportUnavailableReason = reason
		}
	}
	maps.Copy(s.EventsTotal, h.eventsTotal)
	maps.Copy(s.Dropped, h.dropped)
	maps.Copy(s.AttributedByTool, h.attributedByTool)
	return s
}
