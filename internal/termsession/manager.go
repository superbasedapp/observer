package termsession

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termlease"
)

// Errors returned by the Manager.
var (
	// ErrInvalidSpec is returned by Create when a required Spec field is
	// missing: BinPath and Subcommand are always required; SessionID is
	// required for a handoff launch but not for a fresh launch (Fresh=true).
	ErrInvalidSpec = errors.New("termsession: invalid spec (BinPath, Subcommand and SessionID are required)")
	// ErrTooManySessions is returned when MaxConcurrent live sessions
	// already exist. The dashboard surfaces it honestly (429-shaped).
	ErrTooManySessions = errors.New("termsession: too many concurrent terminal sessions")
	// ErrSetupInFlight is returned by Create when a labelled SpecSetup session of
	// the same kind (Spec.SetupLabel) is already being spawned concurrently — the
	// setup single-flight refusal. A privileged setup PTY (sudo login / install /
	// operator-grant) is spawned at most once per kind; the dashboard surfaces it
	// 409-shaped. Once the winner has registered, a subsequent same-label Create
	// returns the LIVE handle (idempotent) instead of this error.
	ErrSetupInFlight = errors.New("termsession: a setup session of this kind is already starting")
	// ErrNotFound is returned by Subscribe/AcquireWriter*/Close for an unknown
	// handle.
	ErrNotFound = errors.New("termsession: session not found")
	// ErrTooManySubscribers is returned by Subscribe when MaxSubscribers viewers
	// already watch a session (bounded fan-out, §4.α.1).
	ErrTooManySubscribers = errors.New("termsession: too many concurrent viewers for this session")
	// ErrNotWriter is returned by a WriterLease's Write/Resize once the lease is
	// no longer the session's live writer (revoked, taken over, or expired) — the
	// server-side side-effect drop (§4.β): no live lease ⇒ input never reaches
	// the PTY.
	ErrNotWriter = errors.New("termsession: caller does not hold the writer lease")
	// ErrNoGrant is returned by AcquireWriterRemote when the supplied WriterGrant
	// is not authorized (a zero-value or fabricated grant). The §4.δ conjunction
	// is thereby structurally unbypassable (§4.α.2a).
	ErrNoGrant = errors.New("termsession: remote writer path requires a valid WriterGrant")
	// ErrHeldLocally is returned when a remote acquire is refused because the
	// owner-local path holds the writer (no implicit steal — §4.α.3).
	ErrHeldLocally = errors.New("termsession: writer is held locally")
	// ErrWriterHeld is returned when a remote acquire is refused because another
	// remote writer already holds the lease (one input source ever).
	ErrWriterHeld = errors.New("termsession: writer lease already held")
	// ErrSetupSessionLocalOnly is returned when a remote writer acquire targets
	// a SpecSetup session. Setup sessions (e.g. the one-time Tailscale operator
	// grant that types a sudo password) are pinned local-writer-only at the
	// lease seam — a paired remote principal can NEVER drive one, regardless of
	// any (currently un-mintable) grant. CapabilityLocal on the creating POST
	// only protects minting the handle; this pins eligibility on the session
	// itself, checked at the writer-acquisition path (codex review 2026-07-13).
	ErrSetupSessionLocalOnly = errors.New("termsession: setup sessions are local-writer-only")
	// errUnsubscribed unblocks a Subscription's Read when the viewer unsubscribes
	// while the process is still alive (Unsubscribe closes the subscription). The
	// websocket bridge treats any read error as "stop reading", so it is
	// unexported.
	errUnsubscribed = errors.New("termsession: viewer unsubscribed")
)

// Default lifecycle bounds. All overridable via Options.
const (
	defaultMaxConcurrent   = 4
	defaultExitLinger      = 30 * time.Second
	defaultReapInterval    = 10 * time.Second
	defaultMaxSubscribers  = 8
	defaultWriterLeaseIdle = 5 * time.Minute
	defaultWriterLeaseMax  = 30 * time.Minute
)

// Options configures a Manager. The zero value is usable (OS spawner,
// sane bounds, wall-clock).
type Options struct {
	// Spawner creates the PTY-backed process. Nil defaults to the OS
	// spawner (creack/pty on unix; unsupported on native Windows).
	Spawner Spawner
	// MaxConcurrent caps live sessions (default 4). Create errors past it.
	MaxConcurrent int
	// MaxSubscribers caps concurrent read-only viewers PER session (default 8).
	// A slow/malicious viewer is drop-oldest degraded, never a PTY stall; this
	// bound caps the fan-out breadth so a flood of viewers can't exhaust memory.
	MaxSubscribers int
	// IdleTimeout, when > 0, reaps a session whose PTY has seen no I/O for
	// this long (any output or keystroke resets the clock). <= 0 — the
	// DEFAULT — disables idle reaping entirely: a live session stays
	// available until its child exits or it is explicitly closed. An
	// interactive agent sitting at its prompt produces zero PTY I/O for
	// hours; killing it for that reads as data loss, so continuity is the
	// default and reaping is the opt-in.
	IdleTimeout time.Duration
	// WriterLeaseIdle revokes a REMOTE writer lease with no Write/Resize for
	// this long (default 5m), refreshed on each successful write (§4.α.2c).
	// Local leases (the native wrapper, the loopback dashboard seat) AND
	// STANDING-provenance remote leases are exempt — see reapOnce.
	WriterLeaseIdle time.Duration
	// WriterLeaseMax is the hard cap on a REMOTE writer lease's lifetime
	// (default 30m) after which the holder must re-acquire (fresh capability
	// + confirm). Local leases are exempt — see reapOnce.
	WriterLeaseMax time.Duration
	// ExitLinger keeps an exited session in the registry this long after
	// the process ends, so a still-attached (or reconnecting) client can
	// read the final output + exit code before it is swept (default 30s).
	ExitLinger time.Duration
	// ReapInterval is the background reaper tick (default 10s).
	ReapInterval time.Duration
	// RingBytes bounds each session's replay ring (default 256 KiB). The
	// always-on pump drains the PTY into this ring so a reconnecting client
	// can replay recent output; older bytes are dropped once it is full.
	RingBytes int
	// Now is the clock (test hook). Nil defaults to time.Now.
	Now func() time.Time
	// Logger receives operational messages. Nil defaults to a discard
	// logger.
	Logger *slog.Logger
	// OnExit, when non-nil, fires once per session when its process exits —
	// the coarse session-exit signal the Phase-0 notification rail consumes
	// (remote-dashboard-access plan §7 Phase 0). It is invoked from the
	// waitExit goroutine AFTER the exit is recorded, in a fresh goroutine so a
	// slow/blocking sink never stalls session teardown. termsession itself has
	// no notion of notifications — this is a plain callback seam (like the
	// dashboard's LaunchManager), so the outbound HTTP lives in cmd, not here.
	OnExit func(SessionExit)
	// OnProcess, when non-nil, receives the PTY CHILD PROCESS lifecycle signal
	// — one ProcessSpawned when a session's child is running, one
	// ProcessExited when it is gone. It is the process-attribution seam: the
	// child's OS pid is otherwise known only to this package (it is used for
	// the process-group reap and then discarded), so nothing downstream can
	// attribute that process subtree to the terminal it belongs to.
	//
	// termsession stays free of any process-observation dependency — this is a
	// plain injected callback (the same discipline as OnExit / OnOutput), so
	// the pid bridge write lives in cmd, not here. Nil is a clean no-op, and an
	// event is fired ONLY when the backend actually reports a pid (see
	// ProcessReporter) — a fake PTY in a test therefore fires nothing.
	//
	// Both edges are delivered from the owning session's own goroutine and MUST
	// NOT block: spawn fires inline in Create (so a Spawned edge always precedes
	// its Exited edge), and exit fires inline on the waitExit goroutine —
	// deliberately synchronous, because the delay between the child being reaped
	// and its pid being retracted is exactly the window in which a recycled pid
	// could be misattributed to a dead terminal.
	OnProcess func(ProcessEvent)
	// OnOutput, when non-nil, is called by the always-on pump with each chunk
	// of PTY output (handle + the raw bytes). It is the UNTRUSTED byte tap for
	// the OSC hint parser (internal/termscan, F3) — termsession itself never
	// interprets the bytes; it just forwards them through this seam (the same
	// injected-callback discipline as OnExit). The callback MUST consume the
	// slice synchronously (the pump reuses the buffer) and MUST NOT block the
	// pump — a slow sink would stall a detached agent's PTY drain.
	OnOutput func(handle string, p []byte)
	// OnLeaseEvent, when non-nil, is called for every writer-lease transition
	// (acquire/release/revoke/takeover/expiry) — the metadata-only audit tap the
	// remote-execute tier consumes (plan §8.1 audit list). Content-free by
	// construction. The sink must not block.
	OnLeaseEvent func(LeaseEvent)
	// AllowRemoteTakeover is read at the exact writer-policy decision while the
	// session write fence is held. Nil defaults to true. The cmd adapter replaces
	// this source with the live remote-controller gate before serving, so a
	// dashboard toggle takes effect without a daemon restart and cannot be
	// snapshotted early at credential authorization.
	AllowRemoteTakeover func() bool
}

// SessionExit is the metadata handed to Options.OnExit when a session ends.
// Content-free by construction (ids + enums + exit code).
type SessionExit struct {
	Handle     string
	SessionID  string
	Subcommand string
	ExitCode   int
	At         time.Time
	// PID is the OS pid of the exited PTY child, or 0 when the backend did not
	// report one. Additive (2026-07-26): a consumer that seeded process
	// attribution against this pid needs the pid back to retract it. Prefer
	// Options.OnProcess for that — it fires synchronously and therefore closes
	// the pid-reuse window that OnExit's detached delivery leaves open.
	PID int
}

// ProcessEventKind classifies a [ProcessEvent] edge.
type ProcessEventKind string

const (
	// ProcessSpawned — the session's PTY child is running under PID.
	ProcessSpawned ProcessEventKind = "spawned"
	// ProcessExited — the session's PTY child has been reaped; PID is no
	// longer a valid attribution target and must be retracted.
	ProcessExited ProcessEventKind = "exited"
)

// ProcessEvent is the metadata-only PTY child-process lifecycle record handed
// to Options.OnProcess. Content-free by construction: ids, a pid, the launcher
// verb, and the (server-derived, already-validated) launch directory.
type ProcessEvent struct {
	// Kind is the lifecycle edge (ProcessSpawned / ProcessExited).
	Kind ProcessEventKind
	// Handle is the opaque terminal-session handle. It is the join key a
	// consumer uses to reach the terminal RUN identity (and, once correlation
	// establishes it, the agent session id) — the pid alone carries neither.
	Handle string
	// PID is the OS pid of the PTY's direct child (`observer <tool>`), which is
	// also its process-group / job leader, so the whole tool subtree hangs off
	// it. Always > 0 (an event is not fired otherwise).
	PID int
	// Subcommand is the observer launcher verb (e.g. "claude"). It is NOT the
	// canonical tool name — a consumer that needs that resolves it from the run
	// identity.
	Subcommand string
	// SourceSessionID is Spec.SessionID: the session a handoff launch continues
	// FROM. It is explicitly NOT the session this process subtree belongs to
	// (migration 064's identity invariant — the source and any correlated
	// target session are distinct and must never be conflated), so it is named
	// for what it is and must not be used as an attribution target.
	SourceSessionID string
	// Dir is the child's working directory as launched ("" = inherited).
	Dir string
	// ExitCode is the child's exit status; meaningful only for ProcessExited.
	ExitCode int
	// At is the event time.
	At time.Time
}

// LeaseEventKind classifies a writer-lease transition for the audit tap.
type LeaseEventKind string

const (
	// LeaseAcquired — a writer lease was granted.
	LeaseAcquired LeaseEventKind = "lease_acquired"
	// LeaseReleased — the holder voluntarily released the lease.
	LeaseReleased LeaseEventKind = "lease_released"
	// LeaseRevoked — the lease was forcibly revoked (config-off, device revoke,
	// emergency revoke, or teardown). A revoke of this kind means the DEVICE is
	// no longer trusted.
	LeaseRevoked LeaseEventKind = "lease_revoked"
	// LeaseTakenOver — a granted acquire superseded an incumbent writer. The
	// session and losing bridge remain valid; only the old writer lease is fenced.
	LeaseTakenOver LeaseEventKind = "lease_taken_over"
	// LeaseExpired — the lease reached its idle lifetime or hard cap and was
	// swept by the reaper. Split out of LeaseRevoked (2026-07-25, mobile
	// terminal-continuity arc) because the two mean OPPOSITE things to a
	// consumer: a revoke says "this device lost trust — tear the socket down",
	// whereas an expiry says "this credential aged out — re-authorize". Folding
	// expiry into LeaseRevoked made a remote bridge CLOSE the websocket when a
	// 30-minute lease simply aged out, which forced the user to re-issue
	// credentials for a session that was never in doubt. The security bound is
	// unchanged: the lease is still revoked and every write is still fenced —
	// only the socket-teardown consequence differs (see RevokeIsExpiry).
	LeaseExpired LeaseEventKind = "lease_expired"
)

// LeaseEvent is a metadata-only writer-lease transition record (never secrets,
// never terminal contents).
type LeaseEvent struct {
	Kind   LeaseEventKind
	Handle string
	Holder string // "local" or a device-session fingerprint
	// Actor is the incoming writer that caused this transition ("local" or a
	// device-session fingerprint). On a takeover Holder is the superseded seat
	// and Actor is the requester, preserving direction and accountability.
	Actor  string
	Reason string
	At     time.Time
	// Setup marks a lease transition on a privileged SpecSetup (local-only)
	// session. A consumer that persists these events to a remotely-readable
	// surface (remote_audit) MUST NOT record the opaque Handle for a setup
	// session — it stays local-only for its whole lifecycle — and should key the
	// row on Label instead (an opaque "setup:<label>" route). Set from the
	// session's own kind, never inferred by the consumer.
	Setup bool
	// Label is the SpecSetup single-flight kind tag (e.g. "tailscale-login") when
	// Setup is true; empty otherwise. It carries more forensic value than the
	// ephemeral handle and leaks no handle.
	Label string
}

// Manager is the one-owner registry of live PTY terminal sessions. It is
// safe for concurrent use; the dashboard holds exactly one per process.
type Manager struct {
	spawner         Spawner
	maxConcurrent   int
	maxSubscribers  int
	idleTimeout     time.Duration
	writerLeaseIdle time.Duration
	writerLeaseMax  time.Duration
	exitLinger      time.Duration
	ringBytes       int
	now             func() time.Time
	logger          *slog.Logger
	onExit          func(SessionExit)
	onProcess       func(ProcessEvent)
	onOutput        func(handle string, p []byte)
	onLeaseEvent    func(LeaseEvent)
	// allowRemoteTakeover holds a replaceable LIVE policy source. Sessions call
	// remoteTakeoverAllowed while holding their own writeMu at Decide time.
	allowRemoteTakeover atomic.Pointer[func() bool]
	// standingTakeoverHook, when non-nil, fires (async) after a LOCAL writer
	// acquisition supersedes a remote lease that was minted through the
	// STANDING terminal-control secret (grant.Standing()). Registered
	// post-construction by the dashboard (SetOnStandingLocalTakeover) so the
	// OPT-IN revoke-standing-on-takeover policy can kill the standing secret;
	// termsession itself never decides policy — it only reports provenance.
	standingTakeoverHook atomic.Pointer[func(handle, revokedHolder string)]

	mu       sync.Mutex
	sessions map[string]*Session
	// pending counts in-flight Create calls that have reserved a concurrency
	// slot under mu but not yet registered their session. The capacity gate is
	// len(sessions)+pending so N concurrent Creates can never exceed
	// maxConcurrent (the check-then-register window was previously unlocked).
	pending int
	// setupPending tracks labelled SpecSetup spawns currently in flight (label →
	// true), the setup single-flight reservation. It guarantees at most one
	// privileged setup PTY per kind even under concurrent requests.
	setupPending map[string]bool

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewManager builds a Manager and starts its background reaper. Call
// Shutdown to stop the reaper and kill every live session.
func NewManager(opts Options) *Manager {
	m := &Manager{
		spawner:         opts.Spawner,
		maxConcurrent:   opts.MaxConcurrent,
		maxSubscribers:  opts.MaxSubscribers,
		idleTimeout:     opts.IdleTimeout,
		writerLeaseIdle: opts.WriterLeaseIdle,
		writerLeaseMax:  opts.WriterLeaseMax,
		exitLinger:      opts.ExitLinger,
		ringBytes:       opts.RingBytes,
		now:             opts.Now,
		logger:          opts.Logger,
		onExit:          opts.OnExit,
		onProcess:       opts.OnProcess,
		onOutput:        opts.OnOutput,
		onLeaseEvent:    opts.OnLeaseEvent,
		sessions:        make(map[string]*Session),
		stop:            make(chan struct{}),
	}
	allowRemoteTakeover := opts.AllowRemoteTakeover
	if allowRemoteTakeover == nil {
		allowRemoteTakeover = func() bool { return true }
	}
	m.allowRemoteTakeover.Store(&allowRemoteTakeover)
	if m.spawner == nil {
		m.spawner = NewOSSpawner()
	}
	if m.maxConcurrent <= 0 {
		m.maxConcurrent = defaultMaxConcurrent
	}
	if m.maxSubscribers <= 0 {
		m.maxSubscribers = defaultMaxSubscribers
	}
	// idleTimeout <= 0 stays as-is: idle reaping DISABLED (the default —
	// continuity over resource reclamation for live interactive sessions).
	if m.writerLeaseIdle <= 0 {
		m.writerLeaseIdle = defaultWriterLeaseIdle
	}
	if m.writerLeaseMax <= 0 {
		m.writerLeaseMax = defaultWriterLeaseMax
	}
	if m.exitLinger <= 0 {
		m.exitLinger = defaultExitLinger
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.logger == nil {
		m.logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	interval := opts.ReapInterval
	if interval <= 0 {
		interval = defaultReapInterval
	}
	m.wg.Add(1)
	go m.reapLoop(interval)
	return m
}

// Session is one live PTY-backed launcher process. An always-on pump drains
// the PTY into out (the SOLE authoritative bounded replay ring) so the child
// never blocks on a clientless PTY. The read side is a fan-out of N bounded
// output subscribers, each with its own absolute cursor into the ring; the
// write side is at most one exclusive, revocable WriterLease. Done fires when
// the process exits.
type Session struct {
	handle    string
	spec      Spec
	pty       PTY
	out       *outBuf
	createdAt time.Time
	now       func() time.Time
	// pid is the OS pid of the PTY child, snapshotted once at Create from the
	// backend's ProcessReporter (0 when the backend reports none). It is
	// immutable for the session's lifetime, so it needs no lock — the pid of a
	// spawned child never changes, and liveness is read from doneAt.
	pid int
	// startIdentity is the immutable OS process-birth identity captured before
	// the exit waiter can reap the PTY child. It is empty when the platform or
	// backend cannot establish one, which keeps identity-based attribution
	// unavailable without affecting the terminal launch.
	startIdentity string

	lastAct  atomic.Int64 // unixnano of the last PTY I/O
	doneAt   atomic.Int64 // unixnano the process exited (0 = still running)
	exitCode atomic.Int32

	// Read side: the set of live output subscribers. subsMu guards the map;
	// each Subscription owns its own cursor + cancel channel (§4.α.1).
	subsMu  sync.Mutex
	subs    map[*Subscription]struct{}
	maxSubs int

	// Write side: at most one exclusive writer lease. writeMu serializes EVERY
	// PTY side effect (Write/Resize) AND every lease transition (acquire/
	// release/revoke); gen is bumped under writeMu on every transition, and
	// Write/Resize re-validate lease.gen == gen UNDER the lock so an in-flight
	// write on a superseded lease is fenced out before it reaches the PTY
	// (§4.α.2b — one input source ever, not a race).
	writeMu     sync.Mutex
	gen         uint64
	lease       *WriterLease
	writerIdle  time.Duration
	writerMax   time.Duration
	leaseEventf func(LeaseEvent)
	// allowRemoteTakeoverf resolves the live authenticated-remote takeover
	// policy at Decide time under writeMu. It is bound to the manager's
	// replaceable source so existing sessions observe dashboard toggles.
	allowRemoteTakeoverf func() bool
	// standingTakeoverf reports a local takeover of a STANDING-secret remote
	// writer (fired async from acquireWriter). Bound at creation to the
	// manager's late-registered hook dispatcher; nil-safe.
	standingTakeoverf func(handle, revokedHolder string)

	done     chan struct{}
	doneOnce sync.Once

	// PTY window geometry (Feature 2). dimsMu guards all fields below. initial*
	// seed from the launch Spec at Create (or, when the Spec was 0×0, from the
	// FIRST successful resize); current* track the live size, updated in the ONE
	// resize funnel (resizeVia) — the single owner of geometry mutation.
	// haveInitial latches once an initial size is known so a later resize never
	// overwrites it.
	dimsMu      sync.Mutex
	initialRows uint16
	initialCols uint16
	currentRows uint16
	currentCols uint16
	haveInitial bool
	// geomOff is the ABSOLUTE output-ring offset captured at the most recent
	// geometry CHANGE — the replay floor. The ring stores raw PTY bytes with no
	// width tagging, so bytes emitted while the PTY was 152 cols wide render
	// corrupted when replayed into a 47-col terminal (each line's first char
	// lands at the end of the previous line). A reconnecting client does NOT
	// self-heal, because its resize is usually a no-op: the PTY is already that
	// size and the kernel skips SIGWINCH on an unchanged winsize. So a new
	// subscriber starts at max(ring base, geomOff) and only ever replays bytes
	// emitted at the CURRENT width. Written ONLY by recordResize (the one resize
	// funnel, so geometry keeps a single owner); read lock-free by replayStart.
	geomOff atomic.Int64
}

// Token is the opaque session identifier.
func (s *Session) Token() string { return s.handle }

// Subcommand is the observer launcher verb driving this session.
func (s *Session) Subcommand() string { return s.spec.Subcommand }

// SessionID is the source session being continued.
func (s *Session) SessionID() string { return s.spec.SessionID }

// CreatedAt is when the session was spawned.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// PID is the OS pid of this session's PTY child (`observer <tool>`), or 0 when
// the backend reports none. It stays populated after exit; use Exited (or
// Manager.PIDForHandle) to learn whether it is still a valid attribution
// target.
func (s *Session) PID() int { return s.pid }

// Done is closed when the underlying process exits.
func (s *Session) Done() <-chan struct{} { return s.done }

// Exited reports whether the process has ended, and its exit code.
func (s *Session) Exited() (bool, int) {
	if s.doneAt.Load() == 0 {
		return false, 0
	}
	return true, int(s.exitCode.Load())
}

// Size returns the session's PTY geometry (Feature 2): the initial dimensions
// (seeded from the launch Spec, or the first successful resize when the Spec was
// 0×0) and the current dimensions (updated on every successful resize). Race-safe
// under the session's dims lock. A zero pair means "not yet known" (no size at
// spawn and no resize yet).
func (s *Session) Size() (initialRows, initialCols, currentRows, currentCols uint16) {
	s.dimsMu.Lock()
	defer s.dimsMu.Unlock()
	return s.initialRows, s.initialCols, s.currentRows, s.currentCols
}

// seedDims records the launch-Spec geometry as both initial and current at
// Create. A 0×0 Spec leaves haveInitial false so the first successful resize
// becomes the initial size instead.
func (s *Session) seedDims(rows, cols uint16) {
	s.dimsMu.Lock()
	defer s.dimsMu.Unlock()
	s.currentRows, s.currentCols = rows, cols
	if rows != 0 && cols != 0 {
		s.initialRows, s.initialCols = rows, cols
		s.haveInitial = true
	}
}

// recordResize updates the current geometry after a successful pty.Resize and,
// when no initial size was known (0×0 Spec), adopts this first real size as the
// initial. Called only from resizeVia (the one resize funnel), so geometry has a
// single owner.
//
// It is ALSO where the replay floor (geomOff) moves: a geometry change makes
// every already-buffered byte unsafe to replay into the new width, so the ring's
// current end becomes the new subscriber's replay start. Two cases deliberately
// do NOT move the floor: a same-size resize (nothing about the width changed, so
// truncating would silently discard good scrollback) and the first-size adoption
// of a 0×0 Spec (there is no earlier-width content to discard).
//
// Lock order is dimsMu → outBuf.mu, and it can never invert: outBuf holds no
// reference to a Session and so never takes dimsMu.
func (s *Session) recordResize(rows, cols uint16) {
	s.dimsMu.Lock()
	defer s.dimsMu.Unlock()
	firstAdoption := !s.haveInitial && rows != 0 && cols != 0
	changed := rows != s.currentRows || cols != s.currentCols
	s.currentRows, s.currentCols = rows, cols
	if firstAdoption {
		s.initialRows, s.initialCols = rows, cols
		s.haveInitial = true
		return
	}
	if changed {
		s.geomOff.Store(s.out.currentTotal())
	}
}

// replayStart is the absolute ring offset a NEW subscriber must begin reading
// from: the newer of the ring's oldest buffered byte and the last geometry
// boundary. Both Subscribe paths route through it so the cursor rule has one
// owner and cannot drift. The max() also clamps: once the ring has trimmed PAST
// a geometry boundary the base wins, so the cursor never points at dropped bytes
// and never moves backwards.
func (s *Session) replayStart() int64 {
	base := s.out.currentBase()
	if geom := s.geomOff.Load(); geom > base {
		return geom
	}
	return base
}

func (s *Session) touch() { s.lastAct.Store(s.now().UnixNano()) }

func (s *Session) markDone(code int) {
	s.doneOnce.Do(func() {
		s.exitCode.Store(int32(code))
		s.doneAt.Store(s.now().UnixNano())
		close(s.done)
	})
}

func (s *Session) emitLease(kind LeaseEventKind, holder, actor, reason string) {
	if s.leaseEventf == nil {
		return
	}
	// Emit the DISPLAY fingerprint (holderDisplay), never the full holder key:
	// LeaseEvent is the metadata-only audit tap, so it carries the 8-char device
	// token that correlates with the control-audit rows — the lease keeps the
	// full key internally for revoke matching only.
	ev := LeaseEvent{
		Kind: kind, Handle: s.handle, Holder: holderDisplay(holder),
		Actor: holderDisplay(actor), Reason: reason, At: s.now(),
	}
	// A SpecSetup session is local-only for its whole lifecycle; flag it (and
	// carry its label) so a remote-audit consumer redacts the handle at persist
	// time. Branch on the session's own kind, never on the handle string.
	if s.spec.Kind == SpecSetup {
		ev.Setup = true
		ev.Label = s.spec.SetupLabel
	}
	s.leaseEventf(ev)
}

// --- Read side: subscriptions ---

// Subscription is one read-only viewer's cursor over the session's output ring.
// It replays recent scrollback from the session's replayStart (the ring's oldest
// buffered byte, or the last geometry boundary when that is newer — see
// Session.geomOff), then tails live output. Starting at the geometry boundary is
// what keeps a reconnect at a NEW terminal width from repainting bytes that were
// laid out for the OLD width. A slow subscriber that falls behind the ring is
// drop-oldest
// degraded: its Read reports a growing Lost gap counter, and the always-on pump
// NEVER back-pressures on it. Read from it like an io.Reader.
type Subscription struct {
	s        *Session
	off      int64
	cancel   chan struct{}
	canceled atomic.Bool
	lost     atomic.Int64
}

// Read streams terminal output from the ring: it drains buffered bytes first
// (replaying recent scrollback) then tails live output, blocking until more
// arrives. It returns io.EOF once the process has exited and the ring is fully
// drained, and errUnsubscribed when the viewer unsubscribes. Falling behind the
// ring increments Lost (a visible gap) rather than stalling the pump.
func (sub *Subscription) Read(p []byte) (int, error) {
	for {
		n, wait, closed, lost := sub.s.out.read(&sub.off, p)
		if lost > 0 {
			sub.lost.Add(lost)
		}
		if n > 0 {
			return n, nil
		}
		if closed {
			return 0, io.EOF
		}
		select {
		case <-sub.cancel:
			return 0, errUnsubscribed
		case <-wait:
		}
	}
}

// Lost is the number of output bytes this subscriber missed because it fell
// behind the drop-oldest ring. A growing value means the viewer is not keeping
// up; the local terminal is unaffected.
func (sub *Subscription) Lost() int64 { return sub.lost.Load() }

// Done is closed when the underlying process exits (mirrors Session.Done).
func (sub *Subscription) Done() <-chan struct{} { return sub.s.done }

// Exited reports whether the process has ended, and its code.
func (sub *Subscription) Exited() (bool, int) { return sub.s.Exited() }

// Subscribe registers a read-only viewer on the session and returns its
// Subscription. The caller MUST Unsubscribe when done. It fails with
// ErrTooManySubscribers once MaxSubscribers viewers already watch the session.
func (m *Manager) Subscribe(handle string) (*Subscription, error) {
	s := m.get(handle)
	if s == nil {
		return nil, ErrNotFound
	}
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if len(s.subs) >= s.maxSubs {
		return nil, ErrTooManySubscribers
	}
	sub := &Subscription{
		s:      s,
		off:    s.replayStart(), // replay from the last geometry boundary, then tail
		cancel: make(chan struct{}),
	}
	s.subs[sub] = struct{}{}
	return sub, nil
}

// SubscribeRemote is the REMOTE-principal subscribe path. It mirrors
// AcquireWriterRemote's confidentiality pin at the READ seam: a SpecSetup
// session (the one-time privileged operator-grant / login / install PTY) is
// LOCAL-ONLY for reads as well as writes — its output can echo a typed sudo
// password or a login auth URL, so a paired remote principal may NEVER subscribe
// to it (refused ErrSetupSessionLocalOnly). Every other session subscribes
// exactly like the owner-local path. Centralising the refusal HERE (not just at
// the WS call site) keeps the boundary unbypassable by a future second caller,
// the same discipline as AcquireWriterRemote.
func (m *Manager) SubscribeRemote(handle string) (*Subscription, error) {
	s := m.get(handle)
	if s == nil {
		return nil, ErrNotFound
	}
	if s.spec.Kind == SpecSetup {
		return nil, ErrSetupSessionLocalOnly
	}
	return m.Subscribe(handle)
}

// Unsubscribe removes a viewer and unblocks its Read (errUnsubscribed) WITHOUT
// killing the PTY — the session stays live so other viewers keep watching and
// the viewer can reconnect. Idempotent per subscription.
func (m *Manager) Unsubscribe(sub *Subscription) {
	if sub == nil {
		return
	}
	s := sub.s
	s.subsMu.Lock()
	delete(s.subs, sub)
	s.subsMu.Unlock()
	if sub.canceled.CompareAndSwap(false, true) {
		close(sub.cancel)
	}
}

// SubscriberCount returns the number of live viewers on a handle (introspection
// + tests). Unknown handle ⇒ 0.
func (m *Manager) SubscriberCount(handle string) int {
	s := m.get(handle)
	if s == nil {
		return 0
	}
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	return len(s.subs)
}

// --- Write side: the exclusive writer lease ---

// WriterLease is the single exclusive right to drive a session's PTY
// (Write/Resize). At most one exists per session. It is minted by
// AcquireWriterLocal (owner path) or AcquireWriterRemote (validated grant), and
// terminated through the one idempotent Revoke funnel. Every Write/Resize is
// fenced by the session generation, so a superseded lease's in-flight write is
// dropped before it reaches the PTY.
type WriterLease struct {
	s    *Session
	kind termlease.HolderKind
	// holder is the lease holder IDENTITY: the sentinel "local" for the
	// owner-local writer, or the FULL device-session key (grant.HolderKey() =
	// the complete sha256 hex, byte-identical to the dashboard's deviceSessionKey
	// / remoteauth SessionInfo.ID) for a remote writer. It is the full hash — NOT
	// the 8-char display fingerprint — so a per-device revoke matches exactly one
	// lease with no 8-char-prefix over-revoke (mirrors the sensitive-viewer
	// registry's full-key F2b split). Every DISPLAY/audit surface truncates it
	// through holderDisplay; only the revoke-by-holder match compares it whole.
	holder string
	// standing records the credential-leg provenance of a REMOTE lease: true
	// when the WriterGrant was minted via the reusable standing secret
	// (grant.Standing()), false for a single-use capability or the local
	// writer. Read only at local-takeover time by the standing-takeover hook.
	standing  bool
	gen       uint64
	createdAt int64 // unixnano
	lastWrite atomic.Int64
	revoked   chan struct{}
	// revokeKind records WHY the lease terminated. It is written exactly once
	// (inside revokeOnce, before close(revoked)) and read only AFTER the
	// revoked channel closes, so the channel close/receive edge makes the read
	// race-free without an atomic. Zero until revoked.
	revokeKind LeaseEventKind
	// revokedBy records the requester that superseded this lease. It is written
	// inside the same revokeOnce publication as revokeKind and read only after
	// Revoked closes. Non-takeover revocations leave it at RequesterLocal's zero
	// value, but consumers consult it only when RevokeIsTakeover is true.
	revokedBy  termlease.Requester
	revokeOnce sync.Once
}

// Holder returns the lease holder as the DISPLAY fingerprint ("local", or the
// 8-char device-session prefix) for the local-UI display + audit — never the
// full holder key. The full key is stored internally (l.holder) and matched
// whole only by RevokeRemoteWriterByHolder; display surfaces truncate it here,
// mirroring the dashboard's deviceFingerprint / deviceSessionKey split.
func (l *WriterLease) Holder() string { return holderDisplay(l.holder) }

// holderDisplay truncates a lease holder identity to its display form: the
// non-hash sentinels ("local", "") and any value <= 8 chars pass through
// unchanged, while a full device-session key (64 hex chars) is truncated to its
// 8-char fingerprint. Byte-identical to remoteauth.fingerprint /
// deviceFingerprint, so lease-audit rows correlate on ONE device token with the
// control-audit rows even though the lease keys its identity on the full hash.
func holderDisplay(holder string) string {
	if len(holder) <= 8 {
		return holder
	}
	return holder[:8]
}

// IsLocal reports whether this is the owner-local lease.
func (l *WriterLease) IsLocal() bool { return l.kind == termlease.HolderLocal }

// Revoked returns a channel closed when the lease is revoked/released/expired —
// a WS bridge selects on it to tell the (remote) writer it lost control.
func (l *WriterLease) Revoked() <-chan struct{} { return l.revoked }

// RevokeKind reports the terminating LeaseEventKind (why the lease ended). It is
// meaningful ONLY after Revoked() has closed; the channel close/receive edge
// publishes the write. The remote WS bridge reads it to distinguish a local
// takeover (demote to viewer, the device is still trusted) from an admin /
// device-session-invalidation revoke (close the socket, the device is no longer
// trusted). Zero (empty) before revocation.
func (l *WriterLease) RevokeKind() LeaseEventKind { return l.revokeKind }

// RevokedBy reports whether the requester that superseded this lease was local
// or remote. It is meaningful only after Revoked has closed and
// RevokeIsTakeover reports true. Dashboard code accesses it through an additive
// optional interface so the LaunchWriter seam and its fakes remain unchanged.
func (l *WriterLease) RevokedBy() string { return l.revokedBy.String() }

// Gen returns the session-monotonic generation assigned when this writer lease
// was acquired. Dashboard code accesses it through an additive optional
// interface so the LaunchWriter seam and its fakes remain unchanged.
func (l *WriterLease) Gen() uint64 { return l.gen }

// RevokeIsTakeover reports whether the lease terminated because another granted
// writer superseded it (as opposed to an admin/device revoke, expiry, or teardown).
// A takeover leaves the device session valid, so the remote WS bridge only
// DEMOTES the client to a viewer; any other termination CLOSES the socket.
// Meaningful only after Revoked() has closed.
func (l *WriterLease) RevokeIsTakeover() bool { return l.revokeKind == LeaseTakenOver }

// RevokeIsExpiry reports whether the lease terminated because it aged out — its
// idle lifetime or hard cap was reached and the reaper swept it — as opposed to
// an admin/device revoke (untrusted device) or a takeover. Meaningful only after
// Revoked() has closed.
//
// The remote WS bridge treats an expiry like a takeover for TEARDOWN purposes:
// it demotes the client to a read-only viewer instead of closing the socket. It
// also PUBLISHES the distinction — the control_revoked frame carries
// expiry:true — because that is what lets a device holding a standing secret
// re-present it on the still-open socket with no owner round-trip, while a
// single-use holder is told to ask for a fresh capability. (Without the wire
// flag an expiry was indistinguishable from a takeover client-side, and the
// "silently re-acquire" this justification rests on did not actually happen;
// review B3, 2026-07-25.)
//
// The AUTHORITY consequence is unchanged — the lease is gone and every write is
// fenced until a fresh §4.δ conjunction succeeds.
func (l *WriterLease) RevokeIsExpiry() bool { return l.revokeKind == LeaseExpired }

// Write feeds client keystrokes to the terminal. It serializes on the session
// write fence and drops the write (ErrNotWriter) if this lease is no longer the
// session's live writer (revoked, taken over, or expired).
func (l *WriterLease) Write(p []byte) (int, error) { return l.s.writeVia(l, p) }

// Resize sets the terminal window size, subject to the same live-lease fence.
func (l *WriterLease) Resize(rows, cols uint16) error { return l.s.resizeVia(l, rows, cols) }

// Release voluntarily yields the lease (a local yield that lets a remote writer
// acquire, or a viewer closing its writer path). Routes through the one Revoke
// funnel; emits a release audit event.
func (l *WriterLease) Release() { l.s.revokeLease(l, LeaseReleased, "holder released") }

// Revoke forcibly terminates the lease (emergency revoke, config-off, device
// revoke, teardown, expiry). Idempotent; routes through the one funnel.
func (l *WriterLease) Revoke() { l.s.revokeLease(l, LeaseRevoked, "revoked") }

func (s *Session) writeVia(l *WriterLease, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.lease != l || l.gen != s.gen {
		return 0, ErrNotWriter // superseded/revoked lease fenced out before the PTY
	}
	n, err := s.pty.Write(p)
	if n > 0 {
		s.touch()
		l.lastWrite.Store(s.now().UnixNano())
	}
	return n, err
}

func (s *Session) resizeVia(l *WriterLease, rows, cols uint16) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.lease != l || l.gen != s.gen {
		return ErrNotWriter
	}
	s.touch()
	l.lastWrite.Store(s.now().UnixNano())
	if err := s.pty.Resize(rows, cols); err != nil {
		return err
	}
	// Geometry tracking (Feature 2): record the new dimensions only after the
	// PTY actually resized, through the ONE resize funnel.
	s.recordResize(rows, cols)
	return nil
}

// acquireWriter applies the grant/takeover policy table under the write fence
// and, on a grant, installs a fresh lease (bumping gen so any prior lease's
// in-flight write is fenced). It is the shared core of AcquireWriterLocal and
// AcquireWriterRemote.
func (s *Session) acquireWriter(req termlease.Requester, holder string, standing bool) (*WriterLease, error) {
	s.writeMu.Lock()
	current := termlease.HolderNone
	if s.lease != nil {
		current = s.lease.kind
	}
	// Linearization point: read the LIVE policy HERE, under writeMu, immediately
	// before Decide. Credential authorization happens upstream and may consume a
	// single-use capability, but it must never snapshot this flag early: a toggle
	// racing the acquire must decide before any incumbent lease is revoked.
	allowRemoteTakeover := true
	if s.allowRemoteTakeoverf != nil {
		allowRemoteTakeover = s.allowRemoteTakeoverf()
	}
	out := termlease.Decide(req, current, allowRemoteTakeover)
	if !out.Granted() {
		s.writeMu.Unlock()
		if current == termlease.HolderLocal {
			return nil, ErrHeldLocally
		}
		return nil, ErrWriterHeld
	}
	var revokedHolder string
	isLeaseTakeover := false
	isStandingLocalTakeover := false
	prevStanding := false
	if out.RevokeCurrent && s.lease != nil {
		prev := s.lease
		revokedHolder = prev.holder
		prevStanding = prev.standing
		isLeaseTakeover = out.RevokeCurrent
		isStandingLocalTakeover = prev.kind == termlease.HolderRemote && req == termlease.RequesterLocal && prevStanding
		// Record WHY the incumbent lease is ending BEFORE closing its channel so
		// the WS bridge can branch (takeover ⇒ demote / else ⇒ close). Every
		// policy grant with RevokeCurrent is LeaseTakenOver, including local
		// re-acquire and both authenticated remote takeover directions.
		prevKind := LeaseRevoked
		if isLeaseTakeover {
			prevKind = LeaseTakenOver
		}
		prev.revokeOnce.Do(func() {
			prev.revokeKind = prevKind
			prev.revokedBy = req
			close(prev.revoked)
		})
	}
	s.gen++ // one bump per transition: fences any prior lease's in-flight write
	kind := termlease.HolderLocal
	if req == termlease.RequesterRemote {
		kind = termlease.HolderRemote
	}
	l := &WriterLease{
		s:         s,
		kind:      kind,
		holder:    holder,
		standing:  standing,
		gen:       s.gen,
		createdAt: s.now().UnixNano(),
		revoked:   make(chan struct{}),
	}
	l.lastWrite.Store(l.createdAt)
	s.lease = l
	s.writeMu.Unlock()

	if isLeaseTakeover {
		s.emitLease(LeaseTakenOver, revokedHolder, holder, out.Reason)
		// A takeover can point in any direction. If the superseded remote writer
		// held control through the STANDING credential, report it only for the
		// narrowly classified local-over-standing-remote direction (async — the
		// hook may take dashboard-side locks and must never
		// re-enter this session's writeMu path synchronously). Policy — whether the
		// standing secret itself is then revoked — lives entirely behind the hook
		// ([remote].revoke_standing_on_takeover, default off).
		if isStandingLocalTakeover && s.standingTakeoverf != nil {
			go s.standingTakeoverf(s.handle, revokedHolder)
		}
	} else if revokedHolder != "" {
		s.emitLease(LeaseRevoked, revokedHolder, holder, "superseded by new lease")
	}
	s.emitLease(LeaseAcquired, holder, holder, out.Reason)
	return l, nil
}

// revokeLease is the ONE idempotent revocation funnel (§4.α.4) reached by
// Release, Revoke, lease takeover, emergency revoke, device-session revoke,
// allow_terminal→false, and teardown. If this lease is the session's current
// writer it is detached and gen is bumped (fencing its in-flight write); the
// revocation channel is closed exactly once regardless.
func (s *Session) revokeLease(l *WriterLease, kind LeaseEventKind, reason string) {
	if l == nil {
		return
	}
	s.writeMu.Lock()
	if s.lease == l {
		s.lease = nil
		s.gen++
	}
	s.writeMu.Unlock()
	first := false
	l.revokeOnce.Do(func() {
		l.revokeKind = kind // published to RevokeKind readers by the channel close below
		close(l.revoked)
		first = true
	})
	if first {
		s.emitLease(kind, l.holder, l.holder, reason)
	}
}

// AcquireWriterLocal grants the owner-local writer lease (the direct loopback
// path, CapabilityLocal provenance). It is the ONLY path granted without a
// WriterGrant, and it can never be refused: it takes over an incumbent remote
// writer (revoking it) per the policy table (§4.α.2a/§4.α.3).
func (m *Manager) AcquireWriterLocal(handle string) (*WriterLease, error) {
	s := m.get(handle)
	if s == nil {
		return nil, ErrNotFound
	}
	return s.acquireWriter(termlease.RequesterLocal, "local", false)
}

// AcquireWriterRemote grants a writer lease against an unforgeable WriterGrant
// minted only by termlease.Authorize after the full §4.δ conjunction. A
// zero-value / fabricated grant (Authorized()==false) is refused (ErrNoGrant),
// making the conjunction structurally unbypassable (§4.α.2a). ErrHeldLocally
// and ErrWriterHeld surface only when authenticated remote takeover is disabled.
func (m *Manager) AcquireWriterRemote(handle string, grant termlease.WriterGrant) (*WriterLease, error) {
	if !grant.Authorized() {
		return nil, ErrNoGrant
	}
	s := m.get(handle)
	if s == nil {
		return nil, ErrNotFound
	}
	// A setup session (e.g. the operator grant) is local-writer-only: no remote
	// principal may drive it, regardless of grant. Pinned on the session kind,
	// enforced HERE at the acquisition seam — not inferred from the (Local)
	// creation POST (codex review 2026-07-13).
	if s.spec.Kind == SpecSetup {
		return nil, ErrSetupSessionLocalOnly
	}
	// Defence in depth: the grant is handle-bound; refuse a grant minted for a
	// different terminal even if a caller mis-routes it.
	if grant.Handle() != "" && grant.Handle() != handle {
		return nil, ErrNoGrant
	}
	// Store the FULL holder key (grant.HolderKey()) as the lease identity, not the
	// 8-char display fingerprint (grant.Holder()), so a per-device revoke matches
	// exactly one lease with no prefix collision. Display surfaces truncate it.
	return s.acquireWriter(termlease.RequesterRemote, grant.HolderKey(), grant.Standing())
}

// SetAllowRemoteTakeoverSource replaces the live policy source used by every
// session at its writer-decision linearization point. Nil restores the secure
// product default (authenticated remote takeover enabled); the function itself
// must be concurrency-safe and non-blocking in production.
func (m *Manager) SetAllowRemoteTakeoverSource(fn func() bool) {
	if fn == nil {
		fn = func() bool { return true }
	}
	m.allowRemoteTakeover.Store(&fn)
}

func (m *Manager) remoteTakeoverAllowed() bool {
	fn := m.allowRemoteTakeover.Load()
	return fn == nil || (*fn)()
}

// SetOnStandingLocalTakeover registers (or replaces; nil clears) the hook fired
// asynchronously whenever a LOCAL writer acquisition supersedes a remote lease
// that was minted through the STANDING terminal-control secret. Registered
// post-construction by the dashboard layer — termsession reports provenance
// only; the opt-in revoke-standing-on-takeover policy lives behind the hook.
func (m *Manager) SetOnStandingLocalTakeover(fn func(handle, revokedHolder string)) {
	if fn == nil {
		m.standingTakeoverHook.Store(nil)
		return
	}
	m.standingTakeoverHook.Store(&fn)
}

// fireStandingTakeover dispatches to the late-registered standing-takeover
// hook, if any. Bound into each Session at creation so registration order
// (sessions may pre-date the dashboard's SetOnStandingLocalTakeover) never
// matters.
func (m *Manager) fireStandingTakeover(handle, revokedHolder string) {
	if f := m.standingTakeoverHook.Load(); f != nil && *f != nil {
		(*f)(handle, revokedHolder)
	}
}

// RevokeWriter revokes the current writer lease on a handle, if any, through the
// funnel — the manager-level entry for allow_terminal→false / remote disable /
// device-session revoke driven from the cmd/dashboard layer. No-op when there
// is no live writer. Returns whether a lease was revoked.
func (m *Manager) RevokeWriter(handle, reason string) bool {
	s := m.get(handle)
	if s == nil {
		return false
	}
	s.writeMu.Lock()
	l := s.lease
	s.writeMu.Unlock()
	if l == nil {
		return false
	}
	s.revokeLease(l, LeaseRevoked, reason)
	return true
}

// RevokeAllWriters revokes every live session's writer lease (global kill for
// allow_terminal→false / remote disable / rotate). Returns the count revoked.
func (m *Manager) RevokeAllWriters(reason string) int {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	n := 0
	for _, s := range all {
		s.writeMu.Lock()
		l := s.lease
		s.writeMu.Unlock()
		if l != nil {
			s.revokeLease(l, LeaseRevoked, reason)
			n++
		}
	}
	return n
}

// RevokeAllRemoteWriters revokes every live session's REMOTE-held writer lease
// through the funnel, leaving any owner-LOCAL loopback writer untouched. It is
// the manager-level global kill the dashboard drives for remote disable / rotate
// / allow_terminal→false: those admin transitions invalidate the remote device
// tier but must never yank the local operator's own terminal control. Returns
// the count of remote leases revoked.
func (m *Manager) RevokeAllRemoteWriters(reason string) int {
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	n := 0
	for _, s := range all {
		s.writeMu.Lock()
		l := s.lease
		remote := l != nil && l.kind == termlease.HolderRemote
		s.writeMu.Unlock()
		if remote {
			s.revokeLease(l, LeaseRevoked, reason)
			n++
		}
	}
	return n
}

// RevokeRemoteWriterByHolder revokes the REMOTE writer lease whose holder key
// equals holderKey — the FULL device-session hash (grant.HolderKey() /
// deviceSessionKey / remoteauth SessionInfo.ID), NOT the 8-char display
// fingerprint — if any, through the funnel. It is the single-device kill the
// dashboard drives for a device-session revoke, resolving the device to its full
// session hash first so the match hits exactly one lease with no 8-char-prefix
// over-revoke. The comparison is whole-string against the full stored holder, so
// there is no mixed-width window (a bare fingerprint prefix matches nothing). The
// owner-LOCAL loopback writer (holder "local") is never matched. Returns whether
// a lease was revoked.
func (m *Manager) RevokeRemoteWriterByHolder(holderKey, reason string) bool {
	if holderKey == "" || holderKey == "local" {
		return false
	}
	m.mu.Lock()
	all := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	revoked := false
	for _, s := range all {
		s.writeMu.Lock()
		l := s.lease
		match := l != nil && l.kind == termlease.HolderRemote && l.holder == holderKey
		s.writeMu.Unlock()
		if match {
			s.revokeLease(l, LeaseRevoked, reason)
			revoked = true
		}
	}
	return revoked
}

// WriterHolder returns the current writer-lease holder as the DISPLAY
// fingerprint ("local" or the 8-char device-session prefix) for a handle, and
// whether a writer is held. Used by the local UI to surface the controlling
// device — truncated (holderDisplay), never the full holder key.
func (m *Manager) WriterHolder(handle string) (holder string, held bool) {
	s := m.get(handle)
	if s == nil {
		return "", false
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.lease == nil {
		return "", false
	}
	return holderDisplay(s.lease.holder), true
}

// get resolves a handle to its session (nil if unknown).
func (m *Manager) get(handle string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[handle]
}

// liveSetupHandleLocked returns the handle of a still-running SpecSetup session
// with the given label, or "" when none is live. Caller MUST hold m.mu. An
// exited-but-lingering setup session is ignored so a re-request after the PTY
// finished spawns a fresh one.
func (m *Manager) liveSetupHandleLocked(label string) string {
	for h, s := range m.sessions {
		if s.spec.Kind == SpecSetup && s.spec.SetupLabel == label && s.doneAt.Load() == 0 {
			return h
		}
	}
	return ""
}

// IsSetupSession reports whether a handle is a SpecSetup (privileged, local-only
// setup) session. Unknown handle ⇒ false. The dashboard uses it to redact setup
// handles from remotely-visible snapshots and to refuse remote termination — the
// read/terminate half of the confidentiality boundary AcquireWriterRemote pins
// for writes.
func (m *Manager) IsSetupSession(handle string) bool {
	s := m.get(handle)
	return s != nil && s.spec.Kind == SpecSetup
}

// --- lifecycle ---

// Create validates the spec, spawns the PTY process, registers the
// session, and returns its opaque handle. A Wait goroutine records the exit
// and starts the linger clock; the reaper (or Close) removes it.
func (m *Manager) Create(spec Spec) (string, error) {
	switch spec.Kind {
	case SpecSetup:
		// A setup session runs a fixed server-derived argv; no BinPath/
		// Subcommand/SessionID apply.
		if len(spec.SetupArgv) == 0 || spec.SetupArgv[0] == "" {
			return "", ErrInvalidSpec
		}
	case SpecShell:
		// A shell session runs a fixed server-derived argv (the resolved
		// $SHELL / /bin/bash / /bin/sh); no BinPath/Subcommand/SessionID apply,
		// mirroring SpecSetup's shape — but see the single-flight guard below,
		// which deliberately does NOT apply to SpecShell.
		if len(spec.ShellArgv) == 0 || spec.ShellArgv[0] == "" {
			return "", ErrInvalidSpec
		}
	case SpecSSH:
		// An SSH session runs a fixed, server-derived OpenSSH argv composed by
		// internal/sshprofile; no BinPath/Subcommand/SessionID apply, and (see
		// SpecSSH's doc comment) no isolation wrapper is applied either.
		if len(spec.SSHArgv) == 0 || spec.SSHArgv[0] == "" {
			return "", ErrInvalidSpec
		}
	default:
		// BinPath + Subcommand are always required; SessionID is required only
		// for a handoff launch (ArgvModeHandoff) — a fresh/attach/resume launch
		// carries no --continue-from source session.
		if spec.BinPath == "" || spec.Subcommand == "" {
			return "", ErrInvalidSpec
		}
		if spec.ArgvMode == ArgvModeHandoff && spec.SessionID == "" {
			return "", ErrInvalidSpec
		}
	}

	// WrapArgv (B9 sandbox isolation-wrapper prefix) is optional, but when
	// present its argv[0] (the wrapper binary, e.g. bwrap) must be non-empty
	// — an empty argv[0] is a malformed exec target, the same class of
	// mistake the BinPath/Subcommand emptiness checks above guard against.
	if len(spec.WrapArgv) > 0 && spec.WrapArgv[0] == "" {
		return "", ErrInvalidSpec
	}

	// Reserve a concurrency slot (and, for a labelled setup op, a single-flight
	// slot) ATOMICALLY under the lock. The capacity gate counts in-flight
	// reservations (pending) as well as live sessions, so N concurrent Creates
	// can never exceed maxConcurrent — the previous check-then-spawn window was
	// unlocked and racy. A labelled SpecSetup op reuses a live PTY of its kind
	// (idempotent) or fails ErrSetupInFlight while a same-label spawn is in
	// flight, so two privileged setup PTYs of one kind can never both start.
	setupLabel := ""
	if spec.Kind == SpecSetup {
		setupLabel = spec.SetupLabel
	}
	m.mu.Lock()
	if setupLabel != "" {
		if h := m.liveSetupHandleLocked(setupLabel); h != "" {
			m.mu.Unlock()
			return h, nil // reuse the live privileged PTY of this kind
		}
		if m.setupPending[setupLabel] {
			m.mu.Unlock()
			return "", ErrSetupInFlight
		}
	}
	if len(m.sessions)+m.pending >= m.maxConcurrent {
		m.mu.Unlock()
		return "", ErrTooManySessions
	}
	m.pending++
	if setupLabel != "" {
		if m.setupPending == nil {
			m.setupPending = make(map[string]bool)
		}
		m.setupPending[setupLabel] = true
	}
	m.mu.Unlock()

	// releaseReservation drops the pending slot (+ setup single-flight slot) on
	// any failure path. The success path clears them in the SAME critical section
	// that registers the session, so the count never dips to admit an extra spawn.
	// It is idempotent (guarded by `reserved`) and touched only from this one
	// goroutine, so the explicit error-path calls, the success-path conversion,
	// and the deferred panic backstop below can never double-release.
	reserved := true
	releaseReservation := func() {
		if !reserved {
			return
		}
		reserved = false
		m.mu.Lock()
		m.pending--
		if setupLabel != "" {
			delete(m.setupPending, setupLabel)
		}
		m.mu.Unlock()
	}
	// Panic backstop: if Spawner.Spawn, newToken, or Session construction panics
	// AFTER the reservation is taken but BEFORE it is converted to a live
	// registered session, the deferred release runs during stack unwinding so
	// `pending` cannot stay permanently elevated (which would exhaust
	// MaxConcurrent until a daemon restart). Once the success path sets
	// reserved=false in the same critical section that registers the session,
	// this is a no-op — preserving the atomic reservation→live conversion.
	defer releaseReservation()

	p, err := m.spawner.Spawn(spec)
	if err != nil {
		releaseReservation()
		return "", err
	}
	// Capture the child birth before starting its exit waiter. Until Wait reaps
	// the child, this PID cannot be reused for a different process; an already
	// exited zombie is rejected by the platform helper. Failure is deliberately
	// non-fatal because process identity is optional attribution evidence.
	pid := ptyPID(p)
	startIdentity := processStartIdentity(pid)

	handle, err := newToken()
	if err != nil {
		_ = p.Kill()
		releaseReservation()
		return "", err
	}

	s := &Session{
		spec:                 spec,
		pty:                  p,
		pid:                  pid,
		startIdentity:        startIdentity,
		out:                  newOutBuf(m.ringBytes),
		createdAt:            m.now(),
		now:                  m.now,
		subs:                 make(map[*Subscription]struct{}),
		maxSubs:              m.maxSubscribers,
		writerIdle:           m.writerLeaseIdle,
		writerMax:            m.writerLeaseMax,
		leaseEventf:          m.onLeaseEvent,
		allowRemoteTakeoverf: m.remoteTakeoverAllowed,
		standingTakeoverf:    m.fireStandingTakeover,
		done:                 make(chan struct{}),
	}
	s.handle = handle
	s.touch()
	// Seed PTY geometry from the launch Spec (Feature 2). A 0×0 Spec defers the
	// initial size to the first successful resize.
	s.seedDims(spec.Rows, spec.Cols)

	m.mu.Lock()
	m.sessions[handle] = s
	m.pending-- // convert the reservation into a live session atomically
	if setupLabel != "" {
		delete(m.setupPending, setupLabel)
	}
	reserved = false // reservation converted; the deferred release is now a no-op
	m.mu.Unlock()

	// Publish the process-attribution seam BEFORE the lifecycle goroutines
	// start, so a ProcessSpawned edge can never be delivered after its own
	// ProcessExited edge. Inline by contract (see Options.OnProcess).
	m.fireProcess(ProcessEvent{
		Kind:            ProcessSpawned,
		Handle:          handle,
		PID:             s.pid,
		Subcommand:      spec.Subcommand,
		SourceSessionID: spec.SessionID,
		Dir:             spec.Dir,
		At:              s.createdAt,
	})

	m.wg.Add(2)
	go m.waitExit(s)
	go m.pump(s)

	m.logger.Info("termsession: created", "subcommand", spec.Subcommand, "session", spec.SessionID)
	return handle, nil
}

// fireProcess delivers one process-lifecycle edge to the injected sink. A nil
// sink, or a backend that reports no pid, is a clean no-op — there is nothing
// to attribute in either case.
func (m *Manager) fireProcess(ev ProcessEvent) {
	if m.onProcess == nil || ev.PID <= 0 {
		return
	}
	m.onProcess(ev)
}

// PIDForHandle returns the OS pid of a LIVE session's PTY child. ok is false
// when the handle is unknown, when the backend reported no pid, or when the
// child has already exited — an exited pid is not a valid attribution target
// because the OS may have handed it to an unrelated process, so this never
// hands one out.
func (m *Manager) PIDForHandle(handle string) (int, bool) {
	m.mu.Lock()
	s := m.sessions[handle]
	m.mu.Unlock()
	if s == nil || s.pid <= 0 {
		return 0, false
	}
	if exited, _ := s.Exited(); exited {
		return 0, false
	}
	return s.pid, true
}

// ProcessAttributionForHandle returns the OS pid and launch time of a
// handle's PTY child REGARDLESS of live/exited state — unlike PIDForHandle,
// which withholds a pid the instant the child exits (correctly, for its own
// live-attribution purpose). This accessor exists for the opposite case: a
// caller correlating a run's exit against an external observation (e.g. a
// node-intervention audit row keyed by pid + timestamp) needs the pid AT THE
// MOMENT the exit fired, which is exactly when PIDForHandle stops answering.
// ok is false when the handle is unknown or the backend never reported a
// pid. The handle stays resolvable for as long as the session's exit-linger
// window keeps it in m.sessions (see endedHandleGrace in termsvc), which is
// ample for a caller reacting to the exit itself.
func (m *Manager) ProcessAttributionForHandle(handle string) (pid int, launchedAt time.Time, ok bool) {
	m.mu.Lock()
	s := m.sessions[handle]
	m.mu.Unlock()
	if s == nil || s.pid <= 0 {
		return 0, time.Time{}, false
	}
	return s.pid, s.createdAt, true
}

// ProcessIdentityForHandle returns the observed OS identity of a terminal's
// PTY child when the manager has not recorded its exit and the process birth
// observed during this call matches the immutable value captured immediately
// after spawn. Unsupported platforms, PID-less backends, unreadable process
// metadata, and stale or exited handles return ok=false.
func (m *Manager) ProcessIdentityForHandle(handle string) (pid int, startIdentity string, ok bool) {
	m.mu.Lock()
	s := m.sessions[handle]
	m.mu.Unlock()
	if s == nil || s.pid <= 0 || s.startIdentity == "" {
		return 0, "", false
	}
	if exited, _ := s.Exited(); exited {
		return 0, "", false
	}
	if current := processStartIdentity(s.pid); current == "" || current != s.startIdentity {
		return 0, "", false
	}
	// The process metadata read above may overlap exit/reaping. Recheck both
	// session registration and the manager's exit observation before returning
	// the birth that was current during this call.
	m.mu.Lock()
	registered := m.sessions[handle] == s
	m.mu.Unlock()
	if !registered {
		return 0, "", false
	}
	if exited, _ := s.Exited(); exited {
		return 0, "", false
	}
	return s.pid, s.startIdentity, true
}

// waitExit blocks on the process and records its exit. The session lingers
// in the registry (ExitLinger) so an attached client sees the final bytes.
func (m *Manager) waitExit(s *Session) {
	defer m.wg.Done()
	code, _ := s.pty.Wait()
	s.markDone(code)
	// Retract the process-attribution seed FIRST and INLINE. Wait has already
	// reaped the child, so from here until the sink retracts the pid the OS may
	// hand it to an unrelated process — a detached delivery would widen that
	// window for no benefit (see Options.OnProcess).
	m.fireProcess(ProcessEvent{
		Kind:            ProcessExited,
		Handle:          s.handle,
		PID:             s.pid,
		Subcommand:      s.spec.Subcommand,
		SourceSessionID: s.spec.SessionID,
		Dir:             s.spec.Dir,
		ExitCode:        code,
		At:              m.now(),
	})
	// Fire the Phase-0 session-exit signal (plan §7 Phase 0). Detached in its
	// own goroutine so a blocking notification sink never stalls teardown.
	if m.onExit != nil {
		ev := SessionExit{
			Handle:     s.handle,
			SessionID:  s.spec.SessionID,
			Subcommand: s.spec.Subcommand,
			ExitCode:   code,
			At:         m.now(),
			PID:        s.pid,
		}
		go m.onExit(ev)
	}
}

// pump is the always-on PTY drainer: it continuously copies PTY output into
// the session's replay ring (refreshing the idle clock) whether or not a
// client is attached, so a clientless PTY never blocks and a reconnecting
// client can replay recent output. It ends when the PTY read errors (process
// exited or Kill closed the master), closing the ring so a caught-up Read
// returns io.EOF.
func (m *Manager) pump(s *Session) {
	defer m.wg.Done()
	buf := make([]byte, 32*1024)
	for {
		n, err := s.pty.Read(buf)
		if n > 0 {
			s.out.write(buf[:n])
			s.touch()
			// Untrusted byte tap (F3): forward output to the injected sink
			// synchronously. The sink must not retain the slice or block.
			if m.onOutput != nil {
				m.onOutput(s.handle, buf[:n])
			}
		}
		if err != nil {
			s.out.close()
			return
		}
	}
}

// Close kills a session's process tree and removes it from the registry.
// Idempotent: closing an already-gone handle is a no-op.
func (m *Manager) Close(handle string) {
	m.terminate(handle)
}

// terminate is the single idempotent kill+remove funnel every teardown
// path routes through (Close, reaper, Shutdown). It revokes any live writer
// lease first so the remote writer is told it lost control.
func (m *Manager) terminate(handle string) {
	m.mu.Lock()
	s := m.sessions[handle]
	delete(m.sessions, handle)
	m.mu.Unlock()
	if s == nil {
		return
	}
	// Kill the PTY FIRST, before touching writeMu (A2-1). Kill closes the PTY
	// master fd, which unblocks a writer goroutine parked in pty.Write while
	// holding writeMu (a wedged child that stopped draining its input). If we
	// instead acquired writeMu here to read the lease — as the pre-fix order
	// did — a wedged write would hold writeMu forever and this teardown would
	// deadlock, never reaching the Kill that is the very thing that releases
	// it. Kill needs no lock (killOnce-guarded, idempotent), and the freed
	// writer simply observes a closed-fd error and returns. Only AFTER the fd
	// is closed do we take writeMu to revoke the lease.
	_ = s.pty.Kill()
	s.writeMu.Lock()
	l := s.lease
	s.writeMu.Unlock()
	if l != nil {
		s.revokeLease(l, LeaseRevoked, "session terminated")
	}
	s.markDone(-1) // no-op if the process already recorded a real code
}

// Shutdown stops the reaper and kills every live session. Safe to call
// multiple times.
func (m *Manager) Shutdown() {
	m.stopOnce.Do(func() { close(m.stop) })
	m.mu.Lock()
	handles := make([]string, 0, len(m.sessions))
	for h := range m.sessions {
		handles = append(handles, h)
	}
	m.mu.Unlock()
	for _, h := range handles {
		m.terminate(h)
	}
	m.wg.Wait()
}

// Info is a read-only snapshot of a session (Phase 3 session list). ID is
// the opaque session handle.
type Info struct {
	ID         string
	Subcommand string
	SessionID  string
	CreatedAt  time.Time
	// Viewers is the live read-only subscriber count.
	Viewers int
	// WriterHolder is the current writer-lease holder ("local" or a device
	// fingerprint), empty when no writer holds the lease.
	WriterHolder string
	// Setup marks a SpecSetup (privileged, local-only) session. The dashboard
	// redacts these from remotely-visible snapshots (defence in depth).
	Setup    bool
	Exited   bool
	ExitCode int
	// PTY geometry (Feature 2): InitialRows/InitialCols are the size at spawn (or
	// the first resize when the Spec was 0×0); Rows/Cols are the current live
	// size. Zero means not yet known. The dashboard surfaces these so a viewer
	// can restore the real dimensions.
	InitialRows uint16
	InitialCols uint16
	Rows        uint16
	Cols        uint16
}

// LiveCount returns the number of registered PTY sessions.
//
// It is the node-quiescence seam of the enterprise-update-management plan
// (§3.7 step 4a): an in-place binary update DEFERS while a dashboard
// terminal is live, and only `--force` inside an admin maintenance window
// proceeds — after the owners have been warned. The count is deliberately
// the whole seam: the updater is told how many, never which, whose, or in
// what directory.
//
// It counts REGISTERED sessions, not m.pending. A pending entry is a
// concurrency reservation held by an in-flight Create that has not attached
// a PTY yet; counting it would let a racing launch make an apply defer
// forever, while ignoring it can at worst let an apply proceed a few
// milliseconds before a terminal appears — and that terminal's own Create
// would then fail against a swapped binary, which the handshake rolls back.
// A nil Manager reports zero so a --no-dashboard daemon needs no branch at
// the call site.
func (m *Manager) LiveCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Snapshot returns the current live sessions.
func (m *Manager) Snapshot() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(m.sessions))
	for _, s := range m.sessions {
		exited, code := s.Exited()
		s.subsMu.Lock()
		viewers := len(s.subs)
		s.subsMu.Unlock()
		s.writeMu.Lock()
		holder := ""
		if s.lease != nil {
			// Snapshot is a display surface (feeds the dashboard WriterHolder
			// column): expose the 8-char fingerprint, never the full holder key.
			holder = holderDisplay(s.lease.holder)
		}
		s.writeMu.Unlock()
		initRows, initCols, curRows, curCols := s.Size()
		out = append(out, Info{
			ID:           s.handle,
			Subcommand:   s.spec.Subcommand,
			SessionID:    s.spec.SessionID,
			CreatedAt:    s.createdAt,
			Viewers:      viewers,
			WriterHolder: holder,
			Setup:        s.spec.Kind == SpecSetup,
			Exited:       exited,
			ExitCode:     code,
			InitialRows:  initRows,
			InitialCols:  initCols,
			Rows:         curRows,
			Cols:         curCols,
		})
	}
	return out
}

// LastActivity returns the time of the handle's last PTY I/O, or ok=false when
// the handle is unknown. Used by the F4 status classifier to measure output
// silence.
func (m *Manager) LastActivity(handle string) (time.Time, bool) {
	s := m.get(handle)
	if s == nil {
		return time.Time{}, false
	}
	return time.Unix(0, s.lastAct.Load()), true
}

// ExitStatus reports whether the handle's process has exited (and its code), or
// ok=false when the handle is unknown.
func (m *Manager) ExitStatus(handle string) (exited bool, code int, ok bool) {
	s := m.get(handle)
	if s == nil {
		return false, 0, false
	}
	e, c := s.Exited()
	return e, c, true
}

// SessionSize returns the handle's PTY geometry (Feature 2) — the initial and
// current dimensions — or ok=false when the handle is unknown. It is the
// manager-level accessor the dashboard/attach surfaces read to restore or report
// a session's real terminal size.
func (m *Manager) SessionSize(handle string) (initialRows, initialCols, currentRows, currentCols uint16, ok bool) {
	s := m.get(handle)
	if s == nil {
		return 0, 0, 0, 0, false
	}
	ir, ic, cr, cc := s.Size()
	return ir, ic, cr, cc, true
}

func (m *Manager) reapLoop(interval time.Duration) {
	defer m.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.reapOnce(m.now())
		}
	}
}

// SetLimits live-applies the two dashboard-editable [terminal] bounds — the
// concurrency cap and the idle-reap timeout — under m.mu, with NO restart. It
// applies to FUTURE work only: maxConcurrent gates the next Create (Create is
// the sole capacity gate, so lowering it below the live session count NEVER
// kills existing sessions — it only refuses new ones until the count drops);
// idleTimeout is read by the next reap tick. maxConcurrent <= 0 falls back to
// defaultMaxConcurrent — the SAME zero-value fallback NewManager applies — so a
// persisted "0" config (meaning "use the seed default") can never install a
// zero gate that would refuse EVERY Create (len(sessions)+pending >= 0 is
// always true). idleTimeout is applied exactly as given: <= 0 disables idle
// reaping (the continuity default — a live session stays until its child exits
// or an explicit close), a positive duration opts into reaping.
func (m *Manager) SetLimits(maxConcurrent int, idleTimeout time.Duration) {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	m.mu.Lock()
	m.maxConcurrent = maxConcurrent
	m.idleTimeout = idleTimeout
	m.mu.Unlock()
}

// reapOnce terminates sessions that are idle past IdleTimeout or exited
// past ExitLinger, and revokes writer leases past their idle / hard-cap
// lifetime (§4.α.2c). Split from the ticker so tests drive it deterministically.
func (m *Manager) reapOnce(now time.Time) {
	m.mu.Lock()
	var kill []string
	var expire []*Session
	for h, s := range m.sessions {
		// Writer-lease lifetime sweep (independent of session reaping).
		// REMOTE leases only: the idle/hard-cap lifetimes are §4.α.2c
		// security bounds on a remote device's write authority. A LOCAL
		// lease (the native wrapper's seat, the loopback dashboard) is the
		// owner at the keyboard — idle-expiring it silently killed input in
		// long-lived attach sessions ("keys stop working after 5 idle
		// minutes"), which is continuity breakage, not defence.
		//
		// STANDING-provenance remote leases are additionally exempt from the
		// IDLE half (2026-07-25, mobile terminal-continuity arc), mirroring the
		// local exemption above and for the same reason. A standing secret is by
		// design a REUSABLE, non-expiring credential the operator minted once:
		// its holder re-acquires automatically on every fresh socket with no
		// owner round-trip, so idle-expiring the lease it backs bought no
		// authority reduction at all — the next keystroke merely triggered a
		// silent re-acquire — while the revoke ITSELF closed the remote socket
		// and stranded the user ("reconnect to the terminal"). The idle bound
		// remains fully in force for SINGLE-USE-capability remote leases, where
		// it is a real bound: re-acquiring there costs a fresh owner approval.
		// The HARD CAP still applies to standing leases: it forces a periodic
		// re-run of the whole §4.δ conjunction (live device session + live
		// allow_terminal + live standing generation + launch policy), which is a
		// genuine re-authorization and is what an operator revoke relies on to
		// take effect promptly.
		s.writeMu.Lock()
		if l := s.lease; l != nil && l.kind != termlease.HolderLocal {
			idleOver := !l.standing && now.Sub(time.Unix(0, l.lastWrite.Load())) > s.writerIdle
			hardOver := now.Sub(time.Unix(0, l.createdAt)) > s.writerMax
			if idleOver || hardOver {
				expire = append(expire, s)
			}
		}
		s.writeMu.Unlock()

		if da := s.doneAt.Load(); da != 0 {
			if now.Sub(time.Unix(0, da)) > m.exitLinger {
				kill = append(kill, h)
			}
			continue
		}
		// Idle reaping is opt-in (idleTimeout > 0). Disabled — the default —
		// a live session stays until its child exits or an explicit close.
		if m.idleTimeout > 0 && now.Sub(time.Unix(0, s.lastAct.Load())) > m.idleTimeout {
			kill = append(kill, h)
		}
	}
	m.mu.Unlock()
	for _, s := range expire {
		s.writeMu.Lock()
		l := s.lease
		s.writeMu.Unlock()
		if l != nil {
			// LeaseExpired (not LeaseRevoked): an aged-out lease is a
			// re-authorization prompt, not a trust withdrawal — the remote
			// bridge demotes instead of closing the socket (RevokeIsExpiry).
			s.revokeLease(l, LeaseExpired, "writer lease expired")
		}
	}
	for _, h := range kill {
		m.logger.Info("termsession: reaped", "session", h[:min(8, len(h))])
		m.terminate(h)
	}
}

// discard is an io.Writer sink for the default no-op logger.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
