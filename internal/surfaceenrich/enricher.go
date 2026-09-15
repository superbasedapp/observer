package surfaceenrich

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Default cadence / retry knobs. A pointer file is re-resolved every
// DefaultInterval while it is younger than DefaultWindow; the window is
// generous because the agent's own transcript is ingested within seconds
// of its first write, so anything still missing two hours after the host
// recorded the session is not going to appear.
const (
	DefaultInterval = 30 * time.Second
	DefaultWindow   = 2 * time.Hour
	// DefaultTransientRetries is how many extra resolution attempts a
	// candidate earns once a store call failed TRANSIENTLY (SQLite
	// busy/locked/interrupted). They are spent one per tick, and they
	// are the ONLY thing that lets a pointer file older than the window
	// be retried past its one allotted attempt — a lock contended at
	// daemon start must not turn into a permanent attribution gap. At
	// DefaultInterval that is ~10 minutes of retrying.
	DefaultTransientRetries = 20
	// DefaultResumeAttempts is how many EXTRA passes Run makes at
	// startup while anything is still outstanding, on top of its first
	// immediate one. Startup is exactly when the daemon's own
	// migrations / integrity probe / initial scan contend for the write
	// lock, so the first pass is the likeliest to hit a busy store.
	DefaultResumeAttempts = 2
	// DefaultResumeDelay spaces those startup passes.
	DefaultResumeDelay = 5 * time.Second
)

// transientStoreErrorMarkers is the ordered table of substrings that
// make a store error TRANSIENT — the call can be expected to succeed on
// a later attempt without anything else changing. Matched
// case-insensitively against the error text, because the classification
// has to survive the store's own `fmt.Errorf` wrapping
// ("store.SetSessionSurface(hosted): database is locked") without this
// package importing database/sql or a driver (Module Boundaries #1).
//
// Everything NOT on this table is treated as permanent (an unknown
// surface kind, a missing SessionID, a malformed vocabulary) — retrying
// those forever would just relog the same failure.
var transientStoreErrorMarkers = []string{
	"database is locked",
	"database table is locked",
	"sqlite_busy",
	"sqlite_locked",
	"interrupted",
	"resource busy",
	"busy timeout",
	"try again",
}

// IsTransientStoreError reports whether err looks like a momentary
// store-level failure (SQLite BUSY/LOCKED/INTERRUPTED) rather than a
// permanent one. It is the default for Options.Transient; a caller that
// can classify by driver error CODE at its own boundary should inject
// that instead.
func IsTransientStoreError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range transientStoreErrorMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// Candidate is one hosted-surface fact a Source found on disk: the
// pointer file it came from (for the ledger + its mtime), the stamp to
// apply, and the tool that owns the session (diagnostics only — the
// store keys sessions by id).
type Candidate struct {
	Path    string
	ModTime time.Time
	Surface models.SessionSurface
	Tool    string
	// Unresolvable explains, for a candidate the Source could not turn
	// into a stamp (unknown ACP agent, malformed pointer), what was
	// seen — logged ONCE so a new host agent never silently stops
	// attribution. Empty on a resolvable candidate.
	Unresolvable string
}

// Source lists the current candidates under one home root. Implemented
// per host vocabulary (jetbrainsSource); it receives the enricher's
// injected filesystem funcs so it stays pure.
type Source func(h crossmount.HomeRoot, fs FS) []Candidate

// FS is the injected filesystem surface: directory names, file bytes
// and a modification time. Production wiring uses the os package;
// tests use maps.
type FS struct {
	ReadDir  func(path string) ([]string, error)
	ReadFile func(path string) ([]byte, error)
	ModTime  func(path string) (time.Time, error)
}

// OSFS returns the os-backed FS.
func OSFS() FS {
	return FS{
		ReadDir: func(path string) ([]string, error) {
			entries, err := os.ReadDir(path)
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, nil
		},
		ReadFile: os.ReadFile,
		ModTime: func(path string) (time.Time, error) {
			fi, err := os.Stat(path)
			if err != nil {
				return time.Time{}, err
			}
			return fi.ModTime(), nil
		},
	}
}

// Options wires an Enricher. Load and Stamp are the two store seams;
// everything else has a production default.
type Options struct {
	// Load resolves a session's stored surface. found=false means the
	// session row does not exist yet (the candidate is retried later);
	// an error is logged and the candidate retried.
	Load func(ctx context.Context, sessionID string) (sf models.SessionSurface, found bool, err error)
	// Stamp writes a hosted surface (Store.SetSessionSurface). changed
	// reports whether a column actually moved.
	Stamp func(ctx context.Context, sf models.SessionSurface) (changed bool, err error)
	// Homes lists the home roots to scan; default crossmount.AllHomes.
	Homes func() []crossmount.HomeRoot
	// Sources are the host vocabularies to scan; default = JetBrains.
	Sources []Source
	// FS defaults to OSFS().
	FS FS
	// Now defaults to time.Now.
	Now func() time.Time
	// Interval / Window default to DefaultInterval / DefaultWindow.
	Interval time.Duration
	Window   time.Duration
	// Transient classifies a Load/Stamp error as momentary (retry) or
	// permanent (keep the plain age rule). Defaults to
	// IsTransientStoreError.
	Transient func(error) bool
	// TransientRetries bounds how many extra attempts one candidate
	// earns after a transient failure. Zero uses
	// DefaultTransientRetries; a negative value disables the grant
	// (pre-2026-09-03 behaviour: one attempt for a stale pointer, full
	// stop).
	TransientRetries int
	// ResumeAttempts / ResumeDelay shape Run's startup sweep. Zero uses
	// the defaults; a negative ResumeAttempts leaves Run with just its
	// one immediate pass.
	ResumeAttempts int
	ResumeDelay    time.Duration
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Enricher owns the per-process ledger of pointer files it has resolved.
type Enricher struct {
	opts Options

	mu     sync.Mutex
	ledger map[string]*entry
}

// entry is the ledger row for one pointer file.
type entry struct {
	landed   bool
	attempts int
	lastSeen time.Time
	// retriesLeft is the unspent transient-failure grant. Set once, the
	// first time a store call for this candidate failed transiently, and
	// spent one per stale-rule bypass — so a busy store buys a bounded
	// number of extra passes and nothing else does.
	retriesLeft int
	// transientSeen records that the grant was already issued, so a run
	// of transient failures cannot keep re-arming it forever.
	transientSeen bool
	// gaveUp makes the budget-exhausted warning fire once, not once per
	// tick for the rest of the daemon's life.
	gaveUp bool
}

// New builds an Enricher. Load and Stamp are required; nil for either
// returns an Enricher whose Tick is a no-op (so a partially wired caller
// never panics).
func New(opts Options) *Enricher {
	if opts.Homes == nil {
		opts.Homes = crossmount.AllHomes
	}
	if opts.Sources == nil {
		opts.Sources = []Source{jetbrainsSource}
	}
	if opts.FS.ReadDir == nil || opts.FS.ReadFile == nil || opts.FS.ModTime == nil {
		opts.FS = OSFS()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Window <= 0 {
		opts.Window = DefaultWindow
	}
	if opts.Transient == nil {
		opts.Transient = IsTransientStoreError
	}
	if opts.TransientRetries == 0 {
		opts.TransientRetries = DefaultTransientRetries
	}
	if opts.TransientRetries < 0 {
		opts.TransientRetries = 0
	}
	if opts.ResumeAttempts == 0 {
		opts.ResumeAttempts = DefaultResumeAttempts
	}
	if opts.ResumeAttempts < 0 {
		opts.ResumeAttempts = 0
	}
	if opts.ResumeDelay <= 0 {
		opts.ResumeDelay = DefaultResumeDelay
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Enricher{opts: opts, ledger: map[string]*entry{}}
}

// Run ticks until ctx is done. Never returns an error: every failure is
// logged and retried, and the loop must never cancel its errgroup
// siblings.
//
// Startup is a RESUME sweep, not a single pass. The ledger lives in this
// process, so a daemon start begins with every pointer file unresolved
// and each stale one holding exactly one attempt — and that one attempt
// lands in the busiest moment of the daemon's life (migrations, the
// integrity probe, the initial watcher scan all contending for the write
// lock). resume therefore re-attempts anything still outstanding a
// bounded number of times before settling into the interval ticker.
func (e *Enricher) Run(ctx context.Context) {
	if e == nil {
		return
	}
	e.resume(ctx)
	ticker := time.NewTicker(e.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Tick(ctx)
		}
	}
}

// resume runs the startup sweep: one immediate pass plus up to
// ResumeAttempts follow-ups while anything is still outstanding, spaced
// ResumeDelay apart. Stops early the moment a pass leaves nothing
// pending or retrying, and always returns on ctx.
func (e *Enricher) resume(ctx context.Context) {
	for i := 0; ; i++ {
		res := e.Tick(ctx)
		if i >= e.opts.ResumeAttempts || ctx.Err() != nil {
			return
		}
		if res.Pending == 0 && res.Retrying == 0 {
			return
		}
		e.opts.Logger.Info("surfaceenrich: startup resume pass — candidates still outstanding",
			"pass", i+1, "pending", res.Pending, "retrying", res.Retrying)
		t := time.NewTimer(e.opts.ResumeDelay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// TickResult reports what one pass did, for tests and diagnostics.
type TickResult struct {
	Candidates int
	Stamped    int
	Landed     int // resolved as already carrying the hosted value
	Pending    int // session row not there yet; will retry
	Expired    int // pending past the window; given up
	Skipped    int // unknown tool / malformed pointer / ledger says landed
	// Retrying counts candidates whose store call failed TRANSIENTLY
	// this pass and are therefore holding a retry grant. They are also
	// counted in Pending (a transient failure is still "did not land"),
	// so the older fields keep their meaning.
	Retrying int
}

// Tick runs one pass over every home × source.
func (e *Enricher) Tick(ctx context.Context) TickResult {
	var res TickResult
	if e == nil || e.opts.Load == nil || e.opts.Stamp == nil {
		return res
	}
	now := e.opts.Now()
	for _, h := range e.opts.Homes() {
		for _, src := range e.opts.Sources {
			for _, c := range src(h, e.opts.FS) {
				if ctx.Err() != nil {
					return res
				}
				res.Candidates++
				e.resolve(ctx, now, c, &res)
			}
		}
	}
	return res
}

// resolve applies the ledger rules to one candidate.
func (e *Enricher) resolve(ctx context.Context, now time.Time, c Candidate, res *TickResult) {
	key := filepath.Clean(c.Path)
	e.mu.Lock()
	en, ok := e.ledger[key]
	if !ok {
		en = &entry{}
		e.ledger[key] = en
	}
	en.lastSeen = now
	if en.landed {
		e.mu.Unlock()
		res.Skipped++
		return
	}
	// A pointer file older than the window gets exactly ONE resolution
	// per process (a restart re-checks it cheaply); a young one is
	// retried every tick until it lands or ages out.
	//
	// EXCEPT after a transient store failure. Age says "the agent's
	// transcript is never going to appear"; a busy/locked store says
	// nothing about the data at all, and letting it consume the one
	// allotted attempt converted a momentary SQLITE_BUSY at daemon start
	// into a permanent attribution gap (the 2026-09-03 junie + codex
	// `database is locked` stamps). Such a candidate holds a bounded
	// grant of extra attempts and spends one here.
	stale := !c.ModTime.IsZero() && now.Sub(c.ModTime) > e.opts.Window
	if stale && en.attempts > 0 {
		if en.retriesLeft <= 0 {
			exhausted := en.transientSeen && !en.gaveUp
			en.gaveUp = true
			e.mu.Unlock()
			res.Expired++
			if exhausted {
				e.opts.Logger.Warn("surfaceenrich: transient-retry budget exhausted — giving up on this pointer",
					"path", c.Path, "session", c.Surface.SessionID)
			}
			return
		}
		en.retriesLeft--
	}
	en.attempts++
	e.mu.Unlock()

	if c.Surface.SessionID == "" || c.Tool == "" || c.Surface.Surface == "" {
		e.markLanded(key) // nothing will ever resolve; stop looking
		res.Skipped++
		reason := c.Unresolvable
		if reason == "" {
			reason = "no tool/session resolved"
		}
		e.opts.Logger.Info("surfaceenrich: pointer file not attributable — a new host agent needs a table row",
			"path", c.Path, "reason", reason)
		return
	}
	stored, found, err := e.opts.Load(ctx, c.Surface.SessionID)
	if err != nil {
		e.opts.Logger.Warn("surfaceenrich: load failed", "session", c.Surface.SessionID, "err", err)
		e.noteStoreError(key, c, err, res)
		return
	}
	if !found {
		res.Pending++
		return
	}
	if stored.Surface == c.Surface.Surface && stored.SurfaceHost == c.Surface.SurfaceHost {
		e.markLanded(key)
		res.Landed++
		return
	}
	changed, err := e.opts.Stamp(ctx, c.Surface)
	if err != nil {
		e.opts.Logger.Warn("surfaceenrich: stamp failed", "session", c.Surface.SessionID, "err", err)
		e.noteStoreError(key, c, err, res)
		return
	}
	e.markLanded(key)
	if changed {
		res.Stamped++
		e.opts.Logger.Info("surfaceenrich: hosted surface stamped",
			"tool", c.Tool, "session", c.Surface.SessionID,
			"surface", c.Surface.Surface, "host", c.Surface.SurfaceHost,
			"was", stored.Surface+"/"+stored.SurfaceHost)
	} else {
		res.Landed++
	}
}

// noteStoreError records a failed Load/Stamp on the ledger. A TRANSIENT
// failure (busy/locked/interrupted) arms this candidate's bounded retry
// grant exactly once, so the age rule can no longer retire it on the
// strength of a momentary lock; a PERMANENT one changes nothing and the
// candidate keeps the plain rule. The transition is logged so the grant
// is visible in the daemon journal next to the failure that caused it.
func (e *Enricher) noteStoreError(key string, c Candidate, err error, res *TickResult) {
	res.Pending++
	if e.opts.TransientRetries <= 0 || !e.opts.Transient(err) {
		return
	}
	res.Retrying++
	e.mu.Lock()
	en, ok := e.ledger[key]
	if !ok || en.transientSeen {
		e.mu.Unlock()
		return
	}
	en.transientSeen = true
	en.retriesLeft = e.opts.TransientRetries
	e.mu.Unlock()
	e.opts.Logger.Info("surfaceenrich: transient store error — retrying past the stale-pointer rule",
		"path", c.Path, "session", c.Surface.SessionID,
		"retries", e.opts.TransientRetries, "err", err)
}

func (e *Enricher) markLanded(key string) {
	e.mu.Lock()
	if en, ok := e.ledger[key]; ok {
		en.landed = true
	}
	e.mu.Unlock()
}
