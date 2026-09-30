package dashboard

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// statusSnapshotTTL is how long ONE computed diag.Snapshot is reused to serve
// GET /api/status before the underlying scan re-runs.
//
// It is a RATE FLOOR on a whole-database scan, not a freshness policy, and
// that is what decides the value. diag.Snapshot issues an unfiltered
// COUNT(*) against a dozen tables (actions, api_turns, token_usage,
// action_excerpts, …) plus a three-way UNION over the activity tables; on a
// multi-gigabyte corpus that measured ~4-5s per call. The SPA does not call
// it once — TopBar and Sidebar EACH poll /api/status on a 5s ticker and the
// active page (Overview / Analysis / Settings→Health) adds its own — so with
// no memoization a status scan was permanently in flight, competing for the
// same SQLite reader as every other panel's query and pushing first-load
// latencies on the real data endpoints into the tens of seconds.
//
// 15 seconds caps the whole install at ~4 scans a minute however many tabs,
// pages and paired remote devices poll, while staying well inside the human
// loop the numbers sit in: every field on this endpoint is a lifetime row
// count or a "last seen" stamp, i.e. a quantity that moves slowly and is read
// as an order of magnitude, never as a live tick. The one field a human DOES
// watch move — uptime — is deliberately NOT cached (see handleStatus).
//
// A const, not a knob: there is no deployment in which a different value is
// correct, and a tunable would invite a 0 that silently restores the
// saturation this exists to remove. Tests exercise expiry by driving
// Server.now, which is the clock this cache reads.
const statusSnapshotTTL = 15 * time.Second

// statusScanTimeout is the ceiling on ONE detached snapshot scan.
//
// The scan deliberately does not run under the requesting client's context
// (see statusSnapshot), so nothing outside this package can stop it; that
// makes an explicit upper bound mandatory rather than decorative. It is a
// RUNAWAY GUARD, not a latency budget: it must sit far above any plausible
// honest scan so it never truncates a slow-but-progressing one into the
// fabricated zeros of a partial snapshot. The worst measured cost of this
// scan on a real ~16GB corpus was ~5s; two minutes is ~24× that headroom,
// which a healthy database cannot reach and a pathological one (a lock held
// by a long write, a DB on a stalled network mount) should not be allowed to
// exceed while holding the singleflight gate.
const statusScanTimeout = 2 * time.Minute

// statusStaleServeMax bounds STALE-WHILE-REVALIDATE (optimization review
// 2026-09-27, docs/audits/optimization-review-2026-09-27.md finding N3).
//
// Once an entry is older than statusSnapshotTTL it is no longer "fresh", but
// for up to this long it is still SERVED — immediately — while exactly one
// background scan recomputes it. Without this, the first poller after every
// TTL boundary blocked for the whole scan (seconds on a real corpus, 5-18 s
// measured while the watcher was writing), which is the "stale data for many
// seconds, then a jump" the chrome showed every 15 s. The staleness a poller
// can observe is therefore bounded by TTL + one scan, not by TTL alone; every
// field here is a lifetime count or a last-seen stamp read as an order of
// magnitude, so that is the same honesty contract statusSnapshotTTL documents.
// Past this bound (an idle dashboard, a suspended laptop) the entry is too old
// to present as current and the request falls back to the blocking path.
const statusStaleServeMax = 2 * time.Minute

// statusSnapshotCache memoizes the most recent diag.Snapshot for
// GET /api/status.
//
// ONE entry is enough (CLAUDE.md #4, one owner per piece of state): the
// endpoint takes no query parameters, so the only thing that can make a
// cached snapshot describe a different question is WHICH database the data
// endpoints are serving — the real one, or the seeded temp database while
// demo mode is active (P6.7). That identity is the key, so a demo start/stop
// evicts by construction rather than by luck, and no cross-database answer
// can ever be served.
type statusSnapshotCache struct {
	// gate is the singleflight lock. It is held across the ENTIRE
	// check-recheck-compute-store step of a miss, so N concurrent pollers
	// arriving on a cold or expired cache produce exactly ONE scan: the
	// first computes, the rest block, re-check under the gate, and find the
	// fresh entry. Serializing a miss is the entire point — the failure
	// mode being fixed is concurrent scans, so "two requests may both pay"
	// (the etwProbe trade-off, which holds because that probe is an exec,
	// not a query against the contended reader) is exactly wrong here.
	gate sync.Mutex

	// mu guards the entry fields below. It is a SEPARATE, always-briefly-held
	// lock so a reader hitting a live entry never blocks behind an in-flight
	// computation holding gate.
	mu    sync.Mutex
	key   *sql.DB
	at    time.Time
	snap  diag.StatusSnapshot
	valid bool
	// gen counts invalidations. A background refresh captures it before
	// scanning and stores only if it is unchanged, so a scan that straddles
	// a demo start/stop can never resurrect an entry invalidate() dropped.
	gen uint64
	// refreshing is true while a background (stale-while-revalidate) scan
	// is in flight; it keeps a burst of stale hits to ONE refresh.
	refreshing bool
	// bg tracks in-flight background refreshes so tests can wait for them
	// deterministically instead of sleeping.
	bg sync.WaitGroup
}

// load returns the cached snapshot when one is live for this database at now.
func (c *statusSnapshotCache) load(database *sql.DB, now time.Time) (diag.StatusSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid || c.key != database {
		return diag.StatusSnapshot{}, false
	}
	age := now.Sub(c.at)
	// A negative age means the clock moved backwards under us (NTP step,
	// suspend/resume, a test driving Server.now). Treat it as a miss rather
	// than as an arbitrarily long-lived entry.
	if age < 0 || age >= statusSnapshotTTL {
		return diag.StatusSnapshot{}, false
	}
	return c.snap, true
}

// loadStale returns the entry for this database when it is past its TTL but
// still young enough (statusStaleServeMax) to be served while a background
// scan refreshes it. A fresh entry is load's business, not this one's.
func (c *statusSnapshotCache) loadStale(database *sql.DB, now time.Time) (diag.StatusSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid || c.key != database {
		return diag.StatusSnapshot{}, false
	}
	age := now.Sub(c.at)
	if age < statusSnapshotTTL || age >= statusStaleServeMax {
		return diag.StatusSnapshot{}, false
	}
	return c.snap, true
}

// store remembers snap as the entry for this database.
func (c *statusSnapshotCache) store(database *sql.DB, now time.Time, snap diag.StatusSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key, c.at, c.snap, c.valid = database, now, snap, true
}

// storeIfGen is store for a background refresh: it is a no-op when the
// cache was invalidated (gen moved) after the refresh captured gen.
func (c *statusSnapshotCache) storeIfGen(gen uint64, database *sql.DB, now time.Time, snap diag.StatusSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	c.key, c.at, c.snap, c.valid = database, now, snap, true
}

// beginRefresh claims the single background-refresh slot, returning the
// current generation. ok is false when a refresh is already in flight.
func (c *statusSnapshotCache) beginRefresh() (gen uint64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshing {
		return 0, false
	}
	c.refreshing = true
	c.bg.Add(1)
	return c.gen, true
}

// endRefresh releases the background-refresh slot.
func (c *statusSnapshotCache) endRefresh() {
	c.mu.Lock()
	c.refreshing = false
	c.mu.Unlock()
	c.bg.Done()
}

// invalidate drops the cached entry unconditionally.
//
// Required at every point where the CONTENTS of a database the cache may hold
// an entry for change out from under it. Pointer keying alone is not enough:
// demo stop closes the temp handle and demo start may hand back an allocation
// at a previously-seen address, and — the case that actually bites — a
// start/stop round trip with no intervening /api/status request leaves the
// REAL database's pre-demo entry live and servable, even though the operator
// has been looking at a different dataset in between and expects the real
// numbers back the instant the banner clears.
func (c *statusSnapshotCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key, c.snap, c.valid = nil, diag.StatusSnapshot{}, false
	c.at = time.Time{}
	c.gen++
}

// statusSnapshot returns the /api/status snapshot, computing it at most once
// per statusSnapshotTTL per database and at most once at a time.
//
// The returned value is a COPY of the cached struct, so the caller's
// per-request stamping (Version / StartedAt / UptimeSeconds) mutates only its
// own copy. PerToolLastSeen shares a backing array with the cached entry and
// is therefore read-only to callers — nothing on this path writes it.
//
// THE SCAN IS DETACHED FROM THE REQUESTING CLIENT. This is the load-bearing
// decision, not a detail. The SPA polls /api/status on a 5s ticker from two
// always-mounted chrome components, and useApi ABORTS the previous in-flight
// fetch on every tick (web/src/lib/useApi.ts) — so with a 4-5s scan, a
// computation running under its own caller's request context is cancelled a
// beat before it can store its result, essentially every time. A cache that
// only remembers uncancelled scans would then never remember anything: every
// tick would find an empty cache, take the gate, get cancelled, and hand the
// gate to the next one. That is not a degraded cache, it is the ORIGINAL
// saturation with a mutex added — continuous serialized whole-DB scans.
//
// So the computation runs under a server-owned context: the request's VALUES
// are kept (context.WithoutCancel preserves any trace/logging baggage) while
// its cancellation is dropped, bounded instead by statusScanTimeout. The
// consequence is the intended one — the scan runs to completion and is stored
// even when the browser that triggered it has walked away, so the NEXT poller
// gets a hit. This mirrors the proxy's insertTurnDetached precedent, where
// post-response work must likewise outlive the request that occasioned it.
//
// Waiters share that one result by blocking on the gate and re-reading the
// cache; a waiter whose own client aborted is not special-cased, because
// nothing it could do differently would help.
//
// The one snapshot that is NOT stored is a DEGRADED one (QueryErrors > 0).
// diag.Snapshot swallows per-lookup failures into zero values, so a partial
// read is wire-indistinguishable from an empty database; memoizing one would
// keep serving fabricated zeros for the full TTL after the transient cause
// had cleared. It is still returned to the caller that asked — an honest
// best-effort answer for that request — just never remembered.
func (s *Server) statusSnapshot(ctx context.Context) (diag.StatusSnapshot, error) {
	database := s.db()

	if snap, ok := s.statusSnap.load(database, s.now()); ok {
		return snap, nil
	}

	// Stale-while-revalidate: an entry just past its TTL is served NOW and
	// refreshed in the background (statusStaleServeMax), so no poller ever
	// waits for a scan once the cache has been warmed.
	if snap, ok := s.statusSnap.loadStale(database, s.now()); ok {
		s.refreshStatusSnapshotAsync(ctx, database)
		return snap, nil
	}

	s.statusSnap.gate.Lock()
	defer s.statusSnap.gate.Unlock()

	// Re-check under the gate: the request that just released it may have
	// stored exactly the entry this one was about to compute.
	if snap, ok := s.statusSnap.load(database, s.now()); ok {
		return snap, nil
	}

	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusScanTimeout)
	defer cancel()

	snap, err := s.snapshot(scanCtx, database, s.opts.DBPath)
	if err != nil {
		return diag.StatusSnapshot{}, err
	}
	if snap.QueryErrors == 0 {
		s.statusSnap.store(database, s.now(), snap)
	}
	return snap, nil
}

// refreshStatusSnapshotAsync recomputes the snapshot for database in the
// background, at most one refresh at a time. It takes the same singleflight
// gate as the blocking path, so a background refresh and a blocking miss can
// never scan concurrently, and it re-checks freshness under the gate so a
// blocking miss that already refreshed the entry is not scanned twice. The
// scan runs detached from the triggering request exactly like the blocking
// path (see statusSnapshot), bounded by statusScanTimeout. A degraded
// snapshot is never stored, and an invalidation that lands mid-scan wins.
func (s *Server) refreshStatusSnapshotAsync(ctx context.Context, database *sql.DB) {
	gen, ok := s.statusSnap.beginRefresh()
	if !ok {
		return
	}
	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusScanTimeout)
	go func() {
		defer s.statusSnap.endRefresh()
		defer cancel()
		s.statusSnap.gate.Lock()
		defer s.statusSnap.gate.Unlock()
		if _, fresh := s.statusSnap.load(database, s.now()); fresh {
			return
		}
		snap, err := s.snapshot(scanCtx, database, s.opts.DBPath)
		if err != nil || snap.QueryErrors != 0 {
			return
		}
		s.statusSnap.storeIfGen(gen, database, s.now(), snap)
	}()
}

// snapshot is the injected-IO seam in front of diag.Snapshot. Production
// wiring points it at diag.Snapshot itself (set in New); tests override
// Server.snapshotFn to count invocations and to make the scan observable
// without needing a corpus big enough for its cost to show up as latency.
func (s *Server) snapshot(ctx context.Context, database *sql.DB, dbPath string) (diag.StatusSnapshot, error) {
	if s.snapshotFn != nil {
		return s.snapshotFn(ctx, database, dbPath)
	}
	return diag.Snapshot(ctx, database, dbPath)
}
