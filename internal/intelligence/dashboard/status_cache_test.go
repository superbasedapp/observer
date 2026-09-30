package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// countingSnapshot wraps a Server's snapshot seam with an invocation counter
// so a test can assert HOW MANY database scans a sequence of requests
// actually caused — the only direct observation of the cache, since a test
// corpus is far too small for the scan's cost to show up as latency.
//
// delay simulates a slow scan (the production case is seconds against a
// multi-gigabyte DB); it is what makes the singleflight assertion meaningful,
// because without it concurrent requests would serialize by luck.
func countingSnapshot(t *testing.T, s *Server, delay time.Duration) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	real := diag.Snapshot
	s.snapshotFn = func(ctx context.Context, database *sql.DB, dbPath string) (diag.StatusSnapshot, error) {
		calls.Add(1)
		if delay > 0 {
			time.Sleep(delay)
		}
		return real(ctx, database, dbPath)
	}
	return &calls
}

// pinClock replaces Server.now with a test-driven clock and returns a func
// that advances it. The status cache reads Server.now, so this is how expiry
// is exercised without sleeping for statusSnapshotTTL.
func pinClock(s *Server) func(time.Duration) {
	var mu sync.Mutex
	at := time.Now().UTC()
	s.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return at
	}
	return func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		at = at.Add(d)
	}
}

func getStatus(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/api/status = %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode /api/status: %v", err)
	}
	// A request that hit a stale entry triggered a background refresh
	// (stale-while-revalidate); wait for it so scan counts are deterministic.
	s.statusSnap.bg.Wait()
	return got
}

// TestStatusSnapshotCache_TTL is the table-driven core: a sequence of request
// counts interleaved with clock advances, asserting the number of underlying
// diag.Snapshot scans each sequence causes.
//
// This is what makes /api/status cheap under the SPA's polling: TopBar and
// Sidebar each poll it every 5s and the active page adds its own, so a scan
// that costs seconds on a real corpus must not run per request.
func TestStatusSnapshotCache_TTL(t *testing.T) {
	type step struct {
		requests int
		advance  time.Duration
	}
	cases := []struct {
		name      string
		steps     []step
		wantScans int64
	}{
		{
			name:      "single request computes once",
			steps:     []step{{requests: 1}},
			wantScans: 1,
		},
		{
			name: "burst within TTL shares one scan",
			steps: []step{
				{requests: 1},
				{requests: 5, advance: statusSnapshotTTL / 5},
			},
			wantScans: 1,
		},
		{
			name: "just under TTL still hits",
			steps: []step{
				{requests: 1},
				{advance: statusSnapshotTTL - time.Millisecond},
				{requests: 1},
			},
			wantScans: 1,
		},
		{
			name: "at TTL expires and recomputes",
			steps: []step{
				{requests: 1},
				{advance: statusSnapshotTTL},
				{requests: 1},
			},
			wantScans: 2,
		},
		{
			name: "two full windows, many requests each",
			steps: []step{
				{requests: 4},
				{advance: statusSnapshotTTL},
				{requests: 4},
				{advance: statusSnapshotTTL},
				{requests: 4},
			},
			wantScans: 3,
		},
		{
			name: "clock stepping backwards is treated as a miss",
			steps: []step{
				{requests: 1},
				{advance: -time.Second},
				{requests: 1},
			},
			wantScans: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			calls := countingSnapshot(t, s, 0)
			advance := pinClock(s)

			for _, st := range tc.steps {
				if st.advance != 0 {
					advance(st.advance)
				}
				for i := 0; i < st.requests; i++ {
					getStatus(t, s)
				}
			}
			if got := calls.Load(); got != tc.wantScans {
				t.Errorf("diag.Snapshot ran %d times, want %d", got, tc.wantScans)
			}
		})
	}
}

// TestStatusSnapshotCache_Singleflight pins that N pollers arriving together
// on a COLD cache produce exactly one scan, not N.
//
// This is the load-bearing half on a real install: the first paint of the
// dashboard fires TopBar's, Sidebar's and the page's /api/status fetch within
// the same millisecond, and before this change all three ran the full scan
// concurrently against the same SQLite reader every other panel was queued
// behind. A plain TTL would not have helped — none of the three could have
// hit an entry that did not exist yet.
func TestStatusSnapshotCache_Singleflight(t *testing.T) {
	s, _ := newTestServer(t)
	// A scan slow enough that every goroutine is certain to arrive before
	// the leader stores its entry.
	calls := countingSnapshot(t, s, 80*time.Millisecond)
	pinClock(s)

	const pollers = 12
	var wg sync.WaitGroup
	start := make(chan struct{})
	bodies := make([]map[string]any, pollers)
	for i := range pollers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil))
			if rr.Code != http.StatusOK {
				t.Errorf("poller %d: /api/status = %d", i, rr.Code)
				return
			}
			var got map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Errorf("poller %d decode: %v", i, err)
				return
			}
			bodies[i] = got
		}(i)
	}
	close(start)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("%d concurrent pollers caused %d scans, want exactly 1 (singleflight)", pollers, got)
	}
	// Every poller must have been SERVED, not merely deduplicated.
	for i, b := range bodies {
		if b == nil {
			t.Fatalf("poller %d got no body", i)
		}
		if _, ok := b["counts"].(map[string]any); !ok {
			t.Errorf("poller %d: missing counts block: %+v", i, b)
		}
	}
}

// TestStatusSnapshotCache_UptimeNotFrozen pins the field the cache is NOT
// allowed to memoize. Version / StartedAt / UptimeSeconds describe the
// serving process at the instant of the request and are stamped AFTER cache
// retrieval; a cached snapshot that carried a stale uptime would make the
// Settings→Health card claim the daemon had been up for less time than it
// has, which is precisely the class of dishonesty this endpoint must not
// acquire in exchange for being cheap.
func TestStatusSnapshotCache_UptimeNotFrozen(t *testing.T) {
	s, _ := newTestServer(t)
	calls := countingSnapshot(t, s, 0)
	pinClock(s)

	orig := processStartedAt
	t.Cleanup(func() { processStartedAt = orig })

	processStartedAt = time.Now().UTC().Add(-30 * time.Second)
	first := getStatus(t, s)

	// Same cache window (the pinned clock has not advanced), but the process
	// has been up longer. A frozen uptime would report the first value again.
	processStartedAt = time.Now().UTC().Add(-90 * time.Second)
	second := getStatus(t, s)

	if got := calls.Load(); got != 1 {
		t.Fatalf("scans = %d, want 1 — the second response must have been served from cache for this test to mean anything", got)
	}

	up1, ok1 := first["uptime_seconds"].(float64)
	up2, ok2 := second["uptime_seconds"].(float64)
	if !ok1 || !ok2 {
		t.Fatalf("uptime_seconds missing: first=%v second=%v", first["uptime_seconds"], second["uptime_seconds"])
	}
	if up2 <= up1 {
		t.Errorf("uptime_seconds = %v then %v — a cached snapshot froze the uptime clock", up1, up2)
	}
	if up1 < 29 || up1 > 31 {
		t.Errorf("uptime_seconds = %v, want ~30 (stamped per request from processStartedAt)", up1)
	}
	if up2 < 89 || up2 > 91 {
		t.Errorf("uptime_seconds = %v, want ~90 (stamped per request from processStartedAt)", up2)
	}

	// started_at must track the same per-request stamp, not the cached body.
	if first["started_at"] == second["started_at"] {
		t.Errorf("started_at identical across the two responses (%v) — it was served from the cache", first["started_at"])
	}
}

// TestStatusSnapshotCache_UptimeMonotonicUnderPolling pins the plainer
// property a polling client sees: uptime never goes BACKWARDS across a run of
// cached responses.
func TestStatusSnapshotCache_UptimeMonotonicUnderPolling(t *testing.T) {
	s, _ := newTestServer(t)
	calls := countingSnapshot(t, s, 0)
	advance := pinClock(s)

	var prev float64 = -1
	for i := range 8 {
		if i == 4 {
			// Cross a TTL boundary mid-run so the sequence spans both a
			// cache-hit and a recompute.
			advance(statusSnapshotTTL)
		}
		got := getStatus(t, s)
		up, ok := got["uptime_seconds"].(float64)
		if !ok {
			// A daemon up for <1s stamps 0, which json omitempty drops.
			up = 0
		}
		if up < prev {
			t.Fatalf("request %d: uptime_seconds went backwards %v → %v", i, prev, up)
		}
		prev = up
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("scans = %d, want 2 (one per TTL window)", got)
	}
}

// TestStatusSnapshotCache_KeyedByDatabase pins that the cache key is the
// database the data endpoints are actually serving. Demo mode (P6.7) swaps
// that database underneath every data handler; a snapshot cached against the
// real DB must never be served while the seeded demo DB is mounted, or the
// demo would show the operator's own row counts.
func TestStatusSnapshotCache_KeyedByDatabase(t *testing.T) {
	s, _ := newTestServer(t)
	calls := countingSnapshot(t, s, 0)
	pinClock(s) // clock never advances: every miss here is a KEY miss

	getStatus(t, s)
	if got := calls.Load(); got != 1 {
		t.Fatalf("scans after first request = %d, want 1", got)
	}
	getStatus(t, s)
	if got := calls.Load(); got != 1 {
		t.Fatalf("scans after second request = %d, want 1 (same DB, within TTL)", got)
	}

	// Swap the database the way demo mode does.
	other, _ := newTestServer(t)
	s.demoDB.Store(other.opts.DB)
	getStatus(t, s)
	if got := calls.Load(); got != 2 {
		t.Errorf("scans after DB swap = %d, want 2 — a cached snapshot of the previous database was served", got)
	}

	// And back: the swapped-away entry must not be resurrected.
	s.demoDB.Store(nil)
	getStatus(t, s)
	if got := calls.Load(); got != 3 {
		t.Errorf("scans after swapping back = %d, want 3", got)
	}
}

// TestStatusSnapshotCache_AbortingPollersStillPopulate is the PRODUCTION
// SHAPE, and the reason the scan must not run under its caller's context.
//
// web/src/lib/useApi.ts aborts the previous in-flight fetch on every refresh
// tick, and /api/status is polled on a 5s ticker by TWO always-mounted chrome
// components. Against a scan that takes longer than the tick, EVERY request
// that reaches the compute path is cancelled before it can finish — so a
// cache that computed under the request context and refused to store a
// cancelled result would store nothing, ever: each tick would find an empty
// cache, take the gate, get cancelled, and hand the gate on. That is the
// original saturation (continuous serialized whole-DB scans) with a mutex
// added, which is strictly worse than no cache at all.
//
// The assertion is therefore not "the leader survived" but "the work
// survived": N pollers all abort at 1s against a 3s scan, exactly ONE scan
// runs, it completes, it is STORED, and the next poller inside the TTL is a
// hit having caused no scan at all.
func TestStatusSnapshotCache_AbortingPollersStillPopulate(t *testing.T) {
	s, _ := newTestServer(t)
	const scanCost = 3 * time.Second
	calls := countingSnapshot(t, s, scanCost)
	pinClock(s)

	const pollers = 4
	var wg sync.WaitGroup
	for i := range pollers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each poller gives up after 1s — a third of the scan cost —
			// exactly as the SPA's next tick aborts the previous fetch.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(
				rr,
				httptest.NewRequest(http.MethodGet, "/api/status", nil).WithContext(ctx),
			)
		}(i)
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("%d aborting pollers caused %d scans, want exactly 1", pollers, got)
	}

	// The work survived its requesters: a later poller inside the TTL is
	// served from the entry those abandoned requests paid for.
	body := getStatus(t, s)
	if got := calls.Load(); got != 1 {
		t.Errorf("scans after a follow-up poll = %d, want 1 — the detached scan's "+
			"result was not stored, so every poll re-scans (the original saturation)", got)
	}
	if _, ok := body["counts"].(map[string]any); !ok {
		t.Errorf("cached body has no counts block: %+v", body)
	}
}

// TestStatusSnapshotCache_ClientAbortDoesNotCancelScan pins the mechanism the
// test above depends on: the context the scan actually runs under is NOT the
// request's. A cancelled request context must reach the scan as a LIVE
// context, or diag.Snapshot's per-lookup tolerance would quietly turn it into
// a snapshot full of fabricated zeros.
func TestStatusSnapshotCache_ClientAbortDoesNotCancelScan(t *testing.T) {
	s, _ := newTestServer(t)
	pinClock(s)

	type probe struct {
		errAtEntry error
		deadlineOK bool
	}
	seen := make(chan probe, 1)
	real := diag.Snapshot
	s.snapshotFn = func(ctx context.Context, database *sql.DB, dbPath string) (diag.StatusSnapshot, error) {
		_, hasDeadline := ctx.Deadline()
		seen <- probe{errAtEntry: ctx.Err(), deadlineOK: hasDeadline}
		return real(ctx, database, dbPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // client is already gone before the handler even starts
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil).WithContext(ctx))

	got := <-seen
	if got.errAtEntry != nil {
		t.Errorf("scan context was already cancelled (%v) — the client's cancellation "+
			"reached the scan; it must run detached", got.errAtEntry)
	}
	if !got.deadlineOK {
		t.Error("scan context carries no deadline — a detached scan nothing can cancel " +
			"must be bounded by statusScanTimeout")
	}

	// And the result was kept, despite the caller having abandoned it.
	if _, ok := s.statusSnap.load(s.db(), s.now()); !ok {
		t.Error("no entry stored after a scan whose caller had cancelled")
	}
}

// TestStatusSnapshotCache_DegradedNotStored pins the completeness gate.
//
// diag.Snapshot swallows per-lookup failures into zero values, so a partial
// read is wire-indistinguishable from an empty database. Memoizing one would
// serve fabricated zeros — "0 sessions", "no activity yet" — for the whole
// TTL, long after the transient cause had cleared. QueryErrors is the signal
// that tells the two apart; a snapshot carrying any is returned but never
// remembered.
func TestStatusSnapshotCache_DegradedNotStored(t *testing.T) {
	cases := []struct {
		name        string
		queryErrors int
		wantStored  bool
	}{
		{name: "complete snapshot is memoized", queryErrors: 0, wantStored: true},
		{name: "one swallowed lookup blocks the store", queryErrors: 1, wantStored: false},
		{name: "many swallowed lookups block the store", queryErrors: 9, wantStored: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			pinClock(s)
			var calls atomic.Int64
			real := diag.Snapshot
			s.snapshotFn = func(ctx context.Context, database *sql.DB, dbPath string) (diag.StatusSnapshot, error) {
				calls.Add(1)
				snap, err := real(ctx, database, dbPath)
				snap.QueryErrors = tc.queryErrors
				return snap, err
			}

			// The degraded snapshot is still SERVED — an honest best effort
			// for the request that asked.
			body := getStatus(t, s)
			if _, ok := body["counts"].(map[string]any); !ok {
				t.Fatalf("degraded snapshot was not served: %+v", body)
			}
			if tc.queryErrors > 0 {
				if got, ok := body["query_errors"].(float64); !ok || int(got) != tc.queryErrors {
					t.Errorf("query_errors on the wire = %v, want %d", body["query_errors"], tc.queryErrors)
				}
			} else if _, present := body["query_errors"]; present {
				t.Errorf("query_errors present on a healthy snapshot (%v) — omitempty must keep "+
					"the wire shape byte-identical to before the field existed", body["query_errors"])
			}

			_, stored := s.statusSnap.load(s.db(), s.now())
			if stored != tc.wantStored {
				t.Errorf("entry stored = %v, want %v", stored, tc.wantStored)
			}

			// A second request within the TTL re-scans iff nothing was stored.
			getStatus(t, s)
			wantCalls := int64(2)
			if tc.wantStored {
				wantCalls = 1
			}
			if got := calls.Load(); got != wantCalls {
				t.Errorf("scans = %d, want %d", got, wantCalls)
			}
		})
	}
}

// TestStatusSnapshotCache_DemoABA pins the exact A→B→A sequence pointer
// keying cannot cover.
//
// Demo mode swaps the database every data surface reads. If the operator
// starts demo mode and clears it again WITHOUT any /api/status request landing
// in between, the real database's pre-demo entry is still live — and the
// contents of the real DB may well have moved on (the watcher never stopped
// ingesting). Serving it back would show the operator pre-demo numbers as if
// they were current. Both swap sites therefore invalidate explicitly.
func TestStatusSnapshotCache_DemoABA(t *testing.T) {
	realSrv, _ := newTestServer(t)
	demoSrv, _ := newTestServer(t)
	s := realSrv
	pinClock(s) // the clock NEVER advances: every scan below is a key/invalidation miss
	calls := countingSnapshot(t, s, 0)

	s.opts.DemoSeeder = func(ctx context.Context) (*sql.DB, func() error, error) {
		return demoSrv.opts.DB, func() error { return nil }, nil
	}

	// A: populate the real database's entry.
	getStatus(t, s)
	if got := calls.Load(); got != 1 {
		t.Fatalf("scans after first poll = %d, want 1", got)
	}
	getStatus(t, s)
	if got := calls.Load(); got != 1 {
		t.Fatalf("scans after second poll = %d, want 1 (same DB, within TTL)", got)
	}

	post := func(path string) {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("POST %s = %d: %s", path, rr.Code, rr.Body.String())
		}
	}

	// A → B → A, with NO status request while B is mounted. Pointer keying
	// alone sees the same pointer at the end and would serve A's stale entry.
	post("/api/demo/start")
	post("/api/demo/stop")

	getStatus(t, s)
	if got := calls.Load(); got != 2 {
		t.Errorf("scans after a demo start/stop round trip = %d, want 2 — the pre-demo "+
			"snapshot was served back as if it were current", got)
	}
}

// TestStatusSnapshotCache_StaleWhileRevalidate pins the 2026-09-27 change
// (optimization review finding N3): once warmed, NO poller waits for a scan.
// A request just past the TTL gets the previous snapshot immediately while one
// background scan refreshes it; a burst of such requests still causes exactly
// one refresh; and an entry older than statusStaleServeMax is not presented as
// current — that request takes the blocking path.
func TestStatusSnapshotCache_StaleWhileRevalidate(t *testing.T) {
	s, _ := newTestServer(t)
	const scanCost = 400 * time.Millisecond
	calls := countingSnapshot(t, s, scanCost)
	advance := pinClock(s)

	getStatus(t, s) // warm: one blocking scan
	if got := calls.Load(); got != 1 {
		t.Fatalf("scans after warm-up = %d, want 1", got)
	}

	advance(statusSnapshotTTL + time.Second)
	// A burst of stale hits: each must be served well inside the scan cost,
	// and together they must trigger ONE refresh.
	for i := 0; i < 5; i++ {
		start := time.Now()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("stale hit %d: /api/status = %d", i, rr.Code)
		}
		if el := time.Since(start); el >= scanCost {
			t.Errorf("stale hit %d took %v — it waited for the scan instead of serving the stale entry", i, el)
		}
	}
	s.statusSnap.bg.Wait()
	if got := calls.Load(); got != 2 {
		t.Errorf("scans after a stale burst = %d, want 2 (one background refresh)", got)
	}
	// The refresh stored a FRESH entry: the next request is a plain hit.
	if _, ok := s.statusSnap.load(s.db(), s.now()); !ok {
		t.Fatal("background refresh did not store a fresh entry")
	}

	// Too old to serve: blocking path, synchronous scan.
	advance(statusStaleServeMax + time.Second)
	start := time.Now()
	getStatus(t, s)
	if el := time.Since(start); el < scanCost {
		t.Errorf("request past statusStaleServeMax returned in %v — it served an entry too old to present as current", el)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("scans = %d, want 3", got)
	}
}

// TestStatusSnapshotCache_RefreshLosesToInvalidate pins the generation guard:
// a background refresh that is mid-scan when the cache is invalidated (demo
// start/stop) must not store its result over the invalidation.
func TestStatusSnapshotCache_RefreshLosesToInvalidate(t *testing.T) {
	s, _ := newTestServer(t)
	advance := pinClock(s)
	release := make(chan struct{})
	var calls atomic.Int64
	real := diag.Snapshot
	s.snapshotFn = func(ctx context.Context, database *sql.DB, dbPath string) (diag.StatusSnapshot, error) {
		if calls.Add(1) > 1 {
			<-release
		}
		return real(ctx, database, dbPath)
	}
	getStatus(t, s)
	advance(statusSnapshotTTL + time.Second)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/status", nil)) // stale hit, refresh blocks
	s.statusSnap.invalidate()
	close(release)
	s.statusSnap.bg.Wait()
	if _, ok := s.statusSnap.load(s.db(), s.now()); ok {
		t.Error("a refresh that straddled invalidate() stored its entry anyway")
	}
}
