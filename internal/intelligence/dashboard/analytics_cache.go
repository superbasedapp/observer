package dashboard

// Analytics response cache: stale-while-revalidate for the heavy, slow-moving
// analytics GET endpoints.
//
// WHY. On a real node (22 GB DB, ~1M actions, DB larger than RAM, 4 contended
// CPUs) the analytics endpoints cost tens of seconds to minutes each —
// /api/discover ~150 s, /api/verbosity/aggregate up to ~110 s, /api/suggestions
// ~64 s, /api/analysis/* 30-70 s under a page's concurrent load — and every
// page visit recomputed them, because the SPA's own cache is per-tab and
// short-lived. Opening Overview fired 14 of them at once, saturated the disk,
// and its last panel landed after ~2.5 minutes; navigating away and back paid
// it all again. Each response is a pure function of (URL, database contents)
// over a days-scale window, so the right fix is the one status_cache.go and
// watcher_health_cache.go already apply to their single endpoints: remember
// the answer, serve it stale while exactly one background recompute runs.
//
// SEMANTICS CHANGE (only with Options.ReadCaches, i.e. the production daemon;
// every test and every other caller computes per request exactly as before):
//   - A panel can show data up to (its route's fresh TTL + one recompute) old.
//     A request for a short window (analyticsWindowRules: span <= 24h) caps
//     both the fresh TTL (30 s) and the stale-serve bound (2 min), so a 1h
//     chart with 5-minute buckets is never presented far behind.
//     Past the fresh TTL the stored answer is still served — immediately, with
//     `X-Observer-Cache: stale` — while ONE detached recompute refreshes it,
//     for up to analyticsCacheStaleServeMax; older than that the entry is not
//     presented as current and the request blocks on a (singleflight)
//     recompute, `X-Observer-Cache: miss`.
//   - Any successful (2xx) non-GET/HEAD request through the dashboard — a
//     config write, a suggestion dismissal, a reprice apply, demo start/stop —
//     clears the WHOLE cache at once (except the high-frequency / dry-run
//     routes in analyticsNoInvalidateRoutes, whose writes cannot change an
//     analytics answer beyond what the TTL already bounds), and bumps a generation so a recompute
//     that started before the mutation can never store its pre-mutation answer.
//   - Writes by the capture pipeline (watcher, proxy, hooks) and by the CLI do
//     not pass through the dashboard, so they become visible within the fresh
//     TTL (+ one recompute), never instantly.
//
// PLACEMENT (security). The cache wraps each allow-listed handler AT ROUTE
// REGISTRATION (registerRoutes' reg), i.e. INSIDE the mux, which is itself
// inside every guard on both branches of guardedHandler: browserGuard (Host
// allow-list, CSRF), remoteAuthz (capability) on the remote branch, and
// governanceGuard (hidden sections). A request that any guard refuses never
// reaches the wrapper, so it can never be answered from cached bytes. Every
// allow-listed route is a CapabilityView GET read (pinned by a test), and none
// of their handlers reads the principal, a header, a cookie or the governance
// posture, so a response computed for one admitted request is the correct
// answer for any other admitted request with the same key.
//
// KEY. "GET" + the identity of the database the data endpoints read (s.db(),
// which demo mode swaps) + the remote-exposed provenance bit (no allow-listed
// handler reads it today; keyed anyway so a future one that does cannot leak
// a loopback-only answer to a remote principal) + the request path + the
// CANONICAL query (url.ParseQuery → Encode: keys sorted, encoding normalized
// exactly the way the handlers' r.URL.Query() reads it). A query that does not
// parse is never cached.
//
// Only GET is cached. HEAD passes straight through (it is neither served from
// nor stored into a GET entry). Only 200 responses are stored (status, the
// handler's headers — Content-Type, Cache-Control — and the body are replayed
// verbatim); errors are returned to the requests that shared that one
// computation and then forgotten. Memory is bounded (entry count, total bytes,
// per-body ceiling) with least-recently-used eviction.

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// analyticsCacheDefaultFresh is the fresh TTL of an allow-list row that does
// not set its own.
const analyticsCacheDefaultFresh = 30 * time.Second

// analyticsCacheStaleServeMax bounds stale-while-revalidate: an entry older
// than its fresh TTL but younger than this (measured from when it was stored)
// is served immediately while one background recompute refreshes it. Past it
// (an idle dashboard, a suspended laptop) the entry is too old to present as
// current and the request blocks on a recompute. Same value and reasoning as
// watcherHealthStaleServeMax.
const analyticsCacheStaleServeMax = 10 * time.Minute

// analyticsCacheComputeTimeout is the RUNAWAY GUARD on one detached
// recompute. The computation deliberately does not run under the requesting
// client's context (the SPA aborts fetches on navigation; a cancelled
// computation would never be remembered — status_cache.go explains the
// failure mode), so an explicit ceiling is mandatory. It sits well above the
// worst measured honest cost (~150 s for /api/discover) so it never truncates
// a slow-but-progressing recompute.
const analyticsCacheComputeTimeout = 5 * time.Minute

// Memory bounds. A typical analytics body is a few KiB to a few hundred KiB.
const (
	analyticsCacheMaxEntries    = 256
	analyticsCacheMaxBytes      = 32 << 20
	analyticsCacheMaxEntryBytes = 4 << 20
)

// analyticsCacheHeader names the observability header set on every response
// the cache answers: fresh | stale | miss.
const analyticsCacheHeader = "X-Observer-Cache"

// analyticsCacheRoute is one allow-list row: an EXACT registered mux pattern
// (every row is a bare, trailing-slash-free pattern, so the mux has already
// matched the path exactly) and its fresh TTL (0 = analyticsCacheDefaultFresh).
type analyticsCacheRoute struct {
	Pattern string
	Fresh   time.Duration
}

// analyticsCacheRoutes is THE allow-list (CLAUDE.md #5: one table, walked by
// lookup; a route is cached iff it has a row). Every row must be a
// CapabilityView GET read whose output depends only on (URL, DB contents,
// slow-moving config) — see the file header. Routes whose honest recompute is
// measured in minutes get a longer fresh TTL so a page that is left open does
// not keep a minutes-long scan permanently in flight.
var analyticsCacheRoutes = []analyticsCacheRoute{
	{Pattern: "/api/discover", Fresh: 5 * time.Minute},
	// Settings -> Storage: db.StorageStats sums dbstat over EVERY page of the
	// file (71 s on a 22 GB node), so a revisit is served stale while one
	// scan refreshes it. Default fresh TTL, not longer: /api/storage/vacuum
	// and /backup start an asynchronous job, so their POST invalidates before
	// the job finishes and only the short TTL bounds how long pre-job sizes
	// can show.
	{Pattern: "/api/storage"},
	{Pattern: "/api/verbosity/aggregate", Fresh: 2 * time.Minute},
	{Pattern: "/api/suggestions", Fresh: 2 * time.Minute},
	{Pattern: "/api/routing/shadow", Fresh: 2 * time.Minute},
	{Pattern: "/api/cowork/reconcile", Fresh: 2 * time.Minute},
	{Pattern: "/api/tasks", Fresh: 2 * time.Minute},
	{Pattern: "/api/analysis/headline"},
	{Pattern: "/api/analysis/trend"},
	{Pattern: "/api/analysis/movers"},
	{Pattern: "/api/analysis/top-sessions"},
	{Pattern: "/api/analysis/routing-suggestions"},
	{Pattern: "/api/analysis/cost-by-hour"},
	{Pattern: "/api/analysis/cost-by-dow-hour"},
	{Pattern: "/api/analysis/cache-savings-trend"},
	{Pattern: "/api/compression/timeseries"},
	{Pattern: "/api/compaction/events"},
	{Pattern: "/api/cache/overview"},
	{Pattern: "/api/report/monthly"},
	{Pattern: "/api/timeseries/cost"},
	{Pattern: "/api/timeseries/tokens-by-model"},
	{Pattern: "/api/timeseries/actions"},
	{Pattern: "/api/models"},
	{Pattern: "/api/cost"},
	{Pattern: "/api/projects"},
	{Pattern: "/api/sessions/calendar"},
	{Pattern: "/api/status/scoped"},
	{Pattern: "/api/tools"},
	{Pattern: "/api/tools/breakdown"},
	{Pattern: "/api/loc/summary"},
}

// analyticsWindowRule caps a cached entry's freshness by the request's
// window span: a short window moves in minutes (a 1h chart has 5-minute
// buckets), so its answer must not be presented as current for as long as a
// 30-day view's.
type analyticsWindowRule struct {
	// MaxSpan is the largest window span the row applies to (inclusive).
	MaxSpan time.Duration
	// Fresh caps the route's fresh TTL.
	Fresh time.Duration
	// StaleServeMax caps analyticsCacheStaleServeMax.
	StaleServeMax time.Duration
}

// analyticsWindowRules is THE window-freshness table (CLAUDE.md #5), finest
// first; the first row whose MaxSpan covers the request's window applies. A
// request with no window, or a window wider than every row, keeps the
// route's TTL and the global stale-serve bound.
var analyticsWindowRules = []analyticsWindowRule{
	// Sub-day windows (1h, 12h, 1d, a custom range within a day): 30 s
	// fresh, and a stale answer is served while one recompute runs for at
	// most 2 minutes (within one 5-minute bucket of current).
	{MaxSpan: 24 * time.Hour, Fresh: 30 * time.Second, StaleServeMax: 2 * time.Minute},
}

// analyticsEntryFreshness returns the fresh TTL and stale-serve bound for a
// request to a route whose fresh TTL is routeFresh: the route's values,
// capped by the first analyticsWindowRules row covering the request's window
// span (windowRange's tiers: since / hours / days, plus until; no window =
// unbounded, uncapped).
func analyticsEntryFreshness(r *http.Request, routeFresh time.Duration) (fresh, staleServeMax time.Duration) {
	fresh, staleServeMax = routeFresh, analyticsCacheStaleServeMax
	since, until := windowRange(r, 0, 0, 36500)
	if since.IsZero() {
		return fresh, staleServeMax
	}
	if until.IsZero() {
		until = time.Now().UTC() // windowRange's own anchor for hours / days
	}
	// Rounded to the second: windowRange anchored `since` a moment before
	// this read the clock, and a 1-day window is still a 1-day span.
	span := until.Sub(since).Round(time.Second)
	for _, rule := range analyticsWindowRules {
		if span <= rule.MaxSpan {
			fresh = min(fresh, rule.Fresh)
			staleServeMax = min(staleServeMax, rule.StaleServeMax)
			break
		}
	}
	return fresh, staleServeMax
}

// analyticsCacheFreshTTL reports whether pattern is allow-listed and, if so,
// its fresh TTL.
func analyticsCacheFreshTTL(pattern string) (time.Duration, bool) {
	for _, rt := range analyticsCacheRoutes {
		if rt.Pattern == pattern {
			if rt.Fresh <= 0 {
				return analyticsCacheDefaultFresh, true
			}
			return rt.Fresh, true
		}
	}
	return 0, false
}

// analyticsResponse is one captured handler response.
type analyticsResponse struct {
	status int
	header http.Header
	body   []byte
}

// replay writes resp to w verbatim, tagged with the cache state.
func (resp *analyticsResponse) replay(w http.ResponseWriter, state string) {
	h := w.Header()
	for k, v := range resp.header {
		h[k] = append([]string(nil), v...)
	}
	h.Set(analyticsCacheHeader, state)
	w.WriteHeader(resp.status)
	_, _ = w.Write(resp.body)
}

// analyticsEntry is one stored response.
type analyticsEntry struct {
	key   string
	resp  *analyticsResponse
	at    time.Time
	fresh time.Duration
	// staleMax is how long past `at` the entry may still be served stale
	// (analyticsCacheStaleServeMax, or less for a short window).
	staleMax time.Duration
	size     int64
}

// analyticsFlight is one in-progress computation for a key. Every request
// that needs that key's answer while it runs waits on done and reads resp.
type analyticsFlight struct {
	done chan struct{}
	resp *analyticsResponse
	gen  uint64
}

// analyticsCache is the one owner of the memoized analytics responses. Only
// the production handler chain uses it (Options.ReadCaches).
type analyticsCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element // value: *analyticsEntry
	lru     list.List                // front = most recently used
	bytes   int64
	// gen counts invalidations. A computation captures it when it starts and
	// stores only if it is unchanged, so one that straddles a mutation (or a
	// demo start/stop) can never resurrect a pre-mutation answer.
	gen uint64
	// flights holds the in-progress computation per key (singleflight).
	// invalidate() replaces the map, so a request arriving after a mutation
	// starts a new computation instead of joining a pre-mutation one.
	flights map[string]*analyticsFlight
	// bg tracks in-flight computations so tests can wait deterministically.
	bg sync.WaitGroup
}

func (c *analyticsCache) initLocked() {
	if c.entries == nil {
		c.entries = map[string]*list.Element{}
	}
	if c.flights == nil {
		c.flights = map[string]*analyticsFlight{}
	}
}

// lookup returns the entry for key and whether it is fresh or merely
// servable-stale at now. An entry too old to serve (or with a negative age —
// the clock moved backwards) is dropped and reported as absent.
func (c *analyticsCache) lookup(key string, now time.Time) (resp *analyticsResponse, fresh, stale bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initLocked()
	el, ok := c.entries[key]
	if !ok {
		return nil, false, false
	}
	e := el.Value.(*analyticsEntry)
	age := now.Sub(e.at)
	switch {
	case age < 0 || age >= e.staleMax:
		c.removeLocked(el)
		return nil, false, false
	case age < e.fresh:
		c.lru.MoveToFront(el)
		return e.resp, true, false
	default:
		c.lru.MoveToFront(el)
		return e.resp, false, true
	}
}

// storeLocked remembers resp under key, evicting least-recently-used entries
// until both bounds hold. A body over analyticsCacheMaxEntryBytes is never
// stored. Caller holds mu.
func (c *analyticsCache) storeLocked(key string, resp *analyticsResponse, now time.Time, fresh, staleMax time.Duration) {
	if len(resp.body) > analyticsCacheMaxEntryBytes {
		return
	}
	if el, ok := c.entries[key]; ok {
		c.removeLocked(el)
	}
	if staleMax <= 0 {
		staleMax = analyticsCacheStaleServeMax
	}
	e := &analyticsEntry{key: key, resp: resp, at: now, fresh: fresh, staleMax: staleMax, size: int64(len(resp.body) + len(key))}
	c.entries[key] = c.lru.PushFront(e)
	c.bytes += e.size
	for c.lru.Len() > analyticsCacheMaxEntries || c.bytes > analyticsCacheMaxBytes {
		back := c.lru.Back()
		if back == nil {
			break
		}
		c.removeLocked(back)
	}
}

func (c *analyticsCache) removeLocked(el *list.Element) {
	e := el.Value.(*analyticsEntry)
	c.lru.Remove(el)
	delete(c.entries, e.key)
	c.bytes -= e.size
}

// invalidate drops every entry and bumps the generation. Called after every
// successful dashboard mutation and at demo start/stop.
func (c *analyticsCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*list.Element{}
	c.lru.Init()
	c.bytes = 0
	c.flights = map[string]*analyticsFlight{}
	c.gen++
}

// entryCount reports the number of stored entries (tests).
func (c *analyticsCache) entryCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// analyticsCacheKey composes the cache key for r (see the file header). ok is
// false when the query does not parse; such a request is never cached.
func (s *Server) analyticsCacheKey(r *http.Request) (string, bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", false
	}
	prov := "loopback"
	if remoteExposedFromContext(r.Context()) {
		prov = "remote"
	}
	return fmt.Sprintf("GET\x00%p\x00%s\x00%s?%s", s.db(), prov, r.URL.Path, q.Encode()), true
}

// analyticsCacheWrap returns h wrapped by the response cache when the
// production read caches are on and pattern is allow-listed, and h itself
// otherwise — so with ReadCaches off the handler chain is byte-identical to
// before. Called from registerRoutes' reg, i.e. INSIDE every guard.
func (s *Server) analyticsCacheWrap(pattern string, h http.HandlerFunc) http.HandlerFunc {
	if !s.opts.ReadCaches {
		return h
	}
	routeFresh, ok := analyticsCacheFreshTTL(pattern)
	if !ok {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			h(w, r)
			return
		}
		key, ok := s.analyticsCacheKey(r)
		if !ok {
			h(w, r)
			return
		}
		c := &s.analytics
		fresh, staleMax := analyticsEntryFreshness(r, routeFresh)
		resp, isFresh, isStale := c.lookup(key, s.now())
		switch {
		case isFresh:
			resp.replay(w, "fresh")
			return
		case isStale:
			s.analyticsFlight(key, r, h, fresh, staleMax) // one background refresh
			resp.replay(w, "stale")
			return
		}
		f := s.analyticsFlight(key, r, h, fresh, staleMax)
		select {
		case <-f.done:
			f.resp.replay(w, "miss")
		case <-r.Context().Done():
			// The client walked away; the computation carries on and its
			// answer is stored for the next request.
		}
	}
}

// analyticsFlight returns the in-progress computation for key, starting one
// when none is running. The computation runs DETACHED from the triggering
// request: the handler sees a clone of it (same URL, headers and context
// values, so everything the key covers) whose context drops the client's
// cancellation, is bounded by analyticsCacheComputeTimeout, and carries the
// cost row-cache marker exactly as costRowCacheMiddleware sets it for a GET.
func (s *Server) analyticsFlight(key string, r *http.Request, h http.HandlerFunc, fresh, staleMax time.Duration) *analyticsFlight {
	c := &s.analytics
	c.mu.Lock()
	c.initLocked()
	if f, ok := c.flights[key]; ok {
		c.mu.Unlock()
		return f
	}
	f := &analyticsFlight{done: make(chan struct{}), gen: c.gen}
	c.flights[key] = f
	c.bg.Add(1)
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(cost.WithRowCache(context.WithoutCancel(r.Context())), analyticsCacheComputeTimeout)
	req := r.Clone(ctx)
	req.Body = http.NoBody
	go func() {
		defer c.bg.Done()
		defer cancel()
		resp := s.analyticsCompute(h, req)
		c.mu.Lock()
		f.resp = resp
		if c.flights[key] == f {
			delete(c.flights, key)
		}
		if resp.status == http.StatusOK && f.gen == c.gen {
			c.storeLocked(key, resp, s.now(), fresh, staleMax)
		}
		c.mu.Unlock()
		close(f.done)
	}()
	return f
}

// analyticsCompute runs h against req and captures its response. It runs on
// its own goroutine, outside net/http's per-request panic recovery, so a
// handler panic is recovered HERE (a panic would otherwise take the daemon
// down) and becomes an uncached 500.
func (s *Server) analyticsCompute(h http.HandlerFunc, req *http.Request) (resp *analyticsResponse) {
	cw := &analyticsCapture{header: http.Header{}}
	defer func() {
		if p := recover(); p != nil {
			s.opts.Logger.Error("analytics cache: handler panicked", "path", req.URL.Path, "panic", fmt.Sprint(p))
			resp = &analyticsResponse{
				status: http.StatusInternalServerError,
				header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
				body:   []byte("internal error\n"),
			}
		}
	}()
	h(cw, req)
	status := cw.status
	if status == 0 {
		status = http.StatusOK
	}
	return &analyticsResponse{status: status, header: cw.header.Clone(), body: cw.body.Bytes()}
}

// analyticsCapture is the in-memory ResponseWriter a detached computation
// writes into.
type analyticsCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (cw *analyticsCapture) Header() http.Header { return cw.header }

func (cw *analyticsCapture) WriteHeader(code int) {
	if cw.status == 0 && code >= 200 {
		cw.status = code
	}
}

func (cw *analyticsCapture) Write(p []byte) (int, error) {
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	return cw.body.Write(p)
}

// analyticsNoInvalidateRoute is one row of the mutation routes that do NOT
// clear the analytics cache. Path is matched against r.URL.Path: exactly, or
// as a prefix when it ends in "/".
type analyticsNoInvalidateRoute struct {
	Path   string
	Reason string
}

// analyticsNoInvalidateRoutes is the ONE exemption table (CLAUDE.md #5).
// A route belongs here only when it is high-frequency or a dry run AND its
// write cannot change what any allow-listed analytics endpoint returns (or
// changes it only the way the capture pipeline does, which the fresh TTL
// already bounds). Without it, a client that POSTs for unrelated reasons (the
// VS Code extension on every save, the workspace grid on every drag) would
// wipe the cache continuously and silently disable it. The default stays
// conservative: a mutation route NOT in this table invalidates on 2xx.
// Mis-listing a route can only make a panel staler (bounded by the TTL); it
// can never serve a response to a request a guard refused.
var analyticsNoInvalidateRoutes = []analyticsNoInvalidateRoute{
	{"/api/loc/editor-change", "VS Code POSTs on every file save; human-LOC capture, same freshness class as watcher capture (TTL-bounded)"},
	{"/api/update/extension-version", "extension-version telemetry at activation; touches no analytics data"},
	{"/api/terminal/workspace-layout/save", "debounced UI-layout PUT on every grid drag/resize; UI preference only"},
	{"/api/privacy/scrub-test", "dry-run scrub preview; writes nothing"},
	{"/api/routing/simulate", "counterfactual simulation; writes nothing"},
	{"/api/routing/policy/lint", "policy lint (as-you-type); writes nothing"},
	{"/api/guard/simulate", "guard dry-run; writes nothing"},
	{"/api/guard/policy/lint", "policy lint (as-you-type); writes nothing"},
	{"/api/suggest", "CLAUDE.md suggestion preview; writes nothing (the write is /api/suggest/write)"},
	{"/api/obs/admission/test", "admission judge dry-run; records nothing"},
	{"/api/guard/prompt/probe", "prompt-guard detector probe; no analytics data"},
	{"/api/guard/prompt/clear", "prompt-guard decision state; read by no cached endpoint"},
	{"/api/guard/prompt/allow/", "prompt-guard allow-list decisions; read by no cached endpoint"},
	{"/api/guard/approvals", "guard approval grants; read by no cached endpoint"},
	{"/api/guard/approvals/", "guard approval revokes; read by no cached endpoint"},
	{"/api/remote/pair", "device pairing (in-memory auth session); no analytics data"},
	{"/api/remote/whoami", "auth probe; no analytics data"},
	{"/api/remote/logout", "device logout (in-memory auth session); no analytics data"},
	{"/api/terminal/launch", "starts a terminal; the agent's activity arrives via capture (TTL-bounded)"},
	{"/api/launch/", "terminates a launched terminal; terminal bookkeeping only"},
	{"/api/instances/", "remote-instance connect/disconnect/test; no analytics data"},
}

// analyticsMutationInvalidates reports whether a successful mutation to path
// must clear the analytics cache: true unless the exemption table lists it.
func analyticsMutationInvalidates(path string) bool {
	for _, rt := range analyticsNoInvalidateRoutes {
		if strings.HasSuffix(rt.Path, "/") {
			if strings.HasPrefix(path, rt.Path) {
				return false
			}
		} else if path == rt.Path {
			return false
		}
	}
	return true
}

// analyticsInvalidateOnWrite clears the analytics cache after every
// successful (2xx) non-GET/HEAD request through the dashboard, except to a
// route in analyticsNoInvalidateRoutes. It wraps the
// handler chain on both branches (Handler and remoteGuardedHandler) so every
// mutation — built-in routes, ExtraRoutes, the remote controller's own routes
// — is seen. It only ever acts on a request that produced a 2xx, i.e. one the
// guards admitted. Identity when ReadCaches is off.
func (s *Server) analyticsInvalidateOnWrite(next http.Handler) http.Handler {
	if !s.opts.ReadCaches {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || !analyticsMutationInvalidates(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusSniffer{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK // net/http's implicit status
		}
		if status >= 200 && status < 300 {
			s.analytics.invalidate()
		}
	})
}

// statusSniffer records the status a handler wrote. Unwrap keeps
// http.ResponseController (Flush, deadlines, Hijack) working through it.
type statusSniffer struct {
	http.ResponseWriter
	status int
}

func (sw *statusSniffer) WriteHeader(code int) {
	if sw.status == 0 && code >= 200 {
		sw.status = code
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusSniffer) Write(p []byte) (int, error) {
	if sw.status == 0 {
		sw.status = http.StatusOK
	}
	return sw.ResponseWriter.Write(p)
}

// Flush forwards to the underlying writer when it supports flushing.
func (sw *statusSniffer) Flush() {
	_ = http.NewResponseController(sw.ResponseWriter).Flush()
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (sw *statusSniffer) Unwrap() http.ResponseWriter { return sw.ResponseWriter }
