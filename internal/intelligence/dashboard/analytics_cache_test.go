package dashboard

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// analyticsTestServer is newTestServer with the production read caches on
// and a test-driven clock.
func analyticsTestServer(t *testing.T) (*Server, func(time.Duration)) {
	t.Helper()
	s, _ := newTestServer(t)
	s.opts.ReadCaches = true
	return s, pinClock(s)
}

// countingAnalyticsHandler is a stand-in analytics handler: each call returns
// a body naming its call number, so a test can tell a replay from a recompute.
func countingAnalyticsHandler(calls *atomic.Int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		writeJSON(w, map[string]any{"call": n, "q": r.URL.RawQuery})
	}
}

type analyticsResult struct {
	code  int
	state string
	body  string
	ctype string
}

func analyticsGet(h http.Handler, target string) analyticsResult {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
	return analyticsResult{rr.Code, rr.Header().Get(analyticsCacheHeader), rr.Body.String(), rr.Header().Get("Content-Type")}
}

// TestAnalyticsCacheLifecycle is the table-driven core: a sequence of steps
// (request / clock advance) asserting the cache state header, whether the
// body is a replay, and the handler call count after each step.
func TestAnalyticsCacheLifecycle(t *testing.T) {
	fresh, _ := analyticsCacheFreshTTL("/api/cost")
	type step struct {
		name      string
		advance   time.Duration
		wantState string
		wantCalls int64 // after background work settles
		wantBody  int64 // the call number whose body is served
	}
	steps := []step{
		{"cold miss computes", 0, "miss", 1, 1},
		{"fresh hit replays", 0, "fresh", 1, 1},
		{"still fresh just before TTL", fresh - time.Second, "fresh", 1, 1},
		{"stale is served and refreshes once", 2 * time.Second, "stale", 2, 1},
		{"refreshed entry is fresh", 0, "fresh", 2, 2},
		{"too old blocks on a recompute", analyticsCacheStaleServeMax + time.Second, "miss", 3, 3},
		{"and is fresh again", 0, "fresh", 3, 3},
	}
	s, advance := analyticsTestServer(t)
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/cost", countingAnalyticsHandler(&calls))
	for _, st := range steps {
		advance(st.advance)
		got := analyticsGet(h, "/api/cost?days=30")
		s.analytics.bg.Wait()
		if got.code != http.StatusOK || got.state != st.wantState {
			t.Fatalf("%s: code=%d state=%q, want 200 %q", st.name, got.code, got.state, st.wantState)
		}
		if c := calls.Load(); c != st.wantCalls {
			t.Fatalf("%s: handler calls = %d, want %d", st.name, c, st.wantCalls)
		}
		if want := fmt.Sprintf(`"call":%d`, st.wantBody); !strings.Contains(got.body, want) {
			t.Fatalf("%s: body %s, want the response of call %d", st.name, got.body, st.wantBody)
		}
		if got.ctype != "application/json" {
			t.Fatalf("%s: Content-Type %q not replayed", st.name, got.ctype)
		}
	}
}

// TestAnalyticsCacheStaleBurstServesImmediately: a burst of stale hits is
// answered without waiting for the (slow) recompute, and triggers ONE.
func TestAnalyticsCacheStaleBurstServesImmediately(t *testing.T) {
	s, advance := analyticsTestServer(t)
	const cost = 300 * time.Millisecond
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/discover", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(cost)
		writeJSON(w, map[string]any{"ok": true})
	})
	analyticsGet(h, "/api/discover")
	fresh, _ := analyticsCacheFreshTTL("/api/discover")
	advance(fresh + time.Second)
	for i := 0; i < 5; i++ {
		start := time.Now()
		if got := analyticsGet(h, "/api/discover"); got.state != "stale" {
			t.Fatalf("hit %d state %q, want stale", i, got.state)
		}
		if el := time.Since(start); el >= cost {
			t.Fatalf("stale hit %d took %v: it waited for the recompute", i, el)
		}
	}
	s.analytics.bg.Wait()
	if c := calls.Load(); c != 2 {
		t.Fatalf("handler calls = %d, want 2 (warm + ONE background refresh)", c)
	}
}

// TestAnalyticsCacheColdBurstSingleflight: N concurrent cold requests for one
// key run the handler exactly once and all receive its answer.
func TestAnalyticsCacheColdBurstSingleflight(t *testing.T) {
	s, _ := analyticsTestServer(t)
	release := make(chan struct{})
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/analysis/trend", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		writeJSON(w, map[string]any{"v": 42})
	})
	const n = 24
	var wg sync.WaitGroup
	results := make([]analyticsResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = analyticsGet(h, "/api/analysis/trend?days=7")
		}(i)
	}
	// Let every goroutine reach the flight before the computation finishes.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	s.analytics.bg.Wait()
	if c := calls.Load(); c != 1 {
		t.Fatalf("handler calls = %d for a cold burst of %d, want 1", c, n)
	}
	for i, r := range results {
		if r.code != http.StatusOK || !strings.Contains(r.body, `"v":42`) {
			t.Fatalf("request %d got %d %s", i, r.code, r.body)
		}
	}
}

// TestAnalyticsCacheMutationInvalidates drives the invalidation middleware:
// a successful mutation clears the cache, a refused one does not, and a GET
// or HEAD never does.
func TestAnalyticsCacheMutationInvalidates(t *testing.T) {
	s, _ := analyticsTestServer(t)
	var calls atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/api/cost", s.analyticsCacheWrap("/api/cost", countingAnalyticsHandler(&calls)))
	mux.HandleFunc("/api/write/ok", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]any{}) })
	mux.HandleFunc("/api/write/implicit", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/api/write/bad", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusBadRequest) })
	ok200 := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, p := range []string{"/api/loc/editor-change", "/api/terminal/workspace-layout/save", "/api/launch/", "/api/suggest", "/api/suggestions/state", "/api/suggest/write", "/api/config/section/"} {
		mux.HandleFunc(p, ok200)
	}
	h := s.analyticsInvalidateOnWrite(mux)

	cases := []struct {
		method, path string
		invalidates  bool
	}{
		{http.MethodPost, "/api/write/bad", false},
		{http.MethodGet, "/api/write/ok", false},
		{http.MethodHead, "/api/write/ok", false},
		{http.MethodPost, "/api/write/ok", true},
		{http.MethodPut, "/api/write/ok", true},
		{http.MethodDelete, "/api/write/implicit", true}, // implicit 200
		// Exempt high-frequency / dry-run routes keep the cache ...
		{http.MethodPost, "/api/loc/editor-change", false},
		{http.MethodPut, "/api/terminal/workspace-layout/save", false},
		{http.MethodDelete, "/api/launch/abc123", false}, // prefix row
		{http.MethodPost, "/api/suggest", false},
		// ... while exact rows do not leak onto neighbouring mutations.
		{http.MethodPost, "/api/suggestions/state", true},
		{http.MethodPost, "/api/suggest/write", true},
		{http.MethodPut, "/api/config/section/routing", true},
	}
	for _, tc := range cases {
		analyticsGet(h, "/api/cost") // ensure an entry exists
		s.analytics.bg.Wait()
		if got := analyticsGet(h, "/api/cost"); got.state != "fresh" {
			t.Fatalf("%s %s: precondition: state %q, want fresh", tc.method, tc.path, got.state)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		got := analyticsGet(h, "/api/cost")
		s.analytics.bg.Wait()
		wantState := "fresh"
		if tc.invalidates {
			wantState = "miss"
		}
		if got.state != wantState {
			t.Fatalf("after %s %s (%d): state %q, want %q", tc.method, tc.path, rr.Code, got.state, wantState)
		}
	}
}

// TestAnalyticsCacheRefreshLosesToInvalidate pins the generation guard: a
// recompute in flight when a mutation lands does not store its pre-mutation
// answer, and a request after the mutation does not join it.
func TestAnalyticsCacheRefreshLosesToInvalidate(t *testing.T) {
	s, advance := analyticsTestServer(t)
	var calls atomic.Int64
	release := make(chan struct{})
	h := s.analyticsCacheWrap("/api/cost", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 2 {
			<-release // the background refresh straddles the mutation
		}
		writeJSON(w, map[string]any{"call": n})
	})
	analyticsGet(h, "/api/cost")
	fresh, _ := analyticsCacheFreshTTL("/api/cost")
	advance(fresh + time.Second)
	if got := analyticsGet(h, "/api/cost"); got.state != "stale" {
		t.Fatalf("state %q, want stale", got.state)
	}
	// Wait until the background refresh is INSIDE the handler (call 2), so
	// the post-mutation request below is deterministically call 3.
	for deadline := time.Now().Add(10 * time.Second); calls.Load() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("background refresh never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.analytics.invalidate() // the mutation lands mid-refresh
	// A request after the mutation computes afresh instead of joining the
	// pre-mutation flight (which is still blocked).
	after := analyticsGet(h, "/api/cost")
	if after.state != "miss" || !strings.Contains(after.body, `"call":3`) {
		t.Fatalf("post-mutation request: state %q body %s, want a miss served by call 3", after.state, after.body)
	}
	close(release)
	s.analytics.bg.Wait()
	got := analyticsGet(h, "/api/cost")
	if got.state != "fresh" || !strings.Contains(got.body, `"call":3`) {
		t.Fatalf("after the stale refresh finished: state %q body %s — the pre-mutation call 2 must not have been stored", got.state, got.body)
	}
}

// TestAnalyticsCacheNon200NotCached: error responses reach the requests that
// shared the computation but are never stored.
func TestAnalyticsCacheNon200NotCached(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusNoContent, http.StatusNotFound} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s, _ := analyticsTestServer(t)
			var calls atomic.Int64
			h := s.analyticsCacheWrap("/api/models", func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(code)
			})
			for i := 0; i < 2; i++ {
				got := analyticsGet(h, "/api/models")
				s.analytics.bg.Wait()
				if got.code != code || got.state != "miss" {
					t.Fatalf("request %d: %d %q, want %d miss", i, got.code, got.state, code)
				}
			}
			if c := calls.Load(); c != 2 {
				t.Fatalf("calls = %d, want 2 (never cached)", c)
			}
		})
	}
}

// TestAnalyticsCachePanicIsRecovered: a panicking handler on the detached
// goroutine must not crash the process; it becomes an uncached 500.
func TestAnalyticsCachePanicIsRecovered(t *testing.T) {
	s, _ := analyticsTestServer(t)
	h := s.analyticsCacheWrap("/api/models", func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	got := analyticsGet(h, "/api/models")
	s.analytics.bg.Wait()
	if got.code != http.StatusInternalServerError || s.analytics.entryCount() != 0 {
		t.Fatalf("panic: code %d entries %d, want 500 and nothing stored", got.code, s.analytics.entryCount())
	}
}

// TestAnalyticsCacheKeyCanonicalization pins the key: query order and
// encoding variants that the handlers read identically share an entry;
// anything that changes a value, the path, or the database does not.
func TestAnalyticsCacheKeyCanonicalization(t *testing.T) {
	cases := []struct {
		name     string
		a, b     string
		sameKey  bool
		demoSwap bool
	}{
		{"query order", "/api/cost?days=7&tool=codex", "/api/cost?tool=codex&days=7", true, false},
		{"encoding variant", "/api/cost?project=a%20b", "/api/cost?project=a+b", true, false},
		{"different value", "/api/cost?days=7", "/api/cost?days=30", false, false},
		{"repeated key order is significant", "/api/cost?t=a&t=b", "/api/cost?t=b&t=a", false, false},
		{"different path", "/api/cost", "/api/models", false, false},
		{"different database", "/api/cost", "/api/cost", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := analyticsTestServer(t)
			ka, ok := s.analyticsCacheKey(httptest.NewRequest(http.MethodGet, tc.a, nil))
			if !ok {
				t.Fatal("key a not built")
			}
			if tc.demoSwap {
				other, _ := newTestServer(t)
				s.demoDB.Store(other.opts.DB)
				t.Cleanup(func() { s.demoDB.Store(nil) })
			}
			kb, _ := s.analyticsCacheKey(httptest.NewRequest(http.MethodGet, tc.b, nil))
			if (ka == kb) != tc.sameKey {
				t.Fatalf("keys %q / %q: equal=%v, want %v", ka, kb, ka == kb, tc.sameKey)
			}
		})
	}
	// Remote provenance is part of the key.
	s, _ := analyticsTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/cost", nil)
	kl, _ := s.analyticsCacheKey(r)
	kr, _ := s.analyticsCacheKey(r.WithContext(withRemoteExposed(r.Context())))
	if kl == kr {
		t.Fatal("remote-exposed request shares a key with a loopback one")
	}
	// A malformed query is never cached.
	if _, ok := s.analyticsCacheKey(httptest.NewRequest(http.MethodGet, "/api/cost?a=%zz", nil)); ok {
		t.Fatal("malformed query produced a cache key")
	}
	// End to end: order variants are one handler call.
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/cost", countingAnalyticsHandler(&calls))
	analyticsGet(h, "/api/cost?a=1&b=2")
	if got := analyticsGet(h, "/api/cost?b=2&a=1"); got.state != "fresh" || calls.Load() != 1 {
		t.Fatalf("reordered query: state %q calls %d, want fresh/1", got.state, calls.Load())
	}
}

// TestAnalyticsCacheMethodsAndPassthrough: only GET is cached; HEAD and
// mutations pass through untouched; ReadCaches off (every test's default) and
// a route missing from the allow-list return the handler itself.
func TestAnalyticsCacheMethodsAndPassthrough(t *testing.T) {
	cases := []struct {
		name        string
		readCaches  bool
		pattern     string
		method      string
		wantCalls   int64
		wantHeaders bool
	}{
		{"GET cached", true, "/api/cost", http.MethodGet, 1, true},
		{"HEAD passes through", true, "/api/cost", http.MethodHead, 2, false},
		{"POST passes through", true, "/api/cost", http.MethodPost, 2, false},
		{"ReadCaches off", false, "/api/cost", http.MethodGet, 2, false},
		{"not allow-listed", true, "/api/sessions", http.MethodGet, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			s.opts.ReadCaches = tc.readCaches
			var calls atomic.Int64
			h := s.analyticsCacheWrap(tc.pattern, countingAnalyticsHandler(&calls))
			for i := 0; i < 2; i++ {
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.pattern, nil))
				s.analytics.bg.Wait()
				if has := rr.Header().Get(analyticsCacheHeader) != ""; has != tc.wantHeaders {
					t.Fatalf("request %d: cache header present=%v, want %v", i, has, tc.wantHeaders)
				}
			}
			if c := calls.Load(); c != tc.wantCalls {
				t.Fatalf("calls = %d, want %d", c, tc.wantCalls)
			}
		})
	}
	// ReadCaches off: the whole production chain carries no cache header.
	s, _ := newTestServer(t)
	h := s.guardedHandler("127.0.0.1:8081")
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, loopbackRequest(http.MethodGet, "/api/cost"))
		if rr.Code != http.StatusOK || rr.Header().Get(analyticsCacheHeader) != "" {
			t.Fatalf("ReadCaches off: /api/cost = %d, cache header %q", rr.Code, rr.Header().Get(analyticsCacheHeader))
		}
	}
}

// TestAnalyticsCacheMemoryBounds pins LRU eviction on both bounds and the
// per-body ceiling.
func TestAnalyticsCacheMemoryBounds(t *testing.T) {
	t.Run("entry count", func(t *testing.T) {
		s, _ := analyticsTestServer(t)
		var calls atomic.Int64
		h := s.analyticsCacheWrap("/api/cost", countingAnalyticsHandler(&calls))
		for i := 0; i <= analyticsCacheMaxEntries; i++ {
			analyticsGet(h, fmt.Sprintf("/api/cost?i=%d", i))
			s.analytics.bg.Wait()
		}
		if n := s.analytics.entryCount(); n != analyticsCacheMaxEntries {
			t.Fatalf("entries = %d, want the cap %d", n, analyticsCacheMaxEntries)
		}
		// The least-recently-used (i=0) was evicted; the newest survives.
		if got := analyticsGet(h, fmt.Sprintf("/api/cost?i=%d", analyticsCacheMaxEntries)); got.state != "fresh" {
			t.Fatalf("newest entry state %q, want fresh", got.state)
		}
		if got := analyticsGet(h, "/api/cost?i=0"); got.state != "miss" {
			t.Fatalf("LRU entry state %q, want miss (evicted)", got.state)
		}
		s.analytics.bg.Wait()
	})
	t.Run("total bytes and recency", func(t *testing.T) {
		s, _ := analyticsTestServer(t)
		body := bytes.Repeat([]byte("x"), 3<<20)
		h := s.analyticsCacheWrap("/api/cost", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
		n := analyticsCacheMaxBytes/len(body) + 1 // one more than fits
		for i := 0; i < n; i++ {
			analyticsGet(h, fmt.Sprintf("/api/cost?i=%d", i))
			s.analytics.bg.Wait()
			if i == 0 {
				continue
			}
			// Touch i=1 each round so it stays most-recently-used.
			analyticsGet(h, "/api/cost?i=1")
		}
		s.analytics.mu.Lock()
		total := s.analytics.bytes
		s.analytics.mu.Unlock()
		if total > analyticsCacheMaxBytes {
			t.Fatalf("stored bytes %d exceed the cap %d", total, analyticsCacheMaxBytes)
		}
		if got := analyticsGet(h, "/api/cost?i=1"); got.state != "fresh" {
			t.Fatalf("recently used entry state %q, want fresh", got.state)
		}
		if got := analyticsGet(h, "/api/cost?i=0"); got.state != "miss" {
			t.Fatalf("least recently used entry state %q, want miss", got.state)
		}
		s.analytics.bg.Wait()
	})
	t.Run("oversize body never stored", func(t *testing.T) {
		s, _ := analyticsTestServer(t)
		big := bytes.Repeat([]byte("y"), analyticsCacheMaxEntryBytes+1)
		var calls atomic.Int64
		h := s.analyticsCacheWrap("/api/cost", func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			_, _ = w.Write(big)
		})
		for i := 0; i < 2; i++ {
			got := analyticsGet(h, "/api/cost")
			s.analytics.bg.Wait()
			if got.state != "miss" || len(got.body) != len(big) {
				t.Fatalf("request %d: state %q len %d", i, got.state, len(got.body))
			}
		}
		if calls.Load() != 2 || s.analytics.entryCount() != 0 {
			t.Fatalf("oversize body was stored (calls %d, entries %d)", calls.Load(), s.analytics.entryCount())
		}
	})
}

// TestAnalyticsCacheGuardRejectedNeverServedCached drives the REAL production
// chain on both branches: after a cached entry exists, a request any guard
// refuses (Host allow-list, governance, remote authz) gets the guard's
// refusal and never the cached bytes.
func TestAnalyticsCacheGuardRejectedNeverServedCached(t *testing.T) {
	t.Run("loopback branch", func(t *testing.T) {
		var hide atomic.Bool
		hidden := governedProvider(t, []string{"cost"}, nil, nil, nil)
		s := newRemoteTestServer(t, Options{
			ReadCaches: true,
			Governance: func(ctx context.Context) govern.Effective {
				if hide.Load() {
					return hidden(ctx)
				}
				return govern.Effective{}
			},
		})
		h := s.guardedHandler("127.0.0.1:8081")
		serve := func(r *http.Request) *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			s.analytics.bg.Wait()
			return rr
		}
		warm := serve(loopbackRequest(http.MethodGet, "/api/cost?days=30"))
		if warm.Code != http.StatusOK || warm.Header().Get(analyticsCacheHeader) != "miss" {
			t.Fatalf("warm = %d %q", warm.Code, warm.Header().Get(analyticsCacheHeader))
		}
		if hit := serve(loopbackRequest(http.MethodGet, "/api/cost?days=30")); hit.Header().Get(analyticsCacheHeader) != "fresh" {
			t.Fatalf("second request state %q, want fresh", hit.Header().Get(analyticsCacheHeader))
		}
		cached := warm.Body.String()

		rebound := loopbackRequest(http.MethodGet, "/api/cost?days=30")
		rebound.Host = "evil.example:8081"
		hide.Store(true)
		for name, r := range map[string]*http.Request{
			"foreign Host": rebound,
			"governance":   loopbackRequest(http.MethodGet, "/api/cost?days=30"),
		} {
			rr := serve(r)
			if rr.Code == http.StatusOK || rr.Header().Get(analyticsCacheHeader) != "" || rr.Body.String() == cached {
				t.Fatalf("%s: guard-refused request got %d, cache header %q — it was answered from the cache", name, rr.Code, rr.Header().Get(analyticsCacheHeader))
			}
		}
	})
	t.Run("remote branch", func(t *testing.T) {
		rc, enc := newReadyRemoteController(t)
		s := newRemoteTestServer(t, Options{Remote: rc, ReadCaches: true})
		h := s.guardedHandler(testRemoteHost) // non-loopback bind → remote chain
		cookie, csrf := pairSession(t, h, enc)
		do := func(withAuth bool) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/api/cost?days=30", nil)
			req.Host = testRemoteHost
			if withAuth {
				req.AddCookie(cookie)
				req.Header.Set(remoteCSRFHeader, csrf)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			s.analytics.bg.Wait()
			return rr
		}
		warm := do(true)
		if warm.Code != http.StatusOK || warm.Header().Get(analyticsCacheHeader) != "miss" {
			t.Fatalf("paired warm = %d %q", warm.Code, warm.Header().Get(analyticsCacheHeader))
		}
		if hit := do(true); hit.Header().Get(analyticsCacheHeader) != "fresh" {
			t.Fatalf("paired second request state %q, want fresh", hit.Header().Get(analyticsCacheHeader))
		}
		anon := do(false)
		if anon.Code != http.StatusUnauthorized || anon.Header().Get(analyticsCacheHeader) != "" || anon.Body.String() == warm.Body.String() {
			t.Fatalf("anonymous request got %d, cache header %q — it was answered from the cache", anon.Code, anon.Header().Get(analyticsCacheHeader))
		}
	})
}

// TestAnalyticsCacheDemoSwapInvalidates: demo start/stop clears the cache
// (the in-process invalidate at the swap, not only the POST's own).
func TestAnalyticsCacheDemoSwapInvalidates(t *testing.T) {
	s, _ := analyticsTestServer(t)
	demo, _ := newTestServer(t)
	s.opts.DemoSeeder = func(context.Context) (*sql.DB, func() error, error) {
		return demo.opts.DB, func() error { return nil }, nil
	}
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/cost", countingAnalyticsHandler(&calls))
	analyticsGet(h, "/api/cost")
	s.analytics.bg.Wait()
	for _, fn := range []http.HandlerFunc{s.handleDemoStart, s.handleDemoStop} {
		if s.analytics.entryCount() == 0 {
			analyticsGet(h, "/api/cost")
			s.analytics.bg.Wait()
		}
		rr := httptest.NewRecorder()
		fn(rr, httptest.NewRequest(http.MethodPost, "/api/demo", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("demo toggle = %d: %s", rr.Code, rr.Body.String())
		}
		if n := s.analytics.entryCount(); n != 0 {
			t.Fatalf("demo toggle left %d cached entries", n)
		}
	}
}

// TestAnalyticsCacheAllowListIsViewReads pins the allow-list's safety
// precondition: every row is a registered route classified View (a GET read
// a paired viewer may already see), never Local/Execute/Public, and names no
// duplicate.
func TestAnalyticsCacheAllowListIsViewReads(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, _ := s.registerRoutes(nil)
	seen := map[string]bool{}
	for _, rt := range analyticsCacheRoutes {
		if seen[rt.Pattern] {
			t.Errorf("duplicate allow-list row %q", rt.Pattern)
		}
		seen[rt.Pattern] = true
		cap, ok := capMap[rt.Pattern]
		if !ok {
			t.Errorf("allow-list row %q is not a registered route", rt.Pattern)
			continue
		}
		if cap != CapabilityView {
			t.Errorf("allow-list row %q is classified %s, want View", rt.Pattern, cap)
		}
		if fresh, _ := analyticsCacheFreshTTL(rt.Pattern); fresh <= 0 || fresh >= analyticsCacheStaleServeMax {
			t.Errorf("allow-list row %q fresh TTL %v must be in (0, %v)", rt.Pattern, fresh, analyticsCacheStaleServeMax)
		}
	}
}

// TestAnalyticsCacheNoInvalidateTableIsGrounded pins the exemption table:
// every row names a route the dashboard actually serves (a typo would
// silently exempt nothing, or the wrong thing), carries a reason, is not
// itself a cached analytics route, and exact rows are not prefixes.
func TestAnalyticsCacheNoInvalidateTableIsGrounded(t *testing.T) {
	rc, _ := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	_, capMap, _ := s.registerRoutes(rc)
	// ExtraRoutes contributed from cmd/observer (not built in this package).
	external := map[string]bool{"/api/obs/admission/test": true}
	registered := func(path string) bool {
		for pattern := range capMap {
			if _, p, found := strings.Cut(pattern, " "); found {
				pattern = p
			}
			if pattern == path {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, rt := range analyticsNoInvalidateRoutes {
		if seen[rt.Path] {
			t.Errorf("duplicate exemption row %q", rt.Path)
		}
		seen[rt.Path] = true
		if strings.TrimSpace(rt.Reason) == "" {
			t.Errorf("exemption row %q has no reason", rt.Path)
		}
		if _, cached := analyticsCacheFreshTTL(rt.Path); cached {
			t.Errorf("exemption row %q is a cached analytics route", rt.Path)
		}
		if !registered(rt.Path) && !external[rt.Path] {
			t.Errorf("exemption row %q is not a registered route", rt.Path)
		}
		if analyticsMutationInvalidates(rt.Path) {
			t.Errorf("exemption row %q still invalidates", rt.Path)
		}
	}
	for _, p := range []string{"/api/config/section/routing", "/api/reprice/apply", "/api/demo/start", "/api/backfill/run", "/api/suggestions/state", "/api/unknown/mutation"} {
		if !analyticsMutationInvalidates(p) {
			t.Errorf("%s must invalidate (default is conservative)", p)
		}
	}
}

// TestAnalyticsEntryFreshnessScalesWithWindow pins analyticsWindowRules: a
// sub-day window (span <= 24h) caps the fresh TTL at 30 s and the stale-serve
// bound at 2 min; a wider window, or none, keeps the route's values.
func TestAnalyticsEntryFreshnessScalesWithWindow(t *testing.T) {
	since := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)
	cases := []struct {
		query      string
		routeFresh time.Duration
		wantFresh  time.Duration
		wantStale  time.Duration
	}{
		{"hours=1", 2 * time.Minute, 30 * time.Second, 2 * time.Minute},
		{"hours=12", 5 * time.Minute, 30 * time.Second, 2 * time.Minute},
		{"days=1", 2 * time.Minute, 30 * time.Second, 2 * time.Minute},
		{"hours=1", 10 * time.Second, 10 * time.Second, 2 * time.Minute}, // never raises a shorter route TTL
		{"since=" + since, 5 * time.Minute, 30 * time.Second, 2 * time.Minute},
		{"hours=48", 2 * time.Minute, 2 * time.Minute, analyticsCacheStaleServeMax},
		{"days=30", 5 * time.Minute, 5 * time.Minute, analyticsCacheStaleServeMax},
		{"days=0", 30 * time.Second, 30 * time.Second, analyticsCacheStaleServeMax}, // all time
		{"", 2 * time.Minute, 2 * time.Minute, analyticsCacheStaleServeMax},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/timeseries/cost?"+c.query, nil)
		fresh, stale := analyticsEntryFreshness(r, c.routeFresh)
		if fresh != c.wantFresh || stale != c.wantStale {
			t.Errorf("%q (route %s): fresh %s stale %s, want %s / %s", c.query, c.routeFresh, fresh, stale, c.wantFresh, c.wantStale)
		}
	}
}

// TestAnalyticsCacheSubDayWindowStaleBound: through the wrapper, a 1h
// window's entry on a long-TTL route goes stale after 30 s and is no longer
// served stale after 2 minutes, while a 30-day entry keeps the route's TTL.
func TestAnalyticsCacheSubDayWindowStaleBound(t *testing.T) {
	s, advance := analyticsTestServer(t)
	var calls atomic.Int64
	h := s.analyticsCacheWrap("/api/verbosity/aggregate", countingAnalyticsHandler(&calls)) // 2 min route TTL
	get := func(q string) string {
		got := analyticsGet(h, "/api/verbosity/aggregate?"+q)
		s.analytics.bg.Wait()
		return got.state
	}
	if st := get("hours=1"); st != "miss" {
		t.Fatalf("cold: %s", st)
	}
	if st := get("days=30"); st != "miss" {
		t.Fatalf("cold 30d: %s", st)
	}
	advance(31 * time.Second)
	if st := get("hours=1"); st != "stale" {
		t.Errorf("1h after 31s = %s, want stale (30 s fresh cap)", st)
	}
	if st := get("days=30"); st != "fresh" {
		t.Errorf("30d after 31s = %s, want fresh (route TTL 2 min)", st)
	}
	advance(2*time.Minute + time.Second)
	if st := get("hours=1"); st != "miss" {
		t.Errorf("1h entry 2m1s old = %s, want miss (2 min stale-serve cap)", st)
	}
}
