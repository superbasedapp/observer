package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// boxGate is a caller gate that refuses every mutating request (the caller
// is in a box) and records what it saw.
type boxGate struct {
	mu    sync.Mutex
	calls int
	last  struct{ client, server netip.AddrPort }
}

func (g *boxGate) gate(_ context.Context, client, server netip.AddrPort, mutating bool) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	g.last.client, g.last.server = client, server
	return "refused: inside sandboxed run run-1", mutating
}

func newCallerGuardServer(t *testing.T, g *boxGate) http.Handler {
	_, h := newCallerGuardServerAndHandler(t, g)
	return h
}

func newCallerGuardServerAndHandler(t *testing.T, g *boxGate) (*Server, http.Handler) {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, LaunchManager: &fakeLaunchManager{}, LoopbackCallerGate: g.gate})
	if err != nil {
		t.Fatal(err)
	}
	return s, s.guardedHandler("127.0.0.1:8081")
}

// pathFor is a request path the mux routes to pattern.
func pathFor(pattern string) string {
	switch {
	case pattern == "/api/session/":
		return "/api/session/s-1/launch"
	case strings.HasSuffix(pattern, "/"):
		return pattern + "x"
	}
	return pattern
}

// TestCallerGuardCoversEveryRoute walks every registered route: a box
// caller's POST, PUT, PATCH and DELETE are refused (403 sandbox_caller)
// before any handler runs, on every route, by construction; a read passes
// the guard.
func TestCallerGuardCoversEveryRoute(t *testing.T) {
	g := &boxGate{}
	s, h := newCallerGuardServerAndHandler(t, g)
	_, capMap, _ := s.registerRoutes(nil)
	if len(capMap) < 100 {
		t.Fatalf("only %d routes registered; the walk would be vacuous", len(capMap))
	}
	for pattern := range capMap {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			req := httptest.NewRequest(method, "http://127.0.0.1:8081"+pathFor(pattern), strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			var body map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if rec.Code != http.StatusForbidden || body["code"] != callerRefusedCode {
				t.Errorf("%s %s (route %s) = %d %s, want 403 %s", method, pathFor(pattern), pattern, rec.Code, rec.Body.String(), callerRefusedCode)
			}
		}
	}
	// A read reaches its handler.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/api/terminal/policy", nil))
	if strings.Contains(rec.Body.String(), callerRefusedCode) {
		t.Fatalf("a GET was refused: %s", rec.Body.String())
	}
}

// TestCallerGuardRefusesTheTerminalBridge: a WebSocket upgrade (the
// terminal bridge, whose writer lease types into a PTY) is judged like a
// write.
func TestCallerGuardRefusesTheTerminalBridge(t *testing.T) {
	h := newCallerGuardServer(t, &boxGate{})
	for _, path := range []string{"/ws/launch/h-1", "/ws/terminal/status"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081"+path, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), callerRefusedCode) {
			t.Errorf("upgrade %s = %d %s, want refused", path, rec.Code, rec.Body.String())
		}
	}
}

// TestCallerGuardJudgesEveryUpgradeSpelling (callerid fixes-1, H1): a
// handshake coder/websocket accepts is judged however its Upgrade header
// is spelt (a comma list, a second line, any case), and any /ws/ path is
// judged even with no Upgrade header at all.
func TestCallerGuardJudgesEveryUpgradeSpelling(t *testing.T) {
	h := newCallerGuardServer(t, &boxGate{})
	cases := []struct {
		name    string
		path    string
		upgrade []string
	}{
		{"a comma list", "/ws/launch/h-1", []string{"h2c, websocket"}},
		{"two Upgrade lines", "/ws/launch/h-1", []string{"h2c", "websocket"}},
		{"another case and spacing", "/ws/terminal/status", []string{" WebSocket "}},
		{"no Upgrade header under /ws/", "/ws/launch/h-1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081"+tc.path, nil)
			for _, u := range tc.upgrade {
				req.Header.Add("Upgrade", u)
			}
			req.Header.Set("Connection", "Upgrade")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), callerRefusedCode) {
				t.Errorf("%s = %d %s, want refused", tc.path, rec.Code, rec.Body.String())
			}
		})
	}
	// A plain read outside /ws/ with an unrelated Upgrade still passes.
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/api/terminal/policy", nil)
	req.Header.Set("Upgrade", "h2c")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), callerRefusedCode) {
		t.Fatalf("an h2c GET was judged: %s", rec.Body.String())
	}
}

// TestIsWebSocketUpgrade is the token parse, one row per spelling.
func TestIsWebSocketUpgrade(t *testing.T) {
	for _, tc := range []struct {
		lines []string
		want  bool
	}{
		{[]string{"websocket"}, true},
		{[]string{"WebSocket"}, true},
		{[]string{"h2c, websocket"}, true},
		{[]string{"h2c", "websocket"}, true},
		{[]string{"websocket2"}, false},
		{[]string{"h2c"}, false},
		{nil, false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, l := range tc.lines {
			req.Header.Add("Upgrade", l)
		}
		if got := isWebSocketUpgrade(req); got != tc.want {
			t.Errorf("Upgrade %q = %v, want %v", tc.lines, got, tc.want)
		}
	}
}

// TestCallerGuardPassesTheConnectionEnds: the gate receives the client end
// (RemoteAddr) and the listener's end (LocalAddrContextKey).
func TestCallerGuardPassesTheConnectionEnds(t *testing.T) {
	g := &boxGate{}
	h := newCallerGuardServer(t, g)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/api/terminal/launch", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:54321"
	req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8081}))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if g.last.client != netip.MustParseAddrPort("127.0.0.1:54321") || g.last.server != netip.MustParseAddrPort("127.0.0.1:8081") {
		t.Fatalf("gate saw %v -> %v", g.last.client, g.last.server)
	}
	// No gate: nothing is judged.
	database, _ := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	defer func() { _ = database.Close() }()
	s, _ := New(Options{DB: database, LaunchManager: &fakeLaunchManager{}})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/api/terminal/launch", strings.NewReader(`{"tool":"codex"}`)))
	if strings.Contains(rec.Body.String(), callerRefusedCode) {
		t.Fatal("refused with no gate")
	}
}

// TestCallerRefusalLogOncePerPath (callerid fixes-1, L3): a refused path
// logs once, a second path logs once, and the set is bounded.
func TestCallerRefusalLogOncePerPath(t *testing.T) {
	var l callerRefusalLog
	if !l.first("/api/plans/statusline") || l.first("/api/plans/statusline") {
		t.Fatal("the same path logged twice, or not at all")
	}
	if !l.first("/api/config/keys") {
		t.Fatal("a second path did not log")
	}
	for i := range callerRefusalLogPaths {
		l.first("/p/" + strconv.Itoa(i))
	}
	if l.first("/one/more") {
		t.Fatal("the log is unbounded")
	}
}
