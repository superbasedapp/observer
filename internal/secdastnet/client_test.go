package secdastnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secdast"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// target turns an httptest server URL (always 127.0.0.1:<port>) into a
// target.
func target(t *testing.T, srvURL, path string) secdast.Target {
	t.Helper()
	tg, err := secdast.ParseTarget(srvURL + path)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestFetchLoopbackServer(t *testing.T) {
	t.Parallel()
	var gotUA, gotOrigin, gotCookie, gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			gotUA.Store(r.UserAgent())
			gotOrigin.Store(r.Header.Get("Origin"))
			gotCookie.Store(r.Header.Get("Cookie"))
			gotAuth.Store(r.Header.Get("Authorization"))
			w.Header().Set("Set-Cookie", "sid=1; Path=/")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>hi</html>"))
		case "/old":
			http.Redirect(w, r, "/new", http.StatusFound)
		case "/new":
			_, _ = w.Write([]byte("moved"))
		case "/away":
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("a", secdast.MaxBodyBytes+100)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(context.Background(), target(t, srv.URL, "/"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	r := c.Fetch(ctx, secdast.Request{ID: "page", Path: "/", Origin: secdast.CanaryOrigin})
	if r.Err != "" || r.Status != 200 || string(r.Body) != "<html>hi</html>" || r.Header.Get("set-cookie") != "sid=1; Path=/" {
		t.Fatalf("page %+v", r)
	}
	// Two cookie-setting answers: the client keeps no jar.
	_ = c.Fetch(ctx, secdast.Request{ID: "again", Path: "/"})
	if gotUA.Load() != UserAgent || gotCookie.Load() != "" || gotAuth.Load() != "" {
		t.Errorf("sent UA %v cookie %v auth %v", gotUA.Load(), gotCookie.Load(), gotAuth.Load())
	}
	if r := c.Fetch(ctx, secdast.Request{ID: "x", Path: "/", Origin: "https://attacker.example"}); !strings.Contains(r.Err, "canary") {
		t.Errorf("a non-canary Origin was sent: %+v", r)
	}

	if r := c.Fetch(ctx, secdast.Request{ID: "old", Path: "/old"}); r.Err != "" || r.Status != 200 || r.Path != "/new" || string(r.Body) != "moved" {
		t.Errorf("same-origin redirect %+v", r)
	}
	if r := c.Fetch(ctx, secdast.Request{ID: "away", Path: "/away"}); r.Err != "" || r.Status != 302 || !r.OffOriginRedirect || r.Path != "/away" {
		t.Errorf("off-origin redirect followed or misreported: %+v", r)
	}
	before := c.RoundTrips()
	if r := c.Fetch(ctx, secdast.Request{ID: "loop", Path: "/loop"}); r.Status != 302 || c.RoundTrips()-before != secdast.MaxRedirects+1 {
		t.Errorf("redirect loop: %+v after %d round trips", r, c.RoundTrips()-before)
	}
	if r := c.Fetch(ctx, secdast.Request{ID: "big", Path: "/big"}); !r.Truncated || len(r.Body) != secdast.MaxBodyBytes {
		t.Errorf("body cap: truncated %v, %d bytes", r.Truncated, len(r.Body))
	}
	for _, bad := range []string{"http://example.com/", "//example.com/", "relative", "/a b"} {
		if r := c.Fetch(ctx, secdast.Request{ID: "bad", Path: bad}); r.Err == "" {
			t.Errorf("path %q was fetched", bad)
		}
	}
}

func TestRoundTripCap(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	c, err := New(context.Background(), target(t, srv.URL, "/"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var last secdast.Response
	for i := 0; i <= MaxRoundTrips; i++ {
		last = c.Fetch(context.Background(), secdast.Request{ID: fmt.Sprint(i), Path: "/"})
	}
	if !strings.Contains(last.Err, "round trips") || c.RoundTrips() != MaxRoundTrips {
		t.Fatalf("cap not held: %+v after %d", last, c.RoundTrips())
	}
}

func TestTLSLoopback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tls")) }))
	defer srv.Close()
	tg := target(t, srv.URL, "/")
	c, err := New(context.Background(), tg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r := c.Fetch(context.Background(), secdast.Request{ID: "p", Path: "/"}); r.Err == "" {
		t.Error("an untrusted certificate was accepted without InsecureTLS")
	}
	c.Close()
	c, err = New(context.Background(), tg, Options{InsecureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if r := c.Fetch(context.Background(), secdast.Request{ID: "p", Path: "/"}); r.Err != "" || string(r.Body) != "tls" {
		t.Errorf("InsecureTLS fetch %+v", r)
	}
}

// TestNewRefusesNonLoopback: a target that is not loopback, or a name that
// resolves anywhere else, is refused before any connection.
func TestNewRefusesNonLoopback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tg := range []secdast.Target{
		{Scheme: "http", Host: "example.com", Port: "80", Path: "/"},
		{Scheme: "http", Host: "10.0.0.1", Port: "80", Path: "/"},
		{Scheme: "http", Host: "localhost", Port: "", Path: "/"},
		{Scheme: "ftp", Host: "localhost", Port: "21", Path: "/"},
	} {
		if _, err := New(ctx, tg, Options{}); !errors.Is(err, ErrRefused) {
			t.Errorf("%+v: %v, want ErrRefused", tg, err)
		}
	}
	localhost := secdast.Target{Scheme: "http", Host: "localhost", Port: "3000", Path: "/"}
	for name, ips := range map[string][]net.IP{
		"public":            {net.ParseIP("93.184.216.34")},
		"mixed":             {net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.10")},
		"metadata":          {net.ParseIP("169.254.169.254")},
		"none":              {},
		"nat64 of private":  {net.ParseIP("64:ff9b::a00:1")},
		"nat64 of loopback": {net.ParseIP("64:ff9b::7f00:1")},
	} {
		lookup := func(context.Context, string) ([]net.IP, error) { return ips, nil }
		if _, err := New(ctx, localhost, Options{LookupIP: lookup}); !errors.Is(err, ErrRefused) {
			t.Errorf("localhost resolving %s: %v, want ErrRefused", name, err)
		}
	}
	ok := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}, nil
	}
	c, err := New(ctx, localhost, Options{LookupIP: ok})
	if err != nil || !c.ip.Equal(net.ParseIP("::1")) {
		t.Fatalf("loopback resolution refused: %v", err)
	}
	c.Close()
}

// TestLoopbackControl is the dial-time check, after DNS, per connection.
func TestLoopbackControl(t *testing.T) {
	t.Parallel()
	for addr, ok := range map[string]bool{
		"127.0.0.1:3000":       true,
		"127.9.9.9:80":         true,
		"[::1]:5173":           true,
		"[::ffff:127.0.0.1]:1": true,
		"10.0.0.1:3000":        false,
		"93.184.216.34:443":    false,
		"169.254.169.254:80":   false,
		"[fe80::1]:80":         false,
		"0.0.0.0:3000":         false,
		"localhost:3000":       false,
		"[64:ff9b::7f00:1]:80": false,
		"[2002:7f00:1::]:80":   false,
		"[::1%25lo]:80":        false,
		"garbage":              false,
	} {
		err := loopbackControl("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("%s: %v, want allowed=%v", addr, err, ok)
		}
		if err != nil && !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v does not wrap ErrRefused", addr, err)
		}
	}
	if loopbackControl("udp", "127.0.0.1:53", nil) == nil {
		t.Error("a UDP dial was allowed")
	}
}

// TestRunAgainstLoopbackServer: the pure run and the lane together, against
// a real loopback server with the classic misconfigurations.
func TestRunAgainstLoopbackServer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Werkzeug/3.0.1 Python/3.12.0")
		switch r.URL.Path {
		case "/":
			if o := r.Header.Get("Origin"); o != "" {
				w.Header().Set("Access-Control-Allow-Origin", o)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Set-Cookie", "session=abc; Path=/")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script></head><body>app</body></html>`))
		case "/app.js":
			_, _ = w.Write([]byte("run()\n//# sourceMappingURL=app.js.map"))
		case "/app.js.map":
			_, _ = w.Write([]byte(`{"version":3,"sources":["app.ts"],"mappings":"AAAA"}`))
		case "/.git/HEAD":
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
		case "/.env":
			_, _ = w.Write([]byte("SECRET=1\nOTHER=2\n"))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("<h1>Not Found</h1>"))
		}
	}))
	defer srv.Close()
	tg := target(t, srv.URL, "/")
	c, err := New(context.Background(), tg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rep := secdast.Run(context.Background(), tg, "abc123", c.Fetch)
	if rep.Outcome != secdast.OutcomeComplete {
		t.Fatalf("outcome %s: %+v", rep.Outcome, rep.Errors)
	}
	got := map[string]bool{}
	for _, h := range rep.Hits {
		got[h.Check] = true
	}
	for _, want := range []string{
		"dast.headers.csp-missing", "dast.headers.nosniff-missing", "dast.headers.framing-missing",
		"dast.cookies.httponly-missing", "dast.cookies.samesite-missing", "dast.cors.origin-reflected-credentials",
		"dast.exposed.git", "dast.exposed.env", "dast.exposed.sourcemap", "dast.banner.version",
	} {
		if !got[want] {
			t.Errorf("%s not reported (hits %v)", want, got)
		}
	}
	if got["dast.cors.origin-reflected"] || got["dast.headers.hsts-missing"] || got["dast.debug.page"] {
		t.Errorf("unexpected hits %v", got)
	}
	if c.RoundTrips() > secdast.MaxRequests {
		t.Errorf("%d round trips", c.RoundTrips())
	}
}

// TestNoForbiddenImports: the lane may dial, but holds no store, database,
// process or fsnotify, and never reaches back into a daemon path.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "os/exec", "github.com/fsnotify/fsnotify", "net/http/httputil"},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/proxy",
			"github.com/marmutapp/superbased-observer/internal/watcher",
			"github.com/marmutapp/superbased-observer/internal/hook",
		},
		Reason: "internal/secdastnet is the security.dast lane only",
	})
}
