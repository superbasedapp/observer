package sandboxnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// testPublicIP is TEST-NET-3: allowed by the policy, never routed for real.
var testPublicIP = net.ParseIP("203.0.113.7")

// fakeNet injects resolution, dialling and the local-address list. Dial maps
// an allowed "ip:port" onto a real local listener through routes, so the
// policy sees the public address while the bytes go to 127.0.0.1.
type fakeNet struct {
	resolve    map[string][]net.IP
	resolveErr error
	routes     map[string]string
	dialErr    error
	local      []net.IP
	localErr   error
	allow      []netip.Prefix

	mu       sync.Mutex
	resolved []string
	dialed   []string
}

func (f *fakeNet) gateway() *Gateway {
	return &Gateway{
		Resolve: func(_ context.Context, host string) ([]net.IP, error) {
			f.mu.Lock()
			f.resolved = append(f.resolved, host)
			f.mu.Unlock()
			if f.resolveErr != nil {
				return nil, f.resolveErr
			}
			ips, ok := f.resolve[host]
			if !ok {
				return nil, fmt.Errorf("no such host %s", host)
			}
			return ips, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			f.mu.Lock()
			f.dialed = append(f.dialed, addr)
			f.mu.Unlock()
			if f.dialErr != nil {
				return nil, f.dialErr
			}
			target, ok := f.routes[addr]
			if !ok {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
		LocalAddrs: func() ([]net.IP, error) { return f.local, f.localErr },
		Allow:      f.allow,
		Logger:     discardLogger(),
	}
}

func (f *fakeNet) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

func (f *fakeNet) resolves() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.resolved...)
}

// startGateway serves g on a unix socket through a real http.Server, the way
// cmd deploys it, and returns the socket path.
func startGateway(t *testing.T, g *Gateway) string {
	t.Helper()
	ln, path := listenUnix(t, "gw.sock")
	srv := &http.Server{Handler: g, ReadHeaderTimeout: testTimeout}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return path
}

// rawRequest writes a raw request head (plus extra bytes) to the gateway and
// returns the parsed response and the reader positioned after its head.
func rawRequest(t *testing.T, path, method, head, extra string) (*http.Response, *net.UnixConn, *bufio.Reader) {
	t.Helper()
	c := dialUnix(t, path)
	if _, err := io.WriteString(c, head+extra); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, c, br
}

func connectHead(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

func TestGateway_Connect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		target      string
		extra       string // bytes pipelined right after the CONNECT head
		setup       func(f *fakeNet, echo string)
		wantStatus  int
		wantBody    string // substring of a refusal body
		wantDials   []string
		wantResolve []string
		literal     bool // a literal IP must never reach Resolve
	}{
		{
			name:   "allowed public host dials the ip",
			target: "example.test:443",
			setup: func(f *fakeNet, echo string) {
				f.resolve = map[string][]net.IP{"example.test": {testPublicIP}}
				f.routes = map[string]string{"203.0.113.7:443": echo}
			},
			wantStatus:  http.StatusOK,
			wantDials:   []string{"203.0.113.7:443"},
			wantResolve: []string{"example.test"},
		},
		{
			name:   "pipelined bytes after CONNECT are forwarded",
			target: "example.test:443",
			extra:  "early",
			setup: func(f *fakeNet, echo string) {
				f.resolve = map[string][]net.IP{"example.test": {testPublicIP}}
				f.routes = map[string]string{"203.0.113.7:443": echo}
			},
			wantStatus: http.StatusOK,
			wantDials:  []string{"203.0.113.7:443"},
		},
		{
			name:   "host resolving to loopback is refused",
			target: "evil.test:443",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"evil.test": {net.ParseIP("127.0.0.1")}}
			},
			wantStatus:  http.StatusForbidden,
			wantBody:    RuleLoopback,
			wantResolve: []string{"evil.test"},
		},
		{
			name:   "mixed answer dials the allowed address",
			target: "mixed.test:443",
			setup: func(f *fakeNet, echo string) {
				f.resolve = map[string][]net.IP{"mixed.test": {net.ParseIP("127.0.0.1"), testPublicIP}}
				f.routes = map[string]string{"203.0.113.7:443": echo}
			},
			wantStatus: http.StatusOK,
			wantDials:  []string{"203.0.113.7:443"},
		},
		{
			name:       "literal ipv4 loopback skips resolution and is refused",
			target:     "127.0.0.1:8081",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RuleLoopback,
		},
		{
			name:       "literal ipv6 loopback is refused",
			target:     "[::1]:8081",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RuleLoopback,
		},
		{
			name:   "localhost is refused",
			target: "localhost:8081",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"localhost": {net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
			},
			wantStatus:  http.StatusForbidden,
			wantBody:    RuleLoopback,
			wantResolve: []string{"localhost"},
		},
		{
			name:       "cloud metadata literal is refused",
			target:     "169.254.169.254:80",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RuleLinkLocalUnicast,
		},
		{
			name:   "host interface address is refused",
			target: "lan.test:22",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"lan.test": {net.ParseIP("192.168.1.10")}}
				f.local = []net.IP{net.ParseIP("192.168.1.10")}
			},
			wantStatus: http.StatusForbidden,
			wantBody:   RuleHostLocal,
		},
		{
			name:   "wsl2 nat default gateway (the windows host) is refused, naming the config key",
			target: "host.test:8081",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"host.test": {net.ParseIP("172.24.64.1")}}
				f.local = []net.IP{net.ParseIP("172.24.70.5")}
			},
			wantStatus: http.StatusForbidden,
			wantBody:   RulePrivate + " (to allow a private destination, add its CIDR to " + AllowCIDRsConfigKey + ")",
		},
		{
			name:       "docker bridge container literal is refused",
			target:     "172.17.0.2:5432",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RulePrivate,
		},
		{
			name:       "cgnat / tailnet literal is refused",
			target:     "100.101.102.103:443",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RuleSharedAddress,
		},
		{
			name:       "ipv6 ula literal is refused",
			target:     "[fd12:3456::1]:443",
			setup:      func(*fakeNet, string) {},
			literal:    true,
			wantStatus: http.StatusForbidden,
			wantBody:   RuleUniqueLocal,
		},
		{
			name:   "allow-listed private registry is dialled",
			target: "registry.corp.test:443",
			setup: func(f *fakeNet, echo string) {
				f.resolve = map[string][]net.IP{"registry.corp.test": {net.ParseIP("10.20.30.40")}}
				f.routes = map[string]string{"10.20.30.40:443": echo}
				f.allow = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
			},
			wantStatus: http.StatusOK,
			wantDials:  []string{"10.20.30.40:443"},
		},
		{
			name:   "private address outside the allow-list stays refused",
			target: "db.corp.test:5432",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"db.corp.test": {net.ParseIP("10.99.0.1")}}
				f.allow = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
			},
			wantStatus: http.StatusForbidden,
			wantBody:   RulePrivate,
		},
		{
			name:   "allow-list never lifts a host interface address",
			target: "self.test:22",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"self.test": {net.ParseIP("10.20.0.5")}}
				f.local = []net.IP{net.ParseIP("10.20.0.5")}
				f.allow = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
			},
			wantStatus: http.StatusForbidden,
			wantBody:   RuleHostLocal,
		},
		{
			name:   "local address listing failure fails closed",
			target: "example.test:443",
			setup: func(f *fakeNet, echo string) {
				f.resolve = map[string][]net.IP{"example.test": {testPublicIP}}
				f.routes = map[string]string{"203.0.113.7:443": echo}
				f.localErr = errors.New("netlink unavailable")
			},
			wantStatus: http.StatusForbidden,
			wantBody:   ruleLocalAddrsUnavailable,
		},
		{
			name:       "missing port",
			target:     "example.test",
			setup:      func(*fakeNet, string) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "zero port",
			target:     "example.test:0",
			setup:      func(*fakeNet, string) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "out of range port",
			target:     "example.test:99999",
			setup:      func(*fakeNet, string) {},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:   "resolution failure",
			target: "gone.test:443",
			setup: func(f *fakeNet, _ string) {
				f.resolveErr = errors.New("NXDOMAIN")
			},
			wantStatus:  http.StatusBadGateway,
			wantResolve: []string{"gone.test"},
		},
		{
			name:   "dial failure",
			target: "example.test:443",
			setup: func(f *fakeNet, _ string) {
				f.resolve = map[string][]net.IP{"example.test": {testPublicIP}}
				f.dialErr = errors.New("connection refused")
			},
			wantStatus: http.StatusBadGateway,
			wantDials:  []string{"203.0.113.7:443"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			echo := startTCPServer(t, echoHandler)
			f := &fakeNet{}
			tc.setup(f, echo)
			path := startGateway(t, f.gateway())

			resp, c, br := rawRequest(t, path, http.MethodConnect, connectHead(tc.target), tc.extra)
			if resp.StatusCode != tc.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d (%q), want %d", resp.StatusCode, body, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK {
				want := tc.extra + "ping"
				if _, err := io.WriteString(c, "ping"); err != nil {
					t.Fatalf("write through tunnel: %v", err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(br, got); err != nil {
					t.Fatalf("read through tunnel: %v", err)
				}
				if string(got) != want {
					t.Fatalf("tunnel echo = %q, want %q", got, want)
				}
				if err := c.CloseWrite(); err != nil {
					t.Fatalf("CloseWrite: %v", err)
				}
				if rest, err := io.ReadAll(br); err != nil || len(rest) != 0 {
					t.Fatalf("after half-close: rest=%q err=%v, want clean EOF", rest, err)
				}
			} else {
				body, _ := io.ReadAll(resp.Body)
				if tc.wantBody != "" && !strings.Contains(string(body), tc.wantBody) {
					t.Fatalf("body = %q, want it to name %q", body, tc.wantBody)
				}
				if strings.ContainsRune(string(body), '—') {
					t.Fatalf("body %q contains an em-dash", body)
				}
			}
			if got := f.dials(); !equalStrings(got, tc.wantDials) {
				t.Fatalf("dials = %q, want %q", got, tc.wantDials)
			}
			if tc.wantResolve != nil {
				if got := f.resolves(); !equalStrings(got, tc.wantResolve) {
					t.Fatalf("resolves = %q, want %q", got, tc.wantResolve)
				}
			}
			if tc.literal {
				if got := f.resolves(); len(got) != 0 {
					t.Fatalf("literal target resolved: %q", got)
				}
			}
		})
	}
}

// backendRecord is what the fake origin saw for one request.
type backendRecord struct {
	host      string
	proxyAuth string
	proxyConn string
	custom    string
	body      string
}

func TestGateway_AbsoluteForm(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	seen := map[string]backendRecord{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[r.URL.Path] = backendRecord{
			host:      r.Host,
			proxyAuth: r.Header.Get("Proxy-Authorization"),
			proxyConn: r.Header.Get("Proxy-Connection"),
			custom:    r.Header.Get("X-Custom"),
			body:      string(body),
		}
		mu.Unlock()
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/x", http.StatusFound)
			return
		}
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, "hello %s %s %s", r.Method, r.URL.Path, body)
	}))
	t.Cleanup(backend.Close)
	backendAddr := backend.Listener.Addr().String()
	_, backendPort, _ := net.SplitHostPort(backendAddr)

	f := &fakeNet{
		resolve: map[string][]net.IP{
			"example.test": {testPublicIP},
			"loop.test":    {net.ParseIP("127.0.0.1")},
		},
		routes: map[string]string{"203.0.113.7:80": backendAddr},
	}
	path := startGateway(t, f.gateway())

	proxyURL, err := url.Parse("http://user:pass@gw")
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{
		Timeout: testTimeout,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(client.CloseIdleConnections)

	tests := []struct {
		name         string
		method       string
		url          string
		body         string
		wantStatus   int
		wantBody     string // substring
		wantHeader   [2]string
		wantDial     bool
		wantRecorded string // backend path whose record is checked
	}{
		{
			name: "get passes through", method: http.MethodGet, url: "http://example.test/x",
			wantStatus: http.StatusCreated, wantBody: "hello GET /x", wantHeader: [2]string{"X-Backend", "yes"},
			wantDial: true, wantRecorded: "/x",
		},
		{
			name: "post body passes through", method: http.MethodPost, url: "http://example.test/post", body: "data",
			wantStatus: http.StatusCreated, wantBody: "hello POST /post data", wantDial: true, wantRecorded: "/post",
		},
		{
			name: "redirect is returned, not followed", method: http.MethodGet, url: "http://example.test/redir",
			wantStatus: http.StatusFound, wantHeader: [2]string{"Location", "/x"}, wantDial: true,
		},
		{
			name: "literal loopback origin is refused", method: http.MethodGet, url: "http://127.0.0.1:" + backendPort + "/",
			wantStatus: http.StatusForbidden, wantBody: RuleLoopback,
		},
		{
			name: "name resolving to loopback is refused", method: http.MethodGet, url: "http://loop.test/",
			wantStatus: http.StatusForbidden, wantBody: RuleLoopback,
		},
		{
			name: "unresolvable host", method: http.MethodGet, url: "http://nowhere.test/",
			wantStatus: http.StatusBadGateway,
		},
	}
	// Subtests share the gateway and its fake, so they run sequentially.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.dials())
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, tc.method, tc.url, body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Proxy-Connection", "keep-alive")
			req.Header.Set("X-Custom", "1")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			got, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d (%q), want %d", resp.StatusCode, got, tc.wantStatus)
			}
			if tc.wantBody != "" && !strings.Contains(string(got), tc.wantBody) {
				t.Fatalf("body = %q, want substring %q", got, tc.wantBody)
			}
			if tc.wantHeader[0] != "" && resp.Header.Get(tc.wantHeader[0]) != tc.wantHeader[1] {
				t.Fatalf("header %s = %q, want %q", tc.wantHeader[0], resp.Header.Get(tc.wantHeader[0]), tc.wantHeader[1])
			}
			dials := f.dials()[before:]
			if tc.wantDial {
				for _, d := range dials {
					if d != "203.0.113.7:80" {
						t.Fatalf("dialled %q, want the resolved ip 203.0.113.7:80", d)
					}
				}
			} else if len(dials) != 0 {
				t.Fatalf("refused request dialled %q", dials)
			}
			if tc.wantRecorded != "" {
				mu.Lock()
				rec, ok := seen[tc.wantRecorded]
				mu.Unlock()
				if !ok {
					t.Fatalf("backend never saw %s", tc.wantRecorded)
				}
				if rec.host != "example.test" {
					t.Errorf("backend Host = %q, want example.test", rec.host)
				}
				if rec.proxyAuth != "" {
					t.Errorf("Proxy-Authorization forwarded: %q", rec.proxyAuth)
				}
				if rec.proxyConn != "" {
					t.Errorf("Proxy-Connection forwarded: %q", rec.proxyConn)
				}
				if rec.custom != "1" {
					t.Errorf("X-Custom = %q, want 1", rec.custom)
				}
				if rec.body != tc.body {
					t.Errorf("backend body = %q, want %q", rec.body, tc.body)
				}
			}
		})
	}
	if len(f.dials()) == 0 {
		t.Fatal("no request was dialled at all")
	}
}

func TestGateway_BadRequestForms(t *testing.T) {
	t.Parallel()
	f := &fakeNet{resolve: map[string][]net.IP{"example.test": {testPublicIP}}}
	path := startGateway(t, f.gateway())

	tests := []struct {
		name     string
		head     string
		wantBody string
	}{
		{"https absolute-form", "GET https://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", "CONNECT"},
		{"origin-form", "GET /foo HTTP/1.1\r\nHost: gw\r\n\r\n", "forward proxy"},
		{"other scheme", "GET ftp://example.test/f HTTP/1.1\r\nHost: example.test\r\n\r\n", "scheme"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, _, _ := rawRequest(t, path, http.MethodGet, tc.head, "")
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d (%q), want 400", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), tc.wantBody) {
				t.Fatalf("body = %q, want substring %q", body, tc.wantBody)
			}
		})
	}
	if got := f.dials(); len(got) != 0 {
		t.Fatalf("bad request forms dialled %q", got)
	}
}

// TestGateway_ZeroValueDefaults drives the real resolver, dialer and
// interface listing; every target is host-local, so nothing leaves the host.
func TestGateway_ZeroValueDefaults(t *testing.T) {
	t.Parallel()
	echo := startTCPServer(t, echoHandler)
	_, port, _ := net.SplitHostPort(echo)
	path := startGateway(t, &Gateway{Logger: discardLogger()})

	for _, target := range []string{"127.0.0.1:" + port, "localhost:" + port} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			resp, _, _ := rawRequest(t, path, http.MethodConnect, connectHead(target), "")
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d (%q), want 403", resp.StatusCode, body)
			}
		})
	}
}

func TestInterfaceIPs(t *testing.T) {
	t.Parallel()
	ips, err := InterfaceIPs()
	if err != nil {
		t.Skipf("interface listing unavailable here: %v", err)
	}
	for _, ip := range ips {
		if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
			t.Fatalf("malformed interface ip %v", ip)
		}
	}
}

func TestGateway_DirectHandlerBadForms(t *testing.T) {
	t.Parallel()
	g := &Gateway{Logger: discardLogger(), LocalAddrs: func() ([]net.IP, error) { return nil, nil }}
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"origin-form", http.MethodGet, "/foo", http.StatusBadRequest},
		{"https absolute-form", http.MethodGet, "https://example.test/", http.StatusBadRequest},
		{"connect literal loopback", http.MethodConnect, "127.0.0.1:8081", http.StatusForbidden},
		{"connect no port", http.MethodConnect, "example.test", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.method == http.MethodConnect {
				r.Host = tc.target
				r.URL = &url.URL{Host: tc.target}
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d (%q), want %d", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
