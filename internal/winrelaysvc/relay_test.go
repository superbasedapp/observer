package winrelaysvc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

const secret = "sk-ant-relaytest-secret-value"

// seen records what an upstream received.
type seen struct {
	mu      sync.Mutex
	hits    int
	path    string
	apiKey  string
	xff     string
	body    string
	hostHdr string
}

func (s *seen) handler(reply string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hits++
		s.path = r.URL.Path
		s.apiKey = r.Header.Get("X-Api-Key")
		s.xff = r.Header.Get("X-Forwarded-For")
		s.body = string(b)
		s.hostHdr = r.Host
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, reply)
	}
}

func (s *seen) bodyLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.body)
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://"))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

type fixture struct {
	relay   *httptest.Server
	direct  *seen
	journal string
	logs    *strings.Builder
	logMu   *sync.Mutex
}

// newFixture starts a direct (TLS) upstream and a relay whose proxy is at
// proxyPort.
func newFixture(t *testing.T, proxyPort int, journalPath string) fixture {
	t.Helper()
	direct := &seen{}
	directSrv := httptest.NewTLSServer(direct.handler("data: direct\n\n"))
	t.Cleanup(directSrv.Close)
	if journalPath == "" {
		journalPath = filepath.Join(t.TempDir(), winrelay.JournalFile)
	}
	logs, mu := &strings.Builder{}, &sync.Mutex{}
	r, err := New(Options{
		ListenPort:      winrelay.DefaultPort,
		ProxyPort:       proxyPort,
		ProxyHost:       "127.0.0.1",
		Journal:         NewJournal(journalPath, 0),
		DirectOverride:  map[string]string{"claude-code": directSrv.URL},
		DirectTransport: directSrv.Client().Transport,
		Now:             func() time.Time { return time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC) },
		Logf: func(f string, a ...any) {
			mu.Lock()
			defer mu.Unlock()
			logs.WriteString(strings.TrimSpace(fmt.Sprintf(f, a...)) + "\n")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	relaySrv := httptest.NewServer(r)
	t.Cleanup(relaySrv.Close)
	return fixture{relay: relaySrv, direct: direct, journal: journalPath, logs: logs, logMu: mu}
}

func post(t *testing.T, base, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path+"?beta=true", strings.NewReader(`{"model":"claude-x","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Api-Key", secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

func TestForwardsToTheProxyWhenItAnswers(t *testing.T) {
	proxy := &seen{}
	proxySrv := httptest.NewServer(proxy.handler("data: proxied\n\n"))
	defer proxySrv.Close()
	f := newFixture(t, portOf(t, proxySrv.URL), "")

	resp, body := post(t, f.relay.URL, "/r/claude-code/v1/messages")
	if resp.StatusCode != 200 || body != "data: proxied\n\n" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if proxy.count() != 1 || f.direct.count() != 0 {
		t.Fatalf("proxy hits %d, direct hits %d; want 1, 0", proxy.count(), f.direct.count())
	}
	if proxy.path != "/v1/messages" || proxy.apiKey != secret || proxy.xff != "" || !strings.Contains(proxy.body, "claude-x") {
		t.Fatalf("proxy saw path %q key %q xff %q body %q", proxy.path, proxy.apiKey, proxy.xff, proxy.body)
	}
	if _, err := os.Stat(f.journal); !os.IsNotExist(err) {
		t.Fatalf("a proxied request must not be recorded as a bypass: %v", err)
	}
}

func TestFailsOpenToTheProviderAndRecordsTheBypass(t *testing.T) {
	f := newFixture(t, closedPort(t), "")

	resp, body := post(t, f.relay.URL, "/r/claude-code/v1/messages")
	if resp.StatusCode != 200 || body != "data: direct\n\n" {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if f.direct.count() != 1 || f.direct.path != "/v1/messages" || f.direct.apiKey != secret || f.direct.xff != "" {
		t.Fatalf("direct saw hits %d path %q key %q xff %q", f.direct.count(), f.direct.path, f.direct.apiKey, f.direct.xff)
	}
	if !strings.HasPrefix(f.direct.hostHdr, "127.0.0.1:") || strings.HasSuffix(f.direct.hostHdr, ":8829") {
		t.Fatalf("direct Host header %q is not the provider's", f.direct.hostHdr)
	}
	raw, err := os.ReadFile(f.journal)
	if err != nil {
		t.Fatalf("the bypass must be recorded: %v", err)
	}
	entries, skipped := winrelay.ParseJournal(raw)
	if len(entries) != 1 || skipped != 0 {
		t.Fatalf("journal %q: %d entries, %d skipped", raw, len(entries), skipped)
	}
	e := entries[0]
	if e.Tool != "claude-code" || e.Method != "POST" || e.Path != "/v1/messages" || e.Reason != winrelay.ReasonProxyUnreachable || !strings.HasPrefix(e.Upstream, "127.0.0.1:") {
		t.Fatalf("entry = %+v", e)
	}
	f.logMu.Lock()
	logs := f.logs.String()
	f.logMu.Unlock()
	for _, leak := range []string{secret, "beta=true", "claude-x"} {
		if strings.Contains(string(raw), leak) || strings.Contains(logs, leak) {
			t.Fatalf("%q leaked into the journal or the log:\n%s\n%s", leak, raw, logs)
		}
	}
	if !strings.Contains(logs, "recorded bypass") {
		t.Fatalf("a fail-open forward must log a line: %q", logs)
	}
}

func TestRefusesTheBypassItCannotRecord(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "is-a-dir")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, closedPort(t), journal)
	resp, _ := post(t, f.relay.URL, "/r/claude-code/v1/messages")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	if f.direct.count() != 0 {
		t.Fatal("an unrecorded bypass must never be sent")
	}
}

// TestProxyFailureIsNeverRetriedDirect pins that a request the proxy took
// and then failed is answered 502, never sent to the provider as well (the
// request may already have reached the model).
func TestProxyFailureIsNeverRetriedDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
		}
	}()
	f := newFixture(t, ln.Addr().(*net.TCPAddr).Port, "")
	resp, _ := post(t, f.relay.URL, "/r/claude-code/v1/messages")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
	if f.direct.count() != 0 {
		t.Fatal("a proxied request that failed must not be re-sent to the provider")
	}
	if _, err := os.Stat(f.journal); !os.IsNotExist(err) {
		t.Fatal("no bypass happened, so nothing is recorded")
	}
}

// rawStatus sends one raw HTTP request line and headers to addr and returns
// the status code of the answer.
func rawStatus(t *testing.T, addr, raw string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read answer to %q: %v", strings.SplitN(raw, "\r\n", 2)[0], err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestRefusals: one row per refusal the relay makes before it dials
// anything (audit of 492f8b0ab items 2 and 3). Each request goes over a
// real loopback connection, so Host, Origin, the absolute form of the
// request line and CONNECT reach the handler exactly as sent.
func TestRefusals(t *testing.T) {
	var dials atomic.Int32
	r, err := New(Options{
		ProxyPort: closedPort(t), ProxyHost: "127.0.0.1",
		Journal:        NewJournal(filepath.Join(t.TempDir(), "j"), 0),
		DirectOverride: map[string]string{"claude-code": "https://127.0.0.1:1"},
		DialProxy: func(context.Context, string) (net.Conn, error) {
			dials.Add(1)
			return nil, io.EOF
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(r)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(addr)
	const lane = "/r/claude-code/v1/messages"
	body := "Content-Length: 2\r\n\r\n{}"
	req := func(line string, headers ...string) string {
		return line + "\r\n" + strings.Join(headers, "") + body
	}
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"loopback Origin on another port (a dev server page)", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n", "Origin: http://localhost:5173\r\n"), http.StatusForbidden},
		{"Origin on the relay's own origin", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n", "Origin: http://127.0.0.1:"+port+"\r\n"), http.StatusForbidden},
		{"Origin null", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n", "Origin: null\r\n"), http.StatusForbidden},
		{"empty Origin header", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n", "Origin: \r\n"), http.StatusForbidden},
		{"rebinding host 127.0.0.1.evil.com", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1.evil.com:"+port+"\r\n"), http.StatusForbidden},
		{"trailing-dot localhost.", req("POST "+lane+" HTTP/1.1", "Host: localhost.:"+port+"\r\n"), http.StatusForbidden},
		{"foreign host", req("POST "+lane+" HTTP/1.1", "Host: evil.example:"+port+"\r\n"), http.StatusForbidden},
		{"loopback host on another port", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:1\r\n"), http.StatusForbidden},
		{"loopback host with no port", req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1\r\n"), http.StatusForbidden},
		{"missing Host (HTTP/1.0)", req("POST " + lane + " HTTP/1.0"), http.StatusForbidden},
		{"absolute-URI to a foreign host", req("POST http://api.anthropic.com"+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n"), http.StatusForbidden},
		{"CONNECT to a provider", "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n", http.StatusForbidden},
		{"unknown lane", req("POST /r/codex/v1/responses HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n"), http.StatusNotFound},
		{"no route prefix", req("POST /v1/messages HTTP/1.1", "Host: localhost:"+port+"\r\n"), http.StatusNotFound},
	}
	for _, c := range cases {
		if got := rawStatus(t, addr, c.raw); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
	if dials.Load() != 0 {
		t.Fatalf("a refused request dialled the proxy %d times", dials.Load())
	}
	// The control row: the same request from a CLI client (no Origin, its
	// own Host) is served, here by failing open after a refused dial.
	if got := rawStatus(t, addr, req("POST "+lane+" HTTP/1.1", "Host: 127.0.0.1:"+port+"\r\n")); got != http.StatusBadGateway {
		t.Fatalf("a CLI-shaped request: status %d, want 502 (the fake direct upstream is unreachable)", got)
	}
	if dials.Load() != 1 {
		t.Fatalf("the CLI-shaped request dialled the proxy %d times, want 1", dials.Load())
	}
}

func TestNewRefusesUnsafeOptions(t *testing.T) {
	j := NewJournal(filepath.Join(t.TempDir(), "j"), 0)
	cases := map[string]Options{
		"relay on the proxy port":    {ListenPort: 9000, ProxyPort: 9000, Journal: j},
		"relay on the default proxy": {ListenPort: winrelay.DefaultProxyPort, ProxyPort: 9000, Journal: j},
		"no journal":                 {},
		"remote proxy host":          {ProxyHost: "10.1.2.3", Journal: j},
		"plain-http direct":          {Journal: j, DirectOverride: map[string]string{"claude-code": "http://api.example"}},
	}
	for name, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	r, err := New(Options{Journal: j})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.ListenAddr(); got != "127.0.0.1:8829" {
		t.Fatalf("ListenAddr = %q; the relay binds the IPv4 loopback only", got)
	}
}

func TestServeBindsLoopbackAndStops(t *testing.T) {
	r, err := New(Options{ListenPort: closedPort(t), ProxyPort: closedPort(t), Journal: NewJournal(filepath.Join(t.TempDir(), "j"), 0)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := r.Listen()
	if err != nil {
		t.Fatal(err)
	}
	if ip := ln.Addr().(*net.TCPAddr).IP; !ip.IsLoopback() || ip.To4() == nil {
		t.Fatalf("bound %v, want the IPv4 loopback", ip)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, ln) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestJournalRotatesAndRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, winrelay.JournalFile)
	j := NewJournal(path, 300)
	e := winrelay.Entry{At: time.Unix(1, 0), Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: winrelay.ReasonProxyUnreachable}
	for i := 0; i < 5; i++ {
		if err := j.Append(e); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	cur, _ := os.ReadFile(path)
	old, err := os.ReadFile(path + ".1")
	if err != nil || len(cur) > 300 || len(old) == 0 {
		t.Fatalf("rotation: current %d bytes, old %d bytes, err %v", len(cur), len(old), err)
	}
	a, _ := winrelay.ParseJournal(cur)
	b, _ := winrelay.ParseJournal(old)
	if len(a)+len(b) < 2 {
		t.Fatalf("records lost across rotation: %d + %d", len(a), len(b))
	}

	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := NewJournal(link, 0).Append(e); err == nil {
		t.Fatal("a journal path that is a link must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); !os.IsNotExist(err) {
		t.Fatal("the link target must not be created")
	}
}

// TestRequestBodyIsCapped pins audit item 6: a body over MaxRequestBytes is
// not forwarded whole (the upstream sees the read fail and the relay
// answers an error), while the relay's limits are set.
func TestRequestBodyIsCapped(t *testing.T) {
	proxy := &seen{}
	proxySrv := httptest.NewServer(proxy.handler("ok"))
	defer proxySrv.Close()
	f := newFixture(t, portOf(t, proxySrv.URL), "")
	big := strings.NewReader(strings.Repeat("x", MaxRequestBytes+1))
	req, err := http.NewRequest(http.MethodPost, f.relay.URL+"/r/claude-code/v1/messages", big)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && proxy.bodyLen() > MaxRequestBytes {
			t.Fatalf("a %d-byte body reached the upstream whole", proxy.bodyLen())
		}
	}
	if n := proxy.bodyLen(); n > MaxRequestBytes {
		t.Fatalf("the upstream read %d bytes, over the cap", n)
	}
	if IdleTimeout <= 0 || MaxRequestBytes < 32<<20 {
		t.Fatal("the relay's idle timeout and body cap must be set, the cap above the API's own limit")
	}
}
