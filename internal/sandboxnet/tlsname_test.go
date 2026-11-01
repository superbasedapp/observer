package sandboxnet

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// tlsname_test.go pins the host list's TLS server name and port rules (lane
// SBX-P3C audit finding 2): under a host list a tunnel carries only a TLS
// session whose ClientHello names the CONNECT target, CONNECT may use port
// 443 only and a plain absolute-form request port 80 only, and every refusal
// is logged with its rule.

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// recordingUpstream is a destination that reports the first bytes each
// connection receives (none when the gateway closes it first).
func recordingUpstream(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 4)
	addr := startTCPServer(t, func(c *net.TCPConn) {
		buf := make([]byte, 5)
		n, _ := io.ReadFull(c, buf)
		got <- buf[:n]
	})
	return addr, got
}

func listedTLSGateway(t *testing.T, upstream string) (*Gateway, *syncBuffer) {
	t.Helper()
	f := &fakeNet{
		resolve: map[string][]net.IP{"registry.npmjs.org": {testPublicIP}},
		routes:  map[string]string{"203.0.113.7:443": upstream},
	}
	g := f.gateway()
	logs := &syncBuffer{}
	g.Logger = slog.New(slog.NewTextHandler(logs, nil))
	h, err := ParseHostRules([]string{"registry.npmjs.org"})
	if err != nil {
		t.Fatal(err)
	}
	g.Hosts = h
	return g, logs
}

// TestGateway_HostListTunnelServerName: the ClientHello's server name must
// equal the CONNECT target; another name or none is refused before any byte
// reaches the destination, and the refusal is logged with its rule.
func TestGateway_HostListTunnelServerName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		send  func(c net.Conn)
		rule  string
		reach bool
	}{
		{"listed name", func(c net.Conn) { tlsHello(c, "registry.npmjs.org") }, "", true},
		{"listed name upper case", func(c net.Conn) { tlsHello(c, "REGISTRY.npmjs.org") }, "", true},
		{"another site on the same edge", func(c net.Conn) { tlsHello(c, "evil.example.com") }, RuleSNIMismatch, false},
		{"no server name", func(c net.Conn) { tlsHello(c, "") }, RuleSNIAbsent, false},
		{"not TLS", func(c net.Conn) { _, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: evil.example.com\r\n\r\n") }, RuleSNIAbsent, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			upstream, got := recordingUpstream(t)
			g, logs := listedTLSGateway(t, upstream)
			path := startGateway(t, g)
			resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("registry.npmjs.org:443"), "")
			defer func() { _ = conn.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status %d", resp.StatusCode)
			}
			go c.send(conn)
			var first []byte
			select {
			case first = <-got:
			case <-time.After(testTimeout):
				t.Fatal("the destination saw nothing at all (not even a close)")
			}
			if c.reach {
				if len(first) == 0 || first[0] != 0x16 {
					t.Fatalf("the destination did not get the ClientHello: %x", first)
				}
				return
			}
			if len(first) != 0 {
				t.Fatalf("a refused tunnel sent %x to the destination", first)
			}
			if !strings.Contains(logs.String(), LogEgressRefused) || !strings.Contains(logs.String(), "rules="+c.rule) {
				t.Fatalf("the refusal was not logged with rule %s: %s", c.rule, logs.String())
			}
		})
	}
}

// tlsHello starts a TLS handshake naming server (empty: no SNI).
func tlsHello(c net.Conn, server string) {
	cfg := &tls.Config{ServerName: server, InsecureSkipVerify: server == ""} //nolint:gosec // G402: a test client that only sends a ClientHello
	_ = c.SetDeadline(time.Now().Add(testTimeout))
	_ = tls.Client(c, cfg).Handshake()
}

// TestGateway_HostListPorts: under a host list CONNECT may name port 443
// only and an absolute-form request port 80 only; another port is refused
// (logged, never dialled). A list-less gateway keeps every port.
func TestGateway_HostListPorts(t *testing.T) {
	t.Parallel()
	f, g := listedNet(t)
	logs := &syncBuffer{}
	g.Logger = slog.New(slog.NewTextHandler(logs, nil))
	path := startGateway(t, g)
	resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("registry.npmjs.org:8443"), "")
	body, _ := io.ReadAll(resp.Body)
	_ = conn.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "rule "+RulePortNotAllowed) {
		t.Fatalf("CONNECT :8443: %d %q", resp.StatusCode, body)
	}
	resp, conn, _ = rawRequest(t, path, http.MethodGet, "GET http://registry.npmjs.org:8080/x HTTP/1.1\r\nHost: registry.npmjs.org:8080\r\nConnection: close\r\n\r\n", "")
	body, _ = io.ReadAll(resp.Body)
	_ = conn.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "rule "+RulePortNotAllowed) {
		t.Fatalf("absolute-form :8080: %d %q", resp.StatusCode, body)
	}
	resp, conn, _ = rawRequest(t, path, http.MethodConnect, connectHead("registry.npmjs.org:80"), "")
	_ = conn.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT :80 status %d, want 403", resp.StatusCode)
	}
	if len(f.dials()) > 0 {
		t.Fatalf("a refused port was dialled: %v", f.dials())
	}
	if strings.Count(logs.String(), "rules="+RulePortNotAllowed) != 3 {
		t.Fatalf("each refusal is logged: %s", logs.String())
	}
	// Port 80 for a plain absolute-form request to a listed host is dialled.
	resp, conn, _ = rawRequest(t, path, http.MethodGet, "GET http://registry.npmjs.org/x HTTP/1.1\r\nHost: registry.npmjs.org\r\nConnection: close\r\n\r\n", "")
	_, _ = io.ReadAll(resp.Body)
	_ = conn.Close()
	if d := f.dials(); len(d) != 1 || d[0] != "203.0.113.7:80" {
		t.Fatalf("absolute-form :80 dials %v", d)
	}
	for _, c := range []struct {
		form requestForm
		port string
		ok   bool
	}{{formConnect, "443", true}, {formConnect, "80", false}, {formAbsolute, "80", true}, {formAbsolute, "443", false}, {"other", "443", false}} {
		if listedPortAllowed(c.form, c.port) != c.ok {
			t.Errorf("listedPortAllowed(%s, %s) != %v", c.form, c.port, c.ok)
		}
	}
}
