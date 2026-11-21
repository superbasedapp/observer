package sandboxnet

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// refusal_gateway_test.go pins the gateway side of the refusal audit (lane
// N1, M2): every refusal reaches Gateway.Report with its closed rule and
// key, and a refused CONNECT or plain http request is answered with the
// structured JSON 403 on both paths.

// refusalSink collects what a gateway reports.
type refusalSink struct {
	mu  sync.Mutex
	got []Refusal
}

func (s *refusalSink) report(r Refusal) {
	s.mu.Lock()
	s.got = append(s.got, r)
	s.mu.Unlock()
}

func (s *refusalSink) all() []Refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Refusal(nil), s.got...)
}

// waitRefusals waits until n refusals were reported.
func (s *refusalSink) waitRefusals(t *testing.T, n int) []Refusal {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for time.Now().Before(deadline) {
		if got := s.all(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("want %d refusals, got %v", n, s.all())
	return nil
}

// TestGatewayReportsRefusals is one row per refusal path: the request, the
// structured body's rule and key, and the reported refusal.
func TestGatewayReportsRefusals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		listed   bool
		provider bool
		method   string
		head     string
		host     string
		port     int
		rule     RefusalRule
		key      string
	}{
		{"connect loopback", false, false, http.MethodConnect, connectHead("127.0.0.1:443"), "127.0.0.1", 443, RefusalSSRFFloor, KeyEgress},
		{"connect private", false, false, http.MethodConnect, connectHead("10.1.2.3:8443"), "10.1.2.3", 8443, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{"plain http private", false, false, http.MethodGet, "GET http://10.1.2.3/x HTTP/1.1\r\nHost: 10.1.2.3\r\nConnection: close\r\n\r\n", "10.1.2.3", 80, RefusalPrivateRange, KeyEgressAllowCIDRs},
		{"connect not listed", true, false, http.MethodConnect, connectHead("evil.example.com:443"), "evil.example.com", 443, RefusalAllowListMiss, KeyEgressAllowHosts},
		{"plain http not listed", true, false, http.MethodGet, "GET http://evil.example.com/x HTTP/1.1\r\nHost: evil.example.com\r\nConnection: close\r\n\r\n", "evil.example.com", 80, RefusalAllowListMiss, KeyEgressAllowHosts},
		{"connect listed wrong port", true, false, http.MethodConnect, connectHead("registry.npmjs.org:8443"), "registry.npmjs.org", 8443, RefusalPortNotAllowed, KeyEgressAllowHosts},
		{"connect literal under list", true, false, http.MethodConnect, connectHead("203.0.113.7:443"), "203.0.113.7", 443, RefusalLiteralIP, KeyEgressAllowHosts},
		{"connect provider host", false, true, http.MethodConnect, connectHead("api.anthropic.com:443"), "api.anthropic.com", 443, RefusalProviderHost, KeyProviderDirect},
		{"connect literal under provider block", false, true, http.MethodConnect, connectHead("203.0.113.7:443"), "203.0.113.7", 443, RefusalLiteralIP, KeyProviderDirect},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var g *Gateway
			if c.listed {
				_, g = listedNet(t)
			} else {
				f := &fakeNet{resolve: map[string][]net.IP{}}
				g = f.gateway()
			}
			if c.provider {
				g.Providers = NewProviderBlock(nil)
				g.Providers.addrHosts = nil
			}
			g.Logger = discardLogger()
			sink := &refusalSink{}
			g.Report = sink.report
			path := startGateway(t, g)
			resp, conn, _ := rawRequest(t, path, c.method, c.head, "")
			body, _ := io.ReadAll(resp.Body)
			_ = conn.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status %d %q", resp.StatusCode, body)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content type %q", ct)
			}
			var b RefusalBody
			if err := json.Unmarshal(body, &b); err != nil {
				t.Fatalf("body %q: %v", body, err)
			}
			if b.Error != RefusalErrorCode || b.Rule != string(c.rule) || b.Key != c.key || b.Host != c.host || b.NextStep != NextStep(c.rule) || b.Message == "" {
				t.Fatalf("body %+v", b)
			}
			got := sink.waitRefusals(t, 1)
			r := got[0]
			if len(got) != 1 || r.Host != c.host || r.Port != c.port || r.Rule != c.rule || r.Key != c.key || r.At.IsZero() {
				t.Fatalf("reported %+v", got)
			}
			if r.RunID != "" || r.Backend != "" || r.Tier != "" {
				t.Fatalf("the gateway stamped a run identity it does not know: %+v", r)
			}
		})
	}
}

// TestGatewayReportsTunnelServerName: an SNI refusal happens after the
// tunnel is established, so there is no 403; it is still reported.
func TestGatewayReportsTunnelServerName(t *testing.T) {
	t.Parallel()
	upstream, _ := recordingUpstream(t)
	g, _ := listedTLSGateway(t, upstream)
	sink := &refusalSink{}
	g.Report = sink.report
	path := startGateway(t, g)
	resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("registry.npmjs.org:443"), "")
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status %d", resp.StatusCode)
	}
	go tlsHello(conn, "evil.example.com")
	got := sink.waitRefusals(t, 1)
	if got[0].Rule != RefusalTLSServerName || got[0].Host != "registry.npmjs.org" || got[0].Port != 443 || got[0].Key != KeyEgressAllowHosts {
		t.Fatalf("reported %+v", got)
	}
}

// TestGatewayWithoutReportStillAnswersJSON: a gateway built with no Report
// (every existing caller before lane N1) refuses as before, with the JSON
// body.
func TestGatewayWithoutReportStillAnswersJSON(t *testing.T) {
	t.Parallel()
	f := &fakeNet{resolve: map[string][]net.IP{}}
	g := f.gateway()
	g.Logger = discardLogger()
	path := startGateway(t, g)
	resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("127.0.0.1:443"), "")
	body, _ := io.ReadAll(resp.Body)
	_ = conn.Close()
	var b RefusalBody
	if resp.StatusCode != http.StatusForbidden || json.Unmarshal(body, &b) != nil || b.Rule != string(RefusalSSRFFloor) {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

// TestGatewayClosedRefusesEveryAttempt (F-012, audit finding N4-A4): while
// Closed names a reason, every attempt (CONNECT and plain http, allowed or
// not) is answered 503 with that reason before any policy check, and
// nothing is reported; once Closed answers "" the gateway judges as before.
func TestGatewayClosedRefusesEveryAttempt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		method string
		head   string
	}{
		{"connect refused target", http.MethodConnect, connectHead("127.0.0.1:443")},
		{"plain http refused target", http.MethodGet, "GET http://10.1.2.3/x HTTP/1.1\r\nHost: 10.1.2.3\r\nConnection: close\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeNet{resolve: map[string][]net.IP{}}
			g := f.gateway()
			g.Logger = discardLogger()
			sink := &refusalSink{}
			g.Report = sink.report
			var mu sync.Mutex
			reason := "the refusal audit link is lost"
			g.Closed = func() string {
				mu.Lock()
				defer mu.Unlock()
				return reason
			}
			path := startGateway(t, g)
			resp, conn, _ := rawRequest(t, path, c.method, c.head, "")
			body, _ := io.ReadAll(resp.Body)
			_ = conn.Close()
			if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), reason) {
				t.Fatalf("closed: status %d %q", resp.StatusCode, body)
			}
			if got := sink.all(); len(got) != 0 {
				t.Fatalf("a closed attempt was reported as a refusal: %+v", got)
			}
			mu.Lock()
			reason = ""
			mu.Unlock()
			resp, conn, _ = rawRequest(t, path, c.method, c.head, "")
			_, _ = io.ReadAll(resp.Body)
			_ = conn.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("reopened: status %d", resp.StatusCode)
			}
			sink.waitRefusals(t, 1)
		})
	}
}

// TestGatewayHostListNamesItsKey (F-009, audit finding N1-A11): a refusal
// by a host list that is not the owner's (the first-start install step's)
// names that list's key, in the report and in the 403 body; the owner's
// list keeps KeyEgressAllowHosts.
func TestGatewayHostListNamesItsKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"owner's list", "", KeyEgressAllowHosts},
		{"install step's list", KeyInstallHosts, KeyInstallHosts},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, g := listedNet(t)
			if c.key != "" {
				g.Hosts = g.Hosts.WithKey(c.key)
			}
			g.Logger = discardLogger()
			sink := &refusalSink{}
			g.Report = sink.report
			path := startGateway(t, g)
			resp, conn, _ := rawRequest(t, path, http.MethodConnect, connectHead("evil.example.com:443"), "")
			body, _ := io.ReadAll(resp.Body)
			_ = conn.Close()
			var b RefusalBody
			if err := json.Unmarshal(body, &b); err != nil || b.Key != c.want {
				t.Fatalf("body %q key %q, want %q (%v)", body, b.Key, c.want, err)
			}
			// The next step follows the key (audit finding FU5-A3): the
			// install list's never points at the owner's host list.
			if b.NextStep != NextStepFor(RefusalAllowListMiss, c.want) || (c.want == KeyInstallHosts) == strings.Contains(b.NextStep, KeyEgressAllowHosts) {
				t.Fatalf("next_step %q for key %q", b.NextStep, c.want)
			}
			if got := sink.waitRefusals(t, 1); got[0].Key != c.want || got[0].Rule != RefusalAllowListMiss {
				t.Fatalf("reported %+v", got)
			}
		})
	}
}
