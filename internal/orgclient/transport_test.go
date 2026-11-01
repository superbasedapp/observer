package orgclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// blackholeProxy is a TCP relay between the org client and a test org server
// that can go SILENT the way a real network path does during an outage: the
// connections stay open, but bytes in either direction are read and dropped.
// A connection that was silenced stays silenced after the outage ends (the
// path forgot it, as a load balancer's idle timeout or a dropped firewall
// state does); only connections dialled after the outage carry traffic again.
type blackholeProxy struct {
	ln       net.Listener
	upstream string
	outage   atomic.Bool

	mu    sync.Mutex
	conns []*relayConn
}

type relayConn struct {
	dead atomic.Bool
	a, b net.Conn
}

func newBlackholeProxy(t *testing.T, upstream string) *blackholeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &blackholeProxy{ln: ln, upstream: upstream}
	go p.serve()
	t.Cleanup(p.close)
	return p
}

func (p *blackholeProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", p.upstream)
		if err != nil {
			_ = c.Close()
			continue
		}
		rc := &relayConn{a: c, b: up}
		rc.dead.Store(p.outage.Load())
		p.mu.Lock()
		p.conns = append(p.conns, rc)
		p.mu.Unlock()
		go rc.pump(c, up)
		go rc.pump(up, c)
	}
}

// pump copies src to dst while the connection is alive and discards what it
// reads once it is dead (a black hole, never a reset).
func (rc *relayConn) pump(src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !rc.dead.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// startOutage silences every existing connection and every new one until
// endOutage.
func (p *blackholeProxy) startOutage() {
	p.outage.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rc := range p.conns {
		rc.dead.Store(true)
	}
}

// endOutage lets new connections through; silenced ones stay silent.
func (p *blackholeProxy) endOutage() { p.outage.Store(false) }

func (p *blackholeProxy) close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rc := range p.conns {
		_ = rc.a.Close()
		_ = rc.b.Close()
	}
}

// newSilenceFixture starts an HTTP/2 TLS org server behind a black-hole
// relay and returns a client built by newOrgHTTPClient with health tuning h.
func newSilenceFixture(t *testing.T, h connHealth) (*blackholeProxy, *http.Client, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	proxy := newBlackholeProxy(t, srv.Listener.Addr().String())
	client := newOrgHTTPClient(h, tlsCfg)
	t.Cleanup(client.CloseIdleConnections)
	return proxy, client, "https://" + proxy.ln.Addr().String() + "/api/agent/ping"
}

// get runs one GET and reports whether it succeeded over HTTP/2.
func get(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.ProtoMajor != 2 {
		t.Fatalf("protocol %s, want HTTP/2 (the fixture must exercise the pooled HTTP/2 connection)", resp.Proto)
	}
	return nil
}

// recoversWithin calls url until one call succeeds or budget runs out and
// returns how long recovery took.
func recoversWithin(t *testing.T, client *http.Client, url string, budget time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		if err := get(t, client, url); err == nil {
			return time.Since(start)
		} else if time.Since(start) > budget {
			t.Fatalf("no org call succeeded within %s after the outage ended (last error: %v): the client keeps reusing a dead connection", budget, err)
		}
	}
}

// TestOrgClientDropsDeadConnectionAfterOutage pins T-899 (RETEST5 case C):
// after the network path goes silent and comes back, the shared org client
// must not keep reusing the connection the path forgot. Two shapes, one per
// guard of transport.go, each run with the OTHER guard out of reach so a test
// fails if its own guard stops working (a plain client fails both).
func TestOrgClientDropsDeadConnectionAfterOutage(t *testing.T) {
	cases := []struct {
		name   string
		health connHealth
		// during runs while the path is silent.
		during func(t *testing.T, client *http.Client, url string)
	}{
		{
			// A call fails during the outage (the node's push or heartbeat
			// timing out): the failed round trip drops the pooled connection.
			// The health PING is pushed past the test so it cannot help.
			name:   "a call timed out during the outage",
			health: connHealth{requestTimeout: 800 * time.Millisecond, pingAfter: time.Hour, pingTimeout: time.Hour},
			during: func(t *testing.T, client *http.Client, url string) {
				if err := get(t, client, url); err == nil {
					t.Fatal("a call through a silent path succeeded; the fixture is not silencing it")
				}
			},
		},
		{
			// No call is made during the outage: the HTTP/2 health PING
			// finds the idle dead connection and closes it. The request
			// bound is longer than the recovery budget, so a call that
			// reused the dead connection could not fail and retry in time.
			name:   "the connection sat idle during the outage",
			health: connHealth{requestTimeout: 10 * time.Second, pingAfter: 200 * time.Millisecond, pingTimeout: 200 * time.Millisecond},
			during: func(*testing.T, *http.Client, string) {
				time.Sleep(time.Second)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy, client, url := newSilenceFixture(t, tc.health)
			if err := get(t, client, url); err != nil {
				t.Fatalf("call before the outage: %v", err)
			}
			proxy.startOutage()
			tc.during(t, client, url)
			proxy.endOutage()
			// Without the guards every call reuses the silenced connection
			// and times out until the kernel gives up (minutes). With them
			// the next call, or the one after a single failure, succeeds.
			took := recoversWithin(t, client, url, 3*time.Second)
			t.Logf("recovered %s after the outage ended", took)
		})
	}
}

// TestNewUsesOrgTransport pins that the default client New builds is the org
// transport (dead-connection detection), never a bare http.Client.
func TestNewUsesOrgTransport(t *testing.T) {
	c := New(config.OrgClientConfig{}, nil, nil, "", nil, nil)
	tr, ok := c.httpClient.Transport.(*freshPoolOnFailure)
	if !ok {
		t.Fatalf("default transport is %T, want *freshPoolOnFailure", c.httpClient.Transport)
	}
	pool := tr.cur.Load()
	if pool.HTTP2 == nil || pool.HTTP2.SendPingTimeout != defaultConnHealth.pingAfter || pool.HTTP2.PingTimeout != defaultConnHealth.pingTimeout {
		t.Fatalf("HTTP/2 health pings not configured: %+v", pool.HTTP2)
	}
	if fresh := tr.newPool(); fresh.HTTP2 == nil || fresh.HTTP2.SendPingTimeout != defaultConnHealth.pingAfter {
		t.Fatalf("a replacement pool loses the HTTP/2 health pings: %+v", fresh.HTTP2)
	}
	if c.httpClient.Timeout != defaultConnHealth.requestTimeout {
		t.Fatalf("request timeout %s, want %s", c.httpClient.Timeout, defaultConnHealth.requestTimeout)
	}
}
