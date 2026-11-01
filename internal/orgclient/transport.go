package orgclient

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
	"time"
)

// transport.go: the org client's own HTTP transport (T-899, RETEST5 case C).
//
// Every org call (push, integrity report, policy fetches, heartbeats, the
// generated client) shares one *http.Client, so they all share one pooled
// connection to the org server, usually HTTP/2. On the default transport a
// connection the network path forgot during an outage (a load balancer's
// idle timeout, a firewall that dropped its state) stayed in the pool: it
// still read as established, every request was written into it and timed
// out, and the node stalled for about 16 minutes after the network came back,
// until the kernel gave up retransmitting (curl, on a new connection, worked
// at once). Two independent guards close that:
//
//  1. HTTP/2 health pings (http.HTTP2Config): when no frame arrives on a
//     connection for connHealth.pingAfter, the transport sends a PING, and a
//     PING not answered within connHealth.pingTimeout closes the connection.
//     A dead idle connection is found without a request having to fail, and
//     a dead connection a retired pool still holds (guard 2) is closed too.
//  2. A fresh pool after a failed round trip (freshPoolOnFailure): a request
//     that failed (a timeout, a reset) says the path may be dead, so the next
//     call runs on a new pool and dials fresh. The failed pool's idle
//     connections are closed; one still marked busy (an HTTP/2 connection
//     whose cancelled stream is not yet acknowledged, which
//     CloseIdleConnections leaves alone) is never handed out again and is
//     closed by its health PING. The cost is one TLS handshake per failure.
//
// An HTTP/1.1 server is covered too: net/http closes an HTTP/1.1 connection
// whose request was cancelled, and guard 2 retires the rest of the pool.

// connHealth tunes the org client's dead-connection detection.
type connHealth struct {
	// requestTimeout bounds one whole request (http.Client.Timeout).
	requestTimeout time.Duration
	// pingAfter is how long a connection may be silent before an HTTP/2
	// health PING is sent.
	pingAfter time.Duration
	// pingTimeout is how long an unanswered PING may wait before the
	// connection is closed.
	pingTimeout time.Duration
}

// defaultConnHealth is the production tuning: the 30 s request bound the
// client always had, a PING after 30 s of silence and 15 s to answer it, so a
// dead pooled connection is gone within about 45 s instead of the kernel's
// retransmission limit (about 15 minutes on Linux).
var defaultConnHealth = connHealth{
	requestTimeout: 30 * time.Second,
	pingAfter:      30 * time.Second,
	pingTimeout:    15 * time.Second,
}

// newOrgHTTPClient builds the org client's default *http.Client. tlsConfig
// replaces the transport's TLS settings when non-nil (tests trust a local
// certificate with it); production passes nil.
func newOrgHTTPClient(h connHealth, tlsConfig *tls.Config) *http.Client {
	newPool := func() *http.Transport {
		var base *http.Transport
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			base = dt.Clone()
		} else {
			base = &http.Transport{Proxy: http.ProxyFromEnvironment}
		}
		if tlsConfig != nil {
			base.TLSClientConfig = tlsConfig.Clone()
		}
		base.ForceAttemptHTTP2 = true
		base.HTTP2 = &http.HTTP2Config{
			SendPingTimeout: h.pingAfter,
			PingTimeout:     h.pingTimeout,
		}
		return base
	}
	rt := &freshPoolOnFailure{newPool: newPool}
	rt.cur.Store(newPool())
	return &http.Client{Timeout: h.requestTimeout, Transport: rt}
}

// freshPoolOnFailure swaps in a new connection pool after any failed round
// trip (guard 2 above).
type freshPoolOnFailure struct {
	newPool func() *http.Transport
	cur     atomic.Pointer[http.Transport]
}

// RoundTrip implements http.RoundTripper.
func (f *freshPoolOnFailure) RoundTrip(req *http.Request) (*http.Response, error) {
	pool := f.cur.Load()
	resp, err := pool.RoundTrip(req)
	if err != nil && f.cur.CompareAndSwap(pool, f.newPool()) {
		// Only the first failure on a pool retires it; concurrent failures
		// on the same pool find it already replaced.
		pool.CloseIdleConnections()
	}
	return resp, err
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the
// current pool.
func (f *freshPoolOnFailure) CloseIdleConnections() {
	f.cur.Load().CloseIdleConnections()
}
