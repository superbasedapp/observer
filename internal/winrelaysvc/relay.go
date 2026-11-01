package winrelaysvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/ingest/hostguard"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// MaxRequestBytes caps a request body the relay forwards (64 MiB): far above
// any model request a CLI or IDE sends (the Messages API itself refuses
// bodies over 32 MB), so it bounds a misbehaving local client without ever
// cutting a real one.
const MaxRequestBytes = 64 << 20

// IdleTimeout closes a kept-alive client connection idle this long.
const IdleTimeout = 2 * time.Minute

// DefaultDialTimeout bounds the dial that decides whether the proxy is up.
// It is what an outage costs each request: with the daemon down Windows
// refuses a loopback connect only after about 2 s (FU-184, live
// 2026-10-29), so the dial always ends by this timeout and the request then
// fails open, recorded as proxy_unreachable. Kept at 750 ms: a shorter
// budget would keep the record the same but bypass a proxy that is up and
// slow to accept (a resuming VM, a full backlog) more often, and no live run
// has measured that accept time.
const DefaultDialTimeout = 750 * time.Millisecond

// Options configure a Relay.
type Options struct {
	// ListenPort is the relay's own loopback port (winrelay.DefaultPort when
	// zero).
	ListenPort int
	// ProxyPort is Observer's proxy port (winrelay.DefaultProxyPort when
	// zero).
	ProxyPort int
	// ProxyHost is the host the proxy is dialled on ("localhost" when empty):
	// on a WSL2 host, Windows localhost reaches the guest's listener.
	ProxyHost string
	// Journal records every fail-open forward. Required.
	Journal *Journal
	// DialTimeout bounds the proxy dial (DefaultDialTimeout when zero).
	DialTimeout time.Duration
	// Now is the clock for records (time.Now when nil).
	Now func() time.Time
	// Logf receives the relay's metadata-only log lines (discarded when
	// nil).
	Logf func(format string, args ...any)

	// DirectOverride replaces a lane's provider base URL (tests only; an
	// https URL).
	DirectOverride map[string]string
	// DirectTransport sends fail-open forwards (a clone of
	// http.DefaultTransport when nil).
	DirectTransport http.RoundTripper
	// DialProxy opens the proxy connection (a net.Dialer when nil).
	DialProxy func(ctx context.Context, addr string) (net.Conn, error)
}

// Relay is the relay's HTTP handler.
type Relay struct {
	opts    Options
	directs map[string]*url.URL
	direct  http.RoundTripper
}

// New validates opts and returns the relay.
func New(opts Options) (*Relay, error) {
	if opts.ListenPort == 0 {
		opts.ListenPort = winrelay.DefaultPort
	}
	if opts.ProxyPort == 0 {
		opts.ProxyPort = winrelay.DefaultProxyPort
	}
	if err := winrelay.ValidatePorts(opts.ListenPort, opts.ProxyPort); err != nil {
		return nil, err
	}
	if opts.ProxyHost == "" {
		opts.ProxyHost = "localhost"
	}
	if !hostguard.IsLoopbackHost(opts.ProxyHost) {
		return nil, fmt.Errorf("winrelaysvc: proxy host %q is not loopback", opts.ProxyHost)
	}
	if opts.Journal == nil {
		return nil, errors.New("winrelaysvc: a bypass journal is required (a fail-open forward is never silent)")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.DialProxy == nil {
		d := &net.Dialer{Timeout: opts.DialTimeout}
		opts.DialProxy = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	r := &Relay{opts: opts, directs: map[string]*url.URL{}, direct: opts.DirectTransport}
	for _, l := range winrelay.Lanes() {
		raw := l.Direct
		if o, ok := opts.DirectOverride[l.Tool]; ok {
			raw = o
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("winrelaysvc: lane %s: direct upstream must be an https URL", l.Tool)
		}
		r.directs[l.Tool] = u
	}
	if r.direct == nil {
		t, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("winrelaysvc: no default transport")
		}
		r.direct = t.Clone()
	}
	return r, nil
}

// ListenAddr is the one address the relay binds: the IPv4 loopback.
func (r *Relay) ListenAddr() string {
	return net.JoinHostPort("127.0.0.1", fmt.Sprint(r.opts.ListenPort))
}

// Listen binds the relay's loopback address.
func (r *Relay) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", r.ListenAddr())
	if err != nil {
		return nil, fmt.Errorf("winrelaysvc.Listen: %w", err)
	}
	return ln, nil
}

// Serve serves ln until ctx ends.
func (r *Relay) Serve(ctx context.Context, ln net.Listener) error {
	// No WriteTimeout: a streamed model answer can run for minutes. The
	// body cap and the idle timeout bound everything else.
	srv := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
		case <-done:
		}
	}()
	err := srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP decides one request (winrelay.Decide) and acts on it.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		req.Body = http.MaxBytesReader(w, req.Body, MaxRequestBytes)
	}
	tool, rest, laneKnown := winrelay.ParseRoutePath(req.URL.Path)
	facts := winrelay.Facts{LoopbackPeer: loopbackRequest(req), LaneKnown: laneKnown}
	var conn net.Conn
	if winrelay.NeedsProxyDial(facts) {
		c, err := r.opts.DialProxy(req.Context(), net.JoinHostPort(r.opts.ProxyHost, fmt.Sprint(r.opts.ProxyPort)))
		if err == nil {
			conn, facts.ProxyReachable = c, true
		}
	}
	switch winrelay.Decide(facts) {
	case winrelay.DecisionRefusePeer:
		r.opts.Logf("relay: refused a non-loopback request")
		http.Error(w, "observer relay: loopback clients only", http.StatusForbidden)
	case winrelay.DecisionRefuseLane:
		http.Error(w, "observer relay: unknown route", http.StatusNotFound)
	case winrelay.DecisionForwardProxy:
		target := &url.URL{Scheme: "http", Host: net.JoinHostPort(r.opts.ProxyHost, fmt.Sprint(r.opts.ProxyPort))}
		rt := newOneConnTransport(conn)
		r.forward(w, req, target, rest, rt, tool, "proxy")
		rt.release()
	case winrelay.DecisionFailOpen:
		target := r.directs[tool]
		entry := winrelay.Entry{
			At:       r.opts.Now(),
			Tool:     tool,
			Upstream: target.Host,
			Method:   winrelay.SanitizeMethod(req.Method),
			Path:     winrelay.SanitizePath(rest),
			Reason:   winrelay.ReasonProxyUnreachable,
		}
		if err := r.opts.Journal.Append(entry); err != nil {
			r.opts.Logf("relay: %s: proxy unreachable and the bypass could not be recorded; refused", tool)
			http.Error(w, "observer relay: Observer's proxy is unreachable and the bypass could not be recorded, so the request was not sent", http.StatusBadGateway)
			return
		}
		r.opts.Logf("relay: %s: proxy unreachable; forwarded %s %s straight to %s (recorded bypass)", tool, entry.Method, entry.Path, entry.Upstream)
		r.forward(w, req, target, rest, r.direct, tool, "direct")
	}
}

// forward sends req to target+rest through rt and streams the answer back.
// Hop-by-hop headers are dropped and no X-Forwarded header is added
// (ReverseProxy.Rewrite); every other header passes through unread.
func (r *Relay) forward(w http.ResponseWriter, req *http.Request, target *url.URL, rest string, rt http.RoundTripper, tool, lane string) {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.URL.Path = strings.TrimSuffix(target.Path, "/") + rest
			pr.Out.URL.RawPath = ""
			pr.Out.Host = ""
		},
		Transport:     rt,
		FlushInterval: -1,
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			r.opts.Logf("relay: %s: the %s upstream failed", tool, lane)
			http.Error(w, "observer relay: upstream failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, req)
}

// oneConnTransport sends one request on an already opened connection: the
// connection the reachability dial opened, so "the proxy answered" and "the
// request went to the proxy" are one fact. It never dials a second
// connection, so a request the proxy fails is answered 502, never re-sent
// anywhere (a fail-open forward happens only when no connection opened).
type oneConnTransport struct {
	*http.Transport
	conn net.Conn
	used atomic.Bool
}

func newOneConnTransport(conn net.Conn) *oneConnTransport {
	t := &oneConnTransport{conn: conn}
	t.Transport = &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if t.used.Swap(true) {
				return nil, errors.New("winrelaysvc: one connection per request")
			}
			return conn, nil
		},
	}
	return t
}

// release closes the connection when the transport never took it (the
// client went away first) and drops the transport's idle state.
func (t *oneConnTransport) release() {
	if !t.used.Swap(true) {
		_ = t.conn.Close()
	}
	t.CloseIdleConnections()
}

// loopbackRequest reports whether a request comes from a local CLI or IDE
// client, the only clients the relay serves. Every condition is a refusal
// of something such a client never sends:
//
//   - the peer address is not loopback;
//   - CONNECT (the relay is not a forward proxy);
//   - an Origin header, any value including "null": CLI and IDE clients
//     send none, and a browser always does, so this stops a page on any
//     loopback port (a dev server on localhost:5173) from driving
//     fail-open forwards and filling the journal (the DASH-ORIGIN-1
//     mistake was accepting a loopback Origin on another port);
//   - a Host that is empty, carries no port, names a host that is not
//     loopback, or names a port other than the one this connection was
//     accepted on (DNS rebinding, and an absolute-form request line naming
//     a foreign host, both arrive with a foreign Host).
func loopbackRequest(req *http.Request) bool {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return false
	}
	if req.Method == http.MethodConnect {
		return false
	}
	if _, present := req.Header["Origin"]; present {
		return false
	}
	return ownLoopbackHost(req)
}

// ownLoopbackHost reports whether req's Host names a loopback host with the
// port of the connection's own local address.
func ownLoopbackHost(req *http.Request) bool {
	if req.Host == "" {
		return false
	}
	_, port, err := net.SplitHostPort(req.Host)
	if err != nil || port == "" || !hostguard.IsLoopbackHost(req.Host) {
		return false
	}
	local, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	_, localPort, err := net.SplitHostPort(local.String())
	return err == nil && localPort == port
}
