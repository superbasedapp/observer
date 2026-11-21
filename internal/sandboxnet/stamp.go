package sandboxnet

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

// stamp.go is the HTTP-aware hop on the HOST side of a local run's model
// forward (lane N3, SBX-NET-2): where ServeForward would pipe a box
// connection to the proxy byte for byte, a run that has credential
// injection hands the connection to a StampHop instead. The hop reads each
// request, lets Stamp set the run's headers (the host side names the run;
// any value the box sent is replaced), and passes it on to the proxy
// through Dial. It is the same shape as the hosted relay's stamping reverse
// proxy, and a forward with no hop is exactly as before.

// StampHop is one run's stamping reverse proxy.
type StampHop struct {
	srv *http.Server
	ln  *connListener
	tr  *http.Transport
	// stop ends every request the hop is serving (Close).
	stop context.CancelFunc
}

// NewStampHop builds a hop that sends every request to the peer dial
// reaches, after stamp has set its headers. dial and stamp are required.
func NewStampHop(dial func(ctx context.Context) (net.Conn, error), stamp func(http.Header)) (*StampHop, error) {
	if dial == nil || stamp == nil {
		return nil, errors.New("sandboxnet.NewStampHop: nil dial or stamp func")
	}
	tr := &http.Transport{
		DialContext:        func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
		DisableCompression: true,
		IdleConnTimeout:    30 * time.Second,
	}
	quiet := log.New(io.Discard, "", 0)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "observer-proxy"
			// The box's Host (127.0.0.1:<port>) is kept so the proxy's
			// loopback Host guard still passes.
			pr.Out.Host = pr.In.Host
			stamp(pr.Out.Header)
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      quiet,
	}
	ln := newConnListener()
	life, stop := context.WithCancel(context.Background())
	// http.Server cancels a request's context when its client's read side
	// ends, which a client that half-closes after its request does at once
	// (audit N3-A4). A request here is bound to the hop's life instead: a
	// box that is really gone still ends it, at the first response write
	// that fails, and Close ends every request.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
		defer cancel()
		defer context.AfterFunc(life, cancel)()
		rp.ServeHTTP(w, r.WithContext(ctx))
	})
	h := &StampHop{ln: ln, tr: tr, stop: stop, srv: &http.Server{Handler: handler, ReadHeaderTimeout: time.Minute, ErrorLog: quiet}}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

// Conn returns the box end of a fresh connected pair (a unix socket pair,
// so a half-close reaches the hop; stamp_pair_unix.go) whose other end
// the hop serves, for ServeForward's dial func to return in place of a
// connection to the proxy. It fails once the hop is closed.
func (h *StampHop) Conn() (net.Conn, error) {
	box, home, err := stampConnPair()
	if err != nil {
		return nil, err
	}
	if !h.ln.hand(home) {
		_ = box.Close()
		_ = home.Close()
		return nil, net.ErrClosed
	}
	return box, nil
}

// Close stops the hop and every connection it serves.
func (h *StampHop) Close() error {
	h.stop()
	err := h.srv.Close()
	_ = h.ln.Close()
	h.tr.CloseIdleConnections()
	return err
}

// connListener is a net.Listener fed by hand: each handed connection is
// returned by one Accept.
type connListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newConnListener() *connListener {
	return &connListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

// hand queues c for Accept; false once the listener is closed.
func (l *connListener) hand(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

// Accept returns the next handed connection, or net.ErrClosed after Close.
func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close ends Accept and refuses further hands.
func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr is a placeholder address (the connections are in memory).
func (l *connListener) Addr() net.Addr { return stampAddr{} }

type stampAddr struct{}

func (stampAddr) Network() string { return "pipe" }
func (stampAddr) String() string  { return "sandboxnet-stamp-hop" }
