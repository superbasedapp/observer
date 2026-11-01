//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_proxystamp.go names the run on a hosted box's
// relayed model requests (live run 2, finding N5: relayed api_turns rows
// had no session). The box's model stream arrives on the run's own relay
// mux; here, on the HOME side, each request is passed to the model proxy
// through a reverse proxy that sets sandboxremote.RelayRunHeader to this
// run's id (any value the box sent is replaced, so a box cannot name
// another run), and the proxy files the turn under the run's re-keyed
// session, the namespace the run's pulled transcripts land in.

// errHostedProxyDown refuses a model stream when the proxy socket is not
// there (the proxy did not answer when the run's helper started), so the
// in-box launcher's reachability check keeps its meaning.
var errHostedProxyDown = errors.New("the model proxy is not reachable from this run")

// dialHostedProxyStamped serves one relayed model connection.
func dialHostedProxyStamped(sock, runID string) (io.ReadWriteCloser, error) {
	if fi, err := os.Lstat(sock); err != nil || fi.Mode().Type() != fs.ModeSocket {
		return nil, errHostedProxyDown
	}
	box, home := net.Pipe()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableCompression: true,
		MaxIdleConns:       1,
		IdleConnTimeout:    30 * time.Second,
	}
	quiet := log.New(io.Discard, "", 0)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", "observer-proxy"
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set(sandboxremote.RelayRunHeader, runID)
			if f := hostedCredStampHook; f != nil {
				f(pr.Out.Header, runID)
			}
		},
		Transport:     tr,
		FlushInterval: -1,
		ErrorLog:      quiet,
	}
	ln := newHostedOneConnListener(home)
	srv := &http.Server{
		Handler: rp, ReadHeaderTimeout: time.Minute, ErrorLog: quiet,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				_ = ln.Close()
				tr.CloseIdleConnections()
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	return box, nil
}

// hostedOneConnListener hands out one connection, then blocks until closed.
type hostedOneConnListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newHostedOneConnListener(c net.Conn) *hostedOneConnListener {
	l := &hostedOneConnListener{addr: c.LocalAddr(), ch: make(chan net.Conn, 1), done: make(chan struct{})}
	l.ch <- c
	return l
}

// Accept returns the connection once, then net.ErrClosed after Close.
func (l *hostedOneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close ends Accept; the connection handed out is left to its server.
func (l *hostedOneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr is the connection's local address.
func (l *hostedOneConnListener) Addr() net.Addr { return l.addr }
