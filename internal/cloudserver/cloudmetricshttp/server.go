package cloudmetricshttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
)

// EnvListen is the environment variable that enables the listener
// (host:port; empty means off).
const EnvListen = "SBCI_METRICS_LISTEN"

// The fixed port contract with the deploy kit (the kit publishes these on the
// monitoring address only).
const (
	PortAPI    = 9470
	PortWorker = 9471
)

// Path is the one route the listener serves.
const Path = "/metrics"

// ParseListen validates the SBCI_METRICS_LISTEN value: "" (off) or a
// host:port with a numeric port in 1..65535 and a host that is empty, an IP
// literal or "localhost". It refuses a value equal to publicListen (the
// public API's address), so the metrics series can never be served on the
// public listener by configuration. A malformed value is an error: the
// process refuses to start rather than guess.
func ParseListen(raw, publicListen string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("%s=%q: want host:port: %w", EnvListen, v, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%s=%q: the port must be a number in 1..65535", EnvListen, v)
	}
	if host != "" && host != "localhost" && net.ParseIP(host) == nil {
		return "", fmt.Errorf("%s=%q: the host must be empty, an IP address or localhost", EnvListen, v)
	}
	if samePort(v, publicListen) {
		return "", fmt.Errorf("%s=%q: the metrics listener must not share the public API's address %q", EnvListen, v, publicListen)
	}
	return v, nil
}

// samePort reports whether two listen addresses could be the same socket:
// the same port, and the same host or either one a wildcard.
func samePort(a, b string) bool {
	ha, pa, err := net.SplitHostPort(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	hb, pb, err := net.SplitHostPort(strings.TrimSpace(b))
	if err != nil || pa != pb {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || wild(ha) || wild(hb)
}

// Handler serves GET /metrics from reg; every other path or method is 404 or
// 405, and nothing else is mounted.
func Handler(reg *cloudmetrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = reg.Render(w)
	})
	return mux
}

// NewServer returns the listener's http.Server for listen, or nil when listen
// is "" (off). The bounds match the org server's metrics listener.
func NewServer(listen string, reg *cloudmetrics.Registry) *http.Server {
	if listen == "" || reg == nil {
		return nil
	}
	return &http.Server{
		Addr:              listen,
		Handler:           Handler(reg),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Start binds srv.Addr NOW (so a port already in use fails the caller's
// start-up, not a background goroutine) and serves until ctx ends, then
// shuts the listener down. A nil srv returns nil and opens nothing. A serve
// error after the bind is handed to onErr (when non-nil).
func Start(ctx context.Context, srv *http.Server, onErr func(error)) error {
	if srv == nil {
		return nil
	}
	lis, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("cloudmetricshttp: listen %s: %w", srv.Addr, err)
	}
	go func() {
		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) && onErr != nil {
			onErr(fmt.Errorf("cloudmetricshttp: %w", err))
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	return nil
}
