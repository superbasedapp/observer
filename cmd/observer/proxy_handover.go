package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/listenhandover"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// proxy_handover.go: operator ruling L-168 (ii), 2026-11-24: a restart keeps
// the proxy port answering.
//
// The daemon IS the proxy. Its in-place restart (the dashboard's Restart now,
// `observer service restart`) used to close the proxy's socket during the
// graceful shutdown and bind it again in the re-executed image, so every AI
// tool routed through it got ConnectionRefused for the seconds in between.
// Taking the route off the tool's config file (the route hold) does not reach
// a session that is already running: it read the proxy's base URL at its
// start. Now the restart hands the listening socket itself to the new image
// (internal/listenhandover): before the shutdown it stops accepting and
// waits, bounded, for the proxied requests in flight; it duplicates the
// socket; the execve passes the duplicate on; the new image adopts it when
// it is the configured address. Meanwhile the kernel keeps completing
// connections into the socket's backlog, so a client that connects during
// the restart waits and the new daemon serves it. Nothing is refused and no
// route is taken off.
//
// Unix only (execve). A Windows daemon cannot restart in place at all; its
// restart keeps the refusal of internal/service.DecideRestart.

// inheritedProxyListener is the socket the image that exec'd this process
// handed over (nil when none). Claimed in main() before anything else runs,
// so no child this process starts inherits it.
var inheritedProxyListener *listenhandover.Inherited

// claimProxyHandover claims a handed-over proxy socket. It runs first thing
// in main(), for every command: only `observer start` adopts it, and any
// other process closes it on exit.
func claimProxyHandover() {
	inheritedProxyListener = listenhandover.Claim()
}

// restartDrainBound bounds how long an in-place restart waits for the
// proxied requests in flight before the shutdown begins (a streamed turn
// longer than this is cut by the shutdown's own grace, as before). The
// `observer service restart` wait (safeRestartDefaultTimeout) covers it.
const restartDrainBound = 30 * time.Second

// restartDrainPoll is how often the drain looks at the in-flight count.
const restartDrainPoll = 100 * time.Millisecond

// proxyHandover is this process's proxy listener and its hand-over state.
// One per process (processProxyHandover): there is exactly one proxy.
type proxyHandover struct {
	mu sync.Mutex
	// ln is the proxy's listener while it serves; addr is its configured
	// address.
	ln   *listenhandover.Pausable
	addr string
	// prepared is the duplicated socket an in-place restart hands over
	// (nil until prepare).
	prepared *os.File
	// served: this process's proxy bound (or adopted) its port and served
	// it. A daemon whose bind failed never takes another daemon's routes
	// off (internal/service.DecideStopRoutes).
	served atomic.Bool
}

// processProxyHandover is the process's one proxy hand-over state.
var processProxyHandover = &proxyHandover{}

// listen binds the proxy's listener for addr, or adopts the socket a
// restarting daemon handed over when it listens on addr, and records it.
func (h *proxyHandover) listen(addr string, in *listenhandover.Inherited, out io.Writer) (net.Listener, error) {
	ln, adopted, err := listenhandover.Listen(in, addr)
	if err != nil {
		return nil, err
	}
	p := listenhandover.NewPausable(ln)
	h.mu.Lock()
	h.ln, h.addr = p, addr
	h.mu.Unlock()
	h.served.Store(true)
	if adopted {
		fmt.Fprintf(out, "proxy: took over the listening socket on %s from the restarting daemon (no connection was refused)\n", addr)
	}
	return p, nil
}

// proxyServed reports whether this process's proxy bound its port.
func (h *proxyHandover) proxyServed() bool { return h.served.Load() }

// prepare duplicates the serving proxy's socket for an in-place restart.
// ok is false when there is nothing to hand over: no proxy serves in this
// process, or this OS cannot pass a socket across a re-exec.
func (h *proxyHandover) prepare() (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.prepared != nil {
		return true, nil
	}
	if h.ln == nil || !listenhandover.Supported() {
		return false, nil
	}
	f, err := listenhandover.Prepare(h.ln)
	if err != nil {
		return false, err
	}
	h.prepared = f
	return true, nil
}

// handingOver reports whether an in-place restart will hand the socket on.
func (h *proxyHandover) handingOver() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.prepared != nil
}

// drainForRestart stops accepting (connections made from now on wait in the
// socket's backlog for the new image) and waits, bounded, until no proxied
// request is in flight, so the restart does not cut a streamed turn. It
// reports whether the proxy drained within the bound; either way the
// restart goes on.
func (h *proxyHandover) drainForRestart(ctx context.Context, inFlight func() int, bound time.Duration) bool {
	h.mu.Lock()
	ln := h.ln
	h.mu.Unlock()
	if ln == nil {
		return true
	}
	ln.Pause()
	deadline := time.Now().Add(bound)
	for inFlight() > 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(restartDrainPoll):
		}
	}
	return true
}

// execEnv returns env for the re-exec: with the hand-over variables naming
// the prepared socket (close-on-exec cleared right here, so call it right
// before the execve), or env unchanged when nothing was prepared or the
// socket cannot be passed on (the new daemon then binds the port again).
func (h *proxyHandover) execEnv(env []string, stderr io.Writer) []string {
	h.mu.Lock()
	f, addr := h.prepared, h.addr
	h.mu.Unlock()
	if f == nil {
		return env
	}
	out, err := listenhandover.ExecEnv(f, addr, env)
	if err != nil {
		fmt.Fprintf(stderr, "WARN restart: the proxy's listening socket could not be handed over (%v); the restarted daemon binds the port again\n", err)
		_ = f.Close()
		return env
	}
	return out
}

// prepareRestartHandover is the proxy half of an in-place restart, run
// after the restart's own checks passed and before the shutdown begins:
// duplicate the socket, then drain. A socket that cannot be duplicated is
// logged and the restart goes on without a hand-over (the daemon then takes
// its routes off for the restart; DecideStopRoutes).
func prepareRestartHandover(ctx context.Context, h *proxyHandover, inFlight func() int, stderr io.Writer) {
	ok, err := h.prepare()
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "WARN restart: the proxy's listening socket could not be duplicated (%v); the restart closes the port for a moment and the proxy routes come off until it is back\n", err)
		return
	case !ok:
		return
	}
	if !h.drainForRestart(ctx, inFlight, restartDrainBound) {
		fmt.Fprintf(stderr, "restart: proxied requests still in flight after %s; the restart goes on and the shutdown gives them its own grace\n", restartDrainBound)
	}
}

// daemonHandoverReport is what the daemon says about its own restart on its
// dashboard (GET /api/admin/restart): whether it hands its proxy socket
// over, and the digest of the command it runs (service.InvocationDigest),
// which `observer service restart` compares with the installed unit's.
func daemonHandoverReport() (handover bool, invocation string) {
	return listenhandover.Supported() && reexecSupported(), runningInvocationDigest()
}

// runningInvocationDigest is the digest of the command this process runs:
// its executable (symlinks resolved) and the arguments after `start`. ""
// when it is not `<exe> start ...`.
func runningInvocationDigest() string {
	args, ok := service.StartArgs(os.Args)
	if !ok {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return service.InvocationDigest(resolvedExePath(exe), args)
}

// resolvedExePath resolves symlinks in exe; exe itself when it cannot.
func resolvedExePath(exe string) string {
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		return r
	}
	return exe
}
