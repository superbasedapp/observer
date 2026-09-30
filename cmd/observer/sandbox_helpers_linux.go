//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
)

// sandboxHelperFailCode is the exit code a helper returns when it could not
// build the network tier. The launch fails (fail closed); nothing is ever run
// with a weaker network posture than the one planned.
const sandboxHelperFailCode = 125

// runSandboxHost is the host-side helper: create the protected-path
// placeholders, create the per-run socket dir, serve the model-proxy forward
// and (when asked) the egress gateway on unix sockets in it, then run bwrap
// and exit with its status. The socket dir, and every placeholder still
// untouched, are removed on the way out.
func runSandboxHost(args []string) int {
	h, err := sandbox.ParseHostArgs(args)
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	allow, err := sandboxnet.ParseAllowCIDRs(h.AllowCIDRs)
	if err != nil {
		return helperFail("observer sandbox: [terminal.sandbox].egress_allow_cidrs: %v", err)
	}

	// Placeholders first: they must exist before bwrap binds over them, and
	// they are created here (not by bwrap's own mount-point creation) so the
	// helper knows exactly which inode it made and can remove it afterwards.
	created, err := createPlaceholders(h.PlaceholderFiles, h.PlaceholderDirs)
	defer removePlaceholders(created)
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}

	if h.SockDir != "" {
		// Mkdir (not MkdirAll) refuses a pre-existing path, including a
		// planted symlink, so the sockets always land in a fresh 0700 dir
		// we own.
		if err := os.Mkdir(h.SockDir, 0o700); err != nil {
			return helperFail("observer sandbox: create socket dir: %v", err)
		}
		defer func() { _ = os.RemoveAll(h.SockDir) }()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if h.ProxyAddr != "" {
		// Expose the proxy socket only when the proxy answers now, so the
		// in-sandbox launcher's own reachability check keeps its meaning (a
		// down proxy reads as down inside, not as a port that accepts and
		// then drops every request).
		if c, derr := net.DialTimeout("tcp", h.ProxyAddr, 2*time.Second); derr == nil {
			_ = c.Close()
			ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.ProxySocketName))
			if lerr != nil {
				return helperFail("observer sandbox: listen for the model proxy: %v", lerr)
			}
			defer func() { _ = ln.Close() }()
			target := h.ProxyAddr
			go func() {
				_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", target)
				})
			}()
		} else {
			fmt.Fprintf(os.Stderr, "observer sandbox: the model proxy is not reachable at %s; the sandboxed tool will see it as down\n", h.ProxyAddr)
		}
	}

	if h.Gateway {
		ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.GatewaySocketName))
		if lerr != nil {
			return helperFail("observer sandbox: listen for the egress gateway: %v", lerr)
		}
		srv := &http.Server{
			// The helper's stderr IS the sandboxed tool's terminal: a log
			// line there would corrupt a full-screen TUI. Refusals still
			// reach the client in the 403 body, which names the rule.
			Handler:           &sandboxnet.Gateway{Allow: allow, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
			ReadHeaderTimeout: 30 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		defer func() { _ = srv.Close() }()
		go func() { _ = srv.Serve(ln) }()
	}

	return runSupervisedChild(h.Command, nil)
}

// runSandboxGuest is the in-sandbox helper: forward the in-namespace loopback
// ports to the host sockets, point the inner command's HTTP(S)_PROXY at the
// gateway port, then run the inner command and exit with its status.
func runSandboxGuest(args []string) int {
	g, err := sandbox.ParseGuestArgs(args)
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	forward := func(port int, sock string) error {
		ln, lerr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if lerr != nil {
			return lerr
		}
		go func() {
			_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			})
		}()
		return nil
	}

	env := os.Environ()
	if g.ProxyPort > 0 {
		// A missing proxy socket is the host helper's honest "proxy down"
		// signal: leave the port closed so the launcher sees it as down.
		if _, serr := os.Stat(g.ProxySock); serr == nil {
			if ferr := forward(g.ProxyPort, g.ProxySock); ferr != nil {
				return helperFail("observer sandbox: forward the model proxy port: %v", ferr)
			}
		}
	}
	if g.GatewayPort > 0 {
		if _, serr := os.Stat(g.GatewaySock); serr != nil {
			return helperFail("observer sandbox: the egress gateway socket is missing: %v", serr)
		}
		if ferr := forward(g.GatewayPort, g.GatewaySock); ferr != nil {
			return helperFail("observer sandbox: forward the egress gateway port: %v", ferr)
		}
		env = overrideEnv(env, sandbox.GuestProxyEnv(g.GatewayPort))
	}
	return runSupervisedChild(g.Command, env)
}

// runSupervisedChild runs argv with the helper's stdio, a parent-death
// SIGKILL (so the chain host helper -> bwrap -> guest -> tool never leaves an
// orphan), SIGTERM/SIGHUP forwarded, and SIGINT/SIGQUIT ignored (the child is
// in the same foreground process group and gets terminal-generated signals
// itself, like a job under a shell). It returns the child's exit status
// (128+signal when it was killed). env nil inherits the helper's environment.
func runSupervisedChild(argv []string, env []string) int {
	// Pdeathsig fires when the THREAD that forked the child exits; pin this
	// goroutine to its thread for the helper's whole life.
	runtime.LockOSThread()

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	//nolint:gosec // argv is the server-planned bwrap / launcher argv
	// (internal/sandbox.BuildPlan + ParseHostArgs/ParseGuestArgs), never
	// client input.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox: start %s: %v", filepath.Base(argv[0]), err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return helperFail("observer sandbox: wait: %v", err)
}

// createdPlaceholder records one placeholder the helper created, so it is
// removed afterwards only when it is still that inode, unchanged.
type createdPlaceholder struct {
	path    string
	dir     bool
	dev     uint64
	ino     uint64
	content []byte
}

// createPlaceholders creates each missing protected path: a file with
// sandbox.PlaceholderContent (O_EXCL|O_NOFOLLOW, 0600) or an empty dir
// (0700). A path that already exists (created on the host since the launch
// was planned) is left alone: bwrap then protects the real thing. It returns
// what it created even on error, so the caller can clean up.
func createPlaceholders(files, dirs []string) ([]createdPlaceholder, error) {
	var out []createdPlaceholder
	record := func(p string, dir bool, content []byte) error {
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			return fmt.Errorf("stat placeholder %s: %w", p, err)
		}
		out = append(out, createdPlaceholder{path: p, dir: dir, dev: uint64(st.Dev), ino: st.Ino, content: content}) //nolint:unconvert // Dev is uint64 on amd64, uint32 elsewhere
		return nil
	}
	for _, p := range dirs {
		if err := os.Mkdir(p, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return out, fmt.Errorf("create protected placeholder dir %s: %w", p, err)
		}
		if err := record(p, true, nil); err != nil {
			return out, err
		}
	}
	for _, p := range files {
		content := sandbox.PlaceholderContent(p)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return out, fmt.Errorf("create protected placeholder %s: %w", p, err)
		}
		_, werr := f.Write(content)
		cerr := f.Close()
		if err := record(p, false, content); err != nil {
			return out, err
		}
		if werr != nil || cerr != nil {
			return out, fmt.Errorf("write protected placeholder %s: %w", p, errors.Join(werr, cerr))
		}
	}
	return out, nil
}

// removePlaceholders removes each created placeholder that is still the
// inode the helper made and still holds what it was created with (a file
// with the same bytes, an empty dir). Anything the host changed meanwhile
// (the daemon writing real content, an atomic replace) is left in place.
func removePlaceholders(created []createdPlaceholder) {
	for i := len(created) - 1; i >= 0; i-- {
		c := created[i]
		var st syscall.Stat_t
		if err := syscall.Lstat(c.path, &st); err != nil || uint64(st.Dev) != c.dev || st.Ino != c.ino { //nolint:unconvert // see createPlaceholders
			continue
		}
		if c.dir {
			_ = os.Remove(c.path) // fails, and keeps the dir, unless it is empty
			continue
		}
		if st.Size != int64(len(c.content)) {
			continue
		}
		b, err := os.ReadFile(c.path)
		if err != nil || string(b) != string(c.content) {
			continue
		}
		_ = os.Remove(c.path)
	}
}

// overrideEnv returns base with every KEY in set replaced (or added).
func overrideEnv(base, set []string) []string {
	drop := map[string]bool{}
	for _, kv := range set {
		if i := strings.IndexByte(kv, '='); i > 0 {
			drop[kv[:i]] = true
		}
	}
	out := make([]string, 0, len(base)+len(set))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, set...)
}

// helperFail prints a one-line reason and returns the helper failure code.
func helperFail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return sandboxHelperFailCode
}
