//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
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
	stop, err := startHostServices(h)
	defer stop()
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}

	// The re-check (sandbox_recheck_linux.go) runs BEFORE the tool starts
	// (P-017 (d)): bwrap is started with --block-fd, so the sandbox's pid 1
	// is built (namespaces and mounts in place) but waits on a pipe before
	// it execs anything. The helper measures it and writes the release byte
	// only when the build matches the plan; a refused build is killed while
	// still blocked, so the tool never ran.
	gate, err := newStartGate()
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	defer gate.close()
	// bwrap's namespace re-check, or the re-check of the observer helper
	// the host helper runs in its place (the process_lite exec step).
	recheck := func(pid int) error { return sandboxRecheck(h.PrivateNet, pid) }
	matched := recheckBwrapMatched
	if row, ok := gatedHelperFor(h.Command); ok {
		recheck, matched = row.recheck, row.matched
	}
	release := func(pid int) error {
		err := recheck(pid)
		if errors.Is(err, errRecheckChildExited) {
			// The child ended on its own before it was released (its own
			// refusal is on the terminal): nothing to release, and its
			// exit status is the run's.
			return nil
		}
		if err := recheckNoticeFor(err, matched, os.Stderr); err != nil {
			return err
		}
		return gate.release()
	}
	// The tier variable comes from this helper's own network flags, the one
	// tier table, for every row whose wrap runs it (R3).
	// The layer's environment is the allow-list (WINFIX2 R-167).
	return runSupervisedChild(gate.argv(h.Command), sandboxHostChildEnv(os.Environ(), h), gate.files(), release)
}

// startHostServices starts what the host helper owns around ANY isolation
// layer (bwrap here, a container in the oci-runc driver,
// terminal_sandbox_oci_linux.go): the protected-path placeholders, the
// per-run socket dir, the capture relay, the model-proxy forward and the
// egress gateway. The returned stop undoes all of it in reverse order; it
// is safe to call after an error (it releases what was started).
func startHostServices(h sandbox.HostArgs) (func(), error) {
	var undo []func()
	stop := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	allow, err := sandboxnet.ParseAllowCIDRs(h.AllowCIDRs)
	if err != nil {
		return stop, fmt.Errorf("[terminal.sandbox].egress_allow_cidrs: %w", err)
	}

	// Placeholders first: they must exist before the layer binds over them,
	// and they are created here (not by the layer's own mount-point
	// creation) so the helper knows exactly which inode it made and can
	// remove it afterwards.
	//
	// The ledger (sandbox_placeholder_ledger_linux.go) records what is
	// created, locked for this helper's life, so a helper killed with
	// SIGKILL leaves the proof the daemon's start sweep removes its
	// placeholders by (N3). A ledger that cannot be opened does not fail
	// the launch: the helper's own exit still removes its placeholders.
	var ledger *placeholderLedger
	if len(h.PlaceholderFiles)+len(h.PlaceholderDirs) > 0 {
		ledger, _ = openPlaceholderLedger(h.ObserverDir, h.RelayRun)
	}
	created, err := createPlaceholders(h.PlaceholderFiles, h.PlaceholderDirs)
	_ = ledger.record(created)
	undo = append(undo, func() {
		removePlaceholders(created)
		ledger.close()
	})
	if err != nil {
		return stop, err
	}

	if h.SockDir != "" {
		// Mkdir (not MkdirAll) refuses a pre-existing path, including a
		// planted symlink, so the sockets always land in a fresh 0700 dir
		// we own.
		if err := os.Mkdir(h.SockDir, 0o700); err != nil {
			return stop, fmt.Errorf("create socket dir: %w", err)
		}
		dir := h.SockDir
		undo = append(undo, func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G703: SockDir is composed by the daemon for this helper; Mkdir refuses an existing path or symlink
	}

	ctx, cancel := context.WithCancel(context.Background())
	undo = append(undo, cancel)

	// The capture relay (lane sbx-p2): the box's hooks speak to this helper
	// on relay.sock, and it forwards every verified request to the daemon.
	if h.RelayRun != "" {
		relayStop, err := serveRelay(ctx, h)
		if err != nil {
			return stop, fmt.Errorf("capture relay: %w", err)
		}
		undo = append(undo, relayStop)
	}

	if h.ProxyAddr != "" {
		// Expose the proxy socket only when the proxy answers now, so the
		// in-sandbox launcher's own reachability check keeps its meaning (a
		// down proxy reads as down inside, not as a port that accepts and
		// then drops every request).
		if c, derr := net.DialTimeout("tcp", h.ProxyAddr, 2*time.Second); derr == nil {
			_ = c.Close()
			ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.ProxySocketName))
			if lerr != nil {
				return stop, fmt.Errorf("listen for the model proxy: %w", lerr)
			}
			undo = append(undo, func() { _ = ln.Close() })
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
		gw, err := hostEgressGateway(h, allow)
		if err != nil {
			return stop, err
		}
		ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.GatewaySocketName))
		if lerr != nil {
			return stop, fmt.Errorf("listen for the egress gateway: %w", lerr)
		}
		srv := &http.Server{
			Handler:           gw,
			ReadHeaderTimeout: 30 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		undo = append(undo, func() { _ = srv.Close() })
		go func() { _ = srv.Serve(ln) }()
	}
	return stop, nil
}

// hostEgressGateway is the egress gateway of a Linux host helper's run, the
// one builder the launch helper (startHostServices) and the re-adoption
// helper (readoptHostServices) share, so a path cannot rebuild the gateway
// without the run's host list (OSH-R-153). The agent-run host allow-list
// (lane LEFT-SBX), one rule for every row, is read from the daemon config
// the run record names; a record or config that cannot be read refuses the
// gateway (fail closed: the list could be set).
func hostEgressGateway(h sandbox.HostArgs, allow []netip.Prefix) (*sandboxnet.Gateway, error) {
	hosts, err := sandboxAgentEgressRules(h.ObserverDir, h.RelayRun)
	if err != nil {
		return nil, err
	}
	// The helper's stderr IS the sandboxed tool's terminal: a log line there
	// would corrupt a full-screen TUI. Refusals still reach the client in
	// the 403 body, which names the rule.
	return &sandboxnet.Gateway{Allow: allow, Hosts: hosts, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Providers: providerBlockFor(h)}, nil
}

// startGateFD is the descriptor the release pipe lands on in bwrap: fd 3
// stays the inherited trusted launcher channel (OOB), so the gate is fd 4.
const startGateFD = 4

// startGate is the pipe bwrap's --block-fd waits on.
type startGate struct {
	oob  *os.File
	r, w *os.File
}

// newStartGate opens the release pipe and keeps fd 3 in place for the
// child: the inherited OOB fd when one is open, otherwise /dev/null, so the
// gate always lands on startGateFD.
func newStartGate() (*startGate, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("start gate: %w", err)
	}
	g := &startGate{r: r, w: w}
	if _, ferr := unixFcntlGetFD(3); ferr == nil {
		// A duplicate, so this helper never owns (or, through a finalizer,
		// closes) its own fd 3; the child still receives it on fd 3.
		dup, derr := syscall.Dup(3)
		if derr != nil {
			_ = r.Close()
			_ = w.Close()
			return nil, fmt.Errorf("start gate: %w", derr)
		}
		syscall.CloseOnExec(dup)
		g.oob = os.NewFile(uintptr(dup), "observer-oob") //nolint:gosec // G115: a descriptor number from dup(2)
	} else if g.oob, err = os.Open(os.DevNull); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, fmt.Errorf("start gate: %w", err)
	}
	return g, nil
}

// serveRelay starts the box side of the capture relay for the run h names:
// it reads the host run record, writes the box record into the socket dir
// (bound read-only in the box), and serves relay.sock with the forwarder,
// peer credentials checked. The returned stop removes the run record.
func serveRelay(ctx context.Context, h sandbox.HostArgs) (func(), error) {
	rec, err := sandboxrelayd.ReadRun(h.ObserverDir, h.RelayRun)
	if err != nil {
		return nil, err
	}
	// The run's liveness lock, held for this helper's life: if it is
	// killed with SIGKILL the kernel drops the lock and the daemon's sweep
	// ends the run (its session claims, its record) without a restart
	// (P-040). A lock that cannot be taken keeps the earlier rule (the run
	// lives while its record does), so it does not fail the launch.
	unhold, herr := sandboxrelayd.HoldRun(h.ObserverDir, h.RelayRun)
	if herr != nil {
		unhold = func() {}
	}
	if err := sandboxrelayd.WriteBoxRecord(h.SockDir, rec); err != nil {
		unhold()
		return nil, err
	}
	ln, err := net.Listen("unix", filepath.Join(h.SockDir, sandboxrelayd.RelaySocketName))
	if err != nil {
		unhold()
		return nil, err
	}
	fw := &sandboxrelayd.Forwarder{
		Run:        rec,
		DialDaemon: dialSandboxRelay(h.ObserverDir),
		DaemonAddr: sandboxRelayAddr(h.ObserverDir),
		Rules:      relayRules,
		Peer:       sandboxrelayd.PeerSameUser,
		// Continuous hook verification (sandbox plan section 5.2): the
		// launch's registration is read now, before the box is released,
		// and again on a timer and before each spooled replay.
		HookProbe: relayHookProbe(rec),
	}
	fw.ReadLaunchHooks()
	go func() { _ = fw.Serve(ctx, ln) }()
	return func() {
		_ = ln.Close()
		_ = sandboxrelayd.RemoveRun(h.ObserverDir, h.RelayRun)
		unhold()
	}, nil
}

// unixFcntlGetFD reports whether fd is an open descriptor (F_GETFD).
func unixFcntlGetFD(fd uintptr) (uintptr, error) {
	r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

// sandboxGatedHelper is an observer helper verb the host helper may run as
// its child in place of bwrap, registered by its driver (the process_lite
// exec step): the start gate's flag goes after the verb, because main's
// dispatch reads the verb at argv[1] (Linux live check 2026-10-23, LIN-1
// F2: inserted after argv[0], the verb was never dispatched), and the row's
// own re-check replaces bwrap's namespace one.
type sandboxGatedHelper struct {
	// recheck measures the held child pid; the same outcomes as
	// sandboxRecheck, plus errRecheckChildExited.
	recheck func(pid int) error
	// matched is the line a measured match prints.
	matched string
}

// sandboxGatedHelpers is the table of gated helper verbs (filled from the
// drivers' init functions).
var sandboxGatedHelpers = map[string]sandboxGatedHelper{}

// gatedHelperFor returns the row of the helper verb cmd runs, if any: cmd is
// `observer <verb> ...`, the verb at cmd[1].
func gatedHelperFor(cmd []string) (sandboxGatedHelper, bool) {
	if len(cmd) < 2 {
		return sandboxGatedHelper{}, false
	}
	row, ok := sandboxGatedHelpers[cmd[1]]
	return row, ok
}

// argv inserts --block-fd where the child reads it: right after the bwrap
// program path, or right after the verb of a gated observer helper (the
// verb must stay argv[1] for main's dispatch).
func (g *startGate) argv(cmd []string) []string {
	if len(cmd) == 0 {
		return cmd
	}
	at := 1
	if _, ok := gatedHelperFor(cmd); ok {
		at = 2
	}
	out := make([]string, 0, len(cmd)+2)
	out = append(out, cmd[:at]...)
	out = append(out, "--block-fd", strconv.Itoa(startGateFD))
	return append(out, cmd[at:]...)
}

// files is the child's ExtraFiles: fd 3 then the gate's read end on fd 4.
func (g *startGate) files() []*os.File { return []*os.File{g.oob, g.r} }

// release lets the blocked sandbox exec its command.
func (g *startGate) release() error {
	_ = g.r.Close()
	if _, err := g.w.Write([]byte{1}); err != nil {
		return fmt.Errorf("release the sandbox: %w", err)
	}
	return g.w.Close()
}

// close drops both ends and the fd 3 duplicate (idempotent on an already
// closed end).
func (g *startGate) close() {
	_ = g.r.Close()
	_ = g.w.Close()
	if g.oob != nil {
		_ = g.oob.Close()
	}
}

// runSandboxGuest is the in-sandbox helper: forward the in-namespace loopback
// ports to the host sockets, point the inner command's HTTP(S)_PROXY at the
// gateway port, then run the inner command and exit with its status.
func runSandboxGuest(args []string) int {
	if len(args) > 0 && args[0] == sandbox.GuestStagedDiff {
		return runGuestStagedDiff(args[1:])
	}
	if len(args) > 0 && args[0] == sandbox.GuestDBCopy {
		return runGuestDBCopy(args[1:])
	}
	if len(args) > 0 && args[0] == relayStdioFlag {
		return runGuestRelayStdio(args[1:])
	}
	if len(args) > 0 && args[0] == guestAttachVerb { // the hosted guest PTY's reattach (lane SBX-UPD)
		return runGuestAttach(args[1:])
	}
	g, err := sandbox.ParseGuestArgs(args)
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env, err := startGuestForwards(ctx, g, os.Environ())
	if err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	return runSupervisedChild(g.Command, env, nil, nil)
}

// guestForwardRow is one forward a guest network command starts: a
// loopback port in the box onto a host socket bound into it.
type guestForwardRow struct {
	name string
	port int
	sock string
	// missingOK: a missing socket leaves the port closed instead of failing
	// (the model proxy's honest "proxy down" signal: the launcher sees the
	// port as down).
	missingOK bool
	// env is set in the launcher's environment once the forward is up.
	env []string
}

// guestForwardRows is THE table of a guest network command's forwards. Its
// one reader, startGuestForwards, is called by both places that run a guest
// command's forwards: runSandboxGuest (bwrap and the guest helper) and the
// container init that keeps the OOB descriptor (ociInitTakeGuest, lane
// SBX-P3C audit finding 6, ruling P-121), so the two cannot drift. A
// variable for the test that proves both read it.
var guestForwardRows = func(g sandbox.GuestArgs) []guestForwardRow {
	return []guestForwardRow{
		{name: "model proxy", port: g.ProxyPort, sock: g.ProxySock, missingOK: true},
		{name: "egress gateway", port: g.GatewayPort, sock: g.GatewaySock, env: sandbox.GuestProxyEnv(g.GatewayPort)},
	}
}

// startGuestForwards starts g's forwards (guestForwardRows, top-down) for
// ctx's life and returns env with each started row's variables set.
func startGuestForwards(ctx context.Context, g sandbox.GuestArgs, env []string) ([]string, error) {
	for _, row := range guestForwardRows(g) {
		if row.port <= 0 {
			continue
		}
		if _, err := os.Stat(row.sock); err != nil {
			if row.missingOK {
				continue
			}
			return env, fmt.Errorf("the %s socket is missing: %w", row.name, err)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(row.port)))
		if err != nil {
			return env, fmt.Errorf("forward the %s port: %w", row.name, err)
		}
		sock := row.sock
		go func() {
			_ = sandboxnet.ServeForward(ctx, ln, func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			})
		}()
		if len(row.env) > 0 {
			env = overrideEnv(env, row.env)
		}
	}
	return env, nil
}

// runGuestStagedDiff is the guest one-shot `observer sandbox-guest
// staged-diff [--all]` (sandbox plan section 6, M7): it prints what the box's
// next commit would record, from the box's working directory, capped at
// sandbox.MaxStagedDiff (a cut diff exits sandbox.StagedDiffTruncatedExit).
// It runs inside the box, so a repository config it reads can only act in
// the box; the host treats the output as untrusted input.
func runGuestStagedDiff(args []string) int {
	all, ok := sandbox.ParseStagedDiffArgs(args)
	if !ok {
		return helperFail("observer sandbox-guest %s: usage: %s [%s]", sandbox.GuestStagedDiff, sandbox.GuestStagedDiff, sandbox.StagedDiffAll)
	}
	argv := sandbox.StagedDiffArgv(all)
	//nolint:gosec // G204: a fixed git argv from the pure planner
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_EXTERNAL_DIFF=")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", sandbox.GuestStagedDiff, err)
	}
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox-guest %s: %v", sandbox.GuestStagedDiff, err)
	}
	n, _ := io.Copy(os.Stdout, io.LimitReader(out, sandbox.MaxStagedDiff))
	extra, _ := io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return helperFail("observer sandbox-guest %s: %v", sandbox.GuestStagedDiff, err)
	}
	if n == sandbox.MaxStagedDiff && extra > 0 {
		fmt.Fprintf(os.Stderr, "observer sandbox-guest %s: the diff is over %d bytes and was cut\n", sandbox.GuestStagedDiff, sandbox.MaxStagedDiff)
		return sandbox.StagedDiffTruncatedExit
	}
	return 0
}

// runSupervisedChild runs argv with the helper's stdio, a parent-death
// SIGKILL (so the chain host helper -> bwrap -> guest -> tool never leaves an
// orphan), SIGTERM/SIGHUP forwarded, and SIGINT/SIGQUIT ignored (the child is
// in the same foreground process group and gets terminal-generated signals
// itself, like a job under a shell). It returns the child's exit status
// (128+signal when it was killed). env nil inherits the helper's environment.
// postStart, when set, runs once the child has started; an error kills the
// child and fails the helper (the re-check's refusal). extra become the
// child's descriptors from 3 on.
func runSupervisedChild(argv []string, env []string, extra []*os.File, postStart func(pid int) error) int {
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
	cmd.ExtraFiles = extra
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox: start %s: %v", filepath.Base(argv[0]), err)
	}
	if postStart != nil {
		if err := postStart(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return helperFail("observer sandbox: refused after launch: %v", err)
		}
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

// providerBlockFor builds the gateway's model-provider host block when the
// launch asked for it (section 7.3); nil leaves the gateway as before.
func providerBlockFor(h sandbox.HostArgs) *sandboxnet.ProviderBlock {
	if !h.ProviderBlock {
		return nil
	}
	return sandboxnet.NewProviderBlock(h.ProviderHosts)
}
