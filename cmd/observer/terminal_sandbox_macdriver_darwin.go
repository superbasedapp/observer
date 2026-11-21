//go:build darwin && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

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
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_macdriver_darwin.go is the host side both macOS sandbox
// drivers share (lane SBX-P5): the per-run directories, the capture relay
// on the run's unix socket, the model-proxy forward and the egress gateway,
// and the supervised child. It mirrors startHostServices
// (sandbox_helpers_linux.go) with what macOS changes: no network namespace,
// so the Seatbelt row's gateway listens on a loopback TCP port the profile
// names (a container row keeps the unix socket). Built from Apple's
// documentation; register items MAC-5, MAC-15 and MAC-35 prove it on a Mac.

// macServiceOpts says how the run reaches the proxy and the gateway.
type macServiceOpts struct {
	// GatewayTCP serves the gateway on 127.0.0.1:<ephemeral> (Seatbelt: the
	// box shares the host's network) instead of gateway.sock.
	GatewayTCP bool
	// ProxyForward serves proxy.sock, a forward to the daemon's proxy (a
	// container row, whose box has no route to the host's loopback).
	ProxyForward bool
}

// macServices is what the started services established.
type macServices struct {
	// GatewayPort is the TCP gateway's port (GatewayTCP only).
	GatewayPort int
}

// ensureOwnedDir creates dir (0700) when it is missing and refuses one that
// is a symlink, not a directory, not this user's, or open to others.
func ensureOwnedDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !ownedByMe(fi) {
		return fmt.Errorf("%s is not a private directory this user owns", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		// The common live cause (MAC-38 follow-up): a reused temp parent left
		// group/other-accessible. Name the mode and the one-line remedy.
		return fmt.Errorf("%s is not a private directory this user owns: its mode is %#o, but group and other must have no access; run: chmod 700 %s", dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// startMacHostServices starts the relay, the proxy forward and the gateway
// for h. The returned stop undoes all of it in reverse order and is safe
// after an error.
func startMacHostServices(h sandbox.HostArgs, opts macServiceOpts) (macServices, func(), error) {
	var out macServices
	var undo []func()
	stop := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	allow, err := sandboxnet.ParseAllowCIDRs(h.AllowCIDRs)
	if err != nil {
		return out, stop, fmt.Errorf("[terminal.sandbox].egress_allow_cidrs: %w", err)
	}
	if err := ensureOwnedDir(filepath.Dir(h.SockDir)); err != nil {
		return out, stop, fmt.Errorf("socket parent: %w", err)
	}
	// Mkdir (not MkdirAll) refuses a pre-existing path or a planted
	// symlink, so the sockets land in a fresh 0700 dir this helper made.
	if err := os.Mkdir(h.SockDir, 0o700); err != nil {
		return out, stop, fmt.Errorf("create socket dir: %w", err)
	}
	sockDir := h.SockDir
	undo = append(undo, func() { _ = os.RemoveAll(sockDir) }) //nolint:gosec // G703: composed by the daemon; Mkdir refused an existing path

	// Placeholders first (a container row's protected paths that do not
	// exist yet): the helper makes them, so the box cannot make them first,
	// and removes the untouched ones afterwards. They are recorded in the
	// same locked ledger the Linux helper keeps
	// (sandbox_placeholder_ledger_unix.go), so a SIGKILLed helper's
	// placeholders are cleared by the daemon's next start sweep (ledger
	// SBX-MAC-4). A ledger that cannot be opened does not fail the launch:
	// the helper's own exit still removes its placeholders.
	var ledger *placeholderLedger
	if len(h.PlaceholderFiles)+len(h.PlaceholderDirs) > 0 {
		ledger, _ = openPlaceholderLedger(h.ObserverDir, h.RelayRun)
	}
	made, err := createMacPlaceholders(h.PlaceholderFiles, h.PlaceholderDirs)
	_ = ledger.recordMac(made)
	undo = append(undo, func() {
		removeMacPlaceholders(made)
		ledger.close()
	})
	if err != nil {
		return out, stop, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	undo = append(undo, cancel)

	relayStop, err := serveMacRelay(ctx, h)
	if err != nil {
		return out, stop, fmt.Errorf("capture relay: %w", err)
	}
	undo = append(undo, relayStop)

	if opts.ProxyForward && h.ProxyAddr != "" {
		if c, derr := net.DialTimeout("tcp", h.ProxyAddr, 2*time.Second); derr == nil {
			_ = c.Close()
			ln, lerr := net.Listen("unix", filepath.Join(h.SockDir, sandbox.ProxySocketName))
			if lerr != nil {
				return out, stop, fmt.Errorf("listen for the model proxy: %w", lerr)
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
		// The agent-run host allow-list (lane LEFT-SBX), one rule for every
		// row: read from the daemon config the run record names.
		hosts, err := sandboxAgentEgressRules(h.ObserverDir, h.RelayRun)
		if err != nil {
			return out, stop, err
		}
		var ln net.Listener
		if opts.GatewayTCP {
			ln, err = net.Listen("tcp", "127.0.0.1:0")
		} else {
			ln, err = net.Listen("unix", filepath.Join(h.SockDir, sandbox.GatewaySocketName))
		}
		if err != nil {
			return out, stop, fmt.Errorf("listen for the egress gateway: %w", err)
		}
		if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
			out.GatewayPort = tcp.Port
		}
		audit := sandboxEgressRefusalHooks(ctx, h.ObserverDir, h.RelayRun)
		srv := &http.Server{
			// The helper's stderr is the agent's terminal: no log lines.
			// Refusals go to the daemon's refusal audit on the relay link
			// (lane N1); a lost link closes egress under the floor (F-012).
			Handler: &sandboxnet.Gateway{
				Allow: allow, Hosts: hosts, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Providers: providerBlockFor(h),
				Report: audit.Report, Closed: audit.Closed,
			},
			ReadHeaderTimeout: 30 * time.Second,
			BaseContext:       func(net.Listener) context.Context { return ctx },
		}
		undo = append(undo, func() { _ = srv.Close() })
		go func() { _ = srv.Serve(ln) }()
	}
	return out, stop, nil
}

// serveMacRelay starts the box side of the capture relay for the run h
// names (the bwrap helper's serveRelay, on macOS): the box record in the
// socket dir and relay.sock served with the forwarder, peer credentials
// checked (sandboxrelayd.PeerSameUser, LOCAL_PEERCRED).
func serveMacRelay(ctx context.Context, h sandbox.HostArgs) (func(), error) {
	rec, err := sandboxrelayd.ReadRun(h.ObserverDir, h.RelayRun)
	if err != nil {
		return nil, err
	}
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
		HookProbe:  relayHookProbe(rec),
	}
	fw.ReadLaunchHooks()
	go func() { _ = fw.Serve(ctx, ln) }()
	return func() {
		_ = ln.Close()
		_ = sandboxrelayd.RemoveRun(h.ObserverDir, h.RelayRun)
		unhold()
	}, nil
}

// providerBlockFor is the gateway's provider block for h (the bwrap
// helper's rule): nil unless the run asked for it.
func providerBlockFor(h sandbox.HostArgs) *sandboxnet.ProviderBlock {
	if !h.ProviderBlock {
		return nil
	}
	return sandboxnet.NewProviderBlock(h.ProviderHosts)
}

// macOOBFile returns the inherited trusted launcher channel on fd 3, or nil
// when none is open (the child then gets no fd 3).
func macOOBFile() *os.File {
	if _, err := unix.FcntlInt(3, unix.F_GETFD, 0); err != nil {
		return nil
	}
	return os.NewFile(3, "observer-oob")
}

// runMacChild runs argv as the PTY's foreground job and returns its exit
// code: the terminal's own signals (Ctrl-C, Ctrl-\) reach the child through
// the line discipline, so the helper ignores them; SIGTERM and SIGHUP sent
// to the helper are passed on.
func runMacChild(argv, env []string) int { return runMacChildUntil(argv, env, nil) }

// runMacChildUntil is runMacChild that also kills the child when end is
// closed (a failed read-back ends the run); a nil end never fires.
func runMacChildUntil(argv, env []string, end <-chan struct{}) int {
	if len(argv) == 0 {
		return helperFail("observer sandbox: nothing to run")
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: argv composed by this helper from the daemon's plan
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if oob := macOOBFile(); oob != nil {
		cmd.ExtraFiles = []*os.File{oob}
	}
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-fwd:
				_ = cmd.Process.Signal(s)
			case <-end:
				_ = cmd.Process.Kill()
				end = nil
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return exit.ExitCode()
	}
	return helperFail("observer sandbox: %v", err)
}

// helperFail prints a helper failure and returns the fail-closed exit code
// (the Linux helper's rule, sandbox_helpers_linux.go).
func helperFail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	return 125
}

// macPlaceholder is one placeholder the helper made, with the inode it made
// and the body it wrote (the ledger's proof, placeholderLedgerEntry).
type macPlaceholder struct {
	path    string
	dir     bool
	dev     uint64
	ino     uint64
	content []byte
}

// createMacPlaceholders makes each missing placeholder: a file with the
// planner's placeholder content, or an empty directory. An existing path is
// left as it is (and never removed). Directories come first (a file
// placeholder may sit in a directory placeholder), as on Linux. It returns
// what it made even on error,
// so the caller can clean up.
func createMacPlaceholders(files, dirs []string) ([]macPlaceholder, error) {
	var made []macPlaceholder
	record := func(p string, dir bool, content []byte) error {
		dev, ino, _, ok := placeholderInode(p)
		if !ok {
			return fmt.Errorf("stat placeholder %s", p)
		}
		made = append(made, macPlaceholder{path: p, dir: dir, dev: dev, ino: ino, content: content})
		return nil
	}
	for _, p := range dirs {
		if err := os.Mkdir(p, 0o755); err != nil { //nolint:gosec // G301: a placeholder dir mounted read-only
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return made, fmt.Errorf("create placeholder %s: %w", p, err)
		}
		if err := record(p, true, nil); err != nil {
			return made, err
		}
	}
	for _, p := range files {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644) //nolint:gosec // G304,G302: a protected path the daemon planned, mounted read-only
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return made, fmt.Errorf("create placeholder %s: %w", p, err)
		}
		content := sandbox.PlaceholderContent(p)
		_, werr := f.Write(content)
		_ = f.Close()
		if err := record(p, false, content); err != nil {
			return made, err
		}
		if werr != nil {
			return made, werr
		}
	}
	return made, nil
}

// removeMacPlaceholders removes each placeholder this helper made that is
// still untouched: the same inode, a file still holding its content, an
// empty directory (the ledger's rule, removeLedgerPlaceholders).
func removeMacPlaceholders(made []macPlaceholder) {
	entries := make([]placeholderLedgerEntry, 0, len(made))
	for _, m := range made {
		entries = append(entries, placeholderLedgerEntry{Path: m.path, Dir: m.dir, Dev: m.dev, Ino: m.ino, Content: m.content})
	}
	removeLedgerPlaceholders(entries)
}
