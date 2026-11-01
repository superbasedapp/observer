//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// sandbox_guest_relaystdio_linux.go is the `--relay-stdio` mode of `observer
// sandbox-guest` (sandbox plan v2 section 5.7, lane SBX-P7): inside a hosted
// box, the home side starts it as a non-PTY exec and speaks the relay mux
// (internal/sandboxremote/relaymux) over its stdin and stdout. It never
// opens a network connection: everything it serves is a unix socket in the
// box's guest socket dir, and everything it carries goes home over its own
// stdio.
//
// Relay mode (no --pty): it writes the run's box record into the guest
// socket dir (so the in-box hook finds its relay exactly as in a local box)
// and listens on relay.sock and, when the tier allows it, proxy.sock there;
// each accepted connection becomes one mux stream home. The agent's own
// guest forwarder (`observer sandbox-guest --proxy-port ...`, unchanged)
// forwards its loopback port to that proxy.sock.
//
// PTY mode (--pty, for a vendor with no documented resize): it owns the
// box PTY, starts the command after "--" on it, bridges it to the mux's PTY
// stream and applies the sizes the home side sends; its exit status is the
// command's.

// relayStdioFlag selects the mode (runSandboxGuest dispatches on it).
const relayStdioFlag = "--relay-stdio"

// relayStdioArgs are the mode's flags.
type relayStdioArgs struct {
	runID      string
	secretFile string
	ptyMode    bool
	// keep: the PTY mode holds the agent for a reattach when the home side
	// goes (sandbox_guest_attach_linux.go).
	keep bool
	// rekey: a re-adopted run's relay replaces the box record (new keys).
	rekey      bool
	rows, cols uint16
	command    []string
}

func parseRelayStdioArgs(args []string) (relayStdioArgs, error) {
	set := flag.NewFlagSet("sandbox-guest --relay-stdio", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var a relayStdioArgs
	var rows, cols uint
	set.StringVar(&a.runID, "run", "", "")
	set.StringVar(&a.secretFile, "secret-file", "", "")
	set.BoolVar(&a.ptyMode, "pty", false, "")
	set.BoolVar(&a.keep, "keep", false, "")
	set.BoolVar(&a.rekey, "rekey", false, "")
	set.UintVar(&rows, "rows", 24, "")
	set.UintVar(&cols, "cols", 80, "")
	if err := set.Parse(args); err != nil {
		return a, err
	}
	if rows == 0 || rows > 1000 || cols == 0 || cols > 1000 {
		return a, errors.New("rows and cols must be 1 to 1000")
	}
	a.rows, a.cols = uint16(rows), uint16(cols) //nolint:gosec // G115: bounded above
	a.command = set.Args()
	if a.runID == "" || !filepath.IsAbs(a.secretFile) {
		return a, errors.New("--run and an absolute --secret-file are required")
	}
	if a.ptyMode != (len(a.command) > 0) {
		return a, errors.New("--pty needs a command after --, and only --pty takes one")
	}
	if a.keep && !a.ptyMode {
		return a, errors.New("--keep applies to --pty only")
	}
	return a, nil
}

// readRelaySecret reads the per-run mux secret (an owner-only regular file
// the home side uploaded) and removes it.
func readRelaySecret(p string) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || fi.Size() > 4096 {
		return nil, fmt.Errorf("the secret file %s is not an owner-only regular file", p)
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the path the home side passed, lstat-checked above
	_ = os.Remove(p)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

// runGuestRelayStdio is the mode's entry point.
func runGuestRelayStdio(args []string) int {
	a, err := parseRelayStdioArgs(args)
	if err != nil {
		return helperFail("observer sandbox --relay-stdio: %v", err)
	}
	secret, err := readRelaySecret(a.secretFile)
	if err != nil {
		return helperFail("observer sandbox --relay-stdio: %v", err)
	}
	signal.Ignore(syscall.SIGPIPE)
	conn := relaymux.NewDeadlineConn(relaymux.NewLineReader(os.Stdin), relaymux.NewLineWriter(os.Stdout), func() error { return os.Stdin.Close() })
	g, err := relaymux.DialGuest(context.Background(), conn, relaymux.Options{RunID: a.runID, Secret: secret})
	if err != nil {
		return helperFail("observer sandbox --relay-stdio: %v", err)
	}
	defer g.Close()
	if a.ptyMode {
		return guestRunPTY(g, a)
	}
	stop, err := guestServeSockets(g, sandbox.GuestSocketDir, a.rekey)
	if err != nil {
		return helperFail("observer sandbox --relay-stdio: %v", err)
	}
	defer stop()
	// The record is written and the sockets listen: tell the home side, which
	// starts the agent only after this (live run 2026-10-23, finding F2).
	if err := g.Ready(); err != nil {
		return helperFail("observer sandbox --relay-stdio: %v", err)
	}
	<-g.Done()
	return 0
}

// guestSocketNames maps a mux kind to its socket in the guest socket dir.
var guestSocketNames = map[string]string{
	relaymux.KindRelay: sandboxrelayd.RelaySocketName,
	relaymux.KindProxy: sandbox.ProxySocketName,
	// Offered by the Apple container row's tunnel only.
	relaymux.KindGateway: sandbox.GatewaySocketName,
}

// guestSocketOwner is who the guest socket dir, its record and its sockets
// belong to when the server is not that user (the Apple container init
// serves them as the container's root for the agent's uid; the record's
// reader requires a private dir it owns).
type guestSocketOwner struct{ uid, gid int }

// guestServeSockets writes the box record and serves one unix socket per
// kind the home side allows; each connection is bridged to a mux stream.
func guestServeSockets(g *relaymux.Guest, dir string, rekey bool) (func(), error) {
	return guestServeSocketsFor(func() *relaymux.Guest { return g }, g.Hello(), dir, nil, rekey)
}

// guestServeSocketsFor is guestServeSockets over the current session cur
// (a re-opened session replaces it) for the hello's kinds and record. With
// an owner, the dir is made fresh (whatever was at the path removed, never
// followed) and the dir, record and sockets are handed to the owner. With
// rekey, a re-adopted run's relay replaces the box record (new keys).
func guestServeSocketsFor(cur func() *relaymux.Guest, hello relaymux.Hello, dir string, owner *guestSocketOwner, rekey bool) (func(), error) {
	if owner != nil {
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	var owned []string
	if rec := hello.Record; len(rec) > 0 {
		p := filepath.Join(dir, sandboxrelayd.BoxRecordName)
		write := writeGuestRecord
		if rekey {
			write = replaceGuestRecord
		}
		if err := write(p, rec); err != nil {
			return nil, err
		}
		owned = append(owned, p)
	}
	var lns []net.Listener
	stop := func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	}
	for _, kind := range hello.Kinds {
		name, ok := guestSocketNames[kind]
		if !ok {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSocket != 0 {
			// A socket left by an earlier relay process of this run (the home
			// side re-opened the relay after a drop and killed the old one).
			_ = os.Remove(p)
		}
		ln, err := net.Listen("unix", p)
		if err != nil {
			stop()
			return nil, err
		}
		_ = os.Chmod(p, 0o600)
		lns = append(lns, ln)
		owned = append(owned, p)
		go guestAccept(cur, ln, kind)
	}
	if owner != nil {
		for _, p := range append(owned, dir) {
			if err := os.Lchown(p, owner.uid, owner.gid); err != nil {
				stop()
				return nil, err
			}
		}
	}
	return stop, nil
}

// writeGuestRecord writes the box record O_EXCL 0600; an identical record
// already there (a re-opened relay) is kept.
func writeGuestRecord(p string, rec []byte) error {
	if old, err := os.ReadFile(p); err == nil { //nolint:gosec // G304: the fixed record path in the box's socket dir
		if bytes.Equal(old, rec) {
			return nil
		}
		return fmt.Errorf("a different box record is already at %s", p)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(rec)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// guestAccept bridges each connection to a new stream of the current mux
// session.
func guestAccept(cur func() *relaymux.Guest, ln net.Listener, kind string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			g := cur()
			if g == nil {
				return
			}
			s, err := g.Connect(context.Background(), kind)
			if err != nil {
				// The box connection closes without a stream; the reason
				// goes to the run's kept relay log at home (lane SBX-UPD,
				// finding H1), and the box's redial tries again.
				g.Log("closed a " + kind + " connection from the box without a stream home: " + err.Error())
				return
			}
			defer s.Close()
			relayBridge(c, s)
		}()
	}
}

// relayBridge copies both ways until both directions end, half-closing each
// side's write when the other's read ends.
func relayBridge(a, b io.ReadWriter) {
	var wg sync.WaitGroup
	cp := func(dst, src io.ReadWriter) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// guestRunPTY owns the box PTY: it runs the command on it, bridges it to the
// mux's PTY stream and applies the home side's sizes.
func guestRunPTY(g *relaymux.Guest, a relayStdioArgs) int {
	term := g.PTY()
	if term == nil {
		return helperFail("observer sandbox --relay-stdio: the home side opened no PTY stream")
	}
	//nolint:gosec // G204: the planned inner launch the home side composed
	cmd := exec.Command(a.command[0], a.command[1:]...)
	cmd.Env = os.Environ()
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: a.rows, Cols: a.cols})
	if err != nil {
		return helperFail("observer sandbox --relay-stdio: start %s: %v", filepath.Base(a.command[0]), err)
	}
	if a.keep {
		return guestKeepPTY(g, a, cmd, master)
	}
	// A resize may arrive while the PTY closes: both hold mu, so a resize
	// never touches a closed descriptor.
	var mu sync.Mutex
	closed := false
	defer func() {
		mu.Lock()
		closed = true
		_ = master.Close()
		mu.Unlock()
	}()
	go func() {
		for sz := range g.Resizes() {
			mu.Lock()
			if !closed {
				_ = pty.Setsize(master, &pty.Winsize{Rows: sz.Rows, Cols: sz.Cols})
			}
			mu.Unlock()
		}
	}()
	go func() { _, _ = io.Copy(master, term) }()
	out := make(chan struct{})
	go func() {
		_, _ = io.Copy(term, master)
		close(out)
	}()
	go func() {
		// The session ending (the home side gone) ends the command, as a
		// lost terminal hangs up a local one.
		<-g.Done()
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGHUP)
		}
	}()
	err = cmd.Wait()
	// Every byte of output reaches the home side before the session ends:
	// the copy ends when the PTY has nothing left, the half close tells the
	// home side, and the home side closes the session.
	select {
	case <-out:
	case <-time.After(2 * time.Second):
	}
	if cw, ok := term.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	fmt.Fprintln(os.Stderr, "observer sandbox --relay-stdio: "+strconv.Quote(err.Error()))
	return 1
}

// guestRekeyFlag selects replaceGuestRecord (a re-adopted run's relay).
const guestRekeyFlag = "--rekey"

// replaceGuestRecord replaces the box record with rec atomically (a fresh
// 0600 file renamed over it): a re-adopted run's relay carries new keys
// (lane SBX-UPD), so the old record must go.
func replaceGuestRecord(p string, rec []byte) error {
	tmp := p + ".rekey"
	_ = os.Remove(tmp)
	if err := writeGuestRecord(tmp, rec); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
