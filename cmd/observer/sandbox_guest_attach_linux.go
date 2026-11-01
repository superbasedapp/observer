//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/creack/pty"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// sandbox_guest_attach_linux.go is the hosted guest PTY's reattach (lane
// SBX-UPD, sandbox plan v2 section 5.5, Modal and Vercel): on a row whose
// guest helper owns the agent's PTY, the helper started with --keep holds
// the agent in its own session and serves a box-local, owner-only socket in
// the guest socket dir; when the home side is gone (its helper killed, the
// exec stream cut) the agent keeps running there, and `observer
// sandbox-guest attach --run <id> --secret-file <file>`, started by a new
// home helper, authenticates with the run's keeper key and reconnects the
// PTY: output from now on, resizes carried, and the agent's exit status. The
// output produced while no one was attached is not kept (the terminal says
// the scrollback is empty). Whether a vendor keeps the guest helper's process
// after its exec stream ends is a live check (register REM-13): where it
// does not, the agent ends with the stream, exactly as before.
//
// The keeper key (SBX-UPD audit finding 2): the keeper mints it at start,
// holds it in memory and sends it home inside the authenticated mux, where
// it is kept beside the run's own record; a re-adoption hands it to the
// attach verb the same way. The box record, which every process in the box
// can read, does not authenticate an attach, and while the home PTY stream
// is alive an attach is refused, so a tool call in the box cannot take the
// agent's terminal away from its owner or type into it. Each attach starts
// with a notice line. The Modal and Vercel rows hold the path dark
// (GuestReattach false) until REM-13 is checked live.

// guestAttachVerb is the verb's first argument after `sandbox-guest`.
const guestAttachVerb = "attach"

// guestKeepFlag asks --relay-stdio --pty to keep the agent for a reattach.
const guestKeepFlag = "--keep"

// guestAttachSocket is the keeper's socket for a run.
func guestAttachSocket(dir, runID string) string {
	return filepath.Join(dir, "pty-"+runID+".sock")
}

// The attach socket's frames: one type byte, a big-endian uint32 length,
// the payload.
const (
	attachFrameData   = 'd'
	attachFrameResize = 'r'
	attachFrameExit   = 'x'
	attachFrameMax    = 64 << 10
)

// The keeper's one-byte answer after the proof.
const (
	attachOK   = 1
	attachBusy = 2
)

// guestAttachNotice is the first line an attached terminal shows.
func guestAttachNotice(runID string) string {
	return "\r\n[observer: this terminal is attached to the kept agent of run " + runID + "; output from while no terminal was attached is not shown]\r\n"
}

// attachAuthLabel binds the proof to its purpose and run.
const attachAuthLabel = "observer-guest-attach-v1|"

// attachProof is the client's answer to the keeper's nonce.
func attachProof(secret []byte, runID string, nonce []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(attachAuthLabel + runID + "|"))
	m.Write(nonce)
	return m.Sum(nil)
}

func writeAttachFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > attachFrameMax {
		return errors.New("guest attach: frame too large")
	}
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload))) //nolint:gosec // G115: bounded above
	if _, err := w.Write(append(hdr, payload...)); err != nil {
		return err
	}
	return nil
}

func readAttachFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > attachFrameMax {
		return 0, nil, errors.New("guest attach: frame too large")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return 0, nil, err
	}
	return hdr[0], p, nil
}

// ptyKeeper holds the agent's PTY for whoever is attached: the mux's PTY
// stream first, then each authenticated attach. One client at a time; a
// new attach replaces an earlier attach, never the live home stream.
type ptyKeeper struct {
	master  io.ReadWriter
	setsize func(rows, cols uint16)
	runID   string
	secret  []byte

	mu     sync.Mutex
	client io.Writer
	gen    int
	// home: the home side's PTY stream is attached and its session alive;
	// an attach is refused meanwhile.
	home   bool
	exited bool
	code   int
	exitCh chan struct{}
}

func newPTYKeeper(master io.ReadWriter, setsize func(rows, cols uint16), runID string, secret []byte) *ptyKeeper {
	return &ptyKeeper{master: master, setsize: setsize, runID: runID, secret: secret, exitCh: make(chan struct{})}
}

// pump copies the agent's output to the attached client (dropped while
// none is), until the PTY ends.
func (k *ptyKeeper) pump() {
	buf := make([]byte, 32<<10)
	for {
		n, err := k.master.Read(buf)
		if n > 0 {
			k.mu.Lock()
			c := k.client
			k.mu.Unlock()
			if c != nil {
				if _, werr := c.Write(buf[:n]); werr != nil {
					k.detach(c)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// attachWriter makes w the client. An attach connection it replaces is
// closed, so only one client ever types into the agent.
func (k *ptyKeeper) attachWriter(w io.Writer) {
	k.mu.Lock()
	prev := k.client
	k.client = w
	k.gen++
	k.mu.Unlock()
	if pf, ok := prev.(*frameWriter); ok && prev != w {
		_ = pf.c.Close()
	}
}

// setHome records whether the home side's PTY stream is alive.
func (k *ptyKeeper) setHome(alive bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.home = alive
}

// detach drops w when it is still the client.
func (k *ptyKeeper) detach(w io.Writer) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.client == w {
		k.client = nil
	}
}

// exit records the agent's status and wakes every attached client.
func (k *ptyKeeper) exit(code int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.exited {
		return
	}
	k.exited, k.code = true, code
	close(k.exitCh)
}

// serveAttach accepts attach clients on ln until it closes.
func (k *ptyKeeper) serveAttach(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go k.serveOne(c)
	}
}

// frameWriter sends PTY output as data frames (one writer at a time).
type frameWriter struct {
	mu sync.Mutex
	c  net.Conn
}

func (f *frameWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for off := 0; off < len(p); off += attachFrameMax {
		end := min(off+attachFrameMax, len(p))
		if err := writeAttachFrame(f.c, attachFrameData, p[off:end]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// serveOne authenticates one client, then carries its input, its resizes,
// the agent's output and, at the end, the agent's exit status.
func (k *ptyKeeper) serveOne(c net.Conn) {
	defer c.Close()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if _, err := c.Write(nonce); err != nil {
		return
	}
	proof := make([]byte, sha256.Size)
	if _, err := io.ReadFull(c, proof); err != nil {
		return
	}
	k.mu.Lock()
	secret, busy := k.secret, k.home
	k.mu.Unlock()
	if len(secret) == 0 || !hmac.Equal(proof, attachProof(secret, k.runID, nonce)) {
		return // a wrong key is refused: the connection just closes
	}
	if busy {
		// The owner's terminal is still attached at home: no takeover.
		_, _ = c.Write([]byte{attachBusy})
		return
	}
	if _, err := c.Write([]byte{attachOK}); err != nil {
		return
	}
	fw := &frameWriter{c: c}
	if _, err := fw.Write([]byte(guestAttachNotice(k.runID))); err != nil {
		return
	}
	k.attachWriter(fw)
	defer k.detach(fw)
	left := make(chan struct{})
	defer close(left)
	go func() {
		select {
		case <-k.exitCh:
		case <-left:
			return
		}
		k.mu.Lock()
		code := k.code
		k.mu.Unlock()
		fw.mu.Lock()
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(int32(code))) //nolint:gosec // G115: an exit status
		_ = writeAttachFrame(c, attachFrameExit, b)
		fw.mu.Unlock()
		_ = c.Close()
	}()
	for {
		typ, p, err := readAttachFrame(c)
		if err != nil {
			return
		}
		switch typ {
		case attachFrameData:
			if _, err := k.master.Write(p); err != nil {
				return
			}
		case attachFrameResize:
			if len(p) == 4 && k.setsize != nil {
				k.setsize(binary.BigEndian.Uint16(p[:2]), binary.BigEndian.Uint16(p[2:]))
			}
		}
	}
}

// listenAttach serves the keeper on the run's owner-only socket.
func listenAttach(dir, runID string) (net.Listener, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := guestAttachSocket(dir, runID)
	_ = os.Remove(p)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(p, 0o600)
	return ln, nil
}

// attachClient is one authenticated attach connection.
type attachClient struct {
	c  net.Conn
	mu sync.Mutex
}

// armKeeper mints the keeper-only attach key, sends it home through send
// (Guest.SendKeeperKey, inside the authenticated mux) and serves the attach
// socket in dir. The key lives only in this process and beside the home
// side's run record, so the box record no longer authenticates an attach
// (SBX-UPD audit finding 2). A home side that takes no key gets no socket:
// nothing can re-attach to the run.
func armKeeper(k *ptyKeeper, send func([]byte) error, dir string) (net.Listener, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := send(key); err != nil {
		return nil, err
	}
	k.mu.Lock()
	k.secret = key
	k.mu.Unlock()
	ln, err := listenAttach(dir, k.runID)
	if err != nil {
		return nil, err
	}
	go k.serveAttach(ln)
	return ln, nil
}

// dialAttach connects to the keeper and authenticates.
func dialAttach(ctx context.Context, path, runID string, secret []byte) (*attachClient, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("the agent's PTY keeper is not running (%w): the agent ended, or the provider stopped it when the stream was cut", err)
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(c, nonce); err != nil {
		_ = c.Close()
		return nil, err
	}
	if _, err := c.Write(attachProof(secret, runID, nonce)); err != nil {
		_ = c.Close()
		return nil, err
	}
	ok := make([]byte, 1)
	if _, err := io.ReadFull(c, ok); err != nil || ok[0] != attachOK {
		_ = c.Close()
		if err == nil && ok[0] == attachBusy {
			return nil, errors.New("the agent's terminal is still attached at home, so a takeover is refused")
		}
		return nil, errors.New("the agent's PTY keeper refused the keeper key")
	}
	return &attachClient{c: c}, nil
}

// input sends the user's keys.
func (a *attachClient) input(p []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return writeAttachFrame(a.c, attachFrameData, p)
}

// resize sends a size.
func (a *attachClient) resize(rows, cols uint16) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[:2], rows)
	binary.BigEndian.PutUint16(b[2:], cols)
	a.mu.Lock()
	defer a.mu.Unlock()
	return writeAttachFrame(a.c, attachFrameResize, b)
}

// output copies the agent's output to w until the agent exits (its status,
// ok=true) or the keeper goes (ok=false).
func (a *attachClient) output(w io.Writer) (code int, ok bool) {
	for {
		typ, p, err := readAttachFrame(a.c)
		if err != nil {
			return 0, false
		}
		switch typ {
		case attachFrameData:
			if _, err := w.Write(p); err != nil {
				return 0, false
			}
		case attachFrameExit:
			if len(p) == 4 {
				return int(int32(binary.BigEndian.Uint32(p))), true //nolint:gosec // G115: an exit status
			}
			return 1, true
		}
	}
}

// guestAttachArgs are the attach verb's flags.
type guestAttachArgs struct {
	runID, secretFile string
}

func parseGuestAttachArgs(args []string) (guestAttachArgs, error) {
	set := flag.NewFlagSet("sandbox-guest attach", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var a guestAttachArgs
	set.StringVar(&a.runID, "run", "", "")
	set.StringVar(&a.secretFile, "secret-file", "", "")
	if err := set.Parse(args); err != nil {
		return a, err
	}
	if !sandboxrelay.ValidRunID(a.runID) || !filepath.IsAbs(a.secretFile) || set.NArg() != 0 {
		return a, errors.New("--run and an absolute --secret-file are required")
	}
	return a, nil
}

// runGuestAttach is the attach verb: the mux over stdio to the new home
// helper, the PTY stream bridged to the keeper.
func runGuestAttach(args []string) int {
	a, err := parseGuestAttachArgs(args)
	if err != nil {
		return helperFail("observer sandbox-guest attach: %v", err)
	}
	secret, err := readRelaySecret(a.secretFile)
	if err != nil {
		return helperFail("observer sandbox-guest attach: %v", err)
	}
	signal.Ignore(syscall.SIGPIPE)
	conn := relaymux.NewDeadlineConn(relaymux.NewLineReader(os.Stdin), relaymux.NewLineWriter(os.Stdout), func() error { return os.Stdin.Close() })
	g, err := relaymux.DialGuest(context.Background(), conn, relaymux.Options{RunID: a.runID, Secret: secret})
	if err != nil {
		return helperFail("observer sandbox-guest attach: %v", err)
	}
	defer g.Close()
	term := g.PTY()
	if term == nil {
		return helperFail("observer sandbox-guest attach: the home side opened no PTY stream")
	}
	key := g.Hello().AttachKey
	if len(key) == 0 {
		return helperFail("observer sandbox-guest attach: the home side sent no keeper key")
	}
	ac, err := dialAttach(context.Background(), guestAttachSocket(sandbox.GuestSocketDir, a.runID), a.runID, key)
	if err != nil {
		return helperFail("observer sandbox-guest attach: %v", err)
	}
	defer ac.c.Close()
	return bridgeAttach(ac, term, g.Resizes(), g.Done())
}

// bridgeAttach carries the terminal to the keeper and back, and returns the
// agent's exit status (1 when the keeper went without one).
func bridgeAttach(ac *attachClient, term io.ReadWriter, resizes <-chan relaymux.Size, done <-chan struct{}) int {
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := term.Read(buf)
			if n > 0 && ac.input(bytes.Clone(buf[:n])) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case sz, ok := <-resizes:
				if !ok {
					return
				}
				_ = ac.resize(sz.Rows, sz.Cols)
			case <-done:
				return
			}
		}
	}()
	code, ok := ac.output(term)
	if cw, isCW := term.(interface{ CloseWrite() error }); isCW {
		_ = cw.CloseWrite()
	}
	if !ok {
		return 1
	}
	return code
}

// guestKeepPTY is --pty --keep: the agent's PTY goes to the mux's PTY
// stream first and to each authenticated attach after it; the session
// ending does not end the agent. It returns the agent's exit status.
func guestKeepPTY(g *relaymux.Guest, a relayStdioArgs, cmd *exec.Cmd, master *os.File) int {
	var mu sync.Mutex
	closed := false
	setsize := func(rows, cols uint16) {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			_ = pty.Setsize(master, &pty.Winsize{Rows: rows, Cols: cols})
		}
	}
	defer func() {
		mu.Lock()
		closed = true
		_ = master.Close()
		mu.Unlock()
	}()
	k := newPTYKeeper(master, setsize, a.runID, nil)
	k.setHome(true)
	if ln, err := armKeeper(k, g.SendKeeperKey, sandbox.GuestSocketDir); err == nil {
		defer ln.Close()
	} else {
		// The agent still runs; nothing can re-attach to it.
		g.Log("the agent's PTY keeper serves no attach socket, so the run cannot be re-attached: " + err.Error())
	}
	term := g.PTY()
	k.attachWriter(term)
	go func() { _, _ = io.Copy(master, term) }()
	go func() {
		for {
			select {
			case sz, ok := <-g.Resizes():
				if !ok {
					return
				}
				setsize(sz.Rows, sz.Cols)
			case <-g.Done():
				k.detach(term)
				k.setHome(false)
				return
			}
		}
	}()
	go k.pump()
	code := guestWaitCode(cmd.Wait())
	k.exit(code)
	if cw, ok := term.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	return code
}

// guestWaitCode is a finished command's exit status.
func guestWaitCode(err error) int {
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
	return 1
}
