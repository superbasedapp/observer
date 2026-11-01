//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// fakeGuestPTY is a fake guest PTY for the keeper: agent is the agent's end of
// the "PTY", sizes records each resize.
type fakeGuestPTY struct {
	agent  net.Conn
	master net.Conn
	mu     sync.Mutex
	sizes  [][2]uint16
}

func newFakeGuestPTY() *fakeGuestPTY {
	a, m := net.Pipe()
	return &fakeGuestPTY{agent: a, master: m}
}

func (f *fakeGuestPTY) setsize(r, c uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes = append(f.sizes, [2]uint16{r, c})
}

func (f *fakeGuestPTY) lastSize() [2]uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sizes) == 0 {
		return [2]uint16{}
	}
	return f.sizes[len(f.sizes)-1]
}

// startKeeper serves a keeper for run-a on a temp socket dir.
func startKeeper(t *testing.T, secret []byte) (*fakeGuestPTY, *ptyKeeper, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ga")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	box := newFakeGuestPTY()
	k := newPTYKeeper(box.master, box.setsize, "run-a", secret)
	ln, err := listenAttach(dir, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = box.agent.Close() })
	go k.serveAttach(ln)
	go k.pump()
	return box, k, guestAttachSocket(dir, "run-a")
}

// readSome reads until want appears or the deadline.
func readSome(t *testing.T, r io.Reader, want string) {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		var b bytes.Buffer
		buf := make([]byte, 256)
		for !bytes.Contains(b.Bytes(), []byte(want)) {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		got <- b.Bytes()
	}()
	select {
	case b := <-got:
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("read %q, want %q", b, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

// TestGuestAttachAgainstAFakeBox (lane SBX-UPD, reattach): an attach with
// the keeper's key reaches the agent both ways and carries a resize; a
// wrong secret is refused; after the first client goes a second attach
// resumes the PTY; the agent's exit status reaches the attached client.
func TestGuestAttachAgainstAFakeBox(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	box, k, sock := startKeeper(t, secret)
	ctx := context.Background()

	if _, err := dialAttach(ctx, sock, "run-a", bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("a wrong keeper key was accepted")
	}
	if _, err := dialAttach(ctx, sock, "run-b", secret); err == nil {
		t.Fatal("a proof for another run was accepted")
	}

	first, err := dialAttach(ctx, sock, "run-a", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.input([]byte("ls\r")); err != nil {
		t.Fatal(err)
	}
	readSome(t, box.agent, "ls\r")
	if err := first.resize(40, 120); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for box.lastSize() != [2]uint16{40, 120} && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if box.lastSize() != [2]uint16{40, 120} {
		t.Fatalf("resize = %v", box.lastSize())
	}
	pr, pw := io.Pipe()
	go func() { first.output(pw) }()
	go func() { _, _ = box.agent.Write([]byte("one\n")) }()
	readSome(t, pr, "one")
	_ = first.c.Close()

	second, err := dialAttach(ctx, sock, "run-a", secret)
	if err != nil {
		t.Fatalf("the second attach: %v", err)
	}
	pr2, pw2 := io.Pipe()
	codeCh := make(chan [2]int, 1)
	go func() {
		c, ok := second.output(pw2)
		_ = pw2.Close()
		b := 0
		if ok {
			b = 1
		}
		codeCh <- [2]int{c, b}
	}()
	go func() { _, _ = box.agent.Write([]byte("two\n")) }()
	readSome(t, pr2, "two")
	go func() { _, _ = io.Copy(io.Discard, pr2) }()
	k.exit(7)
	select {
	case got := <-codeCh:
		if got != [2]int{7, 1} {
			t.Fatalf("exit = %v, want 7 delivered", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the exit status never arrived")
	}
}

// TestGuestAttachArgs and the socket's owner-only mode.
func TestGuestAttachArgs(t *testing.T) {
	if _, err := parseGuestAttachArgs([]string{"--run", "run-a", "--secret-file", "/r/s"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"--run", "../x", "--secret-file", "/r/s"}, {"--run", "run-a", "--secret-file", "rel"}, {"--run", "run-a", "--secret-file", "/r/s", "extra"}} {
		if _, err := parseGuestAttachArgs(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	dir := t.TempDir()
	ln, err := listenAttach(filepath.Join(dir, "g"), "run-a")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fi, err := os.Stat(guestAttachSocket(filepath.Join(dir, "g"), "run-a"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", fi.Mode().Perm(), err)
	}
	if _, err := parseRelayStdioArgs([]string{"--run", "r", "--secret-file", "/s", "--keep"}); err == nil {
		t.Fatal("--keep without --pty was accepted")
	}
	if a, err := parseRelayStdioArgs([]string{"--run", "r", "--secret-file", "/s", "--pty", "--keep", "--", "sh"}); err != nil || !a.keep {
		t.Fatalf("--pty --keep: %+v %v", a, err)
	}
}

// TestGuestAttachKeeperKey (SBX-UPD audit finding 2): the keeper mints its own
// key and sends it home; the box record's secret, which every process in the
// box can read, no longer authenticates an attach; while the home PTY stream
// is alive an attach with the right key is refused (no takeover); once the
// home stream is gone the right key attaches and the terminal starts with
// the notice; a home side that takes no key leaves no socket at all.
func TestGuestAttachKeeperKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "gk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(dir, rec); err != nil {
		t.Fatal(err)
	}
	box := newFakeGuestPTY()
	t.Cleanup(func() { _ = box.agent.Close() })
	k := newPTYKeeper(box.master, box.setsize, "run-a", nil)
	k.setHome(true)
	var sent []byte
	ln, err := armKeeper(k, func(key []byte) error { sent = bytes.Clone(key); return nil }, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go k.pump()
	if len(sent) != 32 || bytes.Equal(sent, rec.BoxSecret) {
		t.Fatalf("the keeper key %x is not its own", sent)
	}
	ctx := context.Background()
	sock := guestAttachSocket(dir, "run-a")
	if _, err := dialAttach(ctx, sock, "run-a", rec.BoxSecret); err == nil {
		t.Fatal("the box record's secret authenticated an attach")
	}
	if _, err := dialAttach(ctx, sock, "run-a", sent); err == nil || !strings.Contains(err.Error(), "takeover is refused") {
		t.Fatalf("an attach while the home stream is alive = %v, want refused", err)
	}
	k.setHome(false)
	ac, err := dialAttach(ctx, sock, "run-a", sent)
	if err != nil {
		t.Fatalf("the keeper key after the home stream went: %v", err)
	}
	defer ac.c.Close()
	pr, pw := io.Pipe()
	go func() { ac.output(pw) }()
	readSome(t, pr, "attached to the kept agent of run run-a")

	empty := t.TempDir()
	k2 := newPTYKeeper(box.master, box.setsize, "run-b", nil)
	if _, err := armKeeper(k2, func([]byte) error { return errors.New("the home side keeps no keeper key") }, empty); err == nil {
		t.Fatal("a keeper whose key cannot go home armed a socket")
	}
	if _, err := os.Lstat(guestAttachSocket(empty, "run-b")); err == nil {
		t.Fatal("a keeper with no key home serves a socket")
	}
}
