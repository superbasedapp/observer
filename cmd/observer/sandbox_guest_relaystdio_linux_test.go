//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

var relayTestSecret = bytes.Repeat([]byte{3}, 32)

func relayTestStack(c net.Conn) *relaymux.DeadlineConn {
	return relaymux.NewDeadlineConn(relaymux.NewLineReader(c), relaymux.NewLineWriter(c), c.Close)
}

// relayTestPair starts a home side over a pipe and dials the box side.
func relayTestPair(t *testing.T, kinds map[string]bool, pty io.ReadWriteCloser, record []byte, dial func(context.Context, string) (io.ReadWriteCloser, error)) (*relaymux.Host, *relaymux.Guest) {
	t.Helper()
	hc, gc := net.Pipe()
	hch := make(chan *relaymux.Host, 1)
	go func() {
		h, err := relaymux.ServeHost(context.Background(), relayTestStack(hc), relaymux.HostOptions{
			Options: relaymux.Options{RunID: "run-x", Secret: relayTestSecret}, Rand: rand.Reader,
			Kinds: kinds, Dial: dial, PTY: pty, Record: record,
		})
		if err != nil {
			t.Error(err)
		}
		hch <- h
	}()
	g, err := relaymux.DialGuest(context.Background(), relayTestStack(gc), relaymux.Options{RunID: "run-x", Secret: relayTestSecret})
	if err != nil {
		t.Fatal(err)
	}
	h := <-hch
	t.Cleanup(func() { g.Close(); h.Close() })
	return h, g
}

func TestRelayStdioArgs(t *testing.T) {
	cases := []struct {
		args []string
		ok   bool
	}{
		{[]string{"--run", "r1", "--secret-file", "/tmp/s"}, true},
		{[]string{"--run", "r1", "--secret-file", "/tmp/s", "--pty", "--", "sh"}, true},
		{[]string{"--run", "r1", "--secret-file", "rel"}, false},
		{[]string{"--run", "r1", "--secret-file", "/tmp/s", "--", "sh"}, false},
		{[]string{"--run", "r1", "--secret-file", "/tmp/s", "--pty"}, false},
		{[]string{"--run", "r1", "--secret-file", "/tmp/s", "--rows", "0"}, false},
	}
	for _, c := range cases {
		if _, err := parseRelayStdioArgs(c.args); (err == nil) != c.ok {
			t.Errorf("%v: %v", c.args, err)
		}
	}
}

func TestRelaySecretFileRules(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	_ = os.WriteFile(p, []byte("secret\n"), 0o644)
	if _, err := readRelaySecret(p); err == nil {
		t.Error("a world-readable secret file accepted")
	}
	_ = os.Remove(p)
	_ = os.WriteFile(p, []byte("secret\n"), 0o600)
	if b, err := readRelaySecret(p); err != nil || string(b) != "secret" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the secret file outlived its read")
	}
}

// TestRelayStdioServesSockets: the box record lands in the guest socket
// dir, and the relay and proxy sockets there reach the home side's own.
func TestRelayStdioServesSockets(t *testing.T) {
	home := map[string][]byte{}
	dial := func(_ context.Context, kind string) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 5)
			_, _ = io.ReadFull(b, buf)
			home[kind] = buf
			_, _ = b.Write([]byte("ok:" + kind))
			_ = b.Close()
		}()
		return a, nil
	}
	_, g := relayTestPair(t, map[string]bool{relaymux.KindRelay: true, relaymux.KindProxy: true}, nil, []byte(`{"v":1}`), dial)
	dir := filepath.Join(t.TempDir(), "net")
	stop, err := guestServeSockets(g, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if b, err := os.ReadFile(filepath.Join(dir, sandboxrelayd.BoxRecordName)); err != nil || string(b) != `{"v":1}` {
		t.Fatalf("record %q %v", b, err)
	}
	for _, name := range []string{sandboxrelayd.RelaySocketName, "proxy.sock"} {
		c, err := net.Dial("unix", filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("hello"))
		reply, _ := io.ReadAll(c)
		_ = c.Close()
		if !strings.HasPrefix(string(reply), "ok:") {
			t.Errorf("%s: reply %q", name, reply)
		}
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode %v", fi.Mode())
	}
}

// TestRelayStdioPTY: the guest helper owns the box PTY at the size asked,
// its output reaches the home terminal, and a resize applies.
func TestRelayStdioPTY(t *testing.T) {
	term, peer := net.Pipe()
	noDial := func(context.Context, string) (io.ReadWriteCloser, error) { return nil, io.EOF }
	h, g := relayTestPair(t, map[string]bool{relaymux.KindRelay: true}, peer, nil, noDial)
	code := make(chan int, 1)
	go func() {
		code <- guestRunPTY(g, relayStdioArgs{rows: 30, cols: 100, command: []string{"sh", "-c", "stty size; read x; stty size; exit 7"}})
	}()
	buf := make([]byte, 0, 256)
	read := func(want string) {
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(string(buf), want) {
			if time.Now().After(deadline) {
				t.Fatalf("no %q in %q", want, buf)
			}
			_ = term.SetReadDeadline(time.Now().Add(time.Second))
			tmp := make([]byte, 128)
			n, _ := term.Read(tmp)
			buf = append(buf, tmp[:n]...)
		}
	}
	read("30 100")
	if err := h.Resize(50, 160); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	_, _ = term.Write([]byte("go\r"))
	read("50 160")
	select {
	case c := <-code:
		if c != 7 {
			t.Errorf("exit %d", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit")
	}
}
