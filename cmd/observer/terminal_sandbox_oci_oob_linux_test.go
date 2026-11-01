//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/termoob"
)

// ociOOBDir is a socket directory short enough for sun_path.
func ociOOBDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "oob")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// ociReadFrames reads every frame the daemon side receives until EOF.
func ociReadFrames(t *testing.T, r io.Reader, auth string) []termoob.Frame {
	t.Helper()
	dec := termoob.NewDecoder(r, auth)
	var out []termoob.Frame
	for {
		f, err := dec.Read()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("daemon side: %v", err)
		}
		out = append(out, f)
	}
}

// TestOCIOOBForwardsOnlyLoweredSessions: the helper authenticates the
// trusted channel with the daemon's own secret and correlation token and
// reports the container's real exit status; from the box only a session
// announce passes, lowered to discovered; a box Hello naming another run, a
// box lifecycle claim, an unknown id shape and a stream with the wrong
// token are dropped.
func TestOCIOOBForwardsOnlyLoweredSessions(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	dir := ociOOBDir(t)
	oob, boxEnv := ociStartOOB(w, termoob.Hello{AuthToken: "daemon-secret", CorrelationToken: "corr-host", Tool: "claude-code", PID: 7}, dir)
	if oob == nil || len(boxEnv) != 2 || boxEnv[0] != envOOBBoxSock+"="+sandbox.GuestSocketDir+"/"+ociOOBSockName {
		t.Fatalf("box env %v", boxEnv)
	}
	box := strings.TrimPrefix(boxEnv[1], envOOBBoxAuth+"=")
	if box == "" || box == "daemon-secret" {
		t.Fatalf("the box token %q must be its own", box)
	}
	frames := make(chan []termoob.Frame, 1)
	go func() { frames <- ociReadFrames(t, r, "daemon-secret") }()

	dial := func() net.Conn {
		c, err := net.Dial("unix", filepath.Join(dir, ociOOBSockName))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// A stream with the wrong token: nothing of it passes.
	bad := dial()
	enc := termoob.NewEncoder(bad)
	_ = enc.WriteHello(termoob.Hello{AuthToken: "daemon-secret"})
	_ = enc.WriteSession(termoob.Session{SessionID: "forged-1"})
	_ = bad.Close()
	// The box's own stream.
	c := dial()
	enc = termoob.NewEncoder(c)
	_ = enc.WriteHello(termoob.Hello{AuthToken: box, CorrelationToken: "corr-of-another-run", Tool: "other"})
	exit0 := 0
	_ = enc.WriteLifecycle(termoob.Lifecycle{Phase: termoob.PhaseToolExecEnd, ExitCode: &exit0})
	_ = enc.WriteSession(termoob.Session{SessionID: "0b7e2c1a-1111-2222-3333-444455556666"})
	_ = enc.WriteSession(termoob.Session{SessionID: "bad id with spaces\x1b"})
	_ = c.Close()
	time.Sleep(200 * time.Millisecond)
	oob.end(42)
	var got []termoob.Frame
	select {
	case got = <-frames:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon side never saw the channel close")
	}
	if len(got) != 4 {
		t.Fatalf("frames %+v", got)
	}
	if h := got[0].Hello; h == nil || h.CorrelationToken != "corr-host" || h.Tool != "claude-code" {
		t.Fatalf("the trusted hello %+v", got[0])
	}
	if l := got[1].Lifecycle; l == nil || l.Phase != termoob.PhaseLauncherStarted {
		t.Fatalf("start %+v", got[1])
	}
	if s := got[2].Session; s == nil || s.SessionID != "0b7e2c1a-1111-2222-3333-444455556666" || s.Source != termoob.SessionSourceDiscovered {
		t.Fatalf("the box's session is not lowered: %+v", got[2])
	}
	if l := got[3].Lifecycle; l == nil || l.Phase != termoob.PhaseToolExecEnd || l.ExitCode == nil || *l.ExitCode != 42 {
		t.Fatalf("the end must be the container's own status: %+v", got[3])
	}
	oob.end(1) // once
	var none *ociOOB
	none.end(1)
}

// TestOCIOpenOOBNeedsTheTrustedChannel: a helper with no OOB descriptor (a
// CLI launch) or a descriptor that is not a pipe opens nothing.
func TestOCIOpenOOBNeedsTheTrustedChannel(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if o, e := ociOpenOOB(env(nil), t.TempDir()); o != nil || e != nil {
		t.Fatal("opened with no channel")
	}
	f, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if o, _ := ociOpenOOB(env(map[string]string{envOOBFD: "99999", envOOBAuth: "x"}), t.TempDir()); o != nil {
		t.Fatal("opened an fd that is not open")
	}
}

// TestOCIInitOOBHandsTheSocketToTheLauncher: with a box socket the init
// connects, the guest network command's forwards run in the init, and the
// launcher gets the connection as fd 3 with the box token; the box
// variables never reach it. With no socket the launch is as planned.
func TestOCIInitOOBHandsTheSocketToTheLauncher(t *testing.T) {
	dir := ociOOBDir(t)
	sock := filepath.Join(dir, "oob.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	gw := filepath.Join(dir, "gw.sock")
	gl, err := net.Listen("unix", gw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gl.Close() }()
	argv := []string{"/usr/bin/observer", sandbox.GuestVerb, "--gateway-port", "39911", "--gateway-sock", gw, "--", "/usr/bin/observer", "claude"}
	environ := []string{"TERM=xterm", envOOBBoxSock + "=" + sock, envOOBBoxAuth + "=boxtoken", envOOBFD + "=3", envOOBAuth + "=host-secret"}
	run, env, extra, stop := ociInitOOB(argv, environ)
	defer stop()
	if !slices.Equal(run, []string{"/usr/bin/observer", "claude"}) || len(extra) != 1 {
		t.Fatalf("run %v extra %d", run, len(extra))
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, envOOBBoxSock+"=") || strings.HasPrefix(kv, envOOBBoxAuth+"=") || kv == envOOBAuth+"=host-secret" {
			t.Fatalf("the launcher sees %s", kv)
		}
	}
	if !slices.Contains(env, envOOBFD+"=3") || !slices.Contains(env, envOOBAuth+"=boxtoken") || !slices.Contains(env, "HTTPS_PROXY=http://127.0.0.1:39911") {
		t.Fatalf("env %v", env)
	}
	if c, err := net.Dial("tcp", "127.0.0.1:39911"); err != nil {
		t.Fatalf("the init does not serve the guest's gateway forward: %v", err)
	} else {
		_ = c.Close()
	}
	// No socket: as planned.
	run, env, extra, stop2 := ociInitOOB(argv, []string{"TERM=xterm"})
	defer stop2()
	if !slices.Equal(run, argv) || len(extra) != 0 || !slices.Equal(env, []string{"TERM=xterm"}) {
		t.Fatalf("no socket: run %v env %v extra %d", run, env, len(extra))
	}
}
