//go:build !sbo_omit_processobs

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
)

// These tests exercise the ACCEPT transport end to end over real loopback TCP:
// the daemon's bridge.Listener on one side, the capturer's --connect path
// (runProcessBridgeConnect → bridge.Handshake → streamProcessBridgeWith over a
// net.Conn) on the other, with the real poll backend producing the events.
//
// The transport is OS-agnostic even though the ETW capture behind it is not,
// so all of this runs on Linux. What stays unexercised anywhere is the ETW
// capture itself (Windows + elevation); the fake capture below stands in for
// it at the etwNetworkCapture seam.

const testBridgeToken = "0123456789abcdef0123456789abcdef"

// newTestBridgeListener opens a listener on an ephemeral loopback port.
func newTestBridgeListener(t *testing.T, addr string) *bridge.Listener {
	t.Helper()
	l, err := bridge.NewListener(bridge.ListenerOptions{
		Addr:              addr,
		Token:             testBridgeToken,
		HandshakeTimeout:  2 * time.Second,
		NetworkAccounting: &processobs.NetworkAccounting{},
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	return l
}

// writeTokenFile persists a token 0600 and returns its path.
func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "process-bridge-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// drainEvents collects events off ch until n arrive or the deadline passes.
func drainEvents(t *testing.T, ch <-chan processobs.RawEvent, n int, d time.Duration) []processobs.RawEvent {
	t.Helper()
	var got []processobs.RawEvent
	deadline := time.After(d)
	for len(got) < n {
		select {
		case ev, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, ev)
		case <-deadline:
			return got
		}
	}
	return got
}

// TestProcessBridgeConnectEndToEnd is the real thing: a daemon-side listener,
// a capturer that dials it, a correct token, and process events crossing the
// socket into the Backend channel the Observer would consume.
func TestProcessBridgeConnectEndToEnd(t *testing.T) {
	ln := newTestBridgeListener(t, "127.0.0.1:0")
	defer ln.Close()
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	ch, err := ln.Start(lctx)
	if err != nil {
		t.Fatalf("listener Start: %v", err)
	}

	capCtx, capCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer capCancel()
	errOut := &syncBuf{}
	done := make(chan error, 1)
	go func() {
		done <- runProcessBridgeConnect(capCtx, ln.Addr(), writeTokenFile(t, testBridgeToken),
			// A poll interval longer than the test: exactly the initial
			// snapshot is emitted, which is plenty of events.
			processBridgeOptions{Interval: 30 * time.Second}, errOut)
	}()

	got := drainEvents(t, ch, 3, 6*time.Second)
	if len(got) < 3 {
		t.Fatalf("received %d events over the socket, want >= 3 (stderr: %s)", len(got), errOut.String())
	}
	for _, ev := range got {
		if ev.PID <= 0 || ev.BootID == "" {
			t.Fatalf("malformed event crossed the transport: %+v", ev)
		}
	}
	if s := ln.Stats(); s.Connections != 1 || s.AuthFailures != 0 {
		t.Fatalf("listener stats = %+v, want 1 connection / 0 auth failures", s)
	}

	capCancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("capturer returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capturer did not exit after ctx cancel")
	}
}

// TestProcessBridgeConnectRejectsBadToken proves the token is load-bearing:
// a capturer with the wrong token never streams, the refusal is counted, and
// nothing it sends reaches the pipeline.
func TestProcessBridgeConnectRejectsBadToken(t *testing.T) {
	ln := newTestBridgeListener(t, "127.0.0.1:0")
	defer ln.Close()
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	ch, err := ln.Start(lctx)
	if err != nil {
		t.Fatalf("listener Start: %v", err)
	}

	capCtx, capCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer capCancel()
	errOut := &syncBuf{}
	go func() {
		_ = runProcessBridgeConnect(capCtx, ln.Addr(), writeTokenFile(t, "not-the-right-token"),
			processBridgeOptions{Interval: 30 * time.Second}, errOut)
	}()

	if got := drainEvents(t, ch, 1, 2500*time.Millisecond); len(got) != 0 {
		t.Fatalf("an unauthenticated capturer's events reached the pipeline: %+v", got)
	}
	if s := ln.Stats(); s.AuthFailures == 0 || s.Connections != 0 {
		t.Fatalf("listener stats = %+v, want auth failures and no accepted connection", s)
	}
	// The capturer must SAY so rather than fail silently — otherwise a
	// mistyped token is indistinguishable from a daemon that never started.
	if !strings.Contains(errOut.String(), "connect to") {
		t.Fatalf("capturer stderr did not report the failure: %q", errOut.String())
	}
	capCancel()
}

// TestProcessBridgeConnectReconnects covers the accept transport's defining
// difference from spawn mode. The daemon goes away mid-stream and comes back;
// the capturer must reconnect on its own rather than exit, and — critically —
// must NOT restart the ETW capture, whose per-pid accumulator is CUMULATIVE
// (plan §0.1). Restarting it would zero those totals and make the next
// differentiation negative, with no error anywhere.
func TestProcessBridgeConnectReconnects(t *testing.T) {
	// Take an ephemeral port, then rebind the second listener to it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	if cerr := probe.Close(); cerr != nil {
		t.Fatal(cerr)
	}

	ln1 := newTestBridgeListener(t, addr)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ch1, err := ln1.Start(ctx1)
	if err != nil {
		t.Fatalf("listener 1 Start: %v", err)
	}

	capture := &fakeETWCapture{mode: processobs.NetworkAccountingTCP, measured: true, in: 10, out: 20}
	var starts atomic.Int32
	capCtx, capCancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer capCancel()
	errOut := &syncBuf{}
	go func() {
		_ = runProcessBridgeConnect(capCtx, addr, writeTokenFile(t, testBridgeToken), processBridgeOptions{
			Interval: 30 * time.Second,
			ETW:      true,
			startETW: func() (etwNetworkCapture, error) {
				starts.Add(1)
				return capture, nil
			},
		}, errOut)
	}()

	if got := drainEvents(t, ch1, 1, 8*time.Second); len(got) == 0 {
		t.Fatalf("no events on the first connection (stderr: %s)", errOut.String())
	}

	// The daemon goes away.
	cancel1()
	if cerr := ln1.Close(); cerr != nil {
		t.Fatalf("listener 1 Close: %v", cerr)
	}

	// ...and comes back on the same address.
	ln2 := newTestBridgeListener(t, addr)
	defer ln2.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ch2, err := ln2.Start(ctx2)
	if err != nil {
		t.Fatalf("listener 2 Start: %v", err)
	}

	if got := drainEvents(t, ch2, 1, 12*time.Second); len(got) == 0 {
		t.Fatalf("the capturer did not reconnect (stderr: %s)", errOut.String())
	}
	if s := ln2.Stats(); s.Connections == 0 {
		t.Fatalf("listener 2 stats = %+v, want an accepted connection", s)
	}

	// The whole point: ONE capture across both connections, and it is not
	// closed while the loop is still running.
	if n := starts.Load(); n != 1 {
		t.Fatalf("ETW capture started %d times across a reconnect, want exactly 1", n)
	}
	if capture.wasClosed() {
		t.Fatal("the ETW capture was closed by a per-connection stream; it must outlive reconnects")
	}

	capCancel()
	// After the loop exits the shared capture IS closed — the no-op Close is
	// scoped to the per-connection stream, not to the process.
	deadline := time.Now().Add(5 * time.Second)
	for !capture.wasClosed() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !capture.wasClosed() {
		t.Fatal("the shared ETW capture was never closed when the connect loop exited")
	}
}

// syncBuf is a bytes.Buffer safe for the capturer goroutine to write while the
// test reads it.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestResolveProcessBridgeToken pins the capturer's token sources and the
// deliberate absence of an argv one.
func TestResolveProcessBridgeToken(t *testing.T) {
	t.Run("file wins", func(t *testing.T) {
		t.Setenv(processBridgeTokenEnv, "from-env")
		got, err := resolveProcessBridgeToken(writeTokenFile(t, "from-file"))
		if err != nil || got != "from-file" {
			t.Fatalf("= (%q, %v), want from-file", got, err)
		}
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv(processBridgeTokenEnv, "  from-env\n")
		got, err := resolveProcessBridgeToken("")
		if err != nil || got != "from-env" {
			t.Fatalf("= (%q, %v), want from-env", got, err)
		}
	})
	t.Run("empty file is an error", func(t *testing.T) {
		t.Setenv(processBridgeTokenEnv, "")
		if _, err := resolveProcessBridgeToken(writeTokenFile(t, "")); err == nil {
			t.Fatal("want an error for an empty token file")
		}
	})
	t.Run("no source names both channels", func(t *testing.T) {
		t.Setenv(processBridgeTokenEnv, "")
		_, err := resolveProcessBridgeToken("")
		if err == nil {
			t.Fatal("want an error when no token source exists")
		}
		if !strings.Contains(err.Error(), "--token-file") || !strings.Contains(err.Error(), processBridgeTokenEnv) {
			t.Fatalf("error must name both channels, got %q", err)
		}
	})
}

// TestResolveProcessBridgeListenToken pins the daemon side: generate once,
// persist 0600, reuse thereafter — and never persist an operator's own token.
func TestResolveProcessBridgeListenToken(t *testing.T) {
	dir := t.TempDir()
	pc := config.Default().Observer.Process

	first, err := resolveProcessBridgeListenToken(pc, dir)
	if err != nil || first == "" {
		t.Fatalf("first resolve = (%q, %v)", first, err)
	}
	path := filepath.Join(dir, processBridgeTokenFileName)
	info, serr := os.Stat(path)
	if serr != nil {
		t.Fatalf("token file not persisted: %v", serr)
	}
	if perm := info.Mode().Perm(); posixModes && perm != 0o600 {
		t.Fatalf("token file mode = %o, want 600", perm)
	}
	second, err := resolveProcessBridgeListenToken(pc, dir)
	if err != nil || second != first {
		t.Fatalf("second resolve = (%q, %v), want the persisted %q", second, err, first)
	}

	// An explicitly configured token is used as-is and never written out.
	explicitDir := t.TempDir()
	pc.ETW.Token = "operator-supplied"
	got, err := resolveProcessBridgeListenToken(pc, explicitDir)
	if err != nil || got != "operator-supplied" {
		t.Fatalf("= (%q, %v)", got, err)
	}
	if _, serr := os.Stat(filepath.Join(explicitDir, processBridgeTokenFileName)); serr == nil {
		t.Fatal("an explicitly configured token must not be persisted to disk")
	}
}

// TestSelectProcessBackendETWListener covers the hybrid posture: with the ETW
// block enabled the listener is ADDED to the baseline; with it disabled the
// selection is byte-for-byte what it was before this feature existed.
func TestSelectProcessBackendETWListener(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("disabled changes nothing", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if got := b.Name(); got != "poll" {
			t.Fatalf("Name() = %q, want the untouched poll baseline", got)
		}
	})

	t.Run("enabled adds the listener", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "127.0.0.1:0"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if got := b.Name(); !strings.Contains(got, "poll") || !strings.Contains(got, "bridge-listen") {
			t.Fatalf("Name() = %q, want a composite of the poll baseline + the listener", got)
		}
		// Cross-OS events cannot be attributed at capture time.
		uc, ok := b.(processobs.UnattributedCapturer)
		if !ok || !uc.RequiresUnattributedCapture() {
			t.Fatal("the composite must require unattributed capture once the listener is a child")
		}
	})

	t.Run("backend=etw keeps the baseline", func(t *testing.T) {
		// The ETW feed is additive. Selecting it must never trade away the
		// zero-privilege capture that already works.
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "etw"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "127.0.0.1:0"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf(`backend = "etw" must no longer be an error: %v`, err)
		}
		defer b.Close()
		if got := b.Name(); !strings.Contains(got, "bridge-listen") {
			t.Fatalf("Name() = %q, want the listener present", got)
		}
	})

	t.Run("backend=etw without the block still captures", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "etw"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if strings.Contains(b.Name(), "bridge-listen") {
			t.Fatalf("Name() = %q, want no listener when the block is disabled", b.Name())
		}
	})

	t.Run("a bad bind fails open", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "10.1.2.3:8823" // non-loopback → refused
		netStatus := &processobs.NetworkAccounting{}
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, netStatus)
		if err != nil {
			t.Fatalf("a listener failure must not disable capture: %v", err)
		}
		defer b.Close()
		if got := b.Name(); got != "poll" {
			t.Fatalf("Name() = %q, want the bare baseline after a fail-open", got)
		}
		mode, reason := netStatus.Status()
		if mode != processobs.NetworkAccountingUnavailable || !strings.Contains(reason, "could not start") {
			t.Fatalf("status = (%q, %q), want an honest unavailable + reason", mode, reason)
		}
	})
}

// TestProcessBridgeConnectWaitsForTokenFile covers the ordering hazard the
// elevated Scheduled Task introduces (§W4): the task is triggered at LOGON and
// can start minutes before WSL — and therefore before the daemon that
// GENERATES the shared-token file exists. A capturer that read its token once
// at startup would exit on that entirely normal boot order and never come
// back. It must instead re-read the token on every connect attempt.
func TestProcessBridgeConnectWaitsForTokenFile(t *testing.T) {
	ln := newTestBridgeListener(t, "127.0.0.1:0")
	defer ln.Close()
	lctx, lcancel := context.WithCancel(context.Background())
	defer lcancel()
	ch, err := ln.Start(lctx)
	if err != nil {
		t.Fatalf("listener Start: %v", err)
	}

	// The path the daemon WILL write — it does not exist yet.
	tokenPath := filepath.Join(t.TempDir(), "process-bridge-token")

	capCtx, capCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer capCancel()
	errOut := &syncBuf{}
	done := make(chan error, 1)
	go func() {
		done <- runProcessBridgeConnect(capCtx, ln.Addr(), tokenPath,
			processBridgeOptions{Interval: 30 * time.Second}, errOut)
	}()

	// The capturer must still be alive with no token to read.
	select {
	case err := <-done:
		t.Fatalf("capturer exited before the token existed: %v (stderr: %s)", err, errOut.String())
	case <-time.After(1500 * time.Millisecond):
	}

	// The daemon comes up and persists the token.
	if werr := os.WriteFile(tokenPath, []byte(testBridgeToken+"\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	if got := drainEvents(t, ch, 3, 10*time.Second); len(got) < 3 {
		t.Fatalf("received %d events after the token appeared, want >= 3 (stderr: %s)", len(got), errOut.String())
	}
	if !strings.Contains(errOut.String(), "read --token-file") {
		t.Fatalf("the wait must be reported, not silent: %q", errOut.String())
	}

	capCancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("capturer returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("capturer did not exit after ctx cancel")
	}
}

// TestProcessBridgeConnectNoTokenSourceFailsFast is the other half: with NO
// --token-file and no environment token there is nothing to wait FOR, so the
// capturer must exit with the usage error instead of retrying forever.
func TestProcessBridgeConnectNoTokenSourceFailsFast(t *testing.T) {
	t.Setenv(processBridgeTokenEnv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runProcessBridgeConnect(ctx, "127.0.0.1:1", "", processBridgeOptions{Interval: 30 * time.Second}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--token-file") {
		t.Fatalf("err = %v, want the usage error naming --token-file", err)
	}
}
