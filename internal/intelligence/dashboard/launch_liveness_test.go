package dashboard

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// withFastTerminalPing lowers the WS liveness ping cadence for a test and
// restores the production defaults on cleanup.
func withFastTerminalPing(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	oi, ot := terminalPingIntervalNs.Load(), terminalPingTimeoutNs.Load()
	terminalPingIntervalNs.Store(int64(interval))
	terminalPingTimeoutNs.Store(int64(timeout))
	t.Cleanup(func() {
		terminalPingIntervalNs.Store(oi)
		terminalPingTimeoutNs.Store(ot)
	})
}

// TestTerminalBridgePingDetectsDeadPeer proves the server-side liveness probe
// tears down a half-open/unresponsive connection: with a fast ping cadence, a
// client that never reads (so coder/websocket never auto-replies the pong) is
// detected as dead and the socket is closed by the server — WITHOUT any output
// or exit event firing. This is the liveness guarantee (a dead peer is reaped)
// that is deliberately NOT a read-idle timeout.
func TestTerminalBridgePingDetectsDeadPeer(t *testing.T) {
	withFastTerminalPing(t, 40*time.Millisecond, 60*time.Millisecond)

	lm := &fakeLaunchManager{sub: newFakeSubscription()}
	t.Cleanup(func() { close(lm.sub.release) })
	s := newLaunchTestServer(t, lm)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	base := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, base+"/ws/launch/HANDLE-abc", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {ts.URL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()

	// Deliberately do NOT read for long enough that a pong can't be auto-sent;
	// the server pings, times out waiting for the pong, and cancels the bridge.
	time.Sleep(250 * time.Millisecond)

	// The server has torn the socket down: a read now returns an error within a
	// bounded window (it drains any buffered ping frame first, then hits close).
	rctx, rcancel := context.WithTimeout(ctx, 4*time.Second)
	defer rcancel()
	for {
		if _, _, rerr := c.Read(rctx); rerr != nil {
			break // server closed the dead peer — liveness worked
		}
		if rctx.Err() != nil {
			t.Fatal("dead peer was not torn down by the ping-liveness loop")
		}
	}
}

// TestTerminalBridgeLivePeerSurvivesPings is the companion negative: a client
// that DOES read (so coder/websocket auto-replies pongs) is NOT evicted across
// several ping intervals even though it sends no input of its own — an idle-but-
// alive watcher must stay connected (no read-idle timeout).
func TestTerminalBridgeLivePeerSurvivesPings(t *testing.T) {
	withFastTerminalPing(t, 40*time.Millisecond, 500*time.Millisecond)

	lm := &fakeLaunchManager{sub: newFakeSubscription()}
	t.Cleanup(func() { close(lm.sub.release) })
	s := newLaunchTestServer(t, lm)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	base := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, base+"/ws/launch/HANDLE-abc", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {ts.URL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()

	// Read in the background so pongs are auto-sent; the connection must stay up
	// across many ping intervals without any client input.
	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, rerr := c.Read(ctx); rerr != nil {
				readErr <- rerr
				return
			}
		}
	}()

	select {
	case rerr := <-readErr:
		t.Fatalf("live idle watcher was evicted by the ping loop: %v", rerr)
	case <-time.After(400 * time.Millisecond): // ~10 ping intervals
		// Still connected — correct: liveness pings do not evict a responsive peer.
	}
}

// TestOversizedViewerFrameRejected proves the per-message read cap
// (c.SetReadLimit(1<<20)) rejects an oversized frame: a >1 MiB frame from a
// lease-less viewer closes the socket and reaches NO PTY side effect.
func TestOversizedViewerFrameRejected(t *testing.T) {
	lm := newRecordingLaunchManager(nil) // no remote writer ⇒ never a lease
	// Give the handle a KNOWN geometry so the bridge's on-open pty_size frame
	// (Feature 2) actually fires: an all-zero snapshot is the manager's "size
	// not yet known" sentinel, for which the bridge deliberately announces
	// NOTHING, and the drain below would then read the cap-close instead.
	lm.snapshot = []LaunchInfo{{ID: "HANDLE-abc", Rows: 40, Cols: 120, InitialRows: 24, InitialCols: 80}}
	t.Cleanup(func() { close(lm.sub.release) })
	s := newLaunchTestServer(t, lm)
	ts := remoteExposedWSServer(t, s)
	defer ts.Close()

	base := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, base+"/ws/launch/HANDLE-abc", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {ts.URL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()
	// coder/websocket's client enforces the same 32 KiB default read limit on its
	// own reads; raise it so the client can observe the server's close frame
	// rather than erroring on the (irrelevant) inbound path.
	c.SetReadLimit(4 << 20)

	// A 2 MiB binary frame exceeds the server's 1 MiB read cap.
	big := bytes.Repeat([]byte("A"), 2<<20)
	_ = c.Write(ctx, websocket.MessageBinary, big)

	rctx, rcancel := context.WithTimeout(ctx, 4*time.Second)
	defer rcancel()
	// Drain the on-open pty_size geometry frame (Feature 2) the bridge sends to
	// every client before the read loop; the cap-close arrives on the NEXT read.
	if _, _, derr := c.Read(rctx); derr != nil {
		t.Fatalf("expected the on-open pty_size frame, got error: %v", derr)
	}
	// The server rejects the oversized frame and closes; a read returns an error.
	if _, _, rerr := c.Read(rctx); rerr == nil {
		t.Fatal("oversized frame was accepted — read cap not enforced")
	}
	// And no PTY side effect ever occurred (no lease was held).
	if lm.localWriter.writes.Load() != 0 || lm.localWriter.resizes.Load() != 0 {
		t.Fatalf("oversized frame reached the PTY (writes=%d resizes=%d)", lm.localWriter.writes.Load(), lm.localWriter.resizes.Load())
	}
}

// TestTerminalControlSecretsAbsentFromWebSocketHandshake pins §8.1 item 5 for
// the WS upgrade: the /ws/launch handshake carries NO capability / confirm /
// session id in the URL path, query string, or Sec-WebSocket-Protocol
// subprotocol. The capability + confirm are accepted ONLY in the acquire-writer
// TEXT frame body — proven by capturing the AcquireWriterRemote inputs and
// confirming the canary secrets arrived there while being wholly absent from the
// captured HTTP upgrade request.
func TestTerminalControlSecretsAbsentFromWebSocketHandshake(t *testing.T) {
	const (
		canaryCap     = "CANARY-CAP-0f1e2d3c"
		canaryConfirm = "CANARY-CONFIRM-a9b8c7d6"
	)
	rw := newRecordingWriter()
	lm := newRecordingLaunchManager(rw) // grants a writer so the acquire path runs fully
	t.Cleanup(func() { close(lm.sub.release) })
	s := newLaunchTestServer(t, lm)

	// Capture the raw upgrade request the server received.
	var (
		gotPath     string
		gotRawQuery string
		gotProto    string
		gotReqLine  string
	)
	inner := s.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ws/launch/") {
			gotPath = r.URL.Path
			gotRawQuery = r.URL.RawQuery
			gotProto = r.Header.Get("Sec-WebSocket-Protocol")
			gotReqLine = r.Method + " " + r.URL.RequestURI() + " " + strings.Join(r.Header.Values("Sec-WebSocket-Protocol"), ",")
		}
		inner.ServeHTTP(w, r.WithContext(withRemoteExposed(r.Context())))
	}))
	defer ts.Close()

	base := "ws" + strings.TrimPrefix(ts.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The handshake URL carries ONLY the opaque handle — no cap/confirm/session.
	c, _, err := websocket.Dial(ctx, base+"/ws/launch/HANDLE-abc", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {ts.URL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()

	// The secrets ride ONLY the acquire-writer TEXT frame body.
	frame := `{"t":"acquire-writer","cap":"` + canaryCap + `","confirm":"` + canaryConfirm + `"}`
	if werr := c.Write(ctx, websocket.MessageText, []byte(frame)); werr != nil {
		t.Fatalf("write acquire frame: %v", werr)
	}
	if !waitForControl(t, ctx, c, "control_granted") {
		t.Fatal("expected control_granted (cap/confirm accepted in the frame body)")
	}

	// The captured upgrade request must contain none of the secrets, anywhere.
	if gotPath != "/ws/launch/HANDLE-abc" {
		t.Errorf("upgrade path = %q, want /ws/launch/HANDLE-abc", gotPath)
	}
	if gotRawQuery != "" {
		t.Errorf("upgrade carried a query string %q — no secret channel is permitted there", gotRawQuery)
	}
	for _, canary := range []string{canaryCap, canaryConfirm, "HANDLE-abc-session"} {
		if strings.Contains(gotReqLine, canary) || strings.Contains(gotProto, canary) {
			t.Errorf("handshake leaked %q (req=%q proto=%q)", canary, gotReqLine, gotProto)
		}
	}
	// Positive proof the secrets DID arrive via the frame body.
	req := lm.lastRemoteReq.Load()
	if req == nil {
		t.Fatal("AcquireWriterRemote was never called — the frame body was not the accept path")
	}
	if req.CapabilityToken != canaryCap || req.Confirm != canaryConfirm {
		t.Errorf("acquire inputs = {cap:%q confirm:%q}, want the frame-body canaries", req.CapabilityToken, req.Confirm)
	}
}
