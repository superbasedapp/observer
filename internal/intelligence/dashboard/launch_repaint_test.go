package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// --- fakes (thin wrappers over the package's existing launch fakes) ---

// repaintRecordingWriter wraps the package's recordingWriter fake with an
// ORDERED log of every Resize call, so a test can assert the exact winsize
// sequence the reattach repaint nudge puts on the wire (recordingWriter only
// counts). Everything else — Write, Revoked, Release, Holder, RevokeIsTakeover
// — is inherited unchanged from the existing fake.
type repaintRecordingWriter struct {
	*recordingWriter
	mu    sync.Mutex
	sizes [][2]uint16
	// onResize, when set, is invoked with every size this lease APPLIES, so the
	// owning fake manager can fold it back into its live snapshot the way the
	// real launch manager's resize funnel does. Guarded by mu (it is read from
	// the websocket read loop) even though it is only ever set at construction.
	onResize func(rows, cols uint16)
}

// newRepaintRecordingWriter builds a sequence-recording writer lease.
func newRepaintRecordingWriter() *repaintRecordingWriter {
	return &repaintRecordingWriter{recordingWriter: newRecordingWriter()}
}

// setOnResize installs the manager's convergence callback.
func (w *repaintRecordingWriter) setOnResize(fn func(rows, cols uint16)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onResize = fn
}

// Resize appends (rows, cols) to the ordered log, notifies the owning manager
// so its snapshot converges on the applied size, then delegates to the embedded
// recordingWriter so its counter stays authoritative too. The callback runs
// OUTSIDE w.mu so the writer lock is never held across the manager lock.
func (w *repaintRecordingWriter) Resize(rows, cols uint16) error {
	w.mu.Lock()
	w.sizes = append(w.sizes, [2]uint16{rows, cols})
	onResize := w.onResize
	w.mu.Unlock()
	if onResize != nil {
		onResize(rows, cols)
	}
	return w.recordingWriter.Resize(rows, cols)
}

// seq returns a copy of the recorded winsize sequence (race-safe: the bridge's
// read loop appends from its own goroutine).
func (w *repaintRecordingWriter) seq() [][2]uint16 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][2]uint16, len(w.sizes))
	copy(out, w.sizes)
	return out
}

// repaintLaunchManager reuses the package's recordingLaunchManager seam but
// hands the OWNER-LOCAL writer path a sequence-recording lease (the recording
// manager's own localWriter field is typed to the counting fake, so it cannot
// carry one). Every manager method except Snapshot and AcquireWriterLocal is
// promoted unchanged.
//
// Its snapshot CONVERGES: unlike the embedded recording manager's static
// snapshot field, every size the writer lease actually applies is folded back
// into the matching LaunchInfo row, the way the real manager's resize funnel
// updates its live session table. That is what makes ptySizeForHandle a moving
// target — and therefore what lets a test pin WHEN applyResizeFrame reads it
// (see TestTerminalRepaintNudgeReadsGeometryBeforeResize). A static fake can
// never observe that ordering, because it never converges.
type repaintLaunchManager struct {
	*recordingLaunchManager
	writer LaunchWriter

	// mu guards snap and handle. Snapshot() is read from the bridge's goroutine
	// while Resize (hence applyResize) is driven from the websocket read loop.
	mu sync.Mutex
	// snap is this fake's OWN live-session table — deliberately not the embedded
	// recording manager's snapshot field, which is unsynchronised and shared with
	// the other launch tests. Snapshot() is overridden to read this one.
	snap []LaunchInfo
	// handle is the session whose row converges, bound when the bridge takes the
	// owner-local writer lease.
	handle string
}

// newRepaintLaunchManager wires a recording manager whose AcquireWriterLocal
// returns w, with snap as the live-session snapshot ptySizeForHandle reads.
// snap is COPIED: the rows are mutated as resizes land, and the package-level
// repaintGeometry fixture is shared across tests.
func newRepaintLaunchManager(w *repaintRecordingWriter, snap []LaunchInfo) *repaintLaunchManager {
	m := &repaintLaunchManager{
		recordingLaunchManager: newRecordingLaunchManager(nil),
		writer:                 w,
		snap:                   append([]LaunchInfo(nil), snap...),
	}
	w.setOnResize(m.applyResize)
	return m
}

// Snapshot returns a defensive copy of the live session table, mutex-guarded.
// It overrides the embedded recording manager's unsynchronised accessor rather
// than editing that shared fake.
func (m *repaintLaunchManager) Snapshot() []LaunchInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LaunchInfo, len(m.snap))
	copy(out, m.snap)
	return out
}

// applyResize folds an APPLIED winsize back into the live snapshot, so a later
// Snapshot() reports the geometry the PTY actually has now.
//
// An unknown handle stays unknown: with no matching row nothing is invented, so
// ptySizeForHandle keeps reporting all-zero ("size not yet known"). InitialRows
// and InitialCols are never touched — they are the launch-time size, which no
// resize changes.
func (m *repaintLaunchManager) applyResize(rows, cols uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.snap {
		if m.snap[i].ID == m.handle {
			m.snap[i].Rows, m.snap[i].Cols = rows, cols
			return
		}
	}
}

// AcquireWriterLocal grants the sequence-recording lease on the loopback path
// and binds the handle whose snapshot row converges with it.
func (m *repaintLaunchManager) AcquireWriterLocal(handle string) (LaunchWriter, error) {
	m.recordingLaunchManager.localCalls.Add(1)
	m.mu.Lock()
	m.handle = handle
	m.mu.Unlock()
	return m.writer, nil
}

// --- helpers ---

// repaintGeometry is the live PTY size every reattach test starts from.
var repaintGeometry = []LaunchInfo{{ID: "HANDLE-abc", Rows: 40, Cols: 120, InitialRows: 24, InitialCols: 80}}

// dialRepaintWS opens a websocket against ts's /ws/launch/HANDLE-abc and waits
// for the on-open pty_size frame, which proves the bridge's read loop is live
// before the test writes its resize frame.
func dialRepaintWS(t *testing.T, ctx context.Context, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	c := dialRepaintWSRaw(t, ctx, ts)
	if !waitForControl(t, ctx, c, "pty_size") {
		t.Fatal("bridge never sent the on-open pty_size frame")
	}
	return c
}

// dialRepaintWSRaw dials the same bridge WITHOUT waiting for the on-open
// pty_size frame. A session whose geometry is never known sends no such frame —
// the bridge refuses to announce all-zero dimensions, which would carry nothing
// the client could restore (Q1 probe, P4) — so a test in that state must not
// wait for one. Nothing is lost: the client's resize frame is queued on the
// socket and read as soon as the bridge's loop starts, and waitResizeSeq's own
// deadline absorbs that startup gap.
func dialRepaintWSRaw(t *testing.T, ctx context.Context, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/ws/launch/HANDLE-abc", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": {ts.URL}},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

// waitResizeSeq polls w until it has recorded want calls (or the deadline
// expires), then settles briefly and returns the final sequence so a test can
// also prove no EXTRA resize arrived afterwards.
func waitResizeSeq(t *testing.T, w *repaintRecordingWriter, want int) [][2]uint16 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.seq()) >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // settle: catch a late/extra nudge
	return w.seq()
}

// sameSeq compares two winsize sequences.
func sameSeq(a, b [][2]uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- pure decision table ---

// TestTerminalRepaintNudgeDecisionTable pins repaintNudgeRows, the whole
// decision for "does this resize need a forced SIGWINCH, and to what row
// count": only a first, geometry-known, size-IDENTICAL resize nudges, and the
// intermediate row count shrinks (never exceeding the client's viewport) except
// at the 1-row underflow edge.
func TestTerminalRepaintNudgeDecisionTable(t *testing.T) {
	tests := []struct {
		name          string
		before        ptyGeometry
		rows, cols    uint16
		alreadyNudged bool
		wantMid       uint16
		wantNudge     bool
	}{
		{"identical size nudges down one row", ptyGeometry{rows: 40, cols: 120}, 40, 120, false, 39, true},
		{"already nudged on this bridge", ptyGeometry{rows: 40, cols: 120}, 40, 120, true, 0, false},
		{"unknown geometry (all zero)", ptyGeometry{}, 40, 120, false, 0, false},
		{"unknown rows only", ptyGeometry{rows: 0, cols: 120}, 40, 120, false, 0, false},
		{"unknown cols only", ptyGeometry{rows: 40, cols: 0}, 40, 120, false, 0, false},
		{"rows differ — real SIGWINCH already", ptyGeometry{rows: 40, cols: 120}, 30, 120, false, 0, false},
		{"cols differ — real SIGWINCH already", ptyGeometry{rows: 40, cols: 120}, 40, 100, false, 0, false},
		{"both differ", ptyGeometry{rows: 40, cols: 120}, 30, 100, false, 0, false},
		{"two-row terminal still shrinks", ptyGeometry{rows: 2, cols: 80}, 2, 80, false, 1, true},
		{"one-row terminal bounces up (underflow guard)", ptyGeometry{rows: 1, cols: 80}, 1, 80, false, 2, true},
		{"zero requested rows never nudges", ptyGeometry{rows: 0, cols: 80}, 0, 80, false, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mid, ok := repaintNudgeRows(tc.before, tc.rows, tc.cols, tc.alreadyNudged)
			if ok != tc.wantNudge || mid != tc.wantMid {
				t.Fatalf("repaintNudgeRows = (%d, %v), want (%d, %v)", mid, ok, tc.wantMid, tc.wantNudge)
			}
		})
	}
}

// --- bridge-level pins ---

// TestTerminalRepaintNudgeOnWriterReattach is the positive pin: a reattaching
// client holding the writer lease that re-sends the PTY's CURRENT dimensions
// gets exactly ONE nudge pair — (rows-1, cols) then back — and the PTY ends at
// the original size. Without it the identical winsize raises no SIGWINCH and a
// full-screen TUI never repaints.
func TestTerminalRepaintNudgeOnWriterReattach(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, repaintGeometry)
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWS(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":40,"cols":120}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	got := waitResizeSeq(t, w, 3)
	want := [][2]uint16{{40, 120}, {39, 120}, {40, 120}}
	if !sameSeq(got, want) {
		t.Fatalf("resize sequence = %v, want %v (one nudge pair, restored size)", got, want)
	}
}

// TestTerminalRepaintNudgeFiresOnlyOncePerBridge proves the nudge is one-shot:
// a client that re-sends the same no-op resize does not re-flicker every viewer
// of the PTY.
func TestTerminalRepaintNudgeFiresOnlyOncePerBridge(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, repaintGeometry)
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWS(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	for i := 0; i < 3; i++ {
		if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":40,"cols":120}`)); err != nil {
			t.Fatalf("write resize %d: %v", i, err)
		}
	}

	got := waitResizeSeq(t, w, 5)
	want := [][2]uint16{{40, 120}, {39, 120}, {40, 120}, {40, 120}, {40, 120}}
	if !sameSeq(got, want) {
		t.Fatalf("resize sequence = %v, want %v (nudge only on the FIRST no-op resize)", got, want)
	}
}

// TestTerminalRepaintNudgeSkippedForReadOnlyViewer pins the lease requirement:
// a remote-exposed viewer with NO granted writer lease has its resize frame
// dropped at the §4.β boundary, so it issues no resize at all — and certainly
// never a nudge (WriterLease.Resize would return ErrNotWriter anyway).
func TestTerminalRepaintNudgeSkippedForReadOnlyViewer(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, repaintGeometry)
	t.Cleanup(func() { close(lm.sub.release) })
	// remoteWriter is nil on the inner recording manager ⇒ an acquire would be
	// denied; this client stays a pure viewer.
	ts := remoteExposedWSServer(t, newLaunchTestServer(t, lm))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWS(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":40,"cols":120}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	if got := w.seq(); len(got) != 0 {
		t.Fatalf("read-only viewer drove the PTY: resize sequence = %v, want none", got)
	}
	if n := lm.localCalls.Load(); n != 0 {
		t.Fatalf("remote-exposed viewer took the owner-local writer %d times", n)
	}
}

// TestTerminalRepaintNudgeSkippedWhenGeometryUnknown pins the all-zero
// geometry guard: with no live snapshot the manager reports "size not yet
// known", so the client's resize is forwarded once and nothing is bounced.
func TestTerminalRepaintNudgeSkippedWhenGeometryUnknown(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, nil) // no snapshot ⇒ ptySizeForHandle is all zero
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Raw dial: with no geometry there is no on-open pty_size frame to wait for.
	c := dialRepaintWSRaw(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":40,"cols":120}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	got := waitResizeSeq(t, w, 1)
	want := [][2]uint16{{40, 120}}
	if !sameSeq(got, want) {
		t.Fatalf("resize sequence = %v, want %v (no nudge on unknown geometry)", got, want)
	}
}

// TestTerminalRepaintNudgeSkippedWhenResizeAlreadyDiffers pins the redundancy
// guard: a resize that actually CHANGES the winsize raises SIGWINCH on its own,
// so no extra bounce is issued.
func TestTerminalRepaintNudgeSkippedWhenResizeAlreadyDiffers(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, repaintGeometry) // live PTY is 40x120
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWS(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":30,"cols":100}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	got := waitResizeSeq(t, w, 1)
	want := [][2]uint16{{30, 100}}
	if !sameSeq(got, want) {
		t.Fatalf("resize sequence = %v, want %v (a real size change needs no nudge)", got, want)
	}
}

// TestTerminalRepaintNudgeReadsGeometryBeforeResize pins the ORDER of the two
// statements at the top of applyResizeFrame: the geometry snapshot must be read
// BEFORE writer.Resize applies the client's request, never after.
//
// Why it matters: the manager's snapshot converges on whatever size was last
// applied. Read it afterwards and `before` always equals the request, so
// repaintNudgeRows sees "identical size" on EVERY resize and fires a spurious
// nudge even on a genuine size change — a one-row bounce, and the visible
// flicker/churn it costs every viewer of the PTY, on a resize that already
// raised SIGWINCH by itself.
//
// This test is the reason repaintLaunchManager's snapshot converges. Against a
// STATIC fake — one whose Snapshot() keeps returning the construction-time rows
// — the assertion below would hold under BOTH orderings (the fake never
// converges, so a late read still sees 40x120 ≠ 30x100) and would therefore
// prove nothing. It is a live-geometry fake that turns this into a real pin;
// mutating applyResizeFrame to read after the resize makes it fail with
// [[30 100] [29 100] [30 100]].
func TestTerminalRepaintNudgeReadsGeometryBeforeResize(t *testing.T) {
	w := newRepaintRecordingWriter()
	lm := newRepaintLaunchManager(w, repaintGeometry) // live PTY is 40x120
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWS(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	// A GENUINELY different size: 30x100 against a live 40x120.
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"resize","rows":30,"cols":100}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	got := waitResizeSeq(t, w, 1)
	want := [][2]uint16{{30, 100}}
	if !sameSeq(got, want) {
		t.Fatalf("resize sequence = %v, want %v — the geometry snapshot was read AFTER the resize, "+
			"so the converged size misread as a no-op and a spurious nudge fired", got, want)
	}
	// The fake really did converge — otherwise the assertion above is vacuous.
	if g := lm.Snapshot(); len(g) != 1 || g[0].Rows != 30 || g[0].Cols != 100 {
		t.Fatalf("snapshot = %v, want the live row converged on 30x100 (a non-converging fake cannot pin the ordering)", g)
	}
	// InitialRows/InitialCols are launch-time facts a resize must not rewrite.
	if g := lm.Snapshot(); g[0].InitialRows != 24 || g[0].InitialCols != 80 {
		t.Fatalf("snapshot initial size = %dx%d, want 24x80 (a resize must not touch it)", g[0].InitialRows, g[0].InitialCols)
	}
}
