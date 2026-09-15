// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// launch_ptysize_test.go pins the on-open PTY geometry announce (Feature 2) after
// the Q1 first-launch probe found every session's FIRST text frame was literally
// `{"t":"pty_size"}` — rows/cols/initial_rows/initial_cols all zero and stripped
// by omitempty, so the client got nothing to restore. The bridge fired its
// announce before the launch manager's geometry snapshot had converged. The rule
// these tests pin: announce REAL dimensions, or announce nothing yet.

// TestPTYGeometryKnown pins the "size not yet known" predicate the announce gates
// on. Both axes must be present: a 0-row or 0-col winsize does not exist, so a
// half-known pair describes no terminal a client could fit to.
func TestPTYGeometryKnown(t *testing.T) {
	tests := []struct {
		name string
		g    ptyGeometry
		want bool
	}{
		{"both dimensions known", ptyGeometry{rows: 40, cols: 120}, true},
		{"known current size, unknown initial", ptyGeometry{rows: 24, cols: 80}, true},
		{"all zero — not yet known", ptyGeometry{}, false},
		{"rows only", ptyGeometry{rows: 40}, false},
		{"cols only", ptyGeometry{cols: 120}, false},
		{"initial only — current still unknown", ptyGeometry{initialRows: 24, initialCols: 80}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.g.known(); got != tt.want {
				t.Fatalf("known() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAwaitPTYSizeSendsOnceWhenGeometryArrives pins the bounded wait: it keeps
// asking until the announce actually writes a frame, then stops — one frame, not
// a stream.
func TestAwaitPTYSizeSendsOnceWhenGeometryArrives(t *testing.T) {
	var calls int
	send := func() bool {
		calls++
		return calls >= 3 // geometry converges on the third look
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		awaitPTYSize(context.Background(), send, time.Millisecond, 2*time.Second)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("awaitPTYSize never returned after the announce succeeded")
	}
	if calls != 3 {
		t.Fatalf("send called %d times, want exactly 3 (stop on the first successful announce)", calls)
	}
}

// TestAwaitPTYSizeGivesUpAtWindow pins that a session which never acquires a size
// costs a bounded goroutine and never announces an empty frame.
func TestAwaitPTYSizeGivesUpAtWindow(t *testing.T) {
	sent := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		awaitPTYSize(context.Background(), func() bool { sent = true; return false }, time.Millisecond, 60*time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("awaitPTYSize outlived its window")
	}
	if !sent {
		t.Fatal("awaitPTYSize never consulted the announce")
	}
}

// TestAwaitPTYSizeStopsOnContextCancel pins the bridge-teardown exit: the wait
// belongs to the bridge's context, so a client that disconnects while geometry is
// still unknown leaves nothing running.
func TestAwaitPTYSizeStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		awaitPTYSize(ctx, func() bool { return false }, time.Millisecond, time.Hour)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("awaitPTYSize ignored its cancelled context")
	}
}

// geometryLaunchManager is a launch manager whose live geometry snapshot can be
// installed AFTER the bridge has already started — the exact race the Q1 probe
// caught (the bridge announced before the manager converged).
type geometryLaunchManager struct {
	*recordingLaunchManager
	mu   sync.Mutex
	snap []LaunchInfo
}

func newGeometryLaunchManager(snap []LaunchInfo) *geometryLaunchManager {
	return &geometryLaunchManager{recordingLaunchManager: newRecordingLaunchManager(nil), snap: snap}
}

// Snapshot returns a defensive copy under the mutex, overriding the embedded
// fake's unsynchronised accessor.
func (m *geometryLaunchManager) Snapshot() []LaunchInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]LaunchInfo(nil), m.snap...)
}

// converge installs the geometry the PTY has now.
func (m *geometryLaunchManager) converge(snap []LaunchInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap = append([]LaunchInfo(nil), snap...)
}

// ptySizeFrame is the decoded on-the-wire shape of the announce, read back
// through the real JSON so omitempty stripping is part of what is asserted.
type ptySizeFrame struct {
	T           string `json:"t"`
	Rows        uint16 `json:"rows"`
	Cols        uint16 `json:"cols"`
	InitialRows uint16 `json:"initial_rows"`
	InitialCols uint16 `json:"initial_cols"`
}

// ptySizeStream drains a bridge connection on its own goroutine and forwards
// every pty_size frame. A goroutine, deliberately: coder/websocket TEARS DOWN
// the connection when a Read's context expires, so polling with short per-read
// timeouts (the obvious shape for "assert nothing arrives yet") would kill the
// socket before the later assertion could observe anything.
func ptySizeStream(ctx context.Context, c *websocket.Conn) <-chan ptySizeFrame {
	out := make(chan ptySizeFrame, 4)
	go func() {
		for {
			typ, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			var f ptySizeFrame
			if json.Unmarshal(data, &f) != nil || f.T != "pty_size" {
				continue
			}
			select {
			case out <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// TestOnOpenPTYSizeCarriesRealGeometry pins the fixed announce: when the session
// HAS dimensions, the first pty_size frame carries them (non-zero rows/cols),
// rather than the all-zero frame the probe captured.
func TestOnOpenPTYSizeCarriesRealGeometry(t *testing.T) {
	lm := newGeometryLaunchManager([]LaunchInfo{{ID: "HANDLE-abc", Rows: 40, Cols: 120, InitialRows: 24, InitialCols: 80}})
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWSRaw(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	var f ptySizeFrame
	select {
	case f = <-ptySizeStream(ctx, c):
	case <-time.After(3 * time.Second):
		t.Fatal("bridge never sent the on-open pty_size frame for a session with known geometry")
	}
	if f.Rows == 0 || f.Cols == 0 {
		t.Fatalf("on-open pty_size carried no geometry: %+v", f)
	}
	if f.Rows != 40 || f.Cols != 120 || f.InitialRows != 24 || f.InitialCols != 80 {
		t.Fatalf("on-open pty_size = %+v, want rows=40 cols=120 initial 24x80", f)
	}
}

// TestOnOpenPTYSizeWaitsForGeometryInsteadOfAnnouncingZero pins BOTH halves of
// the fix: while the size is unknown NO pty_size frame is sent at all (the probe
// saw `{"t":"pty_size"}` with everything omitempty-stripped), and once the
// manager converges the announce lands carrying the real dimensions.
func TestOnOpenPTYSizeWaitsForGeometryInsteadOfAnnouncingZero(t *testing.T) {
	lm := newGeometryLaunchManager(nil) // size not yet known
	t.Cleanup(func() { close(lm.sub.release) })
	ts := httptest.NewServer(newLaunchTestServer(t, lm).Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := dialRepaintWSRaw(t, ctx, ts)
	defer func() { _ = c.CloseNow() }()

	frames := ptySizeStream(ctx, c)
	select {
	case f := <-frames:
		t.Fatalf("bridge announced an unknown geometry: %+v", f)
	case <-time.After(400 * time.Millisecond):
	}

	lm.converge([]LaunchInfo{{ID: "HANDLE-abc", Rows: 50, Cols: 200, InitialRows: 50, InitialCols: 200}})

	select {
	case f := <-frames:
		if f.Rows != 50 || f.Cols != 200 {
			t.Fatalf("late pty_size = %+v, want rows=50 cols=200", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bridge never announced the geometry once it became known")
	}
}
