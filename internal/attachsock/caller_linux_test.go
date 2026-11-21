//go:build linux

package attachsock

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/peerproc"
)

// callerRecordingHost records the caller pid the server put in the
// controller's context.
type callerRecordingHost struct {
	*fakeControlHost
	pid   int
	found bool
}

func (h *callerRecordingHost) LaunchDetached(ctx context.Context, spec LaunchSpec) (RunInfo, error) {
	h.pid, h.found = CallerPID(ctx)
	return h.fakeControlHost.LaunchDetached(ctx, spec)
}

// TestControlLaunchCarriesCallerPID pins lane cli-2's transport half: over
// a real unix socket the controller sees the connecting process's pid, and
// the client's agent-session hint arrives with the spec.
func TestControlLaunchCarriesCallerPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := &callerRecordingHost{fakeControlHost: newFakeControlHost()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() { _ = Serve(ctx, ln, h, nil) }()
	spec := LaunchSpec{Tool: "claude-code", Project: "/p", AgentEnv: true, AgentEnvSession: "sess-env"}
	if _, err := ControlCall(ctx, path, ControlRequest{Op: opLaunch, Launch: &spec}); err != nil {
		t.Fatalf("ControlCall: %v", err)
	}
	if !h.found || h.pid != os.Getpid() {
		t.Fatalf("CallerPID = %d, %v; want %d", h.pid, h.found, os.Getpid())
	}
	if len(h.launched) != 1 || !h.launched[0].AgentEnv || h.launched[0].AgentEnvSession != "sess-env" {
		t.Fatalf("controller saw %+v", h.launched)
	}
	if _, ok := CallerPID(context.Background()); ok {
		t.Fatal("CallerPID found a pid in a bare context")
	}
}

type snapKey struct{}

// snapshotHost is a control host that snapshots its caller at accept.
type snapshotHost struct {
	*fakeControlHost
	snapPID  int
	snaps    int
	start    string
	startOK  bool
	sawSnap  any
	launches int
}

func (h *snapshotHost) SnapshotCaller(ctx context.Context, pid int) context.Context {
	h.snaps++
	h.snapPID = pid
	return context.WithValue(ctx, snapKey{}, "seen-at-accept")
}

func (h *snapshotHost) LaunchDetached(ctx context.Context, spec LaunchSpec) (RunInfo, error) {
	h.launches++
	h.start, h.startOK = CallerStart(ctx)
	h.sawSnap = ctx.Value(snapKey{})
	return h.fakeControlHost.LaunchDetached(ctx, spec)
}

// TestServerRecordsTheCallerAtAccept pins lane cli-2 fixes-3 (audit M1),
// the transport half: the server reads the connecting process's start
// token and lets a CallerSnapshotter host read its facts once per
// connection, and both reach the controller with the request; a start
// that cannot be read is not recorded.
func TestServerRecordsTheCallerAtAccept(t *testing.T) {
	want, ok := peerproc.StartToken(os.Getpid())
	if !ok {
		t.Skip("no start token here")
	}
	for _, tc := range []struct {
		name      string
		unread    bool
		wantStart string
	}{
		{"start read", false, want},
		{"start unreadable", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unread {
				old := callerStartToken
				callerStartToken = func(int) (string, bool) { return "", false }
				t.Cleanup(func() { callerStartToken = old })
			}
			path := filepath.Join(t.TempDir(), "a.sock")
			ln, err := net.Listen("unix", path)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			h := &snapshotHost{fakeControlHost: newFakeControlHost()}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go func() { _ = Serve(ctx, ln, h, nil) }()
			spec := LaunchSpec{Tool: "claude-code", Project: "/p"}
			if _, err := ControlCall(ctx, path, ControlRequest{Op: opLaunch, Launch: &spec}); err != nil {
				t.Fatalf("ControlCall: %v", err)
			}
			if h.snaps != 1 || h.snapPID != os.Getpid() || h.sawSnap != "seen-at-accept" {
				t.Fatalf("snapshot: %d calls, pid %d, ctx value %v", h.snaps, h.snapPID, h.sawSnap)
			}
			if h.start != tc.wantStart || h.startOK != (tc.wantStart != "") {
				t.Fatalf("CallerStart = %q, %v; want %q", h.start, h.startOK, tc.wantStart)
			}
		})
	}
	if _, ok := CallerStart(context.Background()); ok {
		t.Fatal("CallerStart found a token in a bare context")
	}
	if _, ok := CallerStart(WithCallerStart(context.Background(), "")); ok {
		t.Fatal("an empty start token was recorded")
	}
}
