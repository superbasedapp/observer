package attachsock

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeControlHost is a Host that also implements Controller over an
// in-memory run table (the fake terminal service of the control tests).
type fakeControlHost struct {
	fakeHost
	mu        sync.Mutex
	runs      map[string]RunInfo
	launched  []LaunchSpec
	launchErr error
	stopped   []string
	reads     atomic.Int64
	// onRead, when set, mutates a run on every Run read (the run's life).
	onRead func(n int64, ri *RunInfo)
}

func newFakeControlHost() *fakeControlHost {
	return &fakeControlHost{runs: map[string]RunInfo{}}
}

func (h *fakeControlHost) LaunchDetached(_ context.Context, spec LaunchSpec) (RunInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.launchErr != nil {
		return RunInfo{}, h.launchErr
	}
	h.launched = append(h.launched, spec)
	ri := RunInfo{RunID: "run-1", Handle: "h-1", Tool: spec.Tool, Subcommand: "claude", Kind: "fresh", State: StateRunning, Sandboxed: spec.Sandbox != ""}
	h.runs[ri.RunID] = ri
	return ri, nil
}

func (h *fakeControlHost) Runs(context.Context) ([]RunInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []RunInfo
	for _, r := range h.runs {
		out = append(out, r)
	}
	return out, nil
}

func (h *fakeControlHost) Run(_ context.Context, ref string) (RunInfo, error) {
	n := h.reads.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, r := range h.runs {
		if id == ref || r.Handle == ref {
			if h.onRead != nil {
				h.onRead(n, &r)
				h.runs[id] = r
			}
			return r, nil
		}
	}
	return RunInfo{}, ErrRunNotFound
}

func (h *fakeControlHost) StopRun(_ context.Context, ref string) (RunInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.runs[ref]
	if !ok {
		return RunInfo{}, ErrRunNotFound
	}
	h.stopped = append(h.stopped, ref)
	r.State, r.EndReason = StateEnded, "cli_stop"
	h.runs[ref] = r
	return r, nil
}

func tightWaitPoll(t *testing.T) {
	t.Helper()
	old := waitPoll
	waitPoll = 5 * time.Millisecond
	t.Cleanup(func() { waitPoll = old })
}

func call(t *testing.T, host Host, req ControlRequest) (ControlResult, error) {
	t.Helper()
	cc := startServer(t, host)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return controlOn(ctx, cc, req)
}

// TestControlLaunchRoundTrip: the spec reaches the Controller verbatim and
// the run comes back with its id and handle.
func TestControlLaunchRoundTrip(t *testing.T) {
	h := newFakeControlHost()
	spec := LaunchSpec{Tool: "claude-code", Project: "/p", Sandbox: "auto", Workspace: "clone-local", Branch: "main", Model: "opus"}
	res, err := call(t, h, ControlRequest{Op: opLaunch, Launch: &spec})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if res.Run == nil || res.Run.RunID != "run-1" || res.Run.Handle != "h-1" || !res.Run.Sandboxed {
		t.Fatalf("run = %+v", res.Run)
	}
	if len(h.launched) != 1 || h.launched[0] != spec {
		t.Fatalf("controller saw %+v, want %+v", h.launched, spec)
	}
}

// TestControlLaunchRefusal: a coded refusal (a sandbox that cannot be
// built) reaches the client with its code; nothing is recorded as run.
func TestControlLaunchRefusal(t *testing.T) {
	h := newFakeControlHost()
	h.launchErr = &ControlError{Code: "sandbox_unavailable", Message: "sandbox backend gvisor is unavailable here"}
	_, err := call(t, h, ControlRequest{Op: opLaunch, Launch: &LaunchSpec{Tool: "claude-code", Project: "/p", Sandbox: "gvisor"}})
	var ce *ControlError
	if !errors.As(err, &ce) || ce.Code != "sandbox_unavailable" || ce.Message == "" {
		t.Fatalf("err = %v, want a sandbox_unavailable ControlError", err)
	}
	if len(h.runs) != 0 {
		t.Fatalf("a refused launch left a run: %+v", h.runs)
	}
}

// TestControlLaunchNeedsSpec refuses a launch frame with no spec.
func TestControlLaunchNeedsSpec(t *testing.T) {
	_, err := call(t, newFakeControlHost(), ControlRequest{Op: opLaunch})
	var ce *ControlError
	if !errors.As(err, &ce) || ce.Code != CodeProtocol {
		t.Fatalf("err = %v, want protocol", err)
	}
}

// TestControlListShowStop covers the inventory verbs and their codes.
func TestControlListShowStop(t *testing.T) {
	h := newFakeControlHost()
	res, err := call(t, h, ControlRequest{Op: opList})
	if err != nil || res.Runs == nil || len(res.Runs) != 0 {
		t.Fatalf("empty list = %+v, %v (want a non-nil empty list)", res.Runs, err)
	}
	h.runs["run-9"] = RunInfo{RunID: "run-9", Handle: "h-9", Tool: "codex", State: StateRunning}
	res, err = call(t, h, ControlRequest{Op: opList})
	if err != nil || len(res.Runs) != 1 || res.Runs[0].RunID != "run-9" {
		t.Fatalf("list = %+v, %v", res.Runs, err)
	}
	res, err = call(t, h, ControlRequest{Op: opShow, Run: "h-9"})
	if err != nil || res.Run == nil || res.Run.RunID != "run-9" {
		t.Fatalf("show by handle = %+v, %v", res.Run, err)
	}
	_, err = call(t, h, ControlRequest{Op: opShow, Run: "nope"})
	var ce *ControlError
	if !errors.As(err, &ce) || ce.Code != CodeNotFound {
		t.Fatalf("show unknown = %v, want not_found", err)
	}
	res, err = call(t, h, ControlRequest{Op: opStop, Run: "run-9"})
	if err != nil || res.Run.State != StateEnded || res.Run.EndReason != "cli_stop" {
		t.Fatalf("stop = %+v, %v", res.Run, err)
	}
	if len(h.stopped) != 1 {
		t.Fatalf("stopped = %v", h.stopped)
	}
	_, err = call(t, h, ControlRequest{Op: opStop, Run: "nope"})
	if !errors.As(err, &ce) || ce.Code != CodeNotFound {
		t.Fatalf("stop unknown = %v, want not_found", err)
	}
}

// TestControlWait covers the wait condition table.
func TestControlWait(t *testing.T) {
	tightWaitPoll(t)
	cases := []struct {
		name     string
		cond     string
		timeout  time.Duration
		life     func(n int64, ri *RunInfo)
		wantSess string
		wantSt   string
		timedOut bool
	}{
		{name: "session correlates on the third read", cond: WaitSession, life: func(n int64, ri *RunInfo) {
			if n >= 3 {
				ri.SessionID = "sess-1"
			}
		}, wantSess: "sess-1", wantSt: StateRunning},
		{name: "session wait ends when the run ends uncorrelated", cond: WaitSession, life: func(n int64, ri *RunInfo) {
			if n >= 2 {
				ri.State = StateEnded
			}
		}, wantSt: StateEnded},
		{name: "exit wait", cond: WaitExit, life: func(n int64, ri *RunInfo) {
			if n >= 4 {
				code := 0
				ri.State, ri.ExitCode = StateExited, &code
			}
		}, wantSt: StateExited},
		{name: "default condition is exit", cond: "", life: func(n int64, ri *RunInfo) {
			if n >= 2 {
				ri.State = StateEnded
			}
		}, wantSt: StateEnded},
		{name: "timeout returns the run and the flag", cond: WaitExit, timeout: 40 * time.Millisecond, life: func(int64, *RunInfo) {}, wantSt: StateRunning, timedOut: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeControlHost()
			h.runs["r"] = RunInfo{RunID: "r", Tool: "claude-code", State: StateRunning}
			h.onRead = tc.life
			res, err := call(t, h, ControlRequest{Op: opWait, Run: "r", For: tc.cond, Timeout: tc.timeout})
			if err != nil {
				t.Fatalf("wait: %v", err)
			}
			if res.TimedOut != tc.timedOut || res.Run == nil || res.Run.SessionID != tc.wantSess || res.Run.State != tc.wantSt {
				t.Fatalf("result = %+v run %+v", res, res.Run)
			}
		})
	}
}

// TestControlWaitRefusals: an unknown condition and an unknown run.
func TestControlWaitRefusals(t *testing.T) {
	tightWaitPoll(t)
	h := newFakeControlHost()
	h.runs["r"] = RunInfo{RunID: "r", State: StateRunning}
	var ce *ControlError
	if _, err := call(t, h, ControlRequest{Op: opWait, Run: "r", For: "forever"}); !errors.As(err, &ce) || ce.Code != CodeProtocol {
		t.Fatalf("unknown condition = %v", err)
	}
	if _, err := call(t, h, ControlRequest{Op: opWait, Run: "x"}); !errors.As(err, &ce) || ce.Code != CodeNotFound {
		t.Fatalf("unknown run = %v", err)
	}
}

// TestControlWaitEndsWhenClientHangsUp: a client that goes away stops the
// daemon's polling (no goroutine keeps reading the run forever).
func TestControlWaitEndsWhenClientHangsUp(t *testing.T) {
	tightWaitPoll(t)
	h := newFakeControlHost()
	h.runs["r"] = RunInfo{RunID: "r", State: StateRunning}
	cc := startServer(t, h)
	fc := newFrameConn(cc)
	if err := fc.sendControl(controlMsg{Op: opWait, V: ProtocolVersion, Run: "r"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	waitFor(t, "a few polls", func() bool { return h.reads.Load() >= 3 })
	_ = cc.Close()
	time.Sleep(30 * time.Millisecond)
	settled := h.reads.Load()
	time.Sleep(60 * time.Millisecond)
	if got := h.reads.Load(); got != settled {
		t.Fatalf("polling continued after hang-up: %d -> %d", settled, got)
	}
}

// TestControlUnsupportedHost: a Host without the Controller capability
// answers unsupported, and its spawn path is untouched.
func TestControlUnsupportedHost(t *testing.T) {
	_, err := call(t, newFakeHost(newFakeSession("H", "R")), ControlRequest{Op: opList})
	var ce *ControlError
	if !errors.As(err, &ce) || ce.Code != CodeUnsupported {
		t.Fatalf("err = %v, want unsupported", err)
	}
}

// TestControlBadVersion refuses another protocol version.
func TestControlBadVersion(t *testing.T) {
	cc := startServer(t, newFakeControlHost())
	fc := newFrameConn(cc)
	if err := fc.sendControl(controlMsg{Op: opList, V: ProtocolVersion + 1}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, payload, err := fc.readFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var em errorMsg
	if err := unmarshalControl(payload, &em); err != nil || em.Code != CodeProtocol {
		t.Fatalf("reply = %+v, %v", em, err)
	}
}

// TestControlAgainstOldDaemon: a daemon that only knows spawn answers the
// control frame as a malformed spawn; the client names that as too old.
func TestControlAgainstOldDaemon(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	go func() {
		fc := newFrameConn(serverConn)
		_, payload, err := fc.readFrame()
		if err != nil {
			return
		}
		op, _ := peekOp(payload)
		// The pre-control daemon's handshake: everything is a spawn.
		if _, perr := parseSpawn(op, payload); perr != nil {
			_ = fc.sendError(CodeProtocol, perr.Error())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := controlOn(ctx, clientConn, ControlRequest{Op: opList}); !errors.Is(err, ErrDaemonTooOld) {
		t.Fatalf("err = %v, want ErrDaemonTooOld", err)
	}
}

// TestControlCallRejectsUnknownOp never dials for an op it does not know.
func TestControlCallRejectsUnknownOp(t *testing.T) {
	if _, err := ControlCall(context.Background(), "/nonexistent/attach.sock", ControlRequest{Op: "spawn"}); err == nil {
		t.Fatal("spawn accepted as a control op")
	}
}

// TestRunInfoJSONShape pins the --json field names of a run.
func TestRunInfoJSONShape(t *testing.T) {
	code := 3
	b, err := json.Marshal(RunInfo{
		RunID: "r", Handle: "h", SessionID: "s", Tool: "claude-code", Subcommand: "claude", Kind: "fresh",
		State: StateExited, ExitCode: &code, EndReason: "child_exit", Sandboxed: true, Backend: "bwrap",
		Isolation: "namespace", Capture: "full", LaunchedAt: "2026-11-02T10:00:00Z", EndedAt: "2026-11-02T10:05:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := []string{"run_id", "handle", "session_id", "tool", "subcommand", "kind", "state", "exit_code", "end_reason", "sandboxed", "backend", "isolation", "capture", "launched_at", "ended_at"}
	keys := make([]string, 0, len(got))
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
		keys = append(keys, k)
	}
	if len(got) != len(want) {
		t.Errorf("keys = %v, want exactly %v", got, keys)
	}
	// The minimal run keeps the always-present keys only.
	b, _ = json.Marshal(RunInfo{RunID: "r", Tool: "t", State: StateRunning})
	var min map[string]any
	_ = json.Unmarshal(b, &min)
	if !reflect.DeepEqual(sortedKeys(min), []string{"run_id", "sandboxed", "state", "tool"}) {
		t.Errorf("minimal run = %s", b)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// TestNextWaitPoll: the wait backs off by doubling and stops at the cap.
func TestNextWaitPoll(t *testing.T) {
	d := waitPoll
	var seen []time.Duration
	for i := 0; i < 8; i++ {
		d = nextWaitPoll(d)
		seen = append(seen, d)
	}
	if seen[0] != 2*waitPoll || seen[len(seen)-1] != waitPollMax {
		t.Fatalf("backoff = %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] || seen[i] > waitPollMax {
			t.Fatalf("backoff not monotone and capped: %v", seen)
		}
	}
}

// TestControlWaitBacksOff: a long wait reads the run far fewer times than
// a fixed-interval poll would.
func TestControlWaitBacksOff(t *testing.T) {
	oldP, oldM := waitPoll, waitPollMax
	waitPoll, waitPollMax = 2*time.Millisecond, 32*time.Millisecond
	t.Cleanup(func() { waitPoll, waitPollMax = oldP, oldM })
	h := newFakeControlHost()
	h.runs["r"] = RunInfo{RunID: "r", State: StateRunning}
	res, err := call(t, h, ControlRequest{Op: opWait, Run: "r", Timeout: 400 * time.Millisecond})
	if err != nil || !res.TimedOut {
		t.Fatalf("wait = %+v, %v", res, err)
	}
	// A fixed 2ms poll would read about 200 times in 400ms; the backoff
	// reads about 5 + 400/32.
	if n := h.reads.Load(); n > 30 {
		t.Fatalf("read the run %d times in 400ms; the poll is not backing off", n)
	}
}

// TestControlWaitCap: past maxConcurrentWaits a wait is refused busy, and
// a slot frees when a wait ends.
func TestControlWaitCap(t *testing.T) {
	tightWaitPoll(t)
	old := maxConcurrentWaits
	maxConcurrentWaits = 2
	t.Cleanup(func() { maxConcurrentWaits = old })
	h := newFakeControlHost()
	h.runs["r"] = RunInfo{RunID: "r", State: StateRunning}
	s := &server{host: h, conns: make(map[*frameConn]net.Conn)}
	open := func() net.Conn {
		c, srv := net.Pipe()
		go s.serveConn(context.Background(), srv)
		t.Cleanup(func() { _ = c.Close(); _ = srv.Close() })
		return c
	}
	// Two waits that never end hold both slots.
	for i := 0; i < 2; i++ {
		if err := newFrameConn(open()).sendControl(controlMsg{Op: opWait, V: ProtocolVersion, Run: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "two waits in progress", func() bool { return s.activeWaits.Load() == 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := controlOn(ctx, open(), ControlRequest{Op: opWait, Run: "r"})
	var ce *ControlError
	if !errors.As(err, &ce) || ce.Code != CodeBusy {
		t.Fatalf("third wait = %v, want busy", err)
	}
	if s.activeWaits.Load() != 2 {
		t.Fatalf("a refused wait kept a slot: %d", s.activeWaits.Load())
	}
	// A wait that ends gives its slot back.
	h.mu.Lock()
	h.runs["r"] = RunInfo{RunID: "r", State: StateEnded}
	h.mu.Unlock()
	waitFor(t, "the waits to end", func() bool { return s.activeWaits.Load() == 0 })
	h.mu.Lock()
	h.runs["r"] = RunInfo{RunID: "r", State: StateEnded}
	h.mu.Unlock()
	if _, err := controlOn(ctx, open(), ControlRequest{Op: opWait, Run: "r"}); err != nil {
		t.Fatalf("a wait after the slots freed: %v", err)
	}
}
