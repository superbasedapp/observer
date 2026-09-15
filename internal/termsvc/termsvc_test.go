package termsvc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// testClock is a manually-advanced clock so the byMeta grace/GC tests
// (R2-2 / R2-7) can control time deterministically instead of sleeping.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: time.Unix(1_700_000_000, 0).UTC()} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// metaLen reads the retained per-handle classification count under the lock —
// the in-package view the R2-7 bound test asserts on.
func metaLen(s *Service) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byMeta)
}

// fakeRecorder captures run/correlation writes for assertions.
type fakeRecorder struct {
	mu         sync.Mutex
	runs       []termrun.Run
	ended      map[string]int
	endReasons map[string]string
	corr       []termrun.Correlation
	// guiSpawns captures the post-spawn GUI stamps (pid + wrap verdict), the
	// second write LaunchGUI makes on the same row.
	guiSpawns   []termrun.Run
	guiSpawnErr error
	recordErr   error
	corrErr     error
	endCalls    int
	recordCalls int
	corrCalls   int
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{ended: map[string]int{}, endReasons: map[string]string{}}
}

func (f *fakeRecorder) RecordRun(_ context.Context, run termrun.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordCalls++
	if f.recordErr != nil {
		return f.recordErr
	}
	f.runs = append(f.runs, run)
	return nil
}

func (f *fakeRecorder) EndRun(_ context.Context, runID string, _ time.Time, code int, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endCalls++
	f.ended[runID] = code
	f.endReasons[runID] = reason
	return nil
}

func (f *fakeRecorder) RecordCorrelation(_ context.Context, c termrun.Correlation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.corrCalls++
	if f.corrErr != nil {
		return f.corrErr
	}
	f.corr = append(f.corr, c)
	return nil
}

func (f *fakeRecorder) RecordGUISpawn(_ context.Context, run termrun.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.guiSpawnErr != nil {
		return f.guiSpawnErr
	}
	f.guiSpawns = append(f.guiSpawns, run)
	return nil
}

// fakeLauncher records the request and returns a fixed handle (or an error).
type fakeLauncher struct {
	handle  string
	err     error
	lastReq LaunchRequest
	calls   int
}

func (f *fakeLauncher) Spawn(req LaunchRequest) (string, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return "", f.err
	}
	return f.handle, nil
}

// seqLauncher mints a distinct handle per Spawn ("h-1", "h-2", …) so a test can
// drive many runs through the one Service (the R2-7 bound test).
type seqLauncher struct{ n int }

func (s *seqLauncher) Spawn(LaunchRequest) (string, error) {
	s.n++
	return fmt.Sprintf("h-%d", s.n), nil
}

func newService(t *testing.T, policy Policy, rec RunRecorder, l Launcher, feed *termfeed.Feed) *Service {
	t.Helper()
	return New(Options{
		Policy: policy, Recorder: rec, Launcher: l, Feed: feed,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
}

func TestLaunchFreshAuthorizationGate(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H1"}
	tests := []struct {
		name    string
		policy  Policy
		req     FreshRequest
		wantErr error
	}{
		{
			name:    "disabled by default",
			policy:  Policy{},
			req:     FreshRequest{Tool: "claude-code", Subcommand: "claude"},
			wantErr: ErrFreshLaunchDisabled,
		},
		{
			name:    "tool not in allow-list",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"codex"}},
			req:     FreshRequest{Tool: "claude-code", Subcommand: "claude"},
			wantErr: ErrToolNotAllowed,
		},
		{
			name:    "allowed tool no project root",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
			req:     FreshRequest{Tool: "claude-code", Subcommand: "claude"},
			wantErr: nil,
		},
		{
			name:    "project root denied (no allow-list)",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
			req:     FreshRequest{Tool: "claude-code", Subcommand: "claude", ProjectRoot: t.TempDir()},
			wantErr: ErrProjectRootDenied,
		},
		{
			name:    "shell disabled by default even with fresh-agent allowed",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
			req:     FreshRequest{Shell: true},
			wantErr: ErrShellLaunchDisabled,
		},
		{
			name:    "shell allowed, no tool allow-list required",
			policy:  Policy{AllowShell: true},
			req:     FreshRequest{Shell: true},
			wantErr: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := newService(t, tc.policy, rec, l, nil)
			_, err := svc.LaunchFresh(context.Background(), tc.req)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestLaunchFreshSuccessMintsRun(t *testing.T) {
	rec := newFakeRecorder()
	feed := termfeed.New(termfeed.Options{})
	sub := feed.Subscribe()
	defer feed.Unsubscribe(sub)
	l := &fakeLauncher{handle: "HANDLE"}
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, l, feed)

	res, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude", Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if res.Handle != "HANDLE" || res.RunID == "" {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("expected 1 run recorded, got %d", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindFresh || run.Tool != "claude-code" || run.RunID != res.RunID {
		t.Fatalf("run = %+v", run)
	}
	if run.CorrelationTokenHash == "" {
		t.Fatal("expected a correlation token hash on the run")
	}
	// The launcher got a server-derived request with the raw nonce (never
	// persisted) and the fresh kind.
	if l.lastReq.Kind != termrun.KindFresh || l.lastReq.Subcommand != "claude" || l.lastReq.CorrelationToken == "" {
		t.Fatalf("launch request = %+v", l.lastReq)
	}
	if got, ok := svc.RunIDForHandle("HANDLE"); !ok || got != res.RunID {
		t.Fatalf("handle mapping = %q,%v", got, ok)
	}
	// A launch event reached the feed.
	select {
	case ev := <-sub.C():
		if ev.RunID != res.RunID || ev.Trust != termfeed.TrustTrusted {
			t.Fatalf("feed event = %+v", ev)
		}
	default:
		t.Fatal("expected a launch event on the feed")
	}
}

// TestLaunchFreshModelComposition pins the B5 New Terminal model picker's
// composition seam inside LaunchFresh: given a non-empty FreshRequest.Model,
// the tool's capability-registry ModelSpec decides whether it lands on
// LaunchRequest.ExtraArgs, ExtraEnv, both, or neither — dispatch on
// capability SHAPE (ModelSpec.Kind), never tool name.
func TestLaunchFreshModelComposition(t *testing.T) {
	tests := []struct {
		name          string
		tool          string
		model         string
		wantExtraArgs []string
		wantExtraEnv  []string
	}{
		{
			// claude-code: ModelSpec{Kind: ModelArg, Flag: "--model"}.
			name:          "ModelArg tool composes --model flag",
			tool:          "claude-code",
			model:         "opus",
			wantExtraArgs: []string{"--model", "opus"},
		},
		{
			// goose: ModelSpec{Kind: ModelEnv, EnvVar: "GOOSE_MODEL"}.
			name:         "ModelEnv tool composes an env var, no argv",
			tool:         "goose",
			model:        "gpt-5",
			wantExtraEnv: []string{"GOOSE_MODEL=gpt-5"},
		},
		{
			// kiro-cli: ModelSpec{Kind: ModelArg, Flag: "--model", Lead: []string{"chat"}}.
			name:          "ModelArg tool with a Lead prefix composes lead+flag+value",
			tool:          "kiro-cli",
			model:         "claude-3.7",
			wantExtraArgs: []string{"chat", "--model", "claude-3.7"},
		},
		{
			// openclaw: ModelSpec{Kind: ModelNone} — explicit no-op.
			name:  "ModelNone tool drops the model, launch still succeeds",
			tool:  "openclaw",
			model: "some-model",
		},
		{
			name:  "empty model leaves the launch untouched",
			tool:  "claude-code",
			model: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			l := &fakeLauncher{handle: "H-MODEL"}
			svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{tc.tool}}, rec, l, nil)

			res, err := svc.LaunchFresh(context.Background(), FreshRequest{
				Tool: tc.tool, Subcommand: tc.tool, Model: tc.model,
			})
			if err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}
			if res.Handle != "H-MODEL" {
				t.Fatalf("result = %+v", res)
			}
			if !stringSlicesEqual(l.lastReq.ExtraArgs, tc.wantExtraArgs) {
				t.Errorf("ExtraArgs = %v, want %v", l.lastReq.ExtraArgs, tc.wantExtraArgs)
			}
			if !stringSlicesEqual(l.lastReq.ExtraEnv, tc.wantExtraEnv) {
				t.Errorf("ExtraEnv = %v, want %v", l.lastReq.ExtraEnv, tc.wantExtraEnv)
			}
		})
	}
}

// stringSlicesEqual treats nil and empty as equal (LaunchFresh leaves
// ExtraArgs/ExtraEnv nil rather than an empty-but-non-nil slice when there's
// nothing to compose).
func stringSlicesEqual(a, b []string) bool {
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

func TestLaunchShellSuccessMintsRun(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "SHELLHANDLE"}
	// AllowFresh is deliberately FALSE — shell authorization must be
	// independent of the AI-tool fresh-launch gate.
	svc := newService(t, Policy{AllowShell: true}, rec, l, nil)

	res, err := svc.LaunchFresh(context.Background(), FreshRequest{Shell: true, Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("LaunchFresh(shell): %v", err)
	}
	if res.Handle != "SHELLHANDLE" || res.RunID == "" {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("expected 1 run recorded, got %d", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindFresh || run.Tool != ShellTool {
		t.Fatalf("run = %+v, want Tool=%q", run, ShellTool)
	}
	if !l.lastReq.IsShell {
		t.Fatalf("launch request = %+v, want IsShell=true", l.lastReq)
	}
}

func TestLaunchSpawnFailureClosesRun(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{err: errors.New("spawn boom")}
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, l, nil)
	_, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude"})
	if err == nil {
		t.Fatal("expected spawn error")
	}
	// The run was recorded then closed out (never left dangling as running).
	if rec.recordCalls != 1 || rec.endCalls != 1 {
		t.Fatalf("record=%d end=%d, want 1/1", rec.recordCalls, rec.endCalls)
	}
}

func TestLaunchHandoffMintsRunWithSource(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	// Handoff does NOT consult the fresh allow-list.
	svc := newService(t, Policy{}, rec, l, nil)
	res, err := svc.LaunchHandoff(context.Background(), HandoffRequest{
		Tool: "codex", Subcommand: "codex", SessionID: "sess-1", Carry: "distilled_tail",
	})
	if err != nil {
		t.Fatalf("LaunchHandoff: %v", err)
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindHandoff || run.SourceSessionID != "sess-1" {
		t.Fatalf("run = %+v", run)
	}
	if run.ProjectRootHash != "" {
		t.Fatalf("handoff run should carry no project-root hash, got %q", run.ProjectRootHash)
	}
	if l.lastReq.SessionID != "sess-1" || l.lastReq.Carry != "distilled_tail" {
		t.Fatalf("launch request = %+v", l.lastReq)
	}
	_ = res
}

func TestLaunchAttachableMintsAttachRun(t *testing.T) {
	rec := newFakeRecorder()
	feed := termfeed.New(termfeed.Options{})
	sub := feed.Subscribe()
	defer feed.Unsubscribe(sub)
	l := &fakeLauncher{handle: "ATTACH"}
	// A policy that DENIES every fresh launch — attach must bypass it.
	svc := newService(t, Policy{}, rec, l, feed)

	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{
		Tool:       "claude-code",
		Subcommand: "claude",
		Rows:       40,
		Cols:       120,
		ExtraEnv:   []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:8820"},
		ExtraArgs:  []string{"--no-proxy-route", "--", "--model", "x"},
	})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	if res.Handle != "ATTACH" || res.RunID == "" {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("expected 1 run recorded, got %d", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindAttach || run.Tool != "claude-code" || run.RunID != res.RunID {
		t.Fatalf("run = %+v", run)
	}
	// Recorded BEFORE spawn: the recorder saw the run and the launcher was hit.
	if rec.recordCalls != 1 || l.calls != 1 {
		t.Fatalf("record=%d spawn=%d, want 1/1", rec.recordCalls, l.calls)
	}
	// ExtraEnv + kind propagated to the launcher's request.
	if l.lastReq.Kind != termrun.KindAttach || l.lastReq.Subcommand != "claude" {
		t.Fatalf("launch request = %+v", l.lastReq)
	}
	if len(l.lastReq.ExtraEnv) != 1 || l.lastReq.ExtraEnv[0] != "ANTHROPIC_BASE_URL=http://127.0.0.1:8820" {
		t.Fatalf("extra env = %v", l.lastReq.ExtraEnv)
	}
	// ExtraArgs (the allow-listed argv escape hatch + tool remainder) reaches
	// the launcher unmodified (B2/B3).
	wantArgs := []string{"--no-proxy-route", "--", "--model", "x"}
	if len(l.lastReq.ExtraArgs) != len(wantArgs) {
		t.Fatalf("extra args = %v, want %v", l.lastReq.ExtraArgs, wantArgs)
	}
	for i := range wantArgs {
		if l.lastReq.ExtraArgs[i] != wantArgs[i] {
			t.Fatalf("extra args[%d] = %q, want %q", i, l.lastReq.ExtraArgs[i], wantArgs[i])
		}
	}
	if got, ok := svc.RunIDForHandle("ATTACH"); !ok || got != res.RunID {
		t.Fatalf("handle mapping = %q,%v", got, ok)
	}
	// A launch event reached the feed under the attach kind.
	select {
	case ev := <-sub.C():
		if ev.RunID != res.RunID || ev.Trust != termfeed.TrustTrusted {
			t.Fatalf("feed event = %+v", ev)
		}
	default:
		t.Fatal("expected a launch event on the feed")
	}
}

func TestLaunchAttachableBypassesFreshAllowLists(t *testing.T) {
	// The exact policy that TestLaunchFreshAuthorizationGate proves denies a
	// fresh claude-code launch (AllowFresh:false) must STILL permit an attach
	// launch of the same tool — the attach socket's 0600 owner-only perms are
	// the authorization, not the dashboard allow-lists (§3.3).
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	denyAll := Policy{} // AllowFresh false, empty AllowedTools
	svc := newService(t, denyAll, rec, l, nil)

	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude"}); !errors.Is(err, ErrFreshLaunchDisabled) {
		t.Fatalf("LaunchFresh under deny-all should fail, got %v", err)
	}
	if _, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"}); err != nil {
		t.Fatalf("LaunchAttachable under the same deny-all policy should succeed, got %v", err)
	}
}

func TestLaunchAttachableValidation(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	svc := newService(t, Policy{}, rec, l, nil)
	tests := []struct {
		name    string
		req     AttachRequest
		wantErr error
	}{
		{"empty tool", AttachRequest{Subcommand: "claude"}, ErrAttachToolRequired},
		{"empty subcommand", AttachRequest{Tool: "claude-code"}, ErrAttachSubcommandRequired},
		{"relative dir", AttachRequest{Tool: "claude-code", Subcommand: "claude", Dir: "rel/path"}, ErrAttachDirNotAbsolute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.LaunchAttachable(context.Background(), tc.req); !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
	// No spawn should have happened for any invalid request.
	if l.calls != 0 {
		t.Fatalf("expected no spawns for invalid requests, got %d", l.calls)
	}
}

func TestEndRunByHandle(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "HX"}
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, l, nil)
	res, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	svc.EndRunByHandle(context.Background(), "HX", 7)
	if rec.ended[res.RunID] != 7 {
		t.Fatalf("expected exit 7 recorded, got %v", rec.ended)
	}
	// Handle mapping is forgotten; a second call is a no-op.
	if _, ok := svc.RunIDForHandle("HX"); ok {
		t.Fatal("handle should be forgotten after exit")
	}
	svc.EndRunByHandle(context.Background(), "HX", 9)
	if rec.endCalls != 1 {
		t.Fatalf("expected exactly 1 EndRun, got %d", rec.endCalls)
	}
}

// TestLaunchReconcilesPreRegistrationExit is finding-1(a): a child that exits in
// the window between Spawn returning and the handle→run mapping being installed
// leaves the Manager's OnExit → EndRunByHandle with NO mapping (a silent no-op),
// so the exit would otherwise never be recorded and neither term:exit nor the
// direct OnRunExit seam would fire. launch() must reconcile against the
// authoritative ExitStatus the instant it installs the mapping and run the SAME
// end path — recording child_exit AND firing OnRunExit — exactly once. This is
// the missing-producer case the round-3 tests assumed away.
func TestLaunchReconcilesPreRegistrationExit(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}

	var mu sync.Mutex
	var exitedRuns []string
	svc := New(Options{
		Recorder: rec,
		Launcher: l,
		Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		// The child has ALREADY exited by the time the mapping is installed —
		// modelling the pre-registration race deterministically.
		ExitStatus: func(handle string) (bool, int, bool) {
			if handle == "H" {
				return true, 3, true
			}
			return false, 0, false
		},
		OnRunExit: func(runID string) {
			mu.Lock()
			exitedRuns = append(exitedRuns, runID)
			mu.Unlock()
		},
	})

	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	// The reconcile recorded the exit (child_exit) with the child's code...
	if rec.ended[res.RunID] != 3 {
		t.Fatalf("reconcile recorded exit %d, want 3", rec.ended[res.RunID])
	}
	if rec.endReasons[res.RunID] != reasonChildExit {
		t.Fatalf("reconcile end reason = %q, want %q", rec.endReasons[res.RunID], reasonChildExit)
	}
	// ...and fired the DIRECT exit seam exactly once for the run.
	mu.Lock()
	n, first := len(exitedRuns), ""
	if n > 0 {
		first = exitedRuns[0]
	}
	mu.Unlock()
	if n != 1 || first != res.RunID {
		t.Fatalf("OnRunExit fired %v, want exactly [%s]", exitedRuns, res.RunID)
	}
	// The live mappings are gone, so a later real OnExit for the same handle is
	// the idempotent no-op — it must NOT fire OnRunExit a second time.
	if _, ok := svc.RunIDForHandle("H"); ok {
		t.Fatal("handle mapping must be cleared after the reconcile end")
	}
	svc.EndRunByHandle(context.Background(), "H", 3)
	mu.Lock()
	n2 := len(exitedRuns)
	mu.Unlock()
	if n2 != 1 {
		t.Fatalf("a second EndRunByHandle fired OnRunExit again (total %d) — must be idempotent", n2)
	}
	if rec.endCalls != 1 {
		t.Fatalf("EndRun called %d times, want exactly 1 (idempotent)", rec.endCalls)
	}
}

// TestLaunchNoReconcileWhenChildLive verifies the reconcile is inert when the
// child is still running at mapping-install time: no exit is recorded, the direct
// seam does not fire, and the handle stays live-tracked for the normal OnExit
// path to end later.
func TestLaunchNoReconcileWhenChildLive(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	fired := 0
	svc := New(Options{
		Recorder:   rec,
		Launcher:   l,
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		ExitStatus: func(string) (bool, int, bool) { return false, 0, true }, // still live
		OnRunExit:  func(string) { fired++ },
	})
	if _, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"}); err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	if rec.endCalls != 0 {
		t.Fatalf("endCalls = %d, want 0 (child still live)", rec.endCalls)
	}
	if fired != 0 {
		t.Fatalf("OnRunExit fired %d times, want 0", fired)
	}
	if _, ok := svc.RunIDForHandle("H"); !ok {
		t.Fatal("handle must remain live-tracked when the child is still running")
	}
}

func TestKindForHandleLifecycle(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "AH"}
	clk := newTestClock()
	svc := New(Options{Policy: Policy{}, Recorder: rec, Launcher: l, Now: clk.now})

	// Before any launch the handle is unknown.
	if _, _, ok := svc.KindForHandle("AH"); ok {
		t.Fatal("KindForHandle should be unknown before launch")
	}

	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	// Set on spawn success: the attach kind + the target tool NAME (not the
	// launcher verb).
	kind, tool, ok := svc.KindForHandle("AH")
	if !ok || kind != termrun.KindAttach || tool != "claude-code" {
		t.Fatalf("KindForHandle = (%q,%q,%v), want (attach, claude-code, true)", kind, tool, ok)
	}

	// F1: KindForHandle is RETAINED after EndRunByHandle — the daemon-observed
	// exit only starts termsession's ExitLinger, during which the PTY is still
	// subscribable and the remote sensitivity gates MUST keep classifying the
	// handle. The live-run maps (RunIDForHandle) are gone, but byMeta survives.
	svc.EndRunByHandle(context.Background(), "AH", 0)
	if _, ok := svc.RunIDForHandle("AH"); ok {
		t.Fatal("RunIDForHandle should be forgotten after EndRunByHandle (live-run map)")
	}
	if kind, tool, ok := svc.KindForHandle("AH"); !ok || kind != termrun.KindAttach || tool != "claude-code" {
		t.Fatalf("KindForHandle after exit = (%q,%q,%v), want (attach, claude-code, true) — classification must survive linger", kind, tool, ok)
	}

	// PruneEndedHandles WITH the handle still in the Manager's live set keeps it.
	svc.PruneEndedHandles(map[string]struct{}{"AH": {}})
	if _, _, ok := svc.KindForHandle("AH"); !ok {
		t.Fatal("KindForHandle must survive a prune while the Manager still holds the handle")
	}

	// The Manager reaped the handle (absent from the live set), but the entry is
	// still WITHIN the grace, so a prune does NOT drop it yet (R2-2: grace, not
	// mere set-absence, is the aging clock — this is what keeps a just-ended
	// handle classified against a stale live set).
	svc.PruneEndedHandles(map[string]struct{}{})
	if _, _, ok := svc.KindForHandle("AH"); !ok {
		t.Fatal("KindForHandle must survive a prune while still within endedHandleGrace")
	}

	// Past the grace, the next prune drops the long-dead classification.
	clk.advance(endedHandleGrace + time.Second)
	svc.PruneEndedHandles(map[string]struct{}{})
	if _, _, ok := svc.KindForHandle("AH"); ok {
		t.Fatal("KindForHandle should be pruned once an ended handle ages past endedHandleGrace")
	}
	_ = res
}

// TestPruneEndedHandlesStaleSetSurvives pins R2-2: a byMeta entry for a run that
// registered+exited AFTER a Snapshot captured its live-handle set must survive a
// prune driven by that STALE set. The reviewer's interleaving: (1) a snapshot
// captures a set WITHOUT handle H; (2) H registers + is classified sensitive;
// (3) H exits (EndRunByHandle drops the live-run maps, Manager keeps it for
// linger); (4) the OLD stale set prunes. Pre-fix, step (4) deleted byMeta[H] and
// made KindForHandle(H) false mid-linger; with the endedAt stamp + grace, H is
// retained through its whole linger.
func TestPruneEndedHandlesStaleSetSurvives(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H"}
	clk := newTestClock()
	svc := New(Options{Recorder: rec, Launcher: l, Now: clk.now})

	// (1) A snapshot captured BEFORE H registers — the empty set (H doesn't exist).
	staleSet := map[string]struct{}{}

	// (2) H registers and is classified sensitive.
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	if kind, _, ok := svc.KindForHandle("H"); !ok || !termrun.IsRemoteSensitiveKind(kind) {
		t.Fatal("live attach handle must be remote-sensitive")
	}

	// (3) H exits.
	svc.EndRunByHandle(context.Background(), "H", 0)

	// (4) The OLD, STALE set (which never saw H) prunes. H's endedAt is far
	// younger than the grace, so it must be RETAINED — classification survives.
	svc.PruneEndedHandles(staleSet)
	if kind, _, ok := svc.KindForHandle("H"); !ok || !termrun.IsRemoteSensitiveKind(kind) {
		t.Fatal("R2-2: a just-ended handle must survive a stale-set prune through its linger")
	}
	_ = res
}

// TestEndedMetaBoundedWithoutPrune pins R2-7: on a daemon driven ONLY through
// repeated attach sessions — no dashboard Snapshot ever calls PruneEndedHandles
// — the opportunistic GC in EndRunByHandle keeps byMeta bounded rather than
// leaking one entry per ended run until restart.
func TestEndedMetaBoundedWithoutPrune(t *testing.T) {
	rec := newFakeRecorder()
	clk := newTestClock()
	svc := New(Options{Recorder: rec, Launcher: &seqLauncher{}, Now: clk.now})

	const runs = endedHandleGCBound * 3
	for i := 0; i < runs; i++ {
		res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
		if err != nil {
			t.Fatalf("LaunchAttachable %d: %v", i, err)
		}
		h, ok := svc.HandleForRun(res.RunID)
		if !ok {
			t.Fatalf("no handle for run %d", i)
		}
		// Age the PREVIOUS ended entries past the grace before ending this one, so
		// the GC (which only sheds past-grace entries) can reclaim them.
		clk.advance(endedHandleGrace + time.Second)
		svc.EndRunByHandle(context.Background(), h, 0)
	}

	// Never called PruneEndedHandles, yet byMeta stayed bounded near the GC
	// high-water mark — NOT ~runs (which would be the unbounded leak).
	if n := metaLen(svc); n > endedHandleGCBound+1 {
		t.Fatalf("byMeta grew to %d entries without a Prune call — GC did not bound it (want <= %d)", n, endedHandleGCBound+1)
	}
}

// TestEndedMetaGCTriggeredByReadAfterBurst pins F4: a burst of short runs that
// all END within one grace window leaves every entry too young for the
// EndRunByHandle-time GC (it skips every entry as too young). If activity then
// stops and no dashboard Snapshot ever calls PruneEndedHandles, nothing
// re-triggers the GC once the grace lapses — UNTIL the next read-path call. This
// test ends the WHOLE burst within one grace window (so the exit-time GC sheds
// nothing), advances the clock past the grace, then makes a SINGLE KindForHandle
// call and asserts the aged burst was reclaimed there (the opportunistic
// read-path GC), rather than lingering until a Snapshot or daemon restart.
func TestEndedMetaGCTriggeredByReadAfterBurst(t *testing.T) {
	rec := newFakeRecorder()
	clk := newTestClock()
	svc := New(Options{Recorder: rec, Launcher: &seqLauncher{}, Now: clk.now})

	const runs = endedHandleGCBound * 3
	handles := make([]string, 0, runs)
	for i := 0; i < runs; i++ {
		res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
		if err != nil {
			t.Fatalf("LaunchAttachable %d: %v", i, err)
		}
		h, ok := svc.HandleForRun(res.RunID)
		if !ok {
			t.Fatalf("no handle for run %d", i)
		}
		handles = append(handles, h)
	}
	// End the WHOLE burst within one grace window (NO clock advance between ends),
	// so every EndRunByHandle-time GC sees every ended entry as too young and
	// sheds nothing — byMeta holds the full burst.
	for _, h := range handles {
		svc.EndRunByHandle(context.Background(), h, 0)
	}
	if n := metaLen(svc); n < runs {
		t.Fatalf("a burst ended within the grace should retain all %d entries (exit-time GC too-young), have %d", runs, n)
	}

	// Activity stops; no PruneEndedHandles ever runs. Advance past the grace, then
	// a single read-path call reclaims the now-aged burst (F4).
	clk.advance(endedHandleGrace + time.Second)
	_, _, _ = svc.KindForHandle("nonexistent-handle")
	if n := metaLen(svc); n > endedHandleGCBound+1 {
		t.Fatalf("a KindForHandle call after the grace did not bound the idle burst: have %d (want <= %d)", n, endedHandleGCBound+1)
	}
}

func TestKindForHandleRecordsHandoffAndFreshKinds(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, &fakeLauncher{handle: "FH"}, nil)
	if _, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: "claude-code", Subcommand: "claude"}); err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if kind, tool, ok := svc.KindForHandle("FH"); !ok || kind != termrun.KindFresh || tool != "claude-code" {
		t.Fatalf("fresh KindForHandle = (%q,%q,%v)", kind, tool, ok)
	}

	rec2 := newFakeRecorder()
	svc2 := newService(t, Policy{}, rec2, &fakeLauncher{handle: "HH"}, nil)
	if _, err := svc2.LaunchHandoff(context.Background(), HandoffRequest{Tool: "codex", Subcommand: "codex", SessionID: "sess-9"}); err != nil {
		t.Fatalf("LaunchHandoff: %v", err)
	}
	if kind, tool, ok := svc2.KindForHandle("HH"); !ok || kind != termrun.KindHandoff || tool != "codex" {
		t.Fatalf("handoff KindForHandle = (%q,%q,%v)", kind, tool, ok)
	}
}

func TestSessionForRunAfterCorrelate(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{}, rec, &fakeLauncher{handle: "SH"}, nil)
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	// No established link yet — an attach run carries no source session at spawn.
	if _, ok := svc.SessionForRun(res.RunID); ok {
		t.Fatal("SessionForRun should be empty before any correlation")
	}

	// A WEAK (heuristic, 0.40 < MinLinkConfidence) observation does NOT surface
	// a session id — links attach only once established.
	at := time.Unix(1_700_000_200, 0).UTC()
	if err := svc.Correlate(context.Background(), res.RunID, "sess-weak", termrun.SourceHeuristic, at); err != nil {
		t.Fatalf("Correlate heuristic: %v", err)
	}
	if _, ok := svc.SessionForRun(res.RunID); ok {
		t.Fatal("a sub-threshold heuristic correlation must not fill a session id")
	}

	// An OOB (0.95) observation IS established → SessionForRun surfaces it.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-strong", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate oob: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-strong" {
		t.Fatalf("SessionForRun = (%q,%v), want (sess-strong, true)", sid, ok)
	}

	// Cleaned up when the run ends.
	svc.EndRunByHandle(context.Background(), "SH", 0)
	if _, ok := svc.SessionForRun(res.RunID); ok {
		t.Fatal("SessionForRun should be forgotten after EndRunByHandle")
	}
}

// TestSessionLinkForRun covers the confidence-carrying companion of
// SessionForRun: an unknown run reports ok=false with zero confidence, an
// established link returns id+confidence, and a MAX-upgrade is visible through
// the confidence field (a stronger source raises the reported confidence; a
// weaker later observation never lowers it).
func TestSessionLinkForRun(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{}, rec, &fakeLauncher{handle: "SH"}, nil)
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	at := time.Unix(1_700_000_200, 0).UTC()

	// A sequence of correlations, each with the id + confidence
	// SessionLinkForRun must report AFTER it lands. correlate=="" means "no
	// correlation applied yet" (the initial probe).
	steps := []struct {
		name      string
		correlate string
		source    termrun.Source
		wantOK    bool
		wantID    string
		wantConf  float64
	}{
		{name: "before any correlation", correlate: "", wantOK: false, wantID: "", wantConf: 0},
		{name: "sub-threshold heuristic stays unlinked", correlate: "sess-weak", source: termrun.SourceHeuristic, wantOK: false, wantID: "", wantConf: 0},
		{name: "marker establishes link with its confidence", correlate: "sess-marker", source: termrun.SourceMarker, wantOK: true, wantID: "sess-marker", wantConf: 0.70},
		{name: "OOB MAX-upgrade raises confidence", correlate: "sess-oob", source: termrun.SourceOOB, wantOK: true, wantID: "sess-oob", wantConf: 0.95},
		{name: "weaker marker never downgrades", correlate: "sess-weak-marker", source: termrun.SourceMarker, wantOK: true, wantID: "sess-oob", wantConf: 0.95},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.correlate != "" {
				if err := svc.Correlate(context.Background(), res.RunID, st.correlate, st.source, at); err != nil {
					t.Fatalf("Correlate: %v", err)
				}
			}
			sid, conf, ok := svc.SessionLinkForRun(res.RunID)
			if ok != st.wantOK || sid != st.wantID || conf != st.wantConf {
				t.Fatalf("SessionLinkForRun = (%q, %v, %v), want (%q, %v, %v)", sid, conf, ok, st.wantID, st.wantConf, st.wantOK)
			}
		})
	}

	// Unknown run: never launched → ok=false, zeroed.
	if sid, conf, ok := svc.SessionLinkForRun("ghost-run"); ok || sid != "" || conf != 0 {
		t.Fatalf("SessionLinkForRun(unknown) = (%q, %v, %v), want (\"\", 0, false)", sid, conf, ok)
	}

	// Cleaned up when the run ends (same lifecycle as SessionForRun).
	svc.EndRunByHandle(context.Background(), "SH", 0)
	if _, _, ok := svc.SessionLinkForRun(res.RunID); ok {
		t.Fatal("SessionLinkForRun should be forgotten after EndRunByHandle")
	}
}

// TestResolveHandleLink pins the single-lock composition (F4): one call resolves
// liveness + run identity (kind/tool) + correlation (session id/confidence)
// atomically, matching the three-call chain it replaces, and reports ok=false
// for an unknown/exited handle.
func TestResolveHandleLink(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{}, rec, &fakeLauncher{handle: "SH"}, nil)

	// Unknown handle: never launched → ok=false, everything zeroed.
	if runID, kind, tool, sid, conf, ok := svc.ResolveHandleLink("ghost"); ok || runID != "" || kind != "" || tool != "" || sid != "" || conf != 0 {
		t.Fatalf("ResolveHandleLink(unknown) = (%q,%q,%q,%q,%v,%v), want all-zero+false", runID, kind, tool, sid, conf, ok)
	}

	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	// Live but uncorrelated: known=true, run identity present, empty session link.
	runID, kind, tool, sid, conf, ok := svc.ResolveHandleLink(res.Handle)
	if !ok || runID != res.RunID || tool != "claude-code" || sid != "" || conf != 0 {
		t.Fatalf("ResolveHandleLink(live, uncorrelated) = (%q,%q,%q,%q,%v,%v), want (%q, attach-kind, claude-code, \"\", 0, true)",
			runID, kind, tool, sid, conf, ok, res.RunID)
	}
	if kind == "" {
		t.Fatalf("expected a non-empty run Kind for a launched attach run")
	}

	// After an established (OOB) correlation the same call carries the session id
	// + confidence — identical to chaining RunIDForHandle→KindForHandle→
	// SessionLinkForRun, but under one lock.
	at := time.Unix(1_700_000_200, 0).UTC()
	if err := svc.Correlate(context.Background(), res.RunID, "sess-strong", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	_, _, _, sid, conf, ok = svc.ResolveHandleLink(res.Handle)
	if !ok || sid != "sess-strong" || conf != 0.95 {
		t.Fatalf("ResolveHandleLink(correlated) session = (%q, %v, %v), want (sess-strong, 0.95, true)", sid, conf, ok)
	}
	// Cross-check parity with the composed chain it replaces.
	wantSID, wantConf, wantOK := svc.SessionLinkForRun(res.RunID)
	if sid != wantSID || conf != wantConf || ok != wantOK {
		t.Fatalf("ResolveHandleLink vs SessionLinkForRun mismatch: (%q,%v,%v) vs (%q,%v,%v)", sid, conf, ok, wantSID, wantConf, wantOK)
	}

	// Exited handle: forgotten by the live maps → ok=false.
	svc.EndRunByHandle(context.Background(), res.Handle, 0)
	if _, _, _, _, _, ok := svc.ResolveHandleLink(res.Handle); ok {
		t.Fatal("ResolveHandleLink should report ok=false after EndRunByHandle")
	}
}

// TestCorrelateUnknownRunNoCacheEntry pins P2-3 (a): a Correlate for a run the
// service never launched records the durable store correlation but NEVER
// populates the in-memory bySession cache (which is a strict subset of live
// runs). Otherwise an unknown/never-launched run id could leave a cache entry
// nothing can ever delete.
func TestCorrelateUnknownRunNoCacheEntry(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{}, rec, &fakeLauncher{}, nil)
	at := time.Unix(1_700_000_100, 0).UTC()
	if err := svc.Correlate(context.Background(), "ghost-run", "sess-x", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	// Store records it (durable), but the live cache must stay empty.
	if len(rec.corr) != 1 {
		t.Fatalf("store should record the correlation, got %d", len(rec.corr))
	}
	if _, ok := svc.SessionForRun("ghost-run"); ok {
		t.Fatal("SessionForRun must be empty for a run the service never launched (no cache resurrection)")
	}
}

// TestCorrelateEndedDuringCorrelationNoResurrection pins P2-3 (a): once a run
// has ended (EndRunByHandle deleted its maps), a late Correlate for that run —
// e.g. a store write that was in flight when the run exited — must NOT recreate
// its bySession entry. RecordCorrelation runs without the lock, so this models
// the end landing between the store write and the cache update.
func TestCorrelateEndedDuringCorrelationNoResurrection(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "EH"}
	svc := newService(t, Policy{}, rec, l, nil)
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	// The run ends BEFORE the correlation lands.
	svc.EndRunByHandle(context.Background(), "EH", 0)
	at := time.Unix(1_700_000_100, 0).UTC()
	if err := svc.Correlate(context.Background(), res.RunID, "sess-late", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if _, ok := svc.SessionForRun(res.RunID); ok {
		t.Fatal("SessionForRun must stay empty for an ended run (no resurrection after EndRunByHandle)")
	}
}

// TestCorrelateMaxUpgradeNoDowngrade pins P2-3 (b): a strong OOB link is not
// clobbered in memory by a later weaker (marker) observation — the in-memory
// cache honors the same MAX-upgrade contract as the store. It also checks the
// upgrade direction (a stronger observation DOES replace a weaker established
// link).
func TestCorrelateMaxUpgradeNoDowngrade(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "UH"}
	svc := newService(t, Policy{}, rec, l, nil)
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	at := time.Unix(1_700_000_100, 0).UTC()

	// A marker (0.70) establishes the link first.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-marker", termrun.SourceMarker, at); err != nil {
		t.Fatalf("Correlate marker: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-marker" {
		t.Fatalf("after marker: SessionForRun = (%q,%v), want (sess-marker,true)", sid, ok)
	}

	// A stronger OOB (0.95) observation upgrades it.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-oob", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate oob: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-oob" {
		t.Fatalf("after oob upgrade: SessionForRun = (%q,%v), want (sess-oob,true)", sid, ok)
	}

	// A later WEAKER marker observation must NOT downgrade the established OOB link.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-weak-marker", termrun.SourceMarker, at); err != nil {
		t.Fatalf("Correlate weaker marker: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-oob" {
		t.Fatalf("after weaker marker: SessionForRun = (%q,%v), want (sess-oob,true) — a weaker observation must not overwrite a stronger link", sid, ok)
	}
}

// TestCorrelateDiscoveredLinksThenOOBUpgrades pins the distinct-confidence-source
// intent for a HEURISTICALLY-DISCOVERED codex session id: a SourceDiscovered
// observation (0.75) is above MinLinkConfidence, so it establishes a link on its
// own — but a later SourceOOB (0.95) observation carrying a DIFFERENT id strictly
// upgrades it (the stronger-evidence MAX-upgrade rule, P2-3 (b)). This is the
// termsvc-level counterpart of the codex discovery path recording at discovered
// confidence and a subsequent known-id echo overriding it.
func TestCorrelateDiscoveredLinksThenOOBUpgrades(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "DH"}
	svc := newService(t, Policy{}, rec, l, nil)
	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	at := time.Unix(1_700_000_100, 0).UTC()

	// A DISCOVERED id (0.75) establishes the link — it clears MinLinkConfidence.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-discovered", termrun.SourceDiscovered, at); err != nil {
		t.Fatalf("Correlate discovered: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-discovered" {
		t.Fatalf("after discovered: SessionForRun = (%q,%v), want (sess-discovered,true) — a discovered id must link", sid, ok)
	}
	// The durable store row records it at the discovered source/confidence.
	if last := rec.corr[len(rec.corr)-1]; last.Source != termrun.SourceDiscovered || !last.Linkable() {
		t.Fatalf("stored discovered correlation = %+v, want source=discovered + linkable", last)
	}

	// A stronger KNOWN-id OOB observation (0.95) strictly upgrades the link.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-known", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate oob: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-known" {
		t.Fatalf("after oob upgrade: SessionForRun = (%q,%v), want (sess-known,true) — a stronger OOB echo must override a discovered link", sid, ok)
	}

	// A later DISCOVERED observation must NOT downgrade the established OOB link.
	if err := svc.Correlate(context.Background(), res.RunID, "sess-late-discovered", termrun.SourceDiscovered, at); err != nil {
		t.Fatalf("Correlate late discovered: %v", err)
	}
	if sid, ok := svc.SessionForRun(res.RunID); !ok || sid != "sess-known" {
		t.Fatalf("after late discovered: SessionForRun = (%q,%v), want (sess-known,true) — a weaker discovered observation must not overwrite a stronger OOB link", sid, ok)
	}
}

// correlatingLauncher models the PRODUCTION launcher's ordering exactly: the
// real ptyLauncher.Spawn starts the OOB drain goroutine BEFORE it returns
// (cmd/observer/terminal_launch.go), so a trusted session frame can reach
// Correlate while launch() is still inside Spawn — before byHandle/byRun are
// installed. Calling Correlate synchronously from Spawn makes that interleave
// DETERMINISTIC (no sleep, no timing dependence): the correlation provably
// happens in the pre-registration window on every run.
type correlatingLauncher struct {
	// onSpawn receives the LaunchRequest (carrying the minted RunID) so the test
	// can drive svc.Correlate from inside the window.
	onSpawn func(req LaunchRequest)
	handle  string
	err     error
	// panicOnSpawn makes Spawn panic AFTER onSpawn, to prove the deferred
	// catch-all release also frees the reservation on a panicking Launcher.
	panicOnSpawn bool
}

func (c *correlatingLauncher) Spawn(req LaunchRequest) (string, error) {
	if c.onSpawn != nil {
		c.onSpawn(req)
	}
	if c.panicOnSpawn {
		panic("correlatingLauncher: boom")
	}
	if c.err != nil {
		return "", c.err
	}
	return c.handle, nil
}

// launchingLen / sessionLen read the in-package maps under the lock so the
// reservation tests can assert that nothing leaks.
func launchingLen(s *Service) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.launching)
}

func sessionLen(s *Service) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bySession)
}

// TestCorrelateBeforeRegistrationIsKept is the regression test for the
// correlate-before-registration race. The OOB drain goroutine starts inside
// Spawn, so a one-shot trusted session frame can reach Correlate before
// launch() installs byHandle/byRun. Before the launch reservation, Correlate's
// liveness guard (which exists to stop an ENDED run being resurrected) found an
// empty byRun and silently DISCARDED the link — and because the frame is
// one-shot, that run's "Jump in" stayed blank forever. The correlation must now
// survive: the run is reserved in launching before Spawn, and the reservation is
// consumed in the same critical section that registers the handle.
func TestCorrelateBeforeRegistrationIsKept(t *testing.T) {
	rec := newFakeRecorder()
	at := time.Unix(1_700_000_100, 0).UTC()
	var svc *Service
	l := &correlatingLauncher{handle: "PRH"}
	l.onSpawn = func(req LaunchRequest) {
		// Inside the pre-registration window, deterministically.
		if _, live := svc.HandleForRun(req.RunID); live {
			t.Errorf("run %q already registered inside Spawn — the test no longer exercises the pre-registration window", req.RunID)
		}
		if err := svc.Correlate(context.Background(), req.RunID, "sess-early", termrun.SourceOOB, at); err != nil {
			t.Errorf("Correlate inside Spawn: %v", err)
		}
	}
	svc = newService(t, Policy{}, rec, l, nil)

	res, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}
	sid, ok := svc.SessionForRun(res.RunID)
	if !ok || sid != "sess-early" {
		t.Fatalf("SessionForRun(%q) = (%q,%v), want (sess-early,true) — a correlation that arrived before the handle was registered was dropped", res.RunID, sid, ok)
	}
	// The reservation is consumed by registration, not left behind.
	if n := launchingLen(svc); n != 0 {
		t.Fatalf("launching reservations after a successful launch = %d, want 0", n)
	}
	// And the normal lifecycle still cleans the link up at exit.
	svc.EndRunByHandle(context.Background(), res.Handle, 0)
	if _, ok := svc.SessionForRun(res.RunID); ok {
		t.Fatal("SessionForRun must be empty after EndRunByHandle")
	}
}

// TestCorrelateBeforeRegistrationSpawnFailureNoOrphan pins the other half of the
// reservation contract. If Correlate writes bySession while the run is only
// RESERVED and Spawn then FAILS, no handle is ever produced — and bySession is
// only ever deleted by EndRunByHandle, which is keyed by handle. Such an entry
// would be permanently unreachable garbage: precisely the resurrection leak the
// liveness guard exists to prevent. The Spawn-error path must therefore release
// the reservation AND the session link it may have accumulated.
func TestCorrelateBeforeRegistrationSpawnFailureNoOrphan(t *testing.T) {
	rec := newFakeRecorder()
	at := time.Unix(1_700_000_100, 0).UTC()
	spawnErr := errors.New("spawn exploded")
	var svc *Service
	l := &correlatingLauncher{err: spawnErr}
	var runID string
	l.onSpawn = func(req LaunchRequest) {
		runID = req.RunID
		if err := svc.Correlate(context.Background(), req.RunID, "sess-orphan", termrun.SourceOOB, at); err != nil {
			t.Errorf("Correlate inside Spawn: %v", err)
		}
	}
	svc = newService(t, Policy{}, rec, l, nil)

	if _, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"}); !errors.Is(err, spawnErr) {
		t.Fatalf("LaunchAttachable err = %v, want %v", err, spawnErr)
	}
	if runID == "" {
		t.Fatal("Spawn was never called")
	}
	if sid, ok := svc.SessionForRun(runID); ok {
		t.Fatalf("SessionForRun(%q) = %q after a FAILED spawn — the link is unreachable garbage (no handle exists, so EndRunByHandle can never delete it)", runID, sid)
	}
	if n := sessionLen(svc); n != 0 {
		t.Fatalf("bySession entries after a failed spawn = %d, want 0", n)
	}
	if n := launchingLen(svc); n != 0 {
		t.Fatalf("launching reservations after a failed spawn = %d, want 0", n)
	}
	// The durable store row is still written — only the in-memory cache is
	// released (the run itself is closed out as ended).
	if len(rec.corr) != 1 {
		t.Fatalf("store correlations = %d, want 1 (the durable write is unconditional)", len(rec.corr))
	}
	if _, ended := rec.ended[runID]; !ended {
		t.Fatal("a failed spawn must still close the run out as ended")
	}
}

// TestCorrelateBeforeRegistrationSpawnPanicNoOrphan proves the LAST path out of
// launch() after the reservation: a panicking Launcher. The deferred catch-all
// release is the only thing that runs, and it must free both the reservation and
// any session link written in the window.
func TestCorrelateBeforeRegistrationSpawnPanicNoOrphan(t *testing.T) {
	rec := newFakeRecorder()
	at := time.Unix(1_700_000_100, 0).UTC()
	var svc *Service
	l := &correlatingLauncher{panicOnSpawn: true}
	var runID string
	l.onSpawn = func(req LaunchRequest) {
		runID = req.RunID
		if err := svc.Correlate(context.Background(), req.RunID, "sess-panic", termrun.SourceOOB, at); err != nil {
			t.Errorf("Correlate inside Spawn: %v", err)
		}
	}
	svc = newService(t, Policy{}, rec, l, nil)

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected the launcher panic to propagate")
			}
		}()
		_, _ = svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"})
	}()

	if runID == "" {
		t.Fatal("Spawn was never called")
	}
	if _, ok := svc.SessionForRun(runID); ok {
		t.Fatal("SessionForRun must be empty after a panicking spawn")
	}
	if n := launchingLen(svc); n != 0 {
		t.Fatalf("launching reservations after a panicking spawn = %d, want 0", n)
	}
	if n := sessionLen(svc); n != 0 {
		t.Fatalf("bySession entries after a panicking spawn = %d, want 0", n)
	}
}

// TestCorrelateStillRejectsUnknownRunAfterReservation guards against the fix
// widening the liveness gate too far: membership in `launching` is the ONLY new
// acceptance, so a run that was never launched (or already released) is still
// rejected from the in-memory cache.
func TestCorrelateStillRejectsUnknownRunAfterReservation(t *testing.T) {
	rec := newFakeRecorder()
	l := &correlatingLauncher{handle: "GH"}
	svc := newService(t, Policy{}, rec, l, nil)
	at := time.Unix(1_700_000_100, 0).UTC()
	if err := svc.Correlate(context.Background(), "never-launched", "sess-x", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if _, ok := svc.SessionForRun("never-launched"); ok {
		t.Fatal("a run that was never launched must not enter the in-memory cache")
	}
}

func TestCorrelate(t *testing.T) {
	rec := newFakeRecorder()
	svc := newService(t, Policy{}, rec, &fakeLauncher{}, nil)
	at := time.Unix(1_700_000_100, 0).UTC()
	if err := svc.Correlate(context.Background(), "run-1", "sess-1", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(rec.corr) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(rec.corr))
	}
	c := rec.corr[0]
	if c.RunID != "run-1" || c.SessionID != "sess-1" || c.Source != termrun.SourceOOB || !c.Linkable() {
		t.Fatalf("correlation = %+v", c)
	}
	// Empty ids are a no-op.
	if err := svc.Correlate(context.Background(), "", "s", termrun.SourceOOB, at); err != nil {
		t.Fatalf("Correlate empty: %v", err)
	}
	if len(rec.corr) != 1 {
		t.Fatal("empty correlate should not record")
	}
}

// TestLaunchResumePolicyEnforced pins the deliberate policy CONTRAST between the
// dashboard-initiated native resume and the CLI attach bypass (session-attach
// design §3.3): a resume is an Execute the launch Policy MUST gate, so a
// deny-all policy REFUSES it — whereas LaunchAttachable (authorized by the
// owner-only socket's filesystem permissions) succeeds under the SAME policy.
func TestLaunchResumePolicyEnforced(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		req     ResumeRequest
		wantErr error
	}{
		{
			name:    "deny-all policy refuses resume",
			policy:  Policy{}, // AllowFresh false
			req:     ResumeRequest{Tool: "claude-code", Subcommand: "claude"},
			wantErr: ErrFreshLaunchDisabled,
		},
		{
			name:    "tool not in allow-list",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"codex"}},
			req:     ResumeRequest{Tool: "claude-code", Subcommand: "claude"},
			wantErr: ErrToolNotAllowed,
		},
		{
			name:   "allowed tool, default cwd",
			policy: Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
			req: ResumeRequest{
				Tool:            "claude-code",
				Subcommand:      "claude",
				SourceSessionID: "sess-ok",
				ExtraArgs:       []string{"--resume", "sess-ok"},
			},
			wantErr: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			l := &fakeLauncher{handle: "H-resume"}
			svc := newService(t, tc.policy, rec, l, nil)
			_, err := svc.LaunchResume(context.Background(), tc.req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("LaunchResume err = %v, want %v", err, tc.wantErr)
			}
		})
	}

	// The CONTRAST leg: under the SAME deny-all policy that refused resume,
	// LaunchAttachable succeeds — the socket's filesystem permissions are the
	// authorization, not the launch Policy.
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H-attach"}
	svc := newService(t, Policy{}, rec, l, nil)
	if _, err := svc.LaunchAttachable(context.Background(), AttachRequest{Tool: "claude-code", Subcommand: "claude"}); err != nil {
		t.Fatalf("LaunchAttachable under deny-all policy should succeed (socket-authorized), got %v", err)
	}
}

// TestLaunchResumeMintsKindAndArgs pins that a successful resume mints a
// KindResume run carrying the resumed session as SourceSessionID, that the
// composed ExtraArgs + source session id reach the launcher request verbatim,
// and that the known native target links without relying on platform OOB.
func TestLaunchResumeMintsKindAndArgs(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H-resume"}
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, l, nil)

	res, err := svc.LaunchResume(context.Background(), ResumeRequest{
		Tool:            "claude-code",
		Subcommand:      "claude",
		SourceSessionID: "sess-9",
		ExtraArgs:       []string{"--resume", "sess-9"},
	})
	if err != nil {
		t.Fatalf("LaunchResume: %v", err)
	}
	if res.Handle != "H-resume" || res.RunID == "" {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("expected 1 recorded run, got %d", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindResume {
		t.Errorf("run.Kind = %q, want %q", run.Kind, termrun.KindResume)
	}
	if run.SourceSessionID != "sess-9" {
		t.Errorf("run.SourceSessionID = %q, want sess-9", run.SourceSessionID)
	}
	// The launcher saw KindResume, the source session id, and the resume tail.
	lr := l.lastReq
	if lr.Kind != termrun.KindResume {
		t.Errorf("launch req Kind = %q, want %q", lr.Kind, termrun.KindResume)
	}
	if lr.SessionID != "sess-9" {
		t.Errorf("launch req SessionID = %q, want sess-9", lr.SessionID)
	}
	if len(lr.ExtraArgs) != 2 || lr.ExtraArgs[0] != "--resume" || lr.ExtraArgs[1] != "sess-9" {
		t.Errorf("launch req ExtraArgs = %v, want [--resume sess-9]", lr.ExtraArgs)
	}
	if len(rec.corr) != 1 {
		t.Fatalf("correlations = %d, want 1", len(rec.corr))
	}
	if corr := rec.corr[0]; corr.RunID != res.RunID || corr.SessionID != "sess-9" || corr.Source != termrun.SourceDiscovered || !corr.Linkable() {
		t.Fatalf("known resume correlation = %+v", corr)
	}
	if sid, confidence, ok := svc.SessionLinkForRun(res.RunID); !ok || sid != "sess-9" || confidence != 0.75 {
		t.Fatalf("SessionLinkForRun = (%q,%v,%v), want (sess-9,0.75,true)", sid, confidence, ok)
	}
}

func TestLaunchResumeRejectsUnboundIdentityBeforeSpawn(t *testing.T) {
	tests := []struct {
		name string
		req  ResumeRequest
		err  error
	}{
		{
			name: "empty source id",
			req: ResumeRequest{
				Tool: "claude-code", Subcommand: "claude",
				ExtraArgs: []string{"--resume", "sess-9"},
			},
			err: ErrResumeSessionRequired,
		},
		{
			name: "missing args",
			req: ResumeRequest{
				Tool: "claude-code", Subcommand: "claude", SourceSessionID: "sess-9",
			},
			err: ErrResumeArgsMismatch,
		},
		{
			name: "different id",
			req: ResumeRequest{
				Tool: "claude-code", Subcommand: "claude", SourceSessionID: "sess-9",
				ExtraArgs: []string{"--resume", "sess-other"},
			},
			err: ErrResumeArgsMismatch,
		},
		{
			name: "additional args",
			req: ResumeRequest{
				Tool: "claude-code", Subcommand: "claude", SourceSessionID: "sess-9",
				ExtraArgs: []string{"--resume", "sess-9", "--other"},
			},
			err: ErrResumeArgsMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			launcher := &fakeLauncher{handle: "must-not-spawn"}
			svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, launcher, nil)
			if _, err := svc.LaunchResume(context.Background(), tc.req); !errors.Is(err, tc.err) {
				t.Fatalf("LaunchResume error = %v, want %v", err, tc.err)
			}
			if launcher.calls != 0 || rec.recordCalls != 0 || rec.corrCalls != 0 {
				t.Fatalf("invalid resume touched side effects: launcher=%d record=%d correlate=%d", launcher.calls, rec.recordCalls, rec.corrCalls)
			}
		})
	}
}

func TestLaunchResumeDoesNotCorrelateFailedOrExitedSpawn(t *testing.T) {
	valid := ResumeRequest{
		Tool:            "claude-code",
		Subcommand:      "claude",
		SourceSessionID: "sess-9",
		ExtraArgs:       []string{"--resume", "sess-9"},
	}
	t.Run("spawn failure", func(t *testing.T) {
		rec := newFakeRecorder()
		spawnErr := errors.New("spawn failed")
		svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, &fakeLauncher{err: spawnErr}, nil)
		if _, err := svc.LaunchResume(context.Background(), valid); !errors.Is(err, spawnErr) {
			t.Fatalf("LaunchResume error = %v, want %v", err, spawnErr)
		}
		if rec.corrCalls != 0 {
			t.Fatalf("correlation calls = %d, want 0", rec.corrCalls)
		}
	})
	t.Run("exit reconciled before return", func(t *testing.T) {
		rec := newFakeRecorder()
		svc := New(Options{
			Policy:   Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
			Recorder: rec,
			Launcher: &fakeLauncher{handle: "already-exited"},
			Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			ExitStatus: func(handle string) (bool, int, bool) {
				return handle == "already-exited", 0, true
			},
		})
		res, err := svc.LaunchResume(context.Background(), valid)
		if err != nil {
			t.Fatalf("LaunchResume: %v", err)
		}
		if res.Handle != "already-exited" || res.RunID == "" {
			t.Fatalf("result = %+v", res)
		}
		if rec.corrCalls != 0 {
			t.Fatalf("correlation calls = %d, want 0", rec.corrCalls)
		}
		if _, _, ok := svc.SessionLinkForRun(res.RunID); ok {
			t.Fatal("exited resume must not have a live session link")
		}
	})
}

func TestLaunchResumePreservesStrongerSpawnCorrelation(t *testing.T) {
	rec := newFakeRecorder()
	var svc *Service
	launcher := &correlatingLauncher{handle: "resume-oob"}
	launcher.onSpawn = func(req LaunchRequest) {
		if err := svc.Correlate(context.Background(), req.RunID, "sess-9", termrun.SourceOOB, time.Unix(1_700_000_000, 0).UTC()); err != nil {
			t.Errorf("OOB Correlate: %v", err)
		}
	}
	svc = newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, launcher, nil)
	res, err := svc.LaunchResume(context.Background(), ResumeRequest{
		Tool:            "claude-code",
		Subcommand:      "claude",
		SourceSessionID: "sess-9",
		ExtraArgs:       []string{"--resume", "sess-9"},
	})
	if err != nil {
		t.Fatalf("LaunchResume: %v", err)
	}
	if sid, confidence, ok := svc.SessionLinkForRun(res.RunID); !ok || sid != "sess-9" || confidence != 0.95 {
		t.Fatalf("SessionLinkForRun = (%q,%v,%v), want stronger OOB link", sid, confidence, ok)
	}
	if rec.corrCalls != 2 {
		t.Fatalf("correlation calls = %d, want OOB plus discovered", rec.corrCalls)
	}
}

func TestLaunchResumeCorrelationFailureKeepsSpawnResult(t *testing.T) {
	rec := newFakeRecorder()
	rec.corrErr = errors.New("correlation store unavailable")
	launcher := &fakeLauncher{handle: "resume-live"}
	svc := newService(t, Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}}, rec, launcher, nil)
	res, err := svc.LaunchResume(context.Background(), ResumeRequest{
		Tool:            "claude-code",
		Subcommand:      "claude",
		SourceSessionID: "sess-9",
		ExtraArgs:       []string{"--resume", "sess-9"},
	})
	if err != nil {
		t.Fatalf("LaunchResume returned correlation error after spawn: %v", err)
	}
	if res.Handle != "resume-live" || res.RunID == "" || launcher.calls != 1 {
		t.Fatalf("spawn result = %+v, calls=%d", res, launcher.calls)
	}
	if rec.corrCalls != 1 {
		t.Fatalf("correlation calls = %d, want 1", rec.corrCalls)
	}
	if _, _, ok := svc.SessionLinkForRun(res.RunID); ok {
		t.Fatal("failed correlation must not fabricate an in-memory link")
	}
}

// TestLaunchRecordsSpawnDirSeparatelyFromProjectRoot pins the two-answer
// contract that run→session correlation depends on: ProjectRoot is the
// AUTHORIZED root (empty for a launch with no requested project root — the
// shape every dashboard "New Terminal" takes on a node with no
// [terminal.launch].allowed_project_roots) while SpawnDir is the FACTUAL cwd
// the child inherits from the daemon.
//
// The regression it guards is a real one, reproduced on a remote node: with the
// two answers conflated, the discovery sweep asked ProjectRoot for the run's
// directory, got "no authorized root", and skipped the run forever — an
// opencode terminal sat at "linking…" while its session (started in that very
// directory, /home/azureuser) was ingested normally.
func TestLaunchRecordsSpawnDirSeparatelyFromProjectRoot(t *testing.T) {
	root := t.TempDir()
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks(root): %v", err)
	}
	daemonCwd := t.TempDir() // stands in for the devbox daemon's cwd (/home/azureuser)
	canonCwd, err := filepath.EvalSymlinks(daemonCwd)
	if err != nil {
		t.Fatalf("EvalSymlinks(daemonCwd): %v", err)
	}

	tests := []struct {
		name string
		// projectRoot is the client-requested root ("" = the devbox shape).
		projectRoot string
		// allowedRoots is the operator's [terminal.launch].allowed_project_roots.
		allowedRoots []string
		getwd        func() (string, error)
		wantRoot     string // "" => ProjectRoot reports ok=false
		wantSpawnDir string // "" => SpawnDir reports ok=false
	}{
		{
			name:         "default-cwd launch: no authorized root, but the daemon cwd is the factual spawn dir",
			projectRoot:  "",
			allowedRoots: nil, // the devbox: allowed_project_roots is unset entirely
			getwd:        func() (string, error) { return daemonCwd, nil },
			wantRoot:     "",
			wantSpawnDir: canonCwd,
		},
		{
			name:         "explicit authorized root: both answers are that root",
			projectRoot:  root,
			allowedRoots: []string{root},
			getwd:        func() (string, error) { return daemonCwd, nil },
			wantRoot:     canonRoot,
			wantSpawnDir: canonRoot,
		},
		{
			name:         "default-cwd launch with an unreadable daemon cwd: both are honestly unknown",
			projectRoot:  "",
			allowedRoots: nil,
			getwd:        func() (string, error) { return "", errors.New("getwd: no such directory") },
			wantRoot:     "",
			wantSpawnDir: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &fakeLauncher{handle: "H-SPAWNDIR"}
			svc := New(Options{
				Policy: Policy{
					AllowFresh:          true,
					AllowedTools:        []string{"opencode"},
					AllowedProjectRoots: tc.allowedRoots,
				},
				Recorder: newFakeRecorder(),
				Launcher: l,
				Now:      func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				Getwd:    tc.getwd,
			})
			res, err := svc.LaunchFresh(context.Background(), FreshRequest{
				Tool: "opencode", Subcommand: "opencode", ProjectRoot: tc.projectRoot,
			})
			if err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}

			gotRoot, rootOK := svc.ProjectRoot(res.Handle)
			if tc.wantRoot == "" {
				if rootOK {
					t.Fatalf("ProjectRoot = %q, ok=true; want the honest no-authorized-root miss", gotRoot)
				}
			} else if !rootOK || gotRoot != tc.wantRoot {
				t.Fatalf("ProjectRoot = (%q, %v), want (%q, true)", gotRoot, rootOK, tc.wantRoot)
			}

			gotSpawn, spawnOK := svc.SpawnDir(res.Handle)
			if tc.wantSpawnDir == "" {
				if spawnOK {
					t.Fatalf("SpawnDir = %q, ok=true; want a miss", gotSpawn)
				}
			} else if !spawnOK || gotSpawn != tc.wantSpawnDir {
				t.Fatalf("SpawnDir = (%q, %v), want (%q, true)", gotSpawn, spawnOK, tc.wantSpawnDir)
			}
		})
	}
}

// TestSpawnDirUnknownHandle pins the miss for a handle the service never saw.
func TestSpawnDirUnknownHandle(t *testing.T) {
	svc := New(Options{
		Policy:   Policy{AllowFresh: true},
		Recorder: newFakeRecorder(),
		Launcher: &fakeLauncher{handle: "H"},
		Getwd:    func() (string, error) { return t.TempDir(), nil },
	})
	if dir, ok := svc.SpawnDir("nope"); ok || dir != "" {
		t.Fatalf("SpawnDir(unknown) = (%q, %v), want (\"\", false)", dir, ok)
	}
}
