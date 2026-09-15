package termsvc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// fakeGUILauncher records the spawn request and returns a fixed result (or an
// error). It also retains OnExit so a test can drive the reaper callback
// synchronously.
type fakeGUILauncher struct {
	mu      sync.Mutex
	pid     int
	err     error
	calls   int
	lastReq GUISpawnRequest
	result  GUISpawnResult
}

func (f *fakeGUILauncher) SpawnGUI(req GUISpawnRequest) (GUISpawnResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return GUISpawnResult{}, f.err
	}
	res := f.result
	if res.PID == 0 {
		res.PID = f.pid
	}
	return res, nil
}

func (f *fakeGUILauncher) request() GUISpawnRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

// anyAdvertisedGUIRow returns one advertised GUI launch row from the live
// registry, or skips the test when none exists yet. The GUI ROWS are populated
// by a sibling ticket (T2.1) — this half of the feature must be testable
// before and after they land, so every positive-path test keys off whatever
// the registry advertises rather than hardcoding an id that may not exist.
func anyAdvertisedGUIRow(t *testing.T) integration.GUILaunchable {
	t.Helper()
	for _, g := range integration.GUILaunchables() {
		if g.Advertised() {
			return g
		}
	}
	t.Skip("no advertised GUI launch rows in the registry yet (populated by T2.1)")
	return integration.GUILaunchable{}
}

// guiTestService builds a Service whose policy allows the given GUI id.
func guiTestService(t *testing.T, id string, launcher GUILauncher) (*Service, *fakeRecorder) {
	t.Helper()
	rec := newFakeRecorder()
	svc := New(Options{
		Policy:      Policy{AllowFresh: true, AllowedTools: []string{id}},
		Recorder:    rec,
		Launcher:    &fakeLauncher{handle: "h1"},
		GUILauncher: launcher,
		Now:         func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) },
	})
	return svc, rec
}

func TestLaunchGUIRecordsRunAndStampsSpawnFacts(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	gl := &fakeGUILauncher{result: GUISpawnResult{
		PID: 4242, WrapApplied: true, WrapNote: "cold-start only", Bin: "/usr/bin/app",
	}}
	svc, rec := guiTestService(t, row.Spec.ID, gl)

	res, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID})
	if err != nil {
		t.Fatalf("LaunchGUI: %v", err)
	}
	if res.RunID == "" || res.PID != 4242 || res.ID != row.Spec.ID || res.Label != row.Spec.Label {
		t.Fatalf("result = %+v", res)
	}
	if !res.WrapApplied || res.WrapNote != "cold-start only" {
		t.Errorf("wrap = (%v,%q), want the launcher's verdict carried verbatim", res.WrapApplied, res.WrapNote)
	}

	// The run is recorded BEFORE the spawn, with the GUI kind and no
	// correlation nonce (a GUI child has no out-of-band channel).
	if len(rec.runs) != 1 {
		t.Fatalf("recorded %d runs, want 1", len(rec.runs))
	}
	run := rec.runs[0]
	if run.Kind != termrun.KindGUI || run.Tool != row.Spec.ID {
		t.Errorf("run = %+v, want kind=gui tool=%s", run, row.Spec.ID)
	}
	if run.CorrelationTokenHash != "" || run.SourceSessionID != "" {
		t.Errorf("GUI run must carry no correlation nonce and no source session: %+v", run)
	}
	if run.PID != nil {
		t.Errorf("the pre-spawn record must carry no pid, got %v", run.PID)
	}

	// The post-spawn stamp carries the pid + wrap verdict on the SAME run id.
	if len(rec.guiSpawns) != 1 {
		t.Fatalf("recorded %d gui spawns, want 1", len(rec.guiSpawns))
	}
	stamp := rec.guiSpawns[0]
	if stamp.RunID != res.RunID || stamp.PID == nil || *stamp.PID != 4242 || !stamp.WrapApplied {
		t.Errorf("stamp = %+v (pid %v)", stamp, stamp.PID)
	}
}

func TestLaunchGUIGates(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)

	tests := []struct {
		name    string
		policy  Policy
		gl      GUILauncher
		id      string
		root    string
		wantErr error
	}{
		{
			name:    "no launcher seam",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{row.Spec.ID}},
			gl:      nil,
			id:      row.Spec.ID,
			wantErr: ErrGUIUnsupported,
		},
		{
			name:    "fresh launch disabled",
			policy:  Policy{AllowedTools: []string{row.Spec.ID}},
			gl:      &fakeGUILauncher{pid: 1},
			id:      row.Spec.ID,
			wantErr: ErrFreshLaunchDisabled,
		},
		{
			name:    "id not in the allow-list",
			policy:  Policy{AllowFresh: true},
			gl:      &fakeGUILauncher{pid: 1},
			id:      row.Spec.ID,
			wantErr: ErrToolNotAllowed,
		},
		{
			name:    "unknown gui id",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{"not-a-gui-row"}},
			gl:      &fakeGUILauncher{pid: 1},
			id:      "not-a-gui-row",
			wantErr: ErrGUINotLaunchable,
		},
		{
			name:    "project root denied with an empty allow-list",
			policy:  Policy{AllowFresh: true, AllowedTools: []string{row.Spec.ID}},
			gl:      &fakeGUILauncher{pid: 1},
			id:      row.Spec.ID,
			root:    t.TempDir(),
			wantErr: ErrProjectRootDenied,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := newFakeRecorder()
			svc := New(Options{Policy: tc.policy, Recorder: rec, Launcher: &fakeLauncher{handle: "h"}, GUILauncher: tc.gl})
			_, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: tc.id, ProjectRoot: tc.root})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			// Every gate fails BEFORE a run is minted: no orphan row, no spawn.
			if len(rec.runs) != 0 {
				t.Errorf("a refused launch recorded %d runs, want 0", len(rec.runs))
			}
			if gl, ok := tc.gl.(*fakeGUILauncher); ok && gl.calls != 0 {
				t.Errorf("a refused launch called SpawnGUI %d times, want 0", gl.calls)
			}
		})
	}
}

// TestLaunchGUISpawnFailureClosesOutTheRun pins the launch()-parity behaviour:
// a run that never produced a process is ended (-1, child_exit) rather than
// left dangling as running.
func TestLaunchGUISpawnFailureClosesOutTheRun(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	boom := errors.New("no binary")
	gl := &fakeGUILauncher{err: boom}
	svc, rec := guiTestService(t, row.Spec.ID, gl)

	if _, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the spawn error", err)
	}
	if len(rec.runs) != 1 {
		t.Fatalf("recorded %d runs, want the pre-spawn row", len(rec.runs))
	}
	runID := rec.runs[0].RunID
	if code, ok := rec.ended[runID]; !ok || code != -1 {
		t.Errorf("ended[%s] = (%d,%v), want (-1,true)", runID, code, ok)
	}
	if rec.endReasons[runID] != reasonChildExit {
		t.Errorf("end reason = %q, want %q", rec.endReasons[runID], reasonChildExit)
	}
	if len(svc.GUIRuns()) != 0 {
		t.Errorf("a failed spawn must not appear in GUIRuns")
	}
}

// TestGUIRunsListsNewestFirstAndRecordsExit pins the in-memory history: live
// and exited rows both appear, newest first, and an exit is recorded durably
// exactly once.
func TestGUIRunsListsNewestFirstAndRecordsExit(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	// The seam's mechanism notes (e.g. the launcher-stub pid caveat) must reach
	// the run LIST, not only the launch response — otherwise a stub's
	// `exited (1)` reads as the app's.
	gl := &fakeGUILauncher{pid: 10, result: GUISpawnResult{Notes: []string{"pid belongs to a launcher stub"}}}
	rec := newFakeRecorder()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	var tick int
	svc := New(Options{
		Policy:      Policy{AllowFresh: true, AllowedTools: []string{row.Spec.ID}},
		Recorder:    rec,
		Launcher:    &fakeLauncher{handle: "h"},
		GUILauncher: gl,
		Now: func() time.Time {
			tick++
			return now.Add(time.Duration(tick) * time.Second)
		},
	})

	first, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID})
	if err != nil {
		t.Fatalf("LaunchGUI: %v", err)
	}
	second, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID})
	if err != nil {
		t.Fatalf("LaunchGUI: %v", err)
	}

	runs := svc.GUIRuns()
	if len(runs) != 2 {
		t.Fatalf("GUIRuns() = %d rows, want 2", len(runs))
	}
	if runs[0].RunID != second.RunID || runs[1].RunID != first.RunID {
		t.Errorf("GUIRuns() order = [%s %s], want newest first", runs[0].RunID, runs[1].RunID)
	}
	if runs[0].Exited {
		t.Errorf("a live run must not report exited")
	}
	if len(runs[0].Notes) != 1 || runs[0].Notes[0] != "pid belongs to a launcher stub" {
		t.Errorf("GUIRuns()[0].Notes = %q, want the seam's mechanism note carried into the list", runs[0].Notes)
	}

	// The launcher's reaper reports the exit.
	svc.guiRunExited(first.RunID, 3)
	if code, ok := rec.ended[first.RunID]; !ok || code != 3 {
		t.Errorf("ended[%s] = (%d,%v), want (3,true)", first.RunID, code, ok)
	}
	// A duplicate report is a no-op (idempotent), so the recorder is untouched.
	before := rec.endCalls
	svc.guiRunExited(first.RunID, 3)
	if rec.endCalls != before {
		t.Errorf("a duplicate exit recorded again (%d -> %d)", before, rec.endCalls)
	}

	for _, r := range svc.GUIRuns() {
		if r.RunID == first.RunID && (!r.Exited || r.ExitCode != 3) {
			t.Errorf("exited row = %+v, want exited with code 3", r)
		}
	}
}

// TestGUIRunsBoundedHistory pins the guiRunHistory cap: a daemon launching all
// day keeps a bounded list.
func TestGUIRunsBoundedHistory(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	svc, _ := guiTestService(t, row.Spec.ID, &fakeGUILauncher{pid: 7})
	for i := 0; i < guiRunHistory+10; i++ {
		if _, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID}); err != nil {
			t.Fatalf("LaunchGUI #%d: %v", i, err)
		}
	}
	if got := len(svc.GUIRuns()); got != guiRunHistory {
		t.Errorf("GUIRuns() = %d rows, want the %d-row bound", got, guiRunHistory)
	}
}

// TestLaunchGUIStampFailureStillReportsSuccess pins the trade the launch makes:
// the app IS running, so a failed metadata stamp must not turn a successful
// launch into an error.
func TestLaunchGUIStampFailureStillReportsSuccess(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	rec := newFakeRecorder()
	rec.guiSpawnErr = errors.New("db gone")
	svc := New(Options{
		Policy:      Policy{AllowFresh: true, AllowedTools: []string{row.Spec.ID}},
		Recorder:    rec,
		Launcher:    &fakeLauncher{handle: "h"},
		GUILauncher: &fakeGUILauncher{pid: 55},
	})
	res, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID})
	if err != nil {
		t.Fatalf("LaunchGUI = %v, want success despite the stamp failure", err)
	}
	if res.PID != 55 {
		t.Errorf("pid = %d, want 55", res.PID)
	}
}

// TestLaunchGUIPassesSpecAndRootToTheSeam pins that the service hands the
// launcher the registry ROW and the validated root, and interprets neither.
func TestLaunchGUIPassesSpecAndRootToTheSeam(t *testing.T) {
	t.Parallel()
	row := anyAdvertisedGUIRow(t)
	gl := &fakeGUILauncher{pid: 9}
	rec := newFakeRecorder()
	dir := t.TempDir()
	svc := New(Options{
		Policy: Policy{
			AllowFresh: true, AllowedTools: []string{row.Spec.ID},
			AllowedProjectRoots: []string{dir},
		},
		Recorder:    rec,
		Launcher:    &fakeLauncher{handle: "h"},
		GUILauncher: gl,
	})
	res, err := svc.LaunchGUI(context.Background(), GUIRequest{ID: row.Spec.ID, ProjectRoot: dir})
	if err != nil {
		t.Fatalf("LaunchGUI: %v", err)
	}
	req := gl.request()
	if req.RunID != res.RunID || req.ID != row.Spec.ID {
		t.Errorf("seam request = %+v", req)
	}
	if req.Spec.ID != row.Spec.ID {
		t.Errorf("seam spec = %+v, want the registry row", req.Spec)
	}
	if req.ProjectRoot == "" {
		t.Errorf("seam project root is empty, want the validated directory")
	}
	if req.OnExit == nil {
		t.Errorf("seam request carries no OnExit callback")
	}
}
