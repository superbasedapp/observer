package termsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// fakeSandboxer is a recording, scriptable Sandboxer for the U4 tests.
type fakeSandboxer struct {
	result  PrepareResult
	err     error
	calls   int
	lastReq PrepareRequest
}

func (f *fakeSandboxer) Prepare(_ context.Context, req PrepareRequest) (PrepareResult, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return PrepareResult{}, f.err
	}
	return f.result, nil
}

// mkdirT makes (and returns) an existing directory under base — a helper for
// tests that need canonicalDir/ValidateManagedWorkspace to see a real,
// stat-able directory.
func mkdirT(t *testing.T, base string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{base}, parts...)...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", p, err)
	}
	return p
}

// (a) Sandbox:false leaves LaunchFresh byte-identical to today: no WrapArgv,
// Sandboxed=false, and the Sandboxer (even when configured) is never called.
func TestLaunchFreshSandboxFalseUnchanged(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H1"}
	sb := &fakeSandboxer{result: PrepareResult{Dir: "/should/not/be/used", WrapArgv: []string{"bwrap"}}}
	svc := New(Options{
		Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}},
		Recorder:  rec,
		Launcher:  l,
		Sandboxer: sb,
	})

	res, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: false,
	})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if res.Handle != "H1" {
		t.Fatalf("result = %+v", res)
	}
	if sb.calls != 0 {
		t.Fatalf("Sandboxer.Prepare was called %d times, want 0 for Sandbox:false", sb.calls)
	}
	if len(l.lastReq.WrapArgv) != 0 {
		t.Fatalf("WrapArgv = %v, want empty", l.lastReq.WrapArgv)
	}
	if l.lastReq.Sandboxed {
		t.Fatal("Sandboxed = true, want false")
	}
	if l.lastReq.Dir != "" {
		t.Fatalf("Dir = %q, want empty (default cwd, unchanged)", l.lastReq.Dir)
	}
}

// (b) Sandbox:true with no configured Sandboxer fails closed with
// ErrSandboxUnavailable — no run is minted and the Launcher is never called
// (§12 amendment A5, the fail-closed nil-seam invariant).
func TestLaunchFreshSandboxUnavailableNilSeam(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H2"}
	root := t.TempDir()
	svc := New(Options{
		Policy:   Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
		Recorder: rec,
		Launcher: l,
		// Sandboxer deliberately omitted (nil).
	})
	_, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true, ProjectRoot: root,
	})
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("err = %v, want ErrSandboxUnavailable", err)
	}
	if l.calls != 0 {
		t.Fatalf("Launcher.Spawn was called %d times, want 0", l.calls)
	}
	if rec.recordCalls != 0 {
		t.Fatalf("RecordRun was called %d times, want 0 (no orphan run)", rec.recordCalls)
	}
}

// (c) Sandbox:true with a working Sandboxer that resolves a MANAGED
// (non-"live") workspace: the Launcher receives WrapArgv, Sandboxed=true, and
// the prepared (canonicalized) Dir — not the original project root — and the
// run's ProjectRootHash follows the prepared workspace.
func TestLaunchFreshSandboxManagedWorkspaceSuccess(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H3"}
	base := t.TempDir()
	projectRoot := mkdirT(t, base, "project")
	workspacesRoot := mkdirT(t, base, "observer-workspaces")
	preparedDir := mkdirT(t, workspacesRoot, "run-abc", "repo")

	sb := &fakeSandboxer{result: PrepareResult{
		Dir:      preparedDir,
		WrapArgv: []string{"bwrap", "--ro-bind", "/", "/", "--"},
		Note:     "clone-local",
	}}
	svc := New(Options{
		Policy:               Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{projectRoot}},
		Recorder:             rec,
		Launcher:             l,
		Sandboxer:            sb,
		SandboxWorkspacesDir: workspacesRoot,
	})

	res, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true,
		ProjectRoot: projectRoot, WorkspaceSource: "clone-local",
	})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if res.Handle != "H3" {
		t.Fatalf("result = %+v", res)
	}
	if sb.calls != 1 {
		t.Fatalf("Sandboxer.Prepare called %d times, want 1", sb.calls)
	}
	// The Sandboxer saw the already-validated (canonical) project root and the
	// caller's workspace-source selection.
	wantValidatedRoot, verr := ValidateProjectRoot(projectRoot, []string{projectRoot})
	if verr != nil {
		t.Fatalf("ValidateProjectRoot: %v", verr)
	}
	if sb.lastReq.ProjectRoot != wantValidatedRoot || sb.lastReq.Tool != "claude-code" || sb.lastReq.WorkspaceSource != "clone-local" {
		t.Fatalf("PrepareRequest = %+v", sb.lastReq)
	}
	// The Launcher got the WrapArgv and Sandboxed flag.
	if len(l.lastReq.WrapArgv) != len(sb.result.WrapArgv) {
		t.Fatalf("WrapArgv = %v, want %v", l.lastReq.WrapArgv, sb.result.WrapArgv)
	}
	for i := range sb.result.WrapArgv {
		if l.lastReq.WrapArgv[i] != sb.result.WrapArgv[i] {
			t.Fatalf("WrapArgv[%d] = %q, want %q", i, l.lastReq.WrapArgv[i], sb.result.WrapArgv[i])
		}
	}
	if !l.lastReq.Sandboxed {
		t.Fatal("Sandboxed = false, want true")
	}
	// The Launcher's Dir is the PREPARED workspace, canonicalized — not the
	// original project root.
	wantDir, cerr := canonicalDir(preparedDir)
	if cerr != nil {
		t.Fatalf("canonicalDir: %v", cerr)
	}
	if l.lastReq.Dir != wantDir {
		t.Fatalf("Dir = %q, want %q (prepared workspace)", l.lastReq.Dir, wantDir)
	}
	// Attribution follows the prepared workspace, not the original root.
	if len(rec.runs) != 1 {
		t.Fatalf("expected 1 recorded run, got %d", len(rec.runs))
	}
	run := rec.runs[0]
	if run.ProjectRootHash != termrun.HashProjectRoot(wantDir) {
		t.Fatalf("ProjectRootHash does not follow the prepared workspace")
	}
	if run.ProjectRootHash == termrun.HashProjectRoot(wantValidatedRoot) {
		t.Fatal("ProjectRootHash should NOT equal the original project root's hash for a managed workspace")
	}
	// The Launcher learns the source the clone came from, so the inner
	// launcher's repository trust check honours its accepts.
	if l.lastReq.SourceDir != wantValidatedRoot {
		t.Fatalf("SourceDir = %q, want the validated project root %q", l.lastReq.SourceDir, wantValidatedRoot)
	}
}

// TestLaunchFreshSandboxLiveSourceSkipsManagedCheck: when the Sandboxer
// resolves a "live" source (Dir == the already-validated project root, no
// copy), ValidateManagedWorkspace must be SKIPPED — even with no managed
// workspaces root configured at all, the launch must still succeed.
func TestLaunchFreshSandboxLiveSourceSkipsManagedCheck(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H4"}
	projectRoot := t.TempDir()
	sb := &fakeSandboxer{} // result.Dir filled in below to equal the validated root

	svc := New(Options{
		Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{projectRoot}},
		Recorder:  rec,
		Launcher:  l,
		Sandboxer: sb,
		// SandboxWorkspacesDir deliberately left empty — must not matter for a
		// live source.
	})

	wantValidatedRoot, verr := ValidateProjectRoot(projectRoot, []string{projectRoot})
	if verr != nil {
		t.Fatalf("ValidateProjectRoot: %v", verr)
	}
	sb.result = PrepareResult{Dir: wantValidatedRoot} // live: no WrapArgv, Dir unchanged

	res, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true,
		ProjectRoot: projectRoot, WorkspaceSource: "live",
	})
	if err != nil {
		t.Fatalf("LaunchFresh (live source): %v", err)
	}
	if res.Handle != "H4" {
		t.Fatalf("result = %+v", res)
	}
	if l.lastReq.Dir != wantValidatedRoot {
		t.Fatalf("Dir = %q, want %q", l.lastReq.Dir, wantValidatedRoot)
	}
	if !l.lastReq.Sandboxed {
		t.Fatal("Sandboxed = false, want true")
	}
	if l.lastReq.SourceDir != "" {
		t.Fatalf("SourceDir = %q for a live source, want empty", l.lastReq.SourceDir)
	}
	// The update drain's counter (sandbox plan v2 section 5.5): live while
	// the run is, zero once it ends.
	if n := svc.LiveSandboxedCount(); n != 1 {
		t.Fatalf("LiveSandboxedCount = %d, want 1", n)
	}
	svc.EndRunByHandle(context.Background(), "H4", 0)
	if n := svc.LiveSandboxedCount(); n != 0 {
		t.Fatalf("LiveSandboxedCount after the run ended = %d, want 0", n)
	}
}

// (d) A Sandboxer.Prepare error is wrapped in ErrWorkspacePrepFailed; the
// Launcher is never called and no run is minted.
func TestLaunchFreshSandboxPrepareErrorWraps(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H5"}
	root := t.TempDir()
	prepErr := errors.New("git clone failed: exit status 128")
	sb := &fakeSandboxer{err: prepErr}
	svc := New(Options{
		Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
		Recorder:  rec,
		Launcher:  l,
		Sandboxer: sb,
	})

	_, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true, ProjectRoot: root,
	})
	if !errors.Is(err, ErrWorkspacePrepFailed) {
		t.Fatalf("err = %v, want wrapping ErrWorkspacePrepFailed", err)
	}
	if !errors.Is(err, prepErr) {
		t.Fatalf("err = %v, want wrapping the underlying prep error", err)
	}
	if l.calls != 0 {
		t.Fatalf("Launcher.Spawn was called %d times, want 0", l.calls)
	}
	if rec.recordCalls != 0 {
		t.Fatalf("RecordRun was called %d times, want 0 (no orphan run)", rec.recordCalls)
	}
}

// TestLaunchFreshSandboxManagedDirOutsideRootDenied: a Sandboxer that
// misbehaves and returns a workspace path OUTSIDE the configured managed
// root must also fail closed (wrapped in ErrWorkspacePrepFailed), never
// silently adopted as the launch Dir.
func TestLaunchFreshSandboxManagedDirOutsideRootDenied(t *testing.T) {
	rec := newFakeRecorder()
	l := &fakeLauncher{handle: "H6"}
	base := t.TempDir()
	projectRoot := mkdirT(t, base, "project")
	workspacesRoot := mkdirT(t, base, "workspaces")
	outsideDir := mkdirT(t, base, "elsewhere") // sibling, NOT under workspacesRoot

	sb := &fakeSandboxer{result: PrepareResult{Dir: outsideDir, WrapArgv: []string{"bwrap"}}}
	svc := New(Options{
		Policy:               Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{projectRoot}},
		Recorder:             rec,
		Launcher:             l,
		Sandboxer:            sb,
		SandboxWorkspacesDir: workspacesRoot,
	})

	_, err := svc.LaunchFresh(context.Background(), FreshRequest{
		Tool: "claude-code", Subcommand: "claude", Sandbox: true, ProjectRoot: projectRoot,
	})
	if !errors.Is(err, ErrWorkspacePrepFailed) {
		t.Fatalf("err = %v, want wrapping ErrWorkspacePrepFailed", err)
	}
	if !errors.Is(err, ErrManagedWorkspaceDenied) {
		t.Fatalf("err = %v, want wrapping ErrManagedWorkspaceDenied", err)
	}
	if l.calls != 0 {
		t.Fatalf("Launcher.Spawn was called %d times, want 0", l.calls)
	}
	if rec.recordCalls != 0 {
		t.Fatalf("RecordRun was called %d times, want 0 (no orphan run)", rec.recordCalls)
	}
}

// (e) ValidateManagedWorkspace table: under the managed root, escaping it,
// and an empty/unconfigured managed root (misconfiguration, fail-closed).
func TestValidateManagedWorkspace(t *testing.T) {
	base := t.TempDir()
	managedRoot := mkdirT(t, base, "workspaces")
	underRoot := mkdirT(t, managedRoot, "run-1", "repo")
	outsideRoot := mkdirT(t, base, "not-managed")

	tests := []struct {
		name        string
		path        string
		managedRoot string
		wantErr     bool
	}{
		{name: "path strictly under managed root", path: underRoot, managedRoot: managedRoot, wantErr: false},
		{name: "path equals managed root itself", path: managedRoot, managedRoot: managedRoot, wantErr: false},
		{name: "path escapes managed root (sibling dir)", path: outsideRoot, managedRoot: managedRoot, wantErr: true},
		{name: "empty managed root is a misconfiguration", path: underRoot, managedRoot: "", wantErr: true},
		{name: "empty path", path: "", managedRoot: managedRoot, wantErr: true},
		{name: "nonexistent path", path: filepath.Join(managedRoot, "does-not-exist"), managedRoot: managedRoot, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateManagedWorkspace(tc.path, tc.managedRoot)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateManagedWorkspace(%q, %q) = (%q, nil), want an error", tc.path, tc.managedRoot, got)
				}
				if !errors.Is(err, ErrManagedWorkspaceDenied) {
					t.Fatalf("err = %v, want wrapping ErrManagedWorkspaceDenied", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateManagedWorkspace(%q, %q): unexpected error %v", tc.path, tc.managedRoot, err)
			}
			abs, cerr := filepath.Abs(tc.path)
			if cerr != nil {
				t.Fatalf("filepath.Abs: %v", cerr)
			}
			wantCanon, cerr := filepath.EvalSymlinks(abs)
			if cerr != nil {
				t.Fatalf("filepath.EvalSymlinks: %v", cerr)
			}
			if got != wantCanon {
				t.Fatalf("got %q, want canonical %q", got, wantCanon)
			}
		})
	}
}
