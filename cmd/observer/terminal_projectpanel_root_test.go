package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/sshprofile"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// newDefaultCwdService assembles a REAL termsvc.Service in the devbox shape:
// no [terminal.launch].allowed_project_roots configured, so no launch can carry
// an authorized project root, while every child still runs in (and inherits)
// the daemon's own working directory.
func newDefaultCwdService(t *testing.T, launcher termsvc.Launcher) (*termsvc.Service, string) {
	t.Helper()
	daemonCwd := t.TempDir() // stands in for the devbox daemon's cwd, /home/azureuser
	canonCwd, err := filepath.EvalSymlinks(daemonCwd)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: launcher,
		Policy: termsvc.Policy{
			AllowFresh:   true,
			AllowedTools: []string{"opencode"},
			// Deliberately EMPTY, exactly like the devbox's config: with no
			// allowed_project_roots there is no root the dashboard could pass.
			AllowedProjectRoots: nil,
		},
		Getwd: func() (string, error) { return daemonCwd, nil },
	})
	return svc, canonCwd
}

// TestProjectRootResolverServesSpawnDirForDefaultCwdLaunch pins the OPERATOR
// RULING of 2026-08-28 at the wiring seam: the dashboard's Files/Git panel
// resolves a default-cwd launch to the directory the child ACTUALLY runs in
// (svc.SpawnDir), not to the authorization answer (svc.ProjectRoot), which is
// empty for every launch the operator never allow-listed a root for.
//
// MUTATION PROOF: rewiring browsableRoot's fallback back to svc.ProjectRoot
// fails this test on the "browsable path" assertion, because the launch below
// has no authorized root at all while its child's cwd is perfectly well known.
// Dropping the Authorized flag instead (reporting the spawn dir as an
// allow-listed project root) fails the provenance assertion, which is what
// keeps the panel header honest.
func TestProjectRootResolverServesSpawnDirForDefaultCwdLaunch(t *testing.T) {
	svc, canonCwd := newDefaultCwdService(t, &recordingLauncher{})
	res, err := svc.LaunchFresh(context.Background(), termsvc.FreshRequest{Tool: "opencode", Subcommand: "opencode"})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	// Precondition: this launch genuinely has NO authorized project root. Without
	// it the test could pass on the old wiring.
	if root, ok := svc.ProjectRoot(res.Handle); ok || root != "" {
		t.Fatalf("ProjectRoot = (%q, %v); the devbox shape has no authorized root", root, ok)
	}

	resolve := projectRootResolver(&launchManagerAdapter{svc: svc})
	if resolve == nil {
		t.Fatal("projectRootResolver returned nil for a wired adapter; the panel would be 404-disabled")
	}

	got, known := resolve(res.Handle)
	if !known {
		t.Fatal("resolver reported known=false for a live run")
	}
	if got.Path != canonCwd {
		t.Fatalf("browsable path = %q, want the run's spawn dir %q (operator ruling 2026-08-28: "+
			"Files/Git follow the run's factual working directory)", got.Path, canonCwd)
	}
	if got.Authorized {
		t.Fatal("browsable root reported Authorized=true for a default-cwd launch; " +
			"the panel would call the daemon's cwd an operator-chosen project root")
	}

	// An unknown/exited token stays a miss — the liveness posture is unchanged.
	if _, known := resolve("GHOST"); known {
		t.Fatal("resolver reported known=true for an unknown token")
	}
}

// TestProjectRootResolverKeepsAuthorizedRootUnchanged pins the other half: a
// launch INTO an allow-listed root still resolves to that root and is still
// reported as an authorized project root. The ruling widened the default-cwd
// case; it changed nothing about the allow-listed one.
func TestProjectRootResolverKeepsAuthorizedRootUnchanged(t *testing.T) {
	root := t.TempDir()
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	daemonCwd := t.TempDir() // deliberately DIFFERENT from the launch root
	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: &recordingLauncher{},
		Policy: termsvc.Policy{
			AllowFresh:          true,
			AllowedTools:        []string{"opencode"},
			AllowedProjectRoots: []string{root},
		},
		Getwd: func() (string, error) { return daemonCwd, nil },
	})
	res, err := svc.LaunchFresh(context.Background(), termsvc.FreshRequest{
		Tool: "opencode", Subcommand: "opencode", ProjectRoot: root,
	})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}

	got, known := projectRootResolver(&launchManagerAdapter{svc: svc})(res.Handle)
	if !known || got.Path != canonRoot {
		t.Fatalf("browsable root = (%q, %v), want (%q, true)", got.Path, known, canonRoot)
	}
	if !got.Authorized {
		t.Fatal("an allow-listed launch root must report Authorized=true")
	}
}

// TestBrowsableRootExcludesSSHRun pins the one exclusion from the widening, and
// pins it on run SHAPE rather than tool name: a termrun.KindSSH child's shell
// lives on another machine, so the local directory its ssh client happens to run
// in is NOT the terminal's working directory. Browsing it would be a false
// claim, so the buttons stay honestly disabled (zero TerminalRoot → 409).
func TestBrowsableRootExcludesSSHRun(t *testing.T) {
	daemonCwd := t.TempDir()
	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: &recordingLauncher{},
		Policy: termsvc.Policy{
			AllowSSH: true,
			SSHProfiles: []sshprofile.Profile{
				{Name: "demo-box", Label: "Client demo", Host: "demo.example.com", User: "ubuntu", Port: 2222},
			},
		},
		Getwd: func() (string, error) { return daemonCwd, nil },
	})
	res, err := svc.LaunchSSH(context.Background(), termsvc.SSHRequest{Profile: "demo-box"})
	if err != nil {
		t.Fatalf("LaunchSSH: %v", err)
	}
	// Precondition: the service DOES know a local spawn dir for this run — the
	// exclusion must come from the run's shape, not from a missing directory.
	if dir, ok := svc.SpawnDir(res.Handle); !ok || dir == "" {
		t.Fatalf("SpawnDir = (%q, %v); expected the daemon cwd, otherwise this test is vacuous", dir, ok)
	}
	if got := browsableRoot(svc, res.Handle); got.Path != "" {
		t.Fatalf("browsableRoot = %+v for an SSH run; its files live on another machine", got)
	}
}

// TestSnapshotEnablesProjectPanelForDefaultCwdLaunch pins the button half of the
// ruling through the REAL adapter Snapshot the dashboard reads: a default-cwd
// launch reports HasProjectRoot=true, so the Files/Git buttons in the terminal
// modal are enabled by default. Snapshot and the panel endpoint consult the same
// browsableRoot decision, so they cannot disagree.
func TestSnapshotEnablesProjectPanelForDefaultCwdLaunch(t *testing.T) {
	mgr := termsession.NewManager(termsession.Options{Spawner: fakeSpawner{}})
	t.Cleanup(mgr.Shutdown)

	svc, canonCwd := newDefaultCwdService(t, mgrLauncher{mgr: mgr})
	res, err := svc.LaunchFresh(context.Background(), termsvc.FreshRequest{Tool: "opencode", Subcommand: "opencode"})
	if err != nil {
		t.Fatalf("LaunchFresh: %v", err)
	}
	if _, ok := svc.ProjectRoot(res.Handle); ok {
		t.Fatal("ProjectRoot reported a root for a default-cwd launch; the devbox shape has none")
	}

	adapter := &launchManagerAdapter{svc: svc, mgr: mgr}
	var found *dashboard.LaunchInfo
	for i, info := range adapter.Snapshot() {
		if info.ID == res.Handle {
			found = &adapter.Snapshot()[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("handle %q missing from Snapshot", res.Handle)
	}
	if !found.HasProjectRoot {
		t.Fatal("HasProjectRoot = false for a default-cwd launch; the Files/Git buttons would render disabled " +
			"even though the panel endpoint serves the run's working directory")
	}
	// The path itself is never carried on the wire (LaunchInfo reaches remote
	// viewers) — only the gated panel endpoint discloses it.
	if got := browsableRoot(svc, res.Handle); got.Path != canonCwd {
		t.Fatalf("browsableRoot path = %q, want %q", got.Path, canonCwd)
	}
}
