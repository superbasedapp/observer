//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_oci_merge_test.go: the SBX-P3B merge fixes to the oci
// drivers. F4: a run's projected state and db-copy output are removed at
// Destroy and by the daemon-start sweep once the run is not live. F7: the
// backend a fresh request names reaches chosenDriver through LaunchFresh,
// the Sandboxer seam and ComposePrepare.

// makeOCIRunState makes the two directories a projecting run leaves.
func makeOCIRunState(t *testing.T, observerDir, managedRoot, runID string) {
	t.Helper()
	for _, d := range []string{filepath.Join(ociProjectionRoot(managedRoot, runID), "0"), filepath.Join(ociDBCopyRunDir(observerDir, runID), "0")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "store.db"), []byte("SQLite format 3\x00"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func ociRunStateExists(observerDir, managedRoot, runID string) (proj, copies bool) {
	_, perr := os.Lstat(ociProjectionRoot(managedRoot, runID))
	_, cerr := os.Lstat(ociDBCopyRunDir(observerDir, runID))
	return perr == nil, cerr == nil
}

// TestOCIRunStateRemovedAtDestroyAndSwept (audit SBX-P3B F4).
func TestOCIRunStateRemovedAtDestroyAndSwept(t *testing.T) {
	od, mr := t.TempDir(), t.TempDir()
	const destroyed, live, dead = "destroyedRun0001", "liveRun000000001", "deadRun000000001"
	for _, id := range []string{destroyed, live, dead} {
		makeOCIRunState(t, od, mr, id)
	}
	d := &ociDriver{r: &sandboxRuntime{observerDir: od, managedRoot: mr}}
	if _, err := d.Destroy(context.Background(), termsvc.SandboxRun{ID: destroyed}); err != nil {
		t.Fatal(err)
	}
	if p, c := ociRunStateExists(od, mr, destroyed); p || c {
		t.Fatalf("Destroy left the projection (%v) or the db copies (%v)", p, c)
	}

	// A live run (its relay record exists), a bwrap workspace that merely
	// shares a run id, and a symlinked projection root are left alone.
	if err := os.MkdirAll(sandboxrelayd.RunsDir(od), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sandboxrelayd.RunsDir(od), live+".json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(mr, dead)
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := testSymlink(t, outside, ociProjectionRoot(mr, "linkRun000000001")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := ociSweepRunState(od, mr, ociRunLive(od))
	if err != nil || n != 1 {
		t.Fatalf("swept %d runs (%v), want 1", n, err)
	}
	if p, c := ociRunStateExists(od, mr, dead); p || c {
		t.Fatalf("the sweep left a dead run's projection (%v) or db copies (%v)", p, c)
	}
	if p, c := ociRunStateExists(od, mr, live); !p || !c {
		t.Fatalf("the sweep removed a live run's projection (%v) or db copies (%v)", p, c)
	}
	if _, err := os.Stat(ws); err != nil {
		t.Fatalf("the sweep removed a workspace: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("the sweep followed a symlink: %v", err)
	}
	if err := ociRemoveRunState(od, mr, "../escape"); err == nil {
		t.Fatal("a run id that is not a token was accepted")
	}
}

// chainDriver stands for an active driver: it records the backend each
// Create was asked for and composes a marker argv.
type chainDriver struct {
	sandboxDriver
	asked []string
}

func (c *chainDriver) Create(_ context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	c.asked = append(c.asked, req.Backend)
	return termsvc.CreateResult{Run: termsvc.SandboxRun{ID: "chainRun00000001", Tool: req.Tool, Dir: req.ProjectRoot, ProjectRoot: req.ProjectRoot}}, nil
}

func (c *chainDriver) Attach(context.Context, termsvc.CreateResult) (termsvc.AttachResult, error) {
	return termsvc.AttachResult{WrapArgv: []string{"chain-wrap"}}, nil
}

// TestFreshRequestBackendReachesChosenDriver (audit SBX-P3B F7): a fresh
// request that names oci-runc goes LaunchFresh, the Sandboxer seam,
// ComposePrepare, Create and chosenDriver into that driver, whose argv the
// spawned launch carries; a named row with no active driver refuses and is
// never substituted.
func TestFreshRequestBackendReachesChosenDriver(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("oci-runc runs on Linux and WSL2")
	}
	countProbeEnv(t, true)
	rt := ociTestRuntime(t, ociTestConfig(t, true, "oci-runc", "bwrap"))
	real, ok := rt.drivers[sandboxbackend.BackendOCIRunc]
	if !ok {
		t.Fatal("the oci-runc driver is not active")
	}
	fake := &chainDriver{sandboxDriver: real}
	rt.drivers[sandboxbackend.BackendOCIRunc] = fake
	root := t.TempDir()
	lau := &recordingLauncher{}
	svc := termsvc.New(termsvc.Options{
		Recorder:             assembledRecorder{},
		Launcher:             lau,
		Sandboxer:            rt,
		SandboxWorkspacesDir: rt.managedRoot,
		Policy:               termsvc.Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
	})
	req := termsvc.FreshRequest{Tool: "claude-code", Subcommand: "claude", ProjectRoot: root, Sandbox: true, SandboxBackend: sandboxbackend.BackendOCIRunc}
	if _, err := svc.LaunchFresh(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.asked, []string{sandboxbackend.BackendOCIRunc}) {
		t.Fatalf("the driver was asked for %v", fake.asked)
	}
	if !lau.last.Sandboxed || !slices.Equal(lau.last.WrapArgv, []string{"chain-wrap"}) {
		t.Fatalf("spawned %+v, want the chosen driver's argv", lau.last)
	}

	lau.last = termsvc.LaunchRequest{}
	req.SandboxBackend = sandboxbackend.BackendSeatbelt
	if _, err := svc.LaunchFresh(context.Background(), req); err == nil || !strings.Contains(err.Error(), sandboxbackend.BackendSeatbelt) {
		t.Fatalf("a named row with no active driver: %v", err)
	}
	if len(fake.asked) != 1 || lau.last.Dir != "" {
		t.Fatalf("a refused launch reached a driver (%v) or the spawner (%+v)", fake.asked, lau.last)
	}
}
