//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// fakeProjectionWatcher records the watcher seam's calls.
type fakeProjectionWatcher struct {
	mu      sync.Mutex
	added   [][3]string
	binds   []watcher.ProjectionBinding
	removed []string
}

func (f *fakeProjectionWatcher) add(_ context.Context, tool, host, box string, bind watcher.ProjectionBinding) (func(), error) {
	f.mu.Lock()
	f.added = append(f.added, [3]string{tool, host, box})
	f.binds = append(f.binds, bind)
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		f.removed = append(f.removed, host)
		f.mu.Unlock()
	}, nil
}

func (f *fakeProjectionWatcher) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.added), len(f.removed)
}

// ociProjectionDriver composes a run on the named row with delivery d.
func ociProjectionDriver(t *testing.T, backend string, delivery sandboxoci.Delivery) (*ociDriver, string, ociPlanFile, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	claude := filepath.Join(home, ".claude")
	_ = os.MkdirAll(claude, 0o700)
	_ = os.WriteFile(filepath.Join(claude, "CLAUDE.md"), []byte("be brief\n"), 0o600)
	_ = os.WriteFile(filepath.Join(claude, "settings.json"), []byte(`{"env":{"ANTHROPIC_API_KEY":"sk-not-real"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(claude, ".credentials.json"), []byte(`{"oauth":"not-real"}`), 0o600)
	ws := filepath.Join(home, "proj")
	_ = os.MkdirAll(ws, 0o700)
	cfg := ociTestConfig(t, true, backend)
	cfg.Terminal.Sandbox.OCI.AllowRootful = true
	exe, _ := os.Executable()
	rt, err := newSandboxRuntime(cfg.Terminal.Sandbox, nil, filepath.Join(home, ".observer"), exe, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt.applyDaemonConfig(cfg)
	d, ok := rt.drivers[backend].(*ociDriver)
	if !ok {
		t.Fatalf("no %s driver", backend)
	}
	runID := "runproj0000000001"
	d.choices.Store(runID, ociRunChoice{image: "node@sha256:" + strings.Repeat("b", 64), delivery: delivery})
	res := sandboxoci.ProbeResult{
		Socket:   "/run/docker.sock",
		Identity: sandboxoci.Identity{Engine: sandboxoci.EngineDocker, Mode: sandboxoci.ModeRootful, APIVersion: "1.52", Fingerprint: "f"},
		User:     sandboxoci.UserPlan{Row: "rootful engine (opt-in)", User: "1000:1000"},
		Bridge:   sandboxoci.BridgeHostUDS,
	}
	wrap, err := d.compose(termsvc.CreateResult{Run: termsvc.SandboxRun{ID: runID, Tool: "claude-code", Dir: ws}, ProxyRouted: true}, res)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := readOCIPlan(wrap[3])
	if err != nil {
		t.Fatal(err)
	}
	return d, home, plan, runID
}

// TestOCIProjectionSeedsAndWatchesTranscripts is G27 on both projecting
// paths: the runsc row, and an image's own copy of the tool on oci-runc.
// The seed row's non-secret file is copied in, the settings file (an env
// block can hold keys) and the sign-in store are not, the transcript
// subtree is created and registered with the watcher for the run, and
// Destroy removes it.
func TestOCIProjectionSeedsAndWatchesTranscripts(t *testing.T) {
	cases := []struct {
		name, backend string
		delivery      sandboxoci.Delivery
	}{
		{"runsc row", sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind},
		{"image copy on oci-runc", sandboxbackend.BackendOCIRunc, sandboxoci.DeliveryImageInstalled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fw := &fakeProjectionWatcher{}
			setSandboxProjectionWatcher(fw.add)
			t.Cleanup(func() { setSandboxProjectionWatcher(nil) })
			d, home, plan, runID := ociProjectionDriver(t, c.backend, c.delivery)
			if len(plan.Projections) != 3 {
				t.Fatalf("projections %+v", plan.Projections)
			}
			claude := filepath.Join(home, ".claude")
			var pd sandboxoci.ProjectedDir
			for _, p := range plan.Projections {
				if p.Target == claude {
					pd = p
				}
			}
			for _, b := range plan.Create.Binds {
				if b.Source == claude {
					t.Fatalf("the real tool state is bound: %+v", b)
				}
			}
			if b, err := os.ReadFile(filepath.Join(pd.Host, "CLAUDE.md")); err != nil || string(b) != "be brief\n" {
				t.Fatalf("the seed file was not copied: %q %v", b, err)
			}
			for _, secret := range []string{"settings.json", ".credentials.json"} {
				if _, err := os.Lstat(filepath.Join(pd.Host, secret)); err == nil {
					t.Fatalf("%s was seeded into the projection", secret)
				}
			}
			host := filepath.Join(pd.Host, "projects")
			if fi, err := os.Stat(host); err != nil || !fi.IsDir() {
				t.Fatalf("the transcript subtree was not made: %v", err)
			}
			if len(plan.TranscriptRoots) != 1 || plan.TranscriptRoots[0] != host {
				t.Fatalf("plan transcript roots %v", plan.TranscriptRoots)
			}
			fw.mu.Lock()
			added := append([][3]string(nil), fw.added...)
			binds := append([]watcher.ProjectionBinding(nil), fw.binds...)
			fw.mu.Unlock()
			if len(added) != 1 || added[0] != [3]string{"claude-code", host, filepath.Join(claude, "projects")} {
				t.Fatalf("watch roots %v", added)
			}
			// The root is bound to the run (audit finding 3).
			if len(binds) != 1 || binds[0].RunID != runID || !filepath.IsAbs(binds[0].Workspace) {
				t.Fatalf("the projection root is not bound to the run: %+v", binds)
			}
			if _, err := d.Destroy(context.Background(), termsvc.SandboxRun{ID: runID, Tool: "claude-code"}); err != nil {
				t.Fatal(err)
			}
			if a, r := fw.counts(); a != 1 || r != 1 {
				t.Fatalf("added %d removed %d after Destroy", a, r)
			}
		})
	}
}

// TestOCIProjectionUnwatchedWhenTheRunEnds: the helper removes the
// projection when the container ends; the daemon then drops the root.
func TestOCIProjectionUnwatchedWhenTheRunEnds(t *testing.T) {
	old := ociProjectionWatchPoll
	ociProjectionWatchPoll = 20 * time.Millisecond
	t.Cleanup(func() { ociProjectionWatchPoll = old })
	fw := &fakeProjectionWatcher{}
	setSandboxProjectionWatcher(fw.add)
	t.Cleanup(func() { setSandboxProjectionWatcher(nil) })
	_, _, plan, _ := ociProjectionDriver(t, sandboxbackend.BackendOCIRunsc, sandboxoci.DeliveryHostBind)
	if err := ociRemoveProjection(plan.Projections); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, r := fw.counts(); r == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the projection root stayed watched after its directory was removed")
}

// TestOCISameKernelBindsTheRealStateForAProvenTool: a host-bound tool and a
// cache install pinned to the host's version keep the real state bound on
// oci-runc (nothing is projected or watched).
func TestOCISameKernelBindsTheRealStateForAProvenTool(t *testing.T) {
	for _, dl := range []sandboxoci.Delivery{sandboxoci.DeliveryHostBind, sandboxoci.DeliveryInstallCache} {
		fw := &fakeProjectionWatcher{}
		setSandboxProjectionWatcher(fw.add)
		_, home, plan, _ := ociProjectionDriver(t, sandboxbackend.BackendOCIRunc, dl)
		setSandboxProjectionWatcher(nil)
		if len(plan.Projections) != 0 || len(plan.TranscriptRoots) != 0 {
			t.Fatalf("%s: projected %+v", dl, plan.Projections)
		}
		bound := false
		for _, b := range plan.Create.Binds {
			bound = bound || (b.Source == filepath.Join(home, ".claude") && !b.ReadOnly)
		}
		if !bound {
			t.Fatalf("%s: the real state is not bound", dl)
		}
		if a, _ := fw.counts(); a != 0 {
			t.Fatalf("%s: a root was watched", dl)
		}
	}
}

// TestCrossesKernelRowsAlwaysProject: no delivery lets a row that crosses a
// kernel bind the real state (plan 5.4's coverage rule, Projection = bind
// refused for every CrossesKernel row).
func TestCrossesKernelRowsAlwaysProject(t *testing.T) {
	for _, p := range sandboxoci.RuntimeProfiles() {
		row, _ := sandboxbackend.Get(p.Backend)
		if !row.Iso.CrossesKernel {
			continue
		}
		for _, dl := range []sandboxoci.Delivery{sandboxoci.DeliveryHostBind, sandboxoci.DeliveryImageInstalled, sandboxoci.DeliveryInstallCache} {
			if !sandboxoci.ProjectsState(dl, row.Iso.CrossesKernel) {
				t.Errorf("%s binds the real state for delivery %s", p.Backend, dl)
			}
		}
	}
}
