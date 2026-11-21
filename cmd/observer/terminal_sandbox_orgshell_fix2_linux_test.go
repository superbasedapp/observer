//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestOrgShellRunRecordMapsTheBoxWorkspace (fix round 2, G4-R2): the org
// row's run record maps /sandbox/workspace onto the run's directory and
// never lists the box path as a root, so a box-path hook read resolves to
// the laptop's file and the laptop's own /sandbox/workspace is never read;
// a same-path vendor maps nothing.
func TestOrgShellRunRecordMapsTheBoxWorkspace(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	obs := relayShortDir(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("laptop copy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrStUw", Tool: "claude-code", Dir: dir, ProjectRoot: dir}
	if err := (&sandboxRuntime{observerDir: obs}).writeRunRecord(run, hostedPathMap(hostedPathInput{vendor: v, runDir: run.Dir})...); err != nil {
		t.Fatal(err)
	}
	rec, err := sandboxrelayd.ReadRun(obs, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.PathMap) != 1 || rec.PathMap[0].Box != v.BoxWorkspace || rec.PathMap[0].Host != dir {
		t.Fatalf("path map %+v", rec.PathMap)
	}
	if slices.Contains(rec.Roots, v.BoxWorkspace) || sandboxrelayd.RootsContain(rec.Roots, v.BoxWorkspace+"/notes.md") {
		t.Errorf("the box path is a root on this machine: %v", rec.Roots)
	}
	mapped, ok := sandboxrelayd.MapBoxPath(rec.PathMap, v.BoxWorkspace+"/notes.md")
	if b, err := sandboxrelayd.ConfinedFiles(rec.Roots).ReadFile(mapped); !ok || err != nil || string(b) != "laptop copy\n" {
		t.Errorf("box-path read %q %v %v", b, ok, err)
	}
	if _, ok := sandboxrelayd.MapBoxPath(rec.PathMap, "/sandbox/run/sessions.json"); ok {
		t.Error("a path outside the map was mapped")
	}
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	if m := hostedPathMap(hostedPathInput{vendor: e2b, runDir: dir}); m != nil {
		t.Errorf("a same-path vendor maps %v", m)
	}
}

// TestOrgShellRunRecordPathClasses (FX4 item 3, live L3-07): the org row's
// run record carries both box-path classes: the workspace onto the run's
// directory, and the tool's state dir in the box's agent home onto the
// matching directory of the run's quarantine, which is where the transcript
// pull writes the same file (the pull's LocalRel root) and a read root for
// file keys. The agent home itself and the rest of it map nowhere.
func TestOrgShellRunRecordPathClasses(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	obs := relayShortDir(t)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := termsvc.SandboxRun{ID: "AbCdEfGhIjKlMnOpQrStUw", Tool: "claude-code", Dir: dir, ProjectRoot: dir}
	quar := hostedQuarantineDir(obs, run.ID)
	in := hostedPathInput{vendor: v, runDir: dir, quarantine: quar, stateRel: []string{".claude"}}
	if err := (&sandboxRuntime{observerDir: obs}).writeRemoteRunRecord(run, hostedPathMap(in)); err != nil {
		t.Fatal(err)
	}
	rec, err := sandboxrelayd.ReadRun(obs, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := []sandboxrelayd.PathPrefix{{Box: v.BoxWorkspace, Host: dir}, {Box: v.BoxHome + "/.claude", Host: filepath.Join(quar, "0")}}
	if !slices.Equal(rec.PathMap, want) {
		t.Fatalf("path map %+v, want %+v", rec.PathMap, want)
	}
	if !slices.Contains(rec.Roots, filepath.Join(quar, "0")) {
		t.Errorf("the quarantine copy is not a read root: %v", rec.Roots)
	}
	// The transcript pull's own plan puts the same box file at the same
	// host path.
	box := v.BoxHome + "/.claude/projects/-sandbox-workspace/s.jsonl"
	items, _ := sandboxremote.PlanPull([]string{v.BoxHome + "/.claude"}, []sandboxremote.BoxFile{{Path: box, Size: 10, Regular: true}}, sandboxremote.PullLimits{})
	mapped, ok := sandboxrelayd.MapBoxPath(rec.PathMap, box)
	if len(items) != 1 || !ok || mapped != filepath.Join(quar, filepath.FromSlash(items[0].LocalRel)) {
		t.Fatalf("the map (%q %v) and the pull (%+v) disagree", mapped, ok, items)
	}
	for _, p := range []string{v.BoxHome, v.BoxHome + "/.ssh/id_ed25519", v.BoxHome + "/.claude.json"} {
		if m, ok := sandboxrelayd.MapBoxPath(rec.PathMap, p); ok {
			t.Errorf("%s maps to %s", p, m)
		}
	}
}
