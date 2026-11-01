//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestManagedDirectLaunchUsesOnlyCurrentExactProcessCutoff(t *testing.T) {
	ctx := context.Background()
	// The "different manifest" row must still be refused once the bounded
	// wait for the daemon's inventory ends; keep that wait short here.
	settle, poll := budgetLaunchInventorySettle, budgetLaunchInventoryPoll
	budgetLaunchInventorySettle, budgetLaunchInventoryPoll = 200*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { budgetLaunchInventorySettle, budgetLaunchInventoryPoll = settle, poll })
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	executable := filepath.Join(t.TempDir(), "opencode")
	raw, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	candidates := []intervention.InstalledCandidate{{Tool: "opencode", SurfaceID: "opencode/cli", LauncherPath: executable}}
	manifest, err := intervention.BuildInstallManifest(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := manifest.Surface("opencode/cli")
	if !ok || row.State != intervention.BindingReady || len(row.Targets) != 1 {
		t.Fatalf("fixture surface = %+v", row)
	}

	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	controller, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nodeInterventionAuthority(ctx, st, controller.UID, time.Now().UTC())
	if err != nil || !authority.Authorized {
		t.Fatalf("authority = %+v, err=%v", authority, err)
	}
	base := nodeInterventionStatus{
		At: time.Now().UTC(), Controller: controller, Authority: authority.Authority,
		State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		ManifestFingerprint: intervention.InstallManifestFingerprint(manifest),
		ControlledSurfaces:  []string{"opencode/cli"},
		Reason:              "verified installed processes only",
	}
	originalCandidates := budgetLaunchInterventionCandidates
	budgetLaunchInterventionCandidates = func() []intervention.InstalledCandidate { return candidates }
	t.Cleanup(func() { budgetLaunchInterventionCandidates = originalCandidates })

	writeStatus := func(t *testing.T, status nodeInterventionStatus) {
		t.Helper()
		if err := writeNodeInterventionStatus(ctx, dbPath, status); err != nil {
			t.Fatal(err)
		}
	}
	writeStatus(t, base)
	evidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: executable}
	if err := enforceBudgetControlledLaunch(ctx, cfgPath, "opencode", evidence); err != nil {
		t.Fatalf("exact controlled launch refused: %v", err)
	}

	other := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(other, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	// A node-wide INCOMPLETE scan degrades the report's process_cutoff cell —
	// one uninspectable same-UID process anywhere on the machine is enough —
	// and gating recovery on it refused every launch of every tool on any real
	// workstation. Coverage is per SURFACE: this surface is still bound, ready
	// and controlled under the fingerprint being reconciled.
	degraded := base
	degraded.ProcessCutoff = "degraded"
	writeStatus(t, degraded)
	if err := enforceBudgetControlledLaunch(ctx, cfgPath, "opencode", evidence); err != nil {
		t.Fatalf("node-wide degraded scan refused a controlled surface: %v", err)
	}

	cases := []struct {
		name     string
		status   nodeInterventionStatus
		evidence budgetLaunchEvidence
	}{
		{name: "stale report", status: func() nodeInterventionStatus { s := base; s.At = s.At.Add(-time.Minute); return s }(), evidence: evidence},
		{name: "different manifest", status: func() nodeInterventionStatus {
			s := base
			s.ManifestFingerprint = "v1 " + string(make([]byte, 64))
			return s
		}(), evidence: evidence},
		{name: "surface not attested", status: func() nodeInterventionStatus { s := base; s.ControlledSurfaces = nil; return s }(), evidence: evidence},
		// A leading argument the surface declares as NON-billable is not the
		// CLI the controller binds, so it cannot inherit that surface's cutoff
		// coverage. (Under the inverted invocation model an UNDECLARED leading
		// argument — `run`, a prompt, a flag — is the billable CLI and IS
		// covered; only a declared non-billable form falls out here.)
		{name: "declared non-CLI leading argument", status: base, evidence: budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: executable, Arguments: []string{"serve"}}},
		{name: "different executable", status: base, evidence: budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: other}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeStatus(t, tc.status)
			err := enforceBudgetControlledLaunch(ctx, cfgPath, "opencode", tc.evidence)
			if err == nil {
				t.Fatal("uncontrolled launch was admitted")
			}
		})
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	writeStatus(t, base)
	if !nodeProcessCutoffCoversLaunch(ctx, cfg, st, "opencode", evidence) {
		t.Fatal("direct helper lost the exact covered launch")
	}
}

// budgetLaunchLayout is one installed layout read on demo node 1
// (2026-10-08, read-only). build writes it under root with fixture files and
// returns the PATH entry a launcher resolves. Every ELF is a copy of
// /bin/true; nothing here runs a vendor tool.
type budgetLaunchLayout struct {
	tool  string
	build func(t *testing.T, root string, elf []byte) string
}

func writeLayoutFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o700); err != nil {
		t.Fatal(err)
	}
}

func linkLayout(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// budgetLaunchNodeOneLayouts are the five tools the operator reported refused
// under the managed hard budget (D-445, D-453) plus the other registry rows
// found in the same state on node 1 (grok, prime-agent), each in the layout
// its installer left there.
func budgetLaunchNodeOneLayouts() []budgetLaunchLayout {
	node := []byte("#!/usr/bin/env node\n")
	return []budgetLaunchLayout{
		{"junie", func(t *testing.T, root string, elf []byte) string {
			shim := filepath.Join(root, "bin", "junie")
			writeLayoutFile(t, shim, []byte("#!/bin/bash\nexec \"$HOME/.local/share/junie/versions/3579.5/junie\" \"$@\"\n"))
			writeLayoutFile(t, filepath.Join(root, "share", "junie", "versions", "3579.5", "junie"), []byte("#!/bin/bash\nexec \"$(dirname \"$0\")/junie-app/bin/junie\" \"$@\"\n"))
			writeLayoutFile(t, filepath.Join(root, "share", "junie", "versions", "3579.5", "junie-app", "bin", "junie"), elf)
			return shim
		}},
		{"crush", func(t *testing.T, root string, elf []byte) string {
			pkg := filepath.Join(root, "lib", "node_modules", "@charmland", "crush")
			writeLayoutFile(t, filepath.Join(pkg, "run-crush.js"), node)
			writeLayoutFile(t, filepath.Join(pkg, "bin", "crush"), elf)
			link := filepath.Join(root, "bin", "crush")
			linkLayout(t, filepath.Join(pkg, "run-crush.js"), link)
			return link
		}},
		{"cline-cli", func(t *testing.T, root string, elf []byte) string {
			pkg := filepath.Join(root, "lib", "node_modules", "cline")
			writeLayoutFile(t, filepath.Join(pkg, "bin", "cline"), node)
			writeLayoutFile(t, filepath.Join(pkg, "bin", ".cline"), elf)
			link := filepath.Join(root, "bin", "cline")
			linkLayout(t, filepath.Join(pkg, "bin", "cline"), link)
			return link
		}},
		{"aider", func(t *testing.T, root string, elf []byte) string {
			venv := filepath.Join(root, "share", "uv", "tools", "aider-chat", "bin")
			writeLayoutFile(t, filepath.Join(root, "usr", "python3.12"), elf)
			linkLayout(t, filepath.Join(root, "usr", "python3.12"), filepath.Join(venv, "python"))
			writeLayoutFile(t, filepath.Join(venv, "aider"), []byte("#!"+filepath.Join(venv, "python")+"\n"))
			link := filepath.Join(root, "bin", "aider")
			linkLayout(t, filepath.Join(venv, "aider"), link)
			return link
		}},
		{"grok", func(t *testing.T, root string, elf []byte) string {
			writeLayoutFile(t, filepath.Join(root, "grok", "downloads", "grok-linux-x86_64"), elf)
			linkLayout(t, filepath.Join(root, "grok", "downloads", "grok-linux-x86_64"), filepath.Join(root, "grok", "bin", "grok"))
			link := filepath.Join(root, "bin", "grok")
			linkLayout(t, filepath.Join(root, "grok", "bin", "grok"), link)
			return link
		}},
		{"prime-agent", func(t *testing.T, root string, elf []byte) string {
			release := filepath.Join(root, "share", "prime-agent", "releases", "0.9.8-linux-x64", "prime-agent")
			writeLayoutFile(t, release, elf)
			link := filepath.Join(root, "bin", "prime-agent")
			linkLayout(t, release, link)
			return link
		}},
		// T-706: install.sh moves the native pool ELF to ~/.local/bin/pool;
		// with the Linux trajectory store grounded, poolside/cli is cuttable.
		{"poolside", func(t *testing.T, root string, elf []byte) string {
			pool := filepath.Join(root, "bin", "pool")
			writeLayoutFile(t, pool, elf)
			return pool
		}},
	}
}

// TestManagedDirectLaunchAdmitsEveryCuttableNodeOneLayout pins T-693 end to
// end, one row per tool: the install binds, the daemon's report lists the
// tool's CLI surface as controlled, and a hard-budget launch of the PATH
// entry is admitted on process cutoff even though the tool's model route is
// absent (junie), unprovable (crush, aider, grok, prime-agent) or not carried
// (cline-cli launched unrouted on its own provider).
func TestManagedDirectLaunchAdmitsEveryCuttableNodeOneLayout(t *testing.T) {
	elf, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for _, layout := range budgetLaunchNodeOneLayouts() {
		t.Run(layout.tool, func(t *testing.T) {
			ctx := context.Background()
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			launcher := layout.build(t, t.TempDir(), elf)
			surfaceID := layout.tool + "/cli"
			candidates := []intervention.InstalledCandidate{{Tool: layout.tool, SurfaceID: surfaceID, LauncherPath: launcher}}
			manifest, err := intervention.BuildInstallManifest(ctx, candidates)
			if err != nil {
				t.Fatal(err)
			}
			if row, ok := manifest.Surface(surfaceID); !ok || row.State != intervention.BindingReady || len(row.Targets) == 0 {
				t.Fatalf("%s surface = %+v", surfaceID, row)
			}
			controlled := nodeInterventionControlledSurfaces(manifest)
			if !sortedStringContains(controlled, surfaceID) {
				t.Fatalf("controlled surfaces %v do not include %s", controlled, surfaceID)
			}
			writeLiveInterventionReport(t, ctx, dbPath, manifest, controlled, candidates)
			for _, route := range []budgetLaunchRoute{budgetLaunchRouteUnknown, budgetLaunchRouteDirect} {
				if err := enforceBudgetControlledLaunch(ctx, cfgPath, layout.tool, budgetLaunchEvidence{Route: route, Executable: launcher}); err != nil {
					t.Fatalf("%s launch (route %d) under process cutoff refused: %v", layout.tool, route, err)
				}
			}
		})
	}
}

// TestManagedDirectLaunchRefusalNamesTheFailedCutoffCheck pins the live half
// of the refusal: when the declaration allows a cutoff but this launch is not
// covered, the message names the check that failed.
func TestManagedDirectLaunchRefusalNamesTheFailedCutoffCheck(t *testing.T) {
	elf, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	layouts := budgetLaunchNodeOneLayouts()
	launcher := layouts[0].build(t, t.TempDir(), elf)
	candidates := []intervention.InstalledCandidate{{Tool: "junie", SurfaceID: "junie/cli", LauncherPath: launcher}}
	original := budgetLaunchInterventionCandidates
	budgetLaunchInterventionCandidates = func() []intervention.InstalledCandidate { return candidates }
	t.Cleanup(func() { budgetLaunchInterventionCandidates = original })

	err = enforceBudgetControlledLaunch(ctx, cfgPath, "junie", budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: launcher})
	if err == nil || !strings.Contains(err.Error(), "process-control report could not be used") ||
		!strings.Contains(err.Error(), "`junie/cli` under controlled surfaces") {
		t.Fatalf("no daemon report: refusal = %v", err)
	}

	manifest, mErr := intervention.BuildInstallManifest(ctx, candidates)
	if mErr != nil {
		t.Fatal(mErr)
	}
	writeLiveInterventionReport(t, ctx, dbPath, manifest, nil, candidates)
	err = enforceBudgetControlledLaunch(ctx, cfgPath, "junie", budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: launcher})
	if err == nil || !strings.Contains(err.Error(), "does not list `junie/cli` under controlled surfaces") {
		t.Fatalf("surface not attested: refusal = %v", err)
	}
}

// writeLiveInterventionReport points the launch gate at candidates and writes
// a fresh controller report for this test process as the controller.
func writeLiveInterventionReport(t *testing.T, ctx context.Context, dbPath string, manifest intervention.InstallManifest, controlled []string, candidates []intervention.InstalledCandidate) {
	t.Helper()
	original := budgetLaunchInterventionCandidates
	budgetLaunchInterventionCandidates = func() []intervention.InstalledCandidate { return candidates }
	t.Cleanup(func() { budgetLaunchInterventionCandidates = original })
	if err := writeNodeInterventionStatus(ctx, dbPath, liveInterventionReport(t, ctx, dbPath, manifest, controlled)); err != nil {
		t.Fatal(err)
	}
}

// liveInterventionReport composes a fresh controller report for this test
// process as the controller.
func liveInterventionReport(t *testing.T, ctx context.Context, dbPath string, manifest intervention.InstallManifest, controlled []string) nodeInterventionStatus {
	t.Helper()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	controller, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nodeInterventionAuthority(ctx, st, controller.UID, time.Now().UTC())
	if err != nil || !authority.Authorized {
		t.Fatalf("authority = %+v, err=%v", authority, err)
	}
	return nodeInterventionStatus{
		At: time.Now().UTC(), Controller: controller, Authority: authority.Authority,
		State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		ManifestFingerprint: intervention.InstallManifestFingerprint(manifest),
		ControlledSurfaces:  controlled,
		Reason:              "verified installed processes only",
	}
}

// TestManagedDirectLaunchWaitsForTheDaemonToInventoryAFreshInstall pins the
// node 1 aider finding (T-693): the tool was installed at 01:08:06Z and its
// launch refused at 01:08:13Z because the daemon rebuilds its install
// inventory every 30 seconds. The launch now waits, bounded, for a report
// carrying its own inventory fingerprint, and is admitted when one lands.
func TestManagedDirectLaunchWaitsForTheDaemonToInventoryAFreshInstall(t *testing.T) {
	elf, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	settle, poll, notice := budgetLaunchInventorySettle, budgetLaunchInventoryPoll, budgetLaunchSettleNotice
	// The daemon's catch-up write starts when the launch announces its
	// wait, never on a fixed delay: on a loaded host the launch could reach
	// its check after a 300 ms writer had already landed, find the report
	// current, never wait and print no notice (an RB1 gate flake).
	noticed := make(chan string, 1)
	waiting := make(chan struct{})
	budgetLaunchInventorySettle, budgetLaunchInventoryPoll = 5*time.Second, 20*time.Millisecond
	budgetLaunchSettleNotice = func(tool string, _ time.Duration) {
		noticed <- tool
		close(waiting)
	}
	t.Cleanup(func() {
		budgetLaunchInventorySettle, budgetLaunchInventoryPoll, budgetLaunchSettleNotice = settle, poll, notice
	})

	ctx := context.Background()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	var aider budgetLaunchLayout
	for _, layout := range budgetLaunchNodeOneLayouts() {
		if layout.tool == "aider" {
			aider = layout
		}
	}
	launcher := aider.build(t, t.TempDir(), elf)
	candidates := []intervention.InstalledCandidate{{Tool: "aider", SurfaceID: "aider/cli", LauncherPath: launcher}}
	manifest, err := intervention.BuildInstallManifest(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	controlled := nodeInterventionControlledSurfaces(manifest)
	// The daemon's last pass predates the install: its report carries the
	// inventory without aider.
	before, err := intervention.BuildInstallManifest(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeLiveInterventionReport(t, ctx, dbPath, before, nil, candidates)
	caughtUp := liveInterventionReport(t, ctx, dbPath, manifest, controlled)
	done := make(chan error, 1)
	returned := make(chan struct{})
	go func() {
		select {
		case <-waiting:
		case <-returned:
			done <- nil // the launch never waited; the notice check below fails
			return
		}
		time.Sleep(100 * time.Millisecond)
		caughtUp.At = time.Now().UTC()
		done <- writeNodeInterventionStatus(ctx, dbPath, caughtUp)
	}()
	err = enforceBudgetControlledLaunch(ctx, cfgPath, "aider", budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: launcher})
	close(returned)
	if writeErr := <-done; writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil {
		t.Fatalf("launch right after install refused instead of waiting for the daemon's inventory: %v", err)
	}
	select {
	case tool := <-noticed:
		if tool != "aider" {
			t.Fatalf("notice named %q", tool)
		}
	default:
		t.Fatal("the wait printed no notice")
	}
}

// TestManagedDirectLaunchRefusesAVendorBinaryOverride pins the other half of
// admitting a launcher on its declared workers: an environment override the
// vendor launcher honours (cline's CLINE_BIN_PATH, junie's JUNIE_DATA) would
// run a binary the controller never bound, so that launch is not admitted.
func TestManagedDirectLaunchRefusesAVendorBinaryOverride(t *testing.T) {
	elf, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	for tool, name := range map[string]string{"cline-cli": "CLINE_BIN_PATH", "junie": "JUNIE_DATA"} {
		t.Run(tool, func(t *testing.T) {
			var layout budgetLaunchLayout
			for _, candidate := range budgetLaunchNodeOneLayouts() {
				if candidate.tool == tool {
					layout = candidate
				}
			}
			ctx := context.Background()
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			launcher := layout.build(t, t.TempDir(), elf)
			candidates := []intervention.InstalledCandidate{{Tool: tool, SurfaceID: tool + "/cli", LauncherPath: launcher}}
			manifest, err := intervention.BuildInstallManifest(ctx, candidates)
			if err != nil {
				t.Fatal(err)
			}
			writeLiveInterventionReport(t, ctx, dbPath, manifest, nodeInterventionControlledSurfaces(manifest), candidates)
			t.Setenv(name, filepath.Join(t.TempDir(), "elsewhere"))
			err = enforceBudgetControlledLaunch(ctx, cfgPath, tool, budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: launcher})
			if err == nil || !strings.Contains(err.Error(), "this launch sets "+name) {
				t.Fatalf("%s with %s set: refusal = %v", tool, name, err)
			}
		})
	}
}
