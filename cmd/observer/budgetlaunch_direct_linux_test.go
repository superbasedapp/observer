//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestManagedDirectLaunchUsesOnlyCurrentExactProcessCutoff(t *testing.T) {
	ctx := context.Background()
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

	database, err := db.Open(ctx, db.Options{Path: dbPath})
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
