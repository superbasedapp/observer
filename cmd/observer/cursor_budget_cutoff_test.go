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
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCursorProcessCutoffCoversManagedBudget answers the "Cursor budget
// spike" from the 2026-09-22 control-coverage investigation
// (~/sbo-scratch/s8/items/controls/PLAN.md Priority 1, item 1): Cursor never
// proxy-routes (BYOK, Capability.Proxy == nil), so
// BudgetAdmissionChannel() is honestly "none" — but does the SAME node
// process-cutoff chokepoint other direct-launch tools use
// (nodeProcessCutoffCoversLaunch / budgetlaunch_direct_linux.go) also cover
// Cursor?
//
// The answer is YES, and it required no new mechanism: the registry
// (internal/integration/intervention.go) already declares
// `"cursor": {dedicated("cli", nativeInvoking(cursorInvocation()),
// NativeUsageApproximate), ...}` — NativeUsageApproximate.Available() is
// true, exactly the bit nodeProcessCutoffCoversLaunch requires
// (surface.Spec.NativeUsage.Available()). This test is the missing PROOF
// that declaration actually admits a covered launch, mirroring
// TestManagedDirectLaunchUsesOnlyCurrentExactProcessCutoff (opencode) —
// existing coverage only exercised opencode's default invocation shape;
// Cursor's is NOT the default (cursorInvocation()'s inverted
// billable/non-billable argument split), so this also proves that
// classification composes correctly with process-cutoff coverage, not just
// the default one.
func TestCursorProcessCutoffCoversManagedBudget(t *testing.T) {
	ctx := context.Background()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")

	bin := filepath.Join(t.TempDir(), "cursor-agent")
	raw, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	candidates := []intervention.InstalledCandidate{{Tool: "cursor", SurfaceID: "cursor/cli", LauncherPath: bin}}
	manifest, err := intervention.BuildInstallManifest(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := manifest.Surface("cursor/cli")
	if !ok || row.State != intervention.BindingReady || len(row.Targets) != 1 {
		t.Fatalf("fixture surface = %+v", row)
	}
	if !row.Spec.NativeUsage.Available() {
		t.Fatal("cursor/cli's registry row does not declare a native usage source — the spike's premise is false, this test should not exist")
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
	status := nodeInterventionStatus{
		At: time.Now().UTC(), Controller: controller, Authority: authority.Authority,
		State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		ManifestFingerprint: intervention.InstallManifestFingerprint(manifest),
		ControlledSurfaces:  []string{"cursor/cli"},
		Reason:              "verified installed processes only",
	}
	if err := writeNodeInterventionStatus(ctx, dbPath, status); err != nil {
		t.Fatal(err)
	}

	originalCandidates := budgetLaunchInterventionCandidates
	budgetLaunchInterventionCandidates = func() []intervention.InstalledCandidate { return candidates }
	t.Cleanup(func() { budgetLaunchInterventionCandidates = originalCandidates })

	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// A prompt is billable under cursor's inverted invocation model (not in
	// cursorNonBillableArguments) — the launch IS admitted through process
	// cutoff alone, with no proxy route at all.
	promptEvidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: bin, Arguments: []string{"write code"}}
	if !nodeProcessCutoffCoversLaunch(ctx, cfg, st, "cursor", promptEvidence) {
		t.Fatal("cursor's declared NativeUsageApproximate did not cover a billable prompt launch")
	}
	if err := enforceBudgetControlledLaunch(ctx, cfgPath, "cursor", promptEvidence); err != nil {
		t.Fatalf("covered cursor launch refused: %v", err)
	}

	// `status` is one of cursor's declared NON-billable leading arguments
	// (cursorNonBillableArguments) — coverage must NOT extend to it: this is
	// per-invocation admission, not a blanket grant to the binary.
	statusEvidence := budgetLaunchEvidence{Route: budgetLaunchRouteUnknown, Executable: bin, Arguments: []string{"status"}}
	if nodeProcessCutoffCoversLaunch(ctx, cfg, st, "cursor", statusEvidence) {
		t.Fatal("process cutoff covered a declared non-billable cursor invocation (status) — coverage is not scoped correctly")
	}
}
