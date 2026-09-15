//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Launchers that pass no process evidence can never be admitted by the node's
// attested process cutoff, so on a managed node with a hard org cap they are
// refused at $0 no matter how well covered the machine is. These tests pin the
// evidence at the launcher, from the outside: each one runs the real launcher
// against an attested surface and asserts the vendor process STARTED.

// TestKiloLauncherRecoversUnderAttestedProcessCutoff covers the strongest
// case: kilo-code-cli is native-exempt, so it can never prove a proxy route
// and the attested cutoff is its ONLY admission path.
func TestKiloLauncherRecoversUnderAttestedProcessCutoff(t *testing.T) {
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	bin, marker := writeBudgetLaunchMarkerBinary(t, "kilo")
	attestBudgetLaunchSurface(t, dbPath, "kilo-code-cli", "kilo-code-cli/cli", bin)

	if err := runKiloLauncher(cfgPath, dbPath, bin, []string{marker}, t.TempDir()); err != nil {
		t.Fatalf("attested kilo launch refused: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("kilo process did not start: %v", err)
	}
}

// TestKiloLauncherStillRefusesWithoutAttestation is the control: the same
// launcher, the same cap, no attested surface — refused before the process
// starts. Without it the test above could pass on a gate that admits
// everything.
func TestKiloLauncherStillRefusesWithoutAttestation(t *testing.T) {
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	bin, marker := writeBudgetLaunchMarkerBinary(t, "kilo")

	err := runKiloLauncher(cfgPath, dbPath, bin, []string{marker}, t.TempDir())
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("unattested kilo launch error = %v, want managed hard-budget refusal", err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("kilo process started before admission; marker stat error = %v", statErr)
	}
}

// TestCursorLauncherPassesProcessEvidence exercises `observer cursor` end to
// end: with its surface attested, the launch is no longer refused as
// uncontrolled. It asserts only that the BUDGET refusal is gone — what
// cursor-agent itself then does with a stub binary is not this test's subject.
func TestCursorLauncherPassesProcessEvidence(t *testing.T) {
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	bin, _ := writeBudgetLaunchMarkerBinary(t, "cursor-agent")
	attestBudgetLaunchSurface(t, dbPath, "cursor", "cursor/cli", bin)

	cmd := newCursorCmd()
	cmd.SetOut(os.Stderr)
	cmd.SetErr(os.Stderr)
	cmd.SetArgs([]string{
		"--config", cfgPath, "--cursor-agent-path", bin, "--no-attach",
		"--", "write code",
	})
	if err := cmd.Execute(); errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("attested cursor launch still refused as uncontrolled: %v", err)
	}
}

// writeBudgetLaunchMarkerBinary installs a stand-in vendor binary and returns
// it with the path it creates when run.
//
// It must be a NATIVE executable, not a shell script: the install manifest
// refuses to bind a shell launcher (Reasons: shell_launcher), so a script
// could never be the attested surface these tests need. `mkdir` is a real ELF
// whose only side effect is the observable one — given the marker path as its
// argument, the directory exists afterwards if and only if the process ran.
func writeBudgetLaunchMarkerBinary(t *testing.T, name string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("/bin/mkdir")
	if err != nil {
		t.Skipf("no native stand-in binary available: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	if err := os.WriteFile(bin, raw, 0o700); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return bin, filepath.Join(dir, name+"-started")
}

// attestBudgetLaunchSurface leaves a live controller report that attests
// process cutoff over exactly this installed surface, the way a running daemon
// would. The candidate set is stubbed so no real developer tool is discovered
// or signalled.
func attestBudgetLaunchSurface(t *testing.T, dbPath, tool, surfaceID, executable string) {
	t.Helper()
	ctx := context.Background()
	candidates := []intervention.InstalledCandidate{
		{Tool: tool, SurfaceID: surfaceID, LauncherPath: executable},
	}
	manifest, err := intervention.BuildInstallManifest(ctx, candidates)
	if err != nil {
		t.Fatalf("BuildInstallManifest: %v", err)
	}
	if row, ok := manifest.Surface(surfaceID); !ok || row.State != intervention.BindingReady {
		t.Skipf("surface %s is not bindable on this host (%+v); process-cutoff recovery cannot be exercised", surfaceID, row)
	}
	original := budgetLaunchInterventionCandidates
	budgetLaunchInterventionCandidates = func() []intervention.InstalledCandidate { return candidates }
	t.Cleanup(func() { budgetLaunchInterventionCandidates = original })

	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open fixture DB: %v", err)
	}
	defer database.Close()
	controller, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	authority, err := nodeInterventionAuthority(ctx, store.New(database), controller.UID, time.Now().UTC())
	if err != nil || !authority.Authorized {
		t.Fatalf("authority = %+v err=%v", authority, err)
	}
	if err := writeNodeInterventionStatus(ctx, dbPath, nodeInterventionStatus{
		At: time.Now().UTC(), Controller: controller, Authority: authority.Authority,
		State: "partial", ProcessCutoff: "active",
		ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		ManifestFingerprint: intervention.InstallManifestFingerprint(manifest),
		ControlledSurfaces:  []string{surfaceID},
		Reason:              "verified installed processes only",
	}); err != nil {
		t.Fatalf("write controller report: %v", err)
	}
}
