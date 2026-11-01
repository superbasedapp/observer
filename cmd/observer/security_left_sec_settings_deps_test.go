//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_security_deps

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// The left-sec settings tests that read the deps module's hook settings
// writer (R-008: `-tags sbo_omit_security_deps` compiles it out).

// TestLeftSecDefaultsAreToday is the golden of today's behaviour: every new
// key defaults to the built-in value it replaced, the read seam leaves a
// default block unchanged, the posture writer's per-project read is the
// built-in budget, staleness and severity, the hook's settings file is the
// same bytes, the local trust step raises nothing and status says nothing.
func TestLeftSecDefaultsAreToday(t *testing.T) {
	unbindSecurityFloors(t)
	d := config.DefaultSecurityConfig()
	want := config.SecurityScanningConfig{QuickScanBudgetS: 2, MinBlockingSeverity: "high"}
	if d.Scanning != want || d.Trust.Prelaunch != "warn" || d.Deps.UnknownAction != "default" || d.Deps.OnlineUnknownAction != "default" || d.Secrets.PostWriteCapKiB != 256 {
		t.Fatalf("defaults %+v %+v %q %q %d", d.Scanning, d.Trust, d.Deps.UnknownAction, d.Deps.OnlineUnknownAction, d.Secrets.PostWriteCapKiB)
	}
	if got := securityFloorsApplied(d); got.Scanning != want || got.Secrets.PostWriteCapKiB != 256 {
		t.Fatalf("the seam changed a default block: %+v", got)
	}
	if got := securityPostureScanning(d)(""); got.QuickScanBudgetS != 2 || got.MaxScanStalenessMin != 0 || got.MinBlocking != "high" {
		t.Fatalf("posture read %+v", got)
	}
	if age, entries := securityReflogCapsNow(); age != 0 || entries != 0 {
		t.Fatalf("reflog caps by default %v %d, want none", age, entries)
	}
	dir := t.TempDir()
	if err := writeDepsSettingsFor(dir, d.Deps, false); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, depsSettingsFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"ask":false,"online":true,"wait_ms":1500,"min_age_h":72}` {
		t.Fatalf("the hook's settings file changed at the defaults: %s", got)
	}
	checks := decodeDepsHookSettings(b).stampActions([]policy.InstallCheck{{Verdict: policy.InstallUnknownName}, {Verdict: policy.InstallOnlineUnknown}})
	for _, c := range checks {
		if c.Action != "" {
			t.Fatalf("a default action was stamped: %+v", c)
		}
	}
	if repoTrustLocalStep(d.Trust) != "" {
		t.Fatal("the default trust step raises")
	}
	if lines := securityNodeSettingLines(d, d, false); lines != nil {
		t.Fatalf("status at the defaults: %q", lines)
	}
	// The posture file signs the default budget as before (omitted).
	f := secposture.File{ProjectRootHash: "h", Packs: []string{"security"}, QuickScanBudgetS: 2}
	g := f
	g.QuickScanBudgetS = 0
	a, _ := secposture.Encode(f)
	b2, _ := secposture.Encode(g)
	if string(a) != string(b2) || strings.Contains(string(a), "quick_scan_budget") {
		t.Fatalf("default budget changes the signed bytes: %s", a)
	}
}

// TestLeftSecUnknownActionsStamp: the daemon writes the actions in force
// into the hook's settings file and the hook stamps them on the matching
// verdicts only.
func TestLeftSecUnknownActionsStamp(t *testing.T) {
	dir := t.TempDir()
	deps := config.DefaultSecurityConfig().Deps
	deps.UnknownAction, deps.OnlineUnknownAction = "deny", "ask"
	if err := writeDepsSettingsFor(dir, deps, false); err != nil {
		t.Fatal(err)
	}
	set := readDepsHookSettings(dir)
	got := set.stampActions([]policy.InstallCheck{
		{Verdict: policy.InstallUnknownName}, {Verdict: policy.InstallOnlineUnknown}, {Verdict: policy.InstallMalicious},
	})
	if got[0].Action != "deny" || got[1].Action != "ask" || got[2].Action != "" {
		t.Fatalf("stamped %+v", got)
	}
}
