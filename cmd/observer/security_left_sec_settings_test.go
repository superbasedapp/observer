//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// Lane LEFT-SEC milestone 1: the node settings for the four
// security.scanning axes, the post-write cap's managed refusal, the reflog
// caps, the unknown-package actions and the local pre-launch trust step.

// TestLeftSecManagedFloorBoundsLooserLocal: on a managed node an org floor
// in force raises every key that has an axis, status names each one as
// overridden (never silently dropped), a stricter local value stays, and
// the 64 KiB post-write cap is refused there but kept on an individual
// node.
func TestLeftSecManagedFloorBoundsLooserLocal(t *testing.T) {
	local := config.DefaultSecurityConfig()
	local.Secrets.PostWriteCapKiB = 64
	withSecurityScanningNode(t, true, local, "security.deps", "security.trust", "security.secrets")
	installFloor(t, `{"require":{"quick_scan_budget_s":10,"max_scan_staleness_min":60,"min_blocking_severity":"medium","history_scan_on_enrol":true,"install_unknown":"ask","install_online_unknown":"deny","prelaunch_trust":"ask"}}`, 1, true)
	eff := securityFloorsApplied(local)
	if eff.Scanning.QuickScanBudgetS != 10 || eff.Scanning.MaxScanStalenessMin != 60 || eff.Scanning.MinBlockingSeverity != "medium" || !eff.Scanning.HistoryScanOnEnrol {
		t.Fatalf("scanning in force %+v", eff.Scanning)
	}
	if eff.Deps.UnknownAction != "ask" || eff.Deps.OnlineUnknownAction != "deny" || eff.PrelaunchTrustFloor != "ask" {
		t.Fatalf("deps %q %q trust floor %q", eff.Deps.UnknownAction, eff.Deps.OnlineUnknownAction, eff.PrelaunchTrustFloor)
	}
	if eff.Secrets.PostWriteCapKiB != 256 || securityPostWriteCapInForce(local) != 256 {
		t.Fatalf("a managed node kept the 64 KiB cap: %d", eff.Secrets.PostWriteCapKiB)
	}
	lines := strings.Join(securityNodeSettingLines(local, eff, true), "\n")
	for _, k := range []string{
		"security.scanning.quick_scan_budget_s: 2; overridden by the org floor in force: 10",
		"security.scanning.max_scan_staleness_min: 0; overridden by the org floor in force: 60",
		"security.scanning.min_blocking_severity: high; overridden by the org floor in force: medium",
		"security.scanning.history_scan_on_enrol: false; overridden by the org floor in force: true",
		"security.deps.unknown_action: default; overridden by the org floor in force: ask",
		"security.deps.online_unknown_action: default; overridden by the org floor in force: deny",
		"security.trust.prelaunch: warn; overridden by the org floor in force: ask",
		"security.secrets.postwrite_cap_kib: 64 (default 256); refused on a managed node (it scans less), 256 applies",
	} {
		if !strings.Contains(lines, k) {
			t.Errorf("status does not say %q:\n%s", k, lines)
		}
	}
	// A stricter local value stays.
	strict := local
	strict.Scanning.QuickScanBudgetS, strict.Scanning.MinBlockingSeverity, strict.Deps.UnknownAction = 30, "low", "deny"
	if got := securityFloorsApplied(strict); got.Scanning.QuickScanBudgetS != 30 || got.Scanning.MinBlockingSeverity != "low" || got.Deps.UnknownAction != "deny" {
		t.Fatalf("a floor lowered a stricter local value: %+v %q", got.Scanning, got.Deps.UnknownAction)
	}
	// The project read the posture writer signs carries the floor.
	if got := securityPostureScanning(local)(""); got.QuickScanBudgetS != 10 || got.MaxScanStalenessMin != 60 || got.MinBlocking != "medium" {
		t.Fatalf("posture read %+v", got)
	}
}

// TestLeftSecIndividualKeepsSmallCap: an individual node keeps the 64 KiB
// cap it chose, and status names it as not the default only.
func TestLeftSecIndividualKeepsSmallCap(t *testing.T) {
	local := config.DefaultSecurityConfig()
	local.Secrets.PostWriteCapKiB = 64
	withSecurityScanningNode(t, false, local, "security.secrets")
	if got := securityPostWriteCapInForce(local); got != 64 {
		t.Fatalf("an individual node's cap in force = %d, want 64", got)
	}
	lines := strings.Join(securityNodeSettingLines(local, securityFloorsApplied(local), false), "\n")
	if !strings.Contains(lines, "security.secrets.postwrite_cap_kib: 64 (default 256)") || strings.Contains(lines, "refused") {
		t.Fatalf("status:\n%s", lines)
	}
}

// TestLeftSecLocalTrustStep: [security.trust].prelaunch = ask raises a
// verdict that is not clean to an ask with its own wording, never lowers a
// stronger one and leaves a clean launch alone.
func TestLeftSecLocalTrustStep(t *testing.T) {
	step := repoTrustLocalStep(config.SecurityTrustConfig{Prelaunch: "ask"})
	if step != "ask" {
		t.Fatalf("step %q", step)
	}
	v := raiseTrustStepLocal(policy.Verdict{Decision: policy.DecisionFlag, Reason: "r"}, step)
	if v.Decision != policy.DecisionAsk || !strings.Contains(v.Reason, "[security.trust] prelaunch setting: ask") {
		t.Fatalf("flag raised to %+v", v)
	}
	if v := raiseTrustStepLocal(policy.Verdict{Decision: policy.DecisionDeny}, step); v.Decision != policy.DecisionDeny {
		t.Fatalf("a deny was lowered: %+v", v)
	}
	if v := raiseTrustStepLocal(policy.Verdict{Decision: policy.DecisionAllow}, step); v.Decision != policy.DecisionAllow {
		t.Fatalf("a clean launch was raised: %+v", v)
	}
}

// TestLeftSecHistoryOnEnrolOnce: the key off removes the marker and scans
// nothing; on, it scans every project once and writes the marker; a second
// pass scans nothing; off and on again scans again.
func TestLeftSecHistoryOnEnrolOnce(t *testing.T) {
	dir := t.TempDir()
	on := false
	scanned := 0
	d := securityHistoryOnEnrolDeps{
		dir:      dir,
		enabled:  func() bool { return on },
		projects: func(context.Context) ([]string, error) { return []string{"/a", "/b"}, nil },
		scan:     func(context.Context, string) error { scanned++; return nil },
	}
	ctx := context.Background()
	step := func(wantRan bool, wantScanned int) {
		t.Helper()
		ran, err := securityHistoryOnEnrolOnce(ctx, d)
		if err != nil || ran != wantRan || scanned != wantScanned {
			t.Fatalf("ran %v err %v scanned %d, want %v %d", ran, err, scanned, wantRan, wantScanned)
		}
	}
	step(false, 0)
	on = true
	step(true, 2)
	step(false, 2)
	on = false
	step(false, 2)
	if _, err := os.Stat(filepath.Join(dir, securityHistoryOnEnrolMarker)); !os.IsNotExist(err) {
		t.Fatalf("the marker stays while the key is off: %v", err)
	}
	on = true
	step(true, 4)
}

// TestLeftSecReflogCapAsksTheHeldPush is the daemon path of the reflog caps
// (SECP-18): a commit with a secret that only the reflog reaches is held
// (S-792 denies the push under enforce); with an entries cap the reflog
// entry lies past, the next history pass records the cap and one unknown
// run naming it, and the push is asked instead (S-792's capped row), never
// allowed; with the cap removed the commit is held again.
func TestLeftSecReflogCapAsksTheHeldPush(t *testing.T) {
	unbindSecurityFloors(t)
	r := newGate4Repo(t, "origin")
	now := time.Now()
	r.tick(t, now)
	gitRun(t, r.n.root, "reset", "-q", "HEAD~1")
	r.tick(t, now.Add(time.Minute))
	if v := leftSecEnforcePush(t, r, "git push origin main"); v.RuleID != "S-792" || v.Decision != policy.DecisionDeny {
		t.Fatalf("held by the reflog, no cap: %+v, want S-792 deny", v)
	}
	capped := config.DefaultSecurityConfig()
	capped.Scanning.ReflogHoldMaxEntries = 100
	securityReflogBase.Store(&capped)
	t.Cleanup(func() { securityReflogBase.Store(nil) })
	r.tick(t, now.Add(2*time.Minute))
	if v := leftSecEnforcePush(t, r, "git push origin main"); v.Decision != policy.DecisionDeny {
		t.Fatalf("inside a cap of 100 entries: %+v, want still denied", v)
	}
	// HEAD@{1} and main@{1} are the secret's commit: a cap of 1 entry
	// leaves only the reset.
	capped.Scanning.ReflogHoldMaxEntries = 1
	r.tick(t, now.Add(3*time.Minute))
	v := leftSecEnforcePush(t, r, "git push origin main")
	if v.RuleID != "S-792" || v.Decision != policy.DecisionAsk {
		t.Fatalf("past the reflog cap: %+v, want S-792 ask (never an allow)", v)
	}
	if f := r.n.only(t, "secret.aws_access_key"); f.Status != policy.FindingStatusOpen {
		t.Fatalf("finding %s, want open (nothing is released silently)", f.Status)
	}
	run, ok, err := r.n.st.SecLatestRun(context.Background(), securityReflogCapDriver)
	if err != nil || !ok || run.Outcome != "unknown" {
		t.Fatalf("the unknown run naming the cap: %+v %v %v", run, ok, err)
	}
	capped.Scanning.ReflogHoldMaxEntries = 0
	r.tick(t, now.Add(4*time.Minute))
	if v := leftSecEnforcePush(t, r, "git push origin main"); v.Decision != policy.DecisionDeny {
		t.Fatalf("with the cap removed: %+v, want held again", v)
	}
}

// leftSecEnforcePush evaluates an agent push under guard enforce.
func leftSecEnforcePush(t *testing.T, r gate4Repo, cmd string) policy.Verdict {
	t.Helper()
	r.n.signPostureScanned(t, r.gn)
	pe := &policy.Event{Kind: policy.KindShellExec, Target: cmd, ProjectRoot: r.n.root, Cwd: r.n.root}
	securityToolGateEnrich(r.gn.cfgPath, models.ToolClaudeCode, "PreToolUse", nil)(pe)
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{Enabled: true, Mode: "enforce", RetentionDays: 365},
		Home:   t.TempDir(), KnownProjectRoots: []string{r.n.root},
		PackRules: securityHookPackRules(r.gn.cfgPath),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.Evaluate(*pe)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestLeftSecSettingsTableCoversTheContract: every key this lane added to
// the settings contract has a status row, and the contract JSON names it.
func TestLeftSecSettingsTableCoversTheContract(t *testing.T) {
	keys := map[string]bool{}
	for _, s := range securityNodeSettings {
		keys[s.Key] = true
	}
	for _, r := range config.SecuritySettings() {
		if strings.HasPrefix(r.Key, "security.scanning.") || r.Key == "security.trust.prelaunch" || strings.HasSuffix(r.Key, "unknown_action") || r.Key == "security.secrets.postwrite_cap_kib" {
			if !keys[r.Key] {
				t.Errorf("%s has no status row", r.Key)
			}
			delete(keys, r.Key)
		}
	}
	if len(keys) != 0 {
		b, _ := json.Marshal(keys)
		t.Errorf("status rows with no contract row: %s", b)
	}
}

// TestLeftSecHookAsksWithThePostureBudget: the hook asks the quick scan
// with the budget a project's current, verified posture signs, and with the
// built-in 2 s when it signs none or reads unknown.
func TestLeftSecHookAsksWithThePostureBudget(t *testing.T) {
	s := &hookSecurity{}
	if got := s.quickScanBudget("/p"); got != secposture.IndividualQuickScan {
		t.Fatalf("no reading: %v", got)
	}
	clean := secposture.Reading{File: &secposture.File{QuickScanBudgetS: 10, QuickScanAvailable: true}, State: secposture.State{Posture: policy.SecurityPostureDirty}}
	s.noteQuickScan("/p", clean)
	if got := s.quickScanBudget("/p"); got != 10*time.Second {
		t.Fatalf("signed 10 s: %v", got)
	}
	s.noteQuickScan("/p", secposture.Reading{State: secposture.State{Posture: policy.SecurityPostureUnknown}})
	if got := s.quickScanBudget("/p"); got != secposture.IndividualQuickScan {
		t.Fatalf("an unknown reading kept the budget: %v", got)
	}
}
