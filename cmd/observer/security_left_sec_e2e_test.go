//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Lane LEFT-SEC milestone 6: the daemon path of every key the lane built,
// from a config.toml on disk through the daemon's own binding
// (bindSecurityScanning and its loader, the read seam, the posture writer's
// per-project read, the deps settings file the hook reads, the launch's
// local trust step and the status lines), and a box copy run reaching its
// source project's per-project floor.

// leftSecE2EConfig writes a config.toml with the security children
// selected and the given [security.*] body, and returns its path.
func leftSecE2EConfig(t *testing.T, dir, body string) string {
	t.Helper()
	db := filepath.Join(dir, "observer.db")
	head := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(db)) + "\n\n" +
		"[components]\nadd = [\"security\", \"security.secrets\", \"security.deps\", \"security.trust\"]\n\n"
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(head+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// leftSecE2EBody sets every key the lane built away from its default.
const leftSecE2EBody = `[security.scanning]
quick_scan_budget_s = 10
max_scan_staleness_min = 60
min_blocking_severity = "medium"
history_scan_on_enrol = true
reflog_hold_max_age_days = 14
reflog_hold_max_entries = 100

[security.secrets]
postwrite_cap_kib = 64

[security.deps]
unknown_action = "deny"
online_unknown_action = "ask"

[security.trust]
prelaunch = "ask"
`

// TestLeftSecE2EDaemonReadsEveryKey sets each new key in config.toml and
// sees its effect on the daemon's consumers, then changes the file and sees
// the daemon pick the change up with no restart.
func TestLeftSecE2EDaemonReadsEveryKey(t *testing.T) {
	unbindSecurityFloors(t)
	ctx := context.Background()
	dir := t.TempDir()
	cfgPath := leftSecE2EConfig(t, dir, leftSecE2EBody)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("the keys do not load: %v", err)
	}
	bindSecurityScanning(cfgPath, componentSnapshotForConfig(cfg))
	sec := cfg.Security
	securityReflogBase.Store(&sec)
	t.Cleanup(func() { securityReflogBase.Store(nil) })

	// security.scanning: the budget, staleness and blocking bar the posture
	// writer signs into a project's posture.
	if got := securityPostureScanning(sec)(""); got.QuickScanBudgetS != 10 || got.MaxScanStalenessMin != 60 || got.MinBlocking != "medium" {
		t.Fatalf("posture read %+v", got)
	}
	if !securityScanningAt(securityLocalNow(sec), "").HistoryScanOnEnrol {
		t.Fatal("history_scan_on_enrol is not in force")
	}
	// The reflog caps the history check applies.
	if age, entries := securityReflogCapsNow(); age != 14*24*time.Hour || entries != 100 {
		t.Fatalf("reflog caps %v %d", age, entries)
	}
	// The post-write cap: an individual node keeps 64 KiB.
	if got := securityPostWriteCapInForce(sec); got != 64 {
		t.Fatalf("post-write cap in force %d, want 64", got)
	}
	// security.deps: the daemon writes the actions into the hook's settings
	// file, and the hook stamps them on the matching verdicts.
	hookDir := t.TempDir()
	if err := writeDepsSettingsFor(hookDir, depsInForce(sec), false); err != nil {
		t.Fatal(err)
	}
	checks := readDepsHookSettings(hookDir).stampActions([]policy.InstallCheck{{Verdict: policy.InstallUnknownName}, {Verdict: policy.InstallOnlineUnknown}})
	if checks[0].Action != policy.InstallActionDeny || checks[1].Action != policy.InstallActionAsk {
		t.Fatalf("stamped %+v", checks)
	}
	// security.trust: the launch's local step raises a flagged launch to an
	// ask.
	if v := raiseTrustStepLocal(policy.Verdict{Decision: policy.DecisionFlag}, repoTrustLocalStep(sec.Trust)); v.Decision != policy.DecisionAsk {
		t.Fatalf("the trust step did not raise: %+v", v)
	}
	// Status names every key set away from its default.
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(dir, "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	lines := strings.Join(securityNodeSettingStatus(ctx, cfgPath, cfg, store.New(database)), "\n")
	for _, s := range securityNodeSettings {
		if !strings.Contains(lines, s.Key+": ") {
			t.Errorf("status does not name %s:\n%s", s.Key, lines)
		}
	}

	// A picker change reaches the daemon with no restart (the read seam
	// re-reads the file once its view is older than securityBaseTTL).
	leftSecE2EConfig(t, dir, strings.Replace(leftSecE2EBody, "quick_scan_budget_s = 10", "quick_scan_budget_s = 30", 1))
	secScanning.mu.Lock()
	secScanning.loadedAt = time.Now().Add(-2 * securityBaseTTL)
	secScanning.mu.Unlock()
	if got := securityPostureScanning(sec)(""); got.QuickScanBudgetS != 30 {
		t.Fatalf("after the change the budget is %d, want 30", got.QuickScanBudgetS)
	}
}

// TestLeftSecE2EBoxCopyReachesProjectFloor: a box copy run, read through
// the real run index from its host-written record, takes its source
// project's security.scanning section at the copy's root: the commit gate
// floor and the section's budget and blocking bar the
// posture writer signs. The source project's section is the only one set.
func TestLeftSecE2EBoxCopyReachesProjectFloor(t *testing.T) {
	obs := boxRunsFixture(t)
	src, copyTree := filepath.Join(t.TempDir(), "src"), filepath.Join(t.TempDir(), "box", "work")
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: "RUNE2E", Tool: "codex", ProjectRoot: src, WorkspaceDir: copyTree, Roots: []string{copyTree},
		Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: copyTree,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	body := `{"require":{"commit_gate":"quick_scan","quick_scan_budget_s":30,"min_blocking_severity":"low"}}`
	withProjectSections(t, true, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		filepath.Clean(src): matched(guard.ProjectFamilySet{OrgProjectID: "P", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 4, body, "P")}}),
	})
	floors := securityPostureFloors(config.DefaultSecurityConfig())
	scanning := securityPostureScanning(config.DefaultSecurityConfig())
	if cg, _ := floors(copyTree); cg != policy.CommitGateFloorQuickScan {
		t.Fatalf("commit gate floor %q, want the source project's quick_scan", cg)
	}
	if got := scanning(copyTree); got.QuickScanBudgetS != 30 || got.MinBlocking != "low" {
		t.Fatalf("scanning %+v, want the source project's section", got)
	}
	if got := scanning(filepath.Join(t.TempDir(), "elsewhere")); got.QuickScanBudgetS != 2 || got.MinBlocking != "high" {
		t.Fatalf("a tree no copy run holds took the section: %+v", got)
	}
}
