package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPeriodicRegisterWanted is the [observer.hooks] decision table, one row
// per case: auto_register=false always wins, the default re-registers only on
// a managed node (individual nodes keep the start-only behaviour).
func TestPeriodicRegisterWanted(t *testing.T) {
	cases := []struct {
		mode               string
		autoRegister, mngd bool
		want               bool
	}{
		{config.HooksPeriodicRegisterManaged, true, true, true},
		{config.HooksPeriodicRegisterManaged, true, false, false},
		{"", true, true, true},
		{"", true, false, false},
		{"bogus", true, true, true},
		{config.HooksPeriodicRegisterAlways, true, false, true},
		{config.HooksPeriodicRegisterAlways, true, true, true},
		{config.HooksPeriodicRegisterOff, true, true, false},
		{config.HooksPeriodicRegisterAlways, false, true, false},
		{config.HooksPeriodicRegisterManaged, false, true, false},
	}
	for _, tc := range cases {
		if got := periodicRegisterWanted(tc.mode, tc.autoRegister, tc.mngd); got != tc.want {
			t.Errorf("periodicRegisterWanted(%q, auto=%v, managed=%v) = %v, want %v", tc.mode, tc.autoRegister, tc.mngd, got, tc.want)
		}
	}
}

// TestHookMaintenanceTick pins the heartbeat step: re-register when wanted,
// and report the managed-integrity probe on a managed node only (T-849).
func TestHookMaintenanceTick(t *testing.T) {
	cases := []struct {
		name                 string
		managed              bool
		mode                 string
		wantReg, wantReports int
		// wantRepairOwned is the T-872 switch the pass runs with: only a
		// managed node repairs a neutralised artifact Observer owns by name.
		wantRepairOwned bool
	}{
		{"managed node: repair and report", true, config.HooksPeriodicRegisterManaged, 1, 1, true},
		{"individual node: nothing by default", false, config.HooksPeriodicRegisterManaged, 0, 0, false},
		{"individual node opted in: repair, never report", false, config.HooksPeriodicRegisterAlways, 1, 0, false},
		{"managed node opted out: report only", true, config.HooksPeriodicRegisterOff, 0, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			regs, reports := 0, 0
			repairOwned := false
			m := hookMaintenance{
				mode: tc.mode, autoRegister: true,
				managed:    func(context.Context) bool { return tc.managed },
				reregister: func(managed bool) { regs++; repairOwned = managed },
				report:     func(context.Context) { reports++ },
			}
			m.tick(context.Background())
			if regs != tc.wantReg || reports != tc.wantReports {
				t.Fatalf("re-registered %d / reported %d, want %d / %d", regs, reports, tc.wantReg, tc.wantReports)
			}
			if repairOwned != tc.wantRepairOwned {
				t.Fatalf("pass ran with repairOwned=%v, want %v", repairOwned, tc.wantRepairOwned)
			}
		})
	}
}

// fakeLoss is a hookRegistryLossSource with a fixed answer.
type fakeLoss struct{ at time.Time }

func (f fakeLoss) RegistryLostSince(now time.Time, window time.Duration) (time.Time, bool) {
	if f.at.IsZero() || now.Sub(f.at) > window {
		return time.Time{}, false
	}
	return f.at, true
}

// TestCollectIntegritySignalsWithHookInputs pins the T-847 assembly: an
// expected target's dry-run drift and a registry deletion the repair tracker
// saw are located risks on the report, and stay inside the content floor.
func TestCollectIntegritySignalsWithHookInputs(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	rep := collectIntegritySignalsWith(filepath.Join(home, ".observer", "observer.db"), home, "/current/observer", nil, noPostureRoutes, hookIntegrityInputs{
		Expected: []diag.ExpectedHook{{Tool: "cursor", ConfigPath: filepath.Join(home, ".cursor", "hooks.json"), Drift: []string{"preToolUse"}}},
		Tracker:  fakeLoss{at: now.Add(-time.Minute)},
		Now:      now,
	})
	want := map[string]string{
		orgcontract.CaptureRiskHookRegistrationDrift: "cursor ~/.cursor/hooks.json",
		orgcontract.CaptureRiskHookRegistryMissing:   "observer ~/.observer/hook_checksums.json",
	}
	got := map[string]string{}
	for _, it := range rep.CaptureRiskItems {
		got[it.Risk] = it.Tool + " " + it.File
	}
	for risk, where := range want {
		if got[risk] != where {
			t.Errorf("%s located at %q, want %q (items %+v)", risk, got[risk], where, rep.CaptureRiskItems)
		}
	}
	norm := rep.NormalizeLabels()
	if len(norm.CaptureRiskItems) != len(rep.CaptureRiskItems) {
		t.Fatalf("report items do not survive the wire normalization: %+v -> %+v", rep.CaptureRiskItems, norm.CaptureRiskItems)
	}
}
