package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// gen9RejectingPoster models a gen8 server: it 400s a report whose guard row
// carries the gen9 local rule report.
type gen9RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen9RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if lg := row.LocalGuard; lg != nil && (lg.RuleChanges != nil || lg.RemovedDisables != nil || lg.Inputs != nil || lg.Node != nil) {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen9RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// guardRowLocal finds the guard row's LocalGuard posture.
func guardRowLocal(t *testing.T, rep orgcontract.PolicyStateReport) *orgcontract.LocalGuardPosture {
	t.Helper()
	for _, row := range rep.Rows {
		if row.EnforcementPoint == policystate.PointGuard {
			return row.LocalGuard
		}
	}
	t.Fatal("no guard row")
	return nil
}

// TestReporter_LocalRuleChanges (gen9, managed policy visibility
// 2026-11-12): the local rule report rides the guard row's LocalGuard
// posture; a gen8 server refuses it and the reporter sends the gen8 shape
// (the posture's gen3 fields kept) and latches there; a node with no local
// change sends the same bytes as before with no probe; every older
// projection clears the report without touching the input.
func TestReporter_LocalRuleChanges(t *testing.T) {
	at := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	report := localRuleReport{
		changes: []orgcontract.LocalRuleChange{{RuleID: "S-791", Layer: orgcontract.LocalRuleLayerMachine, Kind: orgcontract.LocalRuleKindDisable, Loosens: true}},
		removed: []string{"S-792"}, removedAt: at,
		inputs: localGuardInputsFrom(config.Default().Guard),
		node:   localNodePostureFrom(config.Default()),
	}
	guardWith := func(context.Context) (policystate.PointFacts, error) {
		return policystate.PointFacts{
			LastSeen: time.Now(), EnforceMode: "observe",
			LocalGuard: &orgcontract.LocalGuardPosture{Enabled: true, Mode: "observe", PromptEnabled: true, PromptMode: "ask-once"},
		}, nil
	}
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = withLocalRuleChanges(guardWith, func(context.Context) localRuleReport { return report })
	fp := &gen9RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen9 rejected, gen8 accepted)", len(fp.calls))
	}
	full := guardRowLocal(t, fp.calls[0])
	if full == nil || len(full.RuleChanges) != 1 || full.RemovedDisablesAt != "2026-11-12T10:00:00Z" || full.RemovedDisables[0] != "S-792" {
		t.Fatalf("the full snapshot's local guard = %+v", full)
	}
	if !orgcontract.ValidLocalRuleReport(full) {
		t.Fatalf("the node sent a report the server refuses: %+v", full)
	}
	if full.Inputs == nil || len(orgcontract.LocalGuardInputWeakenings(full.Inputs)) != 0 {
		t.Fatalf("the shipped defaults must report as inputs with no weakening: %+v", full.Inputs)
	}
	gen8 := guardRowLocal(t, fp.calls[1])
	if gen8 == nil || gen8.RuleChanges != nil || gen8.RemovedDisables != nil || gen8.Inputs != nil || gen8.Node != nil || gen8.Mode != "observe" {
		t.Fatalf("gen8 rung local guard = %+v", gen8)
	}
	if !rep.latched.Load() || !rep.latchGen8.Load() || rep.latchGen7.Load() {
		t.Fatalf("latched %v gen8 %v gen7 %v", rep.latched.Load(), rep.latchGen8.Load(), rep.latchGen7.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || guardRowLocal(t, fp.calls[2]).RuleChanges != nil {
		t.Fatalf("a latched gen8 send must go straight out without the report, got %d calls", len(fp.calls))
	}

	// No local change: no gen9 content, so a gen8 server takes the first
	// send and nothing latches.
	readers = gen2Readers(t)
	readers[policystate.PointGuard] = withLocalRuleChanges(guardWith, func(context.Context) localRuleReport { return localRuleReport{} })
	fp = &gen9RejectingPoster{}
	rep = newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 1 || rep.latched.Load() {
		t.Fatalf("no local change: %d calls, latched %v", len(fp.calls), rep.latched.Load())
	}

	lg := &orgcontract.LocalGuardPosture{Mode: "observe", PromptMode: "off", RuleChanges: report.changes}
	rows := []orgcontract.PolicyStateRow{{EnforcementPoint: policystate.PointGuard, LocalGuard: lg}}
	for name, proj := range map[string]func([]orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow{
		"gen8": projectGen8, "gen7": projectGen7, "gen6": projectGen6, "gen5": projectGen5, "gen4": projectGen4, "gen3": projectGen3, "gen2": projectGen2, "gen1": projectGen1,
	} {
		if got := proj(rows)[0].LocalGuard; got != nil && got.RuleChanges != nil {
			t.Fatalf("%s projection kept the gen9 report: %+v", name, got)
		}
	}
	if len(lg.RuleChanges) != 1 {
		t.Fatal("a projection modified the input posture")
	}
}

// TestLocalNodePostureFrom pins the gen9 node posture (gaps G4 to G13): the
// shipped defaults are valid and weaken nothing; each loosening is named; no
// path, host or tool name travels.
func TestLocalNodePostureFrom(t *testing.T) {
	def := localNodePostureFrom(config.Default())
	if !def.Valid() {
		t.Fatalf("defaults invalid: %+v", def)
	}
	if w := orgcontract.LocalNodeWeakenings(def); len(w) != 0 {
		t.Fatalf("the shipped defaults read as weaker: %v", w)
	}
	if def.Share["policy_state"] || def.DefaultWorkspace != orgcontract.LocalListDefault {
		t.Fatalf("defaults: share=%v workspace=%q", def.Share, def.DefaultWorkspace)
	}
	cfg := config.Default()
	cfg.Guard.Prompt.HookLane = false
	cfg.Observer.Hooks.AutoRegister = false
	cfg.Proxy.Enabled = false
	cfg.Terminal.Launch.AllowShell = true
	cfg.Terminal.Launch.AllowedProjectRoots = []string{"/home/dev/secret-project"}
	cfg.Workspace.DefaultDir = "/home/dev/scratch"
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Backends = []string{"bwrap", "Not A Token!"}
	cfg.MCPRelay.Enabled = true
	cfg.Guard.Budget.Window.Util5hWarn = 0.8
	cfg.OrgClient.Share.PolicyState = true
	n := localNodePostureFrom(cfg)
	if !n.Valid() {
		t.Fatalf("invalid: %+v", n)
	}
	want := "guard.prompt.hook_lane,observer.hooks.auto_register,proxy.enabled,terminal.launch.allow_shell"
	if got := strings.Join(orgcontract.LocalNodeWeakenings(n), ","); got != want {
		t.Fatalf("weakenings = %s, want %s", got, want)
	}
	if n.LaunchAllowedProjectRoots != 1 || n.DefaultWorkspace != orgcontract.LocalListCustom || !n.SandboxEnabled ||
		strings.Join(n.SandboxBackends, ",") != "bwrap" || !n.MCPRelayEnabled || n.BudgetWindow != orgcontract.LocalListCustom || !n.Share["policy_state"] {
		t.Fatalf("posture = %+v", n)
	}
	raw, _ := json.Marshal(n)
	for _, leak := range []string{"secret-project", "scratch", "/home/dev"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the posture carries %q: %s", leak, raw)
		}
	}
}

// TestLocalGuardInputsFrom pins the input summary: list shapes and counts
// only, and each loosening named.
func TestLocalGuardInputsFrom(t *testing.T) {
	gc := config.Default().Guard
	gc.Boundary.AllowPaths = []string{"/srv/shared", "/opt/tools"}
	gc.Boundary.ProtectedBranches = []string{}
	gc.Proxy.EgressScan = false
	gc.MCP.Pinning = false
	in := localGuardInputsFrom(gc)
	if in.BoundaryAllowPaths != orgcontract.LocalListCustom || in.BoundaryAllowCount != 2 || in.ProtectedBranches != orgcontract.LocalListNone {
		t.Fatalf("inputs = %+v", in)
	}
	if !in.Valid() {
		t.Fatalf("invalid inputs: %+v", in)
	}
	want := "guard.boundary.allow_paths,guard.boundary.protected_branches,guard.proxy.egress_scan,guard.mcp.pinning"
	if got := strings.Join(orgcontract.LocalGuardInputWeakenings(in), ","); got != want {
		t.Fatalf("weakenings = %s, want %s", got, want)
	}
}

// TestLocalRuleReportStripsStaleDisables (review finding 1, 2026-11-12): on a
// node whose tenancy is managed, the report removes a built-in disable from
// the config file before it reads it, with no org bundle in force (a node
// that enrolled while the daemon ran), and reports the removal; an
// individual node's file is left as it is.
func TestLocalRuleReportStripsStaleDisables(t *testing.T) {
	for _, tc := range []struct {
		name      string
		managed   bool
		wantStrip bool
	}{
		{"managed", true, true},
		{"individual", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processManagedDisableRemoval.Store(nil)
			t.Cleanup(func() { processManagedDisableRemoval.Store(nil) })
			home := t.TempDir()
			cfgPath := filepath.Join(home, "config.toml")
			if err := os.WriteFile(cfgPath, []byte("[guard.rules]\ndisable = [\"R-101\"]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			managed := tc.managed
			g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, ManagedTenancy: func() bool { return managed }})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			rep := localRuleReportFrom(g, nil, func() string { return cfgPath }, quietLogger())(context.Background())
			got, _ := os.ReadFile(cfgPath)
			if stripped := !strings.Contains(string(got), "R-101"); stripped != tc.wantStrip {
				t.Fatalf("stripped = %v, want %v:\n%s", stripped, tc.wantStrip, got)
			}
			if tc.wantStrip {
				if strings.Join(rep.removed, ",") != "R-101" {
					t.Errorf("removed = %v, want [R-101]", rep.removed)
				}
				if _, err := os.Stat(config.GuardStripBackupPath(cfgPath)); err != nil {
					t.Errorf("no strip backup: %v", err)
				}
				for _, c := range rep.changes {
					if c.RuleID == "R-101" {
						t.Errorf("the stripped disable is still reported: %+v", c)
					}
				}
			}
		})
	}
}
