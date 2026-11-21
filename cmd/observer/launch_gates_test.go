package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLaunchGateOrder pins the order of the launch-gate table (F0-4), as a
// whole and as each launch path walks it.
//
// Repository trust (security Phase B, agent_launch) is the repo.trust row:
// after state.load, before hook.switch, on both paths (launch_gates.go
// "Repository trust").
func TestLaunchGateOrder(t *testing.T) {
	wantOrder := []string{
		"tool.disallow",
		"route.maintenance",
		"state.load",
		"terminals.feature",
		"repo.trust",
		"hook.switch",
		"project.match",
		"sandbox.select",
		"budget.authority",
		"budget.guard",
		"budget.coverage",
		"budget.spend",
	}
	if got := launchGateIDs(launchGates, launchPathsAll); !slices.Equal(got, wantOrder) {
		t.Fatalf("table order = %v\nwant          %v", got, wantOrder)
	}
	perPath := []struct {
		path launchPath
		want []string
	}{
		{launchPathDashboardFresh, []string{
			"tool.disallow",
			"state.load",
			"repo.trust",
			"hook.switch", "sandbox.select",
			"budget.authority", "budget.guard", "budget.spend",
		}},
		{launchPathCLI, []string{
			"route.maintenance", "state.load",
			"terminals.feature",
			"repo.trust",
			"hook.switch", "project.match", "sandbox.select",
			"budget.authority", "budget.guard", "budget.coverage", "budget.spend",
		}},
	}
	for _, p := range perPath {
		if got := launchGateIDs(launchGates, p.path); !slices.Equal(got, p.want) {
			t.Errorf("path %b walks %v, want %v", p.path, got, p.want)
		}
	}
	// The trust row sits between state.load and hook.switch; only the
	// terminals row (OSH-R-003), which reads no repository, is between it
	// and state.load, so a refused terminal never reads the repository.
	i := slices.Index(wantOrder, "repo.trust")
	if i < 2 || wantOrder[i-2] != "state.load" || wantOrder[i-1] != "terminals.feature" || wantOrder[i+1] != "hook.switch" {
		t.Fatal("the repository trust row left its slot between state.load and hook.switch")
	}
}

// TestLaunchGateRowsAreWellFormed: every row has a unique id, says what it
// checks, declares what it can return and where it runs, and has a body.
func TestLaunchGateRowsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range launchGates {
		if g.id == "" || seen[g.id] {
			t.Errorf("row id %q is empty or repeated", g.id)
		}
		seen[g.id] = true
		if strings.TrimSpace(g.checks) == "" || g.can == 0 || g.paths == 0 || g.run == nil {
			t.Errorf("row %q is incomplete: checks=%q can=%b paths=%b run=%v", g.id, g.checks, g.can, g.paths, g.run != nil)
		}
		if g.paths&^launchPathsAll != 0 {
			t.Errorf("row %q names an unknown launch path %b", g.id, g.paths)
		}
	}
}

// launchGateIDs is the ids of the rows that run on any of paths, in order.
func launchGateIDs(rows []launchGate, paths launchPath) []string {
	var out []string
	for _, g := range rows {
		if g.paths&paths != 0 {
			out = append(out, g.id)
		}
	}
	return out
}

// launchGateRow is the table row with id.
func launchGateRow(t *testing.T, id string) launchGate {
	t.Helper()
	for _, g := range launchGates {
		if g.id == id {
			return g
		}
	}
	t.Fatalf("no launch gate row %q", id)
	return launchGate{}
}

// TestLaunchGateRows is the one-test-per-row table: each case runs ONE row
// on a prepared launch and checks what it returned, which must also be an
// outcome the row declares. Every row of launchGates has at least one case.
func TestLaunchGateRows(t *testing.T) {
	cases := []struct {
		row  string
		name string
		// prepare builds the launch the row sees, as the rows above it
		// would have left it.
		prepare func(t *testing.T) *launchGateRun
		want    launchGateOutcome
		check   func(t *testing.T, r *launchGateRun, s launchGateStep)
	}{
		// terminals.feature (OSH-R-003)
		{
			row: "terminals.feature", name: "no decision allows",
			prepare: func(*testing.T) *launchGateRun { return &launchGateRun{tool: "codex"} },
			want:    launchGateAllow,
		},
		{
			row: "terminals.feature", name: "the org decision refuses, judged with the launch's box answer",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{tool: "codex", inSandboxFn: func() bool { return true }, terminalGate: func(r *launchGateRun) (bool, string) {
					if !r.inSandbox() {
						return true, ""
					}
					return false, "disabled by organization policy"
				}}
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !strings.Contains(s.refuse.Error(), "disabled by organization policy") {
					t.Fatalf("refusal %v does not carry the org reason", s.refuse)
				}
			},
		},
		// tool.disallow
		{
			row: "tool.disallow", name: "no org list allows",
			prepare: func(*testing.T) *launchGateRun { return &launchGateRun{tool: "codex"} },
			want:    launchGateAllow,
		},
		{
			row: "tool.disallow", name: "allowed tool allows",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{tool: "codex", toolLaunchAllowed: func(string) bool { return true }}
			},
			want: launchGateAllow,
		},
		{
			row: "tool.disallow", name: "disallowed tool refuses and names the request path",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{tool: "codex", toolLaunchAllowed: func(string) bool { return false }}
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !errors.Is(s.refuse, dashapi.ErrLaunchToolNotAllowed) ||
					!strings.Contains(s.refuse.Error(), "codex") || !strings.Contains(s.refuse.Error(), "Requests page") {
					t.Fatalf("refusal = %v", s.refuse)
				}
			},
		},
		// route.maintenance
		{
			row: "route.maintenance", name: "maintenance verb is allowed with no later row",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{evidence: budgetLaunchEvidence{Route: budgetLaunchRouteMaintenance}}
			},
			want: launchGateAllowNow,
		},
		{
			row: "route.maintenance", name: "agent launch goes on",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{evidence: budgetLaunchEvidence{Route: budgetLaunchRouteDirect}}
			},
			want: launchGateAllow,
		},
		// state.load
		{
			// An unreadable config, not a missing one: a missing config loads
			// the defaults and refused only through the Linux ENOTDIR of the
			// test home's ~/.observer file (on Windows that stat is "not found").
			row: "state.load", name: "unreadable config refuses with the safe-state error",
			prepare: func(t *testing.T) *launchGateRun {
				badCfg := filepath.Join(t.TempDir(), "config.toml")
				if err := os.WriteFile(badCfg, []byte("[observer\n"), 0o600); err != nil {
					t.Fatalf("write unparseable config: %v", err)
				}
				return &launchGateRun{ctx: context.Background(), tool: "muse", configPath: badCfg}
			},
			want: launchGateRefuse,
			check: func(t *testing.T, r *launchGateRun, s launchGateStep) {
				if !strings.Contains(s.refuse.Error(), "cannot determine safe launch state") {
					t.Fatalf("refusal = %v", s.refuse)
				}
				if len(r.closers) != 0 {
					t.Fatal("a failed load left something to close")
				}
			},
		},
		{
			row: "state.load", name: "loads config and database for the rows below",
			prepare: func(t *testing.T) *launchGateRun {
				return &launchGateRun{ctx: context.Background(), tool: "muse", configPath: writeLaunchGateConfig(t, "enforce")}
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				if r.database == nil || len(r.closers) != 1 || r.cfg.Guard.Mode != "enforce" {
					t.Fatalf("loaded state: db=%v closers=%d mode=%q", r.database != nil, len(r.closers), r.cfg.Guard.Mode)
				}
				r.close()
			},
		},
		// repo.trust
		{
			row: "repo.trust", name: "inactive component leaves the row inert",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{
					repoTrustFor: func(*launchGateRun) *repoTrustDeps { return nil },
					launchDir:    func() (string, error) { panic("the launch directory must not be read") },
				}
			},
			want: launchGateAllow,
		},
		// hook.switch
		{
			row: "hook.switch", name: "sandbox selection off leaves no gate",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{
					sandboxGateOn: func(*launchGateRun) bool { return false },
					launchDir:     func() (string, error) { panic("the launch directory must not be read") },
					baseToolGate:  currentToolGate,
				}
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				if r.toolGate != nil {
					t.Fatal("a gate was set although the sandbox selection is off")
				}
			},
		},
		{
			row: "hook.switch", name: "no launch directory keeps the node gate",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{
					sandboxGateOn: func(*launchGateRun) bool { return true },
					launchDir:     func() (string, error) { return "", errors.New("no directory") },
					baseToolGate:  currentToolGate,
				}
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				if r.toolGate == nil || !r.toolGate("any").Current {
					t.Fatal("the node gate was not passed on unchanged")
				}
			},
		},
		{
			row: "hook.switch", name: "project hook switch makes the hook not current",
			prepare: func(t *testing.T) *launchGateRun {
				dir, _ := projectHookSwitchFixture(t)
				return &launchGateRun{
					sandboxGateOn: func(*launchGateRun) bool { return true },
					launchDir:     func() (string, error) { return dir, nil },
					baseToolGate:  currentToolGate,
				}
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				_, tool := projectHookSwitchTool(t)
				st := r.toolGate(tool)
				if st.Current || !strings.Contains(st.Reason, "switched off in this project") {
					t.Fatalf("gate for %s = %+v, want not current by the project switch", tool, st)
				}
			},
		},
		// sandbox.select
		{
			row: "sandbox.select", name: "selection off proceeds without building a guard",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{
					tool:          launchGateSandboxTool(),
					sandboxGateOn: func(*launchGateRun) bool { return false },
					guardFor:      func(*launchGateRun) *guard.Guard { panic("no guard may be built") },
				}
			},
			want: launchGateAllow,
		},
		{
			row: "sandbox.select", name: "org_disallow with no sandbox refuses",
			prepare: func(t *testing.T) *launchGateRun {
				return sandboxSelectRun(t, nil, false)
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !errors.Is(s.refuse, dashapi.ErrLaunchSandboxRequired) || !strings.Contains(s.refuse.Error(), "org_disallow") {
					t.Fatalf("refusal = %v", s.refuse)
				}
			},
		},
		{
			row: "sandbox.select", name: "available sandbox upgrades the request",
			prepare: func(t *testing.T) *launchGateRun {
				return sandboxSelectRun(t, func() bool { return true }, false)
			},
			want: launchGateUpgrade | launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				if !r.sandboxed {
					t.Fatal("the upgrade did not mark the launch sandboxed")
				}
			},
		},
		{
			row: "sandbox.select", name: "already sandboxed proceeds",
			prepare: func(t *testing.T) *launchGateRun {
				return sandboxSelectRun(t, nil, true)
			},
			want: launchGateAllow,
		},
		// budget.authority
		{
			row: "budget.authority", name: "no managed budget allows with no later row",
			prepare: func(t *testing.T) *launchGateRun {
				return loadedLaunchGateRun(t, writeLaunchGateConfig(t, "enforce"), "muse")
			},
			want: launchGateAllowNow,
		},
		{
			row: "budget.authority", name: "managed hard budget goes on to the budget rows",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
				return loadedLaunchGateRun(t, cfgPath, "claude-code")
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				if !r.budget.Required || !r.budget.GuardReady {
					t.Fatalf("budget state = %+v", r.budget)
				}
			},
		},
		{
			row: "budget.authority", name: "expired grant without fail_closed warns and allows",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
				rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
					grant.ExpiresAt = time.Now().UTC().Add(-time.Hour)
					grant.SignedExpiresAt = grant.ExpiresAt
				})
				return loadedLaunchGateRun(t, cfgPath, "muse")
			},
			want: launchGateWarn | launchGateAllowNow,
		},
		{
			row: "budget.authority", name: "expired grant under fail_closed refuses",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
				setBudgetLaunchFailClosed(t, cfgPath)
				rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
					grant.ExpiresAt = time.Now().UTC().Add(-time.Hour)
					grant.SignedExpiresAt = grant.ExpiresAt
				})
				return loadedLaunchGateRun(t, cfgPath, "muse")
			},
			want: launchGateRefuse,
		},
		// budget.guard
		{
			row: "budget.guard", name: "guard not ready refuses",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{tool: "claude-code", budget: managedBudgetLaunchState{Required: true}}
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !errors.Is(s.refuse, errBudgetLaunchUncontrolled) {
					t.Fatalf("refusal = %v", s.refuse)
				}
			},
		},
		{
			row: "budget.guard", name: "guard ready goes on",
			prepare: func(*testing.T) *launchGateRun {
				return &launchGateRun{tool: "claude-code", budget: managedBudgetLaunchState{Required: true, GuardReady: true}}
			},
			want: launchGateAllow,
		},
		// budget.coverage
		{
			row: "budget.coverage", name: "proven proxy route is covered",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
				r := loadedLaunchGateRun(t, cfgPath, "claude-code")
				r.evidence = budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"}
				return r
			},
			want: launchGateAllow,
		},
		{
			row: "budget.coverage", name: "unknown route with no cutoff refuses",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
				r := loadedLaunchGateRun(t, cfgPath, "claude-code")
				r.evidence = budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
				return r
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !errors.Is(s.refuse, errBudgetLaunchUncontrolled) {
					t.Fatalf("refusal = %v", s.refuse)
				}
			},
		},
		// project.match
		{
			row: "project.match", name: "no org bundle configured goes on and writes nothing",
			prepare: func(t *testing.T) *launchGateRun {
				dir := t.TempDir()
				return &launchGateRun{ctx: context.Background(), launchDir: func() (string, error) { return dir, nil }}
			},
			want: launchGateAllow,
		},
		{
			row: "project.match", name: "a v3 bundle records the launch directory's match",
			prepare: func(t *testing.T) *launchGateRun {
				bundle, dir := writeProjectAudienceFixture(t)
				r := &launchGateRun{ctx: context.Background(), launchDir: func() (string, error) { return dir, nil }}
				r.cfg.Guard.Rules.OrgBundle = bundle
				return r
			},
			want: launchGateAllow,
			check: func(t *testing.T, r *launchGateRun, _ launchGateStep) {
				dir, _ := r.launchDir()
				root, _ := filepath.EvalSymlinks(dir)
				path := projectmatch.LayoutFor(r.cfg.Guard.Rules.OrgBundle).MatchPath(projectmatch.RootHash(root))
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("no match record at %s: %v", path, err)
				}
			},
		},
		// budget.spend
		{
			row: "budget.spend", name: "under the cap goes on",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
				return budgetResolvedLaunchGateRun(t, cfgPath, "claude-code")
			},
			want: launchGateAllow,
		},
		{
			row: "budget.spend", name: "exhausted cap refuses",
			prepare: func(t *testing.T) *launchGateRun {
				cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
				exhaustManagedBudgetLaunchBudget(t, dbPath, "opencode")
				return budgetResolvedLaunchGateRun(t, cfgPath, "claude-code")
			},
			want: launchGateRefuse,
			check: func(t *testing.T, _ *launchGateRun, s launchGateStep) {
				if !errors.Is(s.refuse, errBudgetLaunchDenied) {
					t.Fatalf("refusal = %v", s.refuse)
				}
			},
		},
	}

	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.row] = true
		t.Run(tc.row+"/"+tc.name, func(t *testing.T) {
			g := launchGateRow(t, tc.row)
			r := tc.prepare(t)
			t.Cleanup(r.close)
			s := g.run(r)
			if got := s.outcomes(); got != tc.want {
				t.Fatalf("outcome = %b, want %b (step %+v)", got, tc.want, s)
			}
			if s.outcomes()&^g.can != 0 {
				t.Fatalf("row returned %b, which is outside its declared %b", s.outcomes(), g.can)
			}
			if tc.check != nil {
				tc.check(t, r, s)
			}
		})
	}
	for _, g := range launchGates {
		if !covered[g.id] {
			t.Errorf("launch gate row %q has no case in TestLaunchGateRows", g.id)
		}
	}
}

// TestWalkLaunchGates pins the walker: rows off the launch's path are
// skipped, a warning is printed and the walk goes on, a refusal or an
// allow-now ends it, and what the rows opened is closed last-first.
func TestWalkLaunchGates(t *testing.T) {
	var ran []string
	var closed []string
	row := func(id string, paths launchPath, step launchGateStep) launchGate {
		return launchGate{id: id, paths: paths, run: func(r *launchGateRun) launchGateStep {
			ran = append(ran, id)
			r.closers = append(r.closers, func() { closed = append(closed, id) })
			return step
		}}
	}
	refusal := errors.New("refused")
	cases := []struct {
		name       string
		rows       []launchGate
		wantErr    error
		wantRan    []string
		wantClosed []string
		wantWarn   string
	}{
		{
			name:       "every row allows",
			rows:       []launchGate{row("a", launchPathCLI, launchGateStep{}), row("b", launchPathCLI, launchGateStep{})},
			wantRan:    []string{"a", "b"},
			wantClosed: []string{"b", "a"},
		},
		{
			name:       "rows off the path are skipped",
			rows:       []launchGate{row("dash", launchPathDashboardFresh, launchGateStep{}), row("cli", launchPathCLI, launchGateStep{})},
			wantRan:    []string{"cli"},
			wantClosed: []string{"cli"},
		},
		{
			name:       "refusal ends the walk",
			rows:       []launchGate{row("a", launchPathCLI, launchGateStep{refuse: refusal}), row("b", launchPathCLI, launchGateStep{})},
			wantErr:    refusal,
			wantRan:    []string{"a"},
			wantClosed: []string{"a"},
		},
		{
			name:       "allow-now ends the walk",
			rows:       []launchGate{row("a", launchPathCLI, launchGateStep{allowNow: true}), row("b", launchPathCLI, launchGateStep{})},
			wantRan:    []string{"a"},
			wantClosed: []string{"a"},
		},
		{
			name:       "warning is printed and the walk goes on",
			rows:       []launchGate{row("a", launchPathCLI, launchGateStep{warn: "careful"}), row("b", launchPathCLI, launchGateStep{})},
			wantRan:    []string{"a", "b"},
			wantClosed: []string{"b", "a"},
			wantWarn:   "observer codex: warning: careful\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ran, closed = nil, nil
			var out bytes.Buffer
			err := walkLaunchGates(&launchGateRun{path: launchPathCLI, tool: "codex", stderr: &out}, tc.rows)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(ran, tc.wantRan) || !slices.Equal(closed, tc.wantClosed) {
				t.Fatalf("ran %v closed %v, want ran %v closed %v", ran, closed, tc.wantRan, tc.wantClosed)
			}
			if out.String() != tc.wantWarn {
				t.Fatalf("stderr = %q, want %q", out.String(), tc.wantWarn)
			}
		})
	}
}

// currentToolGate reports every tool's hook as registered and current.
func currentToolGate(tool string) nodeToolGateState {
	return nodeToolGateState{Tool: tool, Current: true, Installed: true, Reason: "registered"}
}

// writeLaunchGateConfig writes a node config with the guard in mode over a
// fresh, unenrolled database.
func writeLaunchGateConfig(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	body := fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = %q\n", dbPath, mode)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// loadedLaunchGateRun is a CLI launch with state.load already run.
func loadedLaunchGateRun(t *testing.T, cfgPath, tool string) *launchGateRun {
	t.Helper()
	r := &launchGateRun{ctx: context.Background(), path: launchPathCLI, tool: tool, configPath: cfgPath}
	if s := gateStateLoad(r); s.refuse != nil {
		t.Fatalf("state.load: %v", s.refuse)
	}
	return r
}

// budgetResolvedLaunchGateRun is a CLI launch with state.load and
// budget.authority already run, on a proven proxy route.
func budgetResolvedLaunchGateRun(t *testing.T, cfgPath, tool string) *launchGateRun {
	t.Helper()
	r := loadedLaunchGateRun(t, cfgPath, tool)
	r.evidence = budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"}
	if s := gateBudgetAuthority(r); s.refuse != nil || s.allowNow {
		t.Fatalf("budget.authority: %+v", s)
	}
	return r
}

// projectHookSwitchTool is the first project-scope hook switch and a
// launchable tool it silences.
func projectHookSwitchTool(t *testing.T) (hookdisable.Switch, string) {
	t.Helper()
	for _, s := range hookdisable.Switches {
		if s.Scope == hookdisable.ScopeProject && len(s.Tools) > 0 {
			return s, s.Tools[0]
		}
	}
	t.Fatal("the hook.switch row test lost its fixture: hookdisable.Switches has no project-scope switch naming a tool; point projectHookSwitchTool at the row that replaced it")
	return hookdisable.Switch{}, ""
}

// projectHookSwitchFixture writes a project whose settings switch its
// tool's hooks off and returns the project directory.
func projectHookSwitchFixture(t *testing.T) (string, string) {
	t.Helper()
	row, tool := projectHookSwitchTool(t)
	dir := t.TempDir()
	settings := filepath.Join(dir, filepath.FromSlash(row.ProjectRel))
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	segs := strings.Split(row.Key, ".")
	body := fmt.Sprintf("%v", row.Off)
	for i := len(segs) - 1; i >= 0; i-- {
		body = fmt.Sprintf("{%q:%s}", segs[i], body)
	}
	writeFileT(t, settings, body)
	return dir, tool
}

// launchGateSandboxTool is a launchable, proxied tool the Guard can only
// contain with a sandbox.
func launchGateSandboxTool() string {
	for _, c := range integration.Capabilities() {
		if c.Handoff.Launchable() && c.EnforcementChannel() == integration.EnforceSandbox && c.Proxy != nil {
			return c.Tool
		}
	}
	return ""
}

// sandboxSelectRun is a launch of a sandbox-only tool under an enforcing
// Guard on a managed node whose org chose org_disallow, with hook.switch
// already run.
func sandboxSelectRun(t *testing.T, probe func() bool, sandboxed bool) *launchGateRun {
	t.Helper()
	tool := launchGateSandboxTool()
	if tool == "" {
		t.Fatal("the sandbox.select row tests lost their fixture: the integration registry has no launchable, proxied, sandbox-only tool; point launchGateSandboxTool at the row that replaced it")
	}
	dir := t.TempDir()
	gcfg := config.Default().Guard
	gcfg.Enabled, gcfg.Mode = true, "enforce"
	gcfg.Rules.OrgBundle = filepath.Join(dir, "org-policy-bundle.json")
	gcfg.Rules.UserPolicy = ""
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFileT(t, gcfg.Rules.OrgBundle, signedGuardBundleJSON(t, priv, pub, 3, "[fallbacks]\nsandbox_unavailable = \"org_disallow\"\n"))
	gd, err := guard.New(guard.Options{Config: gcfg, Home: dir, OrgKeyPinHash: pinOf(pub), ManagedTenancy: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	return &launchGateRun{
		tool:           tool,
		sandboxGateOn:  func(*launchGateRun) bool { return true },
		guardFor:       func(*launchGateRun) *guard.Guard { return gd },
		sandboxProbe:   probe,
		sandboxRefusal: cliSandboxRefusal,
		sandboxed:      sandboxed,
		toolGate:       func(string) nodeToolGateState { return nodeToolGateState{} },
	}
}
