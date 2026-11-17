package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestP308PublishRewritesADamagedAdmission pins D-359 / review P3-08: once a
// stop is published, a file that is deleted, truncated, made malformed or
// replaced with other stops is re-written on the next tick even though the
// decision did not change. Pre-fix the in-memory fast path returned without
// looking at the disk, so the hook path stopped nothing until the decision
// itself changed.
func TestP308PublishRewritesADamagedAdmission(t *testing.T) {
	t.Parallel()
	stop := []budgetwarnfile.Stop{{RuleID: "B-602", Reason: "spent"}}
	cases := []struct {
		name   string
		damage func(t *testing.T, path string)
	}{
		{"deleted", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"bad json", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign schema", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"schema":99,"stops":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"drifted stops", func(t *testing.T, path string) {
			if err := budgetwarnfile.WriteAdmission(path, budgetwarnfile.Admission{WrittenAt: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dbPath := filepath.Join(t.TempDir(), "observer.db")
			path := budgetwarnfile.AdmissionPath(dbPath)
			now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
			svc := newBudgetWarnService(dbPath, nil, nil, nil)
			svc.now = func() time.Time { return now }
			svc.SetAdmission(func(time.Time, []orgbudget.SubjectCap) ([]budgetwarnfile.Stop, bool) { return stop, true })
			svc.publishAdmission()
			tc.damage(t, path)
			now = now.Add(budgetAdmissionTick)
			svc.publishAdmission()
			a, err := budgetwarnfile.ReadAdmission(path)
			if err != nil || a == nil || !budgetwarnfile.SameStops(a.Stops, stop) {
				t.Fatalf("after damage %q the file = %+v, %v; want the published stop back", tc.name, a, err)
			}
			if _, ok := a.StopFor("cursor", now); !ok {
				t.Fatal("the re-written stop is not in force")
			}
		})
	}
}

// TestP305PublisherKeepsAStopFresh pins the other half of the freshness rule:
// an unchanged stop is re-written every AdmissionRefresh so a hook never sees
// a live publisher's stop as stale, and an unchanged "no stop" is not
// re-written at all.
func TestP305PublisherKeepsAStopFresh(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	path := budgetwarnfile.AdmissionPath(dbPath)
	start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := start
	var stops []budgetwarnfile.Stop
	svc := newBudgetWarnService(dbPath, nil, nil, nil)
	svc.now = func() time.Time { return now }
	svc.SetAdmission(func(time.Time, []orgbudget.SubjectCap) ([]budgetwarnfile.Stop, bool) { return stops, true })

	stops = []budgetwarnfile.Stop{{RuleID: "B-625", Reason: "unavailable"}}
	for now.Sub(start) <= 3*budgetwarnfile.AdmissionMaxAge {
		svc.publishAdmission()
		a, err := budgetwarnfile.ReadAdmission(path)
		if err != nil || a == nil {
			t.Fatalf("at +%s: %+v, %v", now.Sub(start), a, err)
		}
		if _, ok := a.StopFor("", now); !ok {
			t.Fatalf("at +%s a live publisher's stop went stale (written %s)", now.Sub(start), a.WrittenAt)
		}
		now = now.Add(budgetAdmissionTick)
	}

	stops = nil
	svc.publishAdmission()
	info1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(budgetwarnfile.AdmissionMaxAge)
	svc.publishAdmission()
	info2, _ := os.Stat(path)
	if !info2.ModTime().Equal(info1.ModTime()) {
		t.Fatal("an unchanged empty decision was re-written")
	}
}

// graceChecker answers CheckInterventionBudget from a queue of decisions.
type graceChecker struct {
	queue []guard.InterventionBudgetDecision
	ages  []time.Duration
}

func (g *graceChecker) CheckInterventionBudget(in guard.InterventionBudgetInput) guard.InterventionBudgetDecision {
	g.ages = append(g.ages, in.MaxSnapshotAge)
	d := g.queue[0]
	if len(g.queue) > 1 {
		g.queue = g.queue[1:]
	}
	return d
}

func (g *graceChecker) RenderBudgetReason(ruleID, reason string) string {
	return ruleID + ": " + reason
}

// TestP311TransientReadFailureGrace pins D-359 / review P3-11: a spend read
// that fails publishes its fail-closed stop only after hookBudgetGraceFailures
// consecutive failures, keeping the last good decision meanwhile; a decision
// taken on a successful read, and a non-transient fail-closed deny, publish at
// once. Pre-fix one overrunning read was a node-wide B-625 at once.
func TestP311TransientReadFailureGrace(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	ok := guard.InterventionBudgetDecision{Available: true, Required: true}
	readFail := guard.InterventionBudgetDecision{
		Available: true, Required: true, Deny: true, RuleID: "B-603",
		Reason: "accounting unavailable", AccountingUnavailable: true,
	}
	spent := guard.InterventionBudgetDecision{Available: true, Required: true, Deny: true, RuleID: "B-603", Reason: "spent"}
	noEngine := guard.InterventionBudgetDecision{Deny: true, Reason: "budget policy engine is unavailable"}
	type step struct {
		d        guard.InterventionBudgetDecision
		wantRule string
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"failures under the bound keep 'no stop'", []step{{ok, ""}, {readFail, ""}, {readFail, ""}, {ok, ""}, {readFail, ""}}},
		{"the bound publishes the fail-closed stop", []step{{ok, ""}, {readFail, ""}, {readFail, ""}, {readFail, "B-603"}}},
		{"failures keep a real stop in force", []step{{spent, "B-603"}, {readFail, "B-603"}, {readFail, "B-603"}}},
		{"a measured exhaustion stops at once", []step{{ok, ""}, {spent, "B-603"}}},
		{"a non-transient fail-closed deny stops at once", []step{{ok, ""}, {noEngine, "B-625"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			grace := newHookBudgetGrace()
			for i, s := range tc.steps {
				chk := &graceChecker{queue: []guard.InterventionBudgetDecision{s.d}}
				got := hookBudgetStopsGraced(chk, grace, nil, now)
				rule := ""
				if len(got) > 0 {
					rule = got[0].RuleID
				}
				if rule != s.wantRule {
					t.Fatalf("step %d: published %+v, want rule %q", i, got, s.wantRule)
				}
				if len(chk.ages) == 0 || chk.ages[0] != hookBudgetSnapshotAge {
					t.Fatalf("step %d: the publisher must allow a shared snapshot, asked with ages %v", i, chk.ages)
				}
			}
		})
	}
	if hookBudgetSnapshotAge <= budgetAdmissionTick || hookBudgetSnapshotAge >= budgetwarnfile.AdmissionRefresh {
		t.Fatalf("snapshot age %s must span ticks and stay under the refresh %s", hookBudgetSnapshotAge, budgetwarnfile.AdmissionRefresh)
	}
}

// TestP305ClearBudgetAdmission pins the helper the no-publisher start path and
// unenrol use: it removes the file and treats a missing one as success.
func TestP305ClearBudgetAdmission(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	path := budgetwarnfile.AdmissionPath(dbPath)
	if err := budgetwarnfile.WriteAdmission(path, budgetwarnfile.Admission{Stops: []budgetwarnfile.Stop{{RuleID: "B-625"}}}); err != nil {
		t.Fatal(err)
	}
	if err := clearBudgetAdmission(dbPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("admission file still present (err %v)", err)
	}
	if err := clearBudgetAdmission(dbPath); err != nil {
		t.Fatalf("a missing file must be success: %v", err)
	}
	if err := clearBudgetAdmission(""); err != nil {
		t.Fatal(err)
	}
}

// TestP305LeaveRemovesTheBudgetAdmission is the unenrol red/green: leaving
// the organization (the shared performUnenrol both `observer unenroll` and
// the dashboard's Leave run) removes budget-admission.json. Pre-fix it
// survived, and a B-625 in it denied every hook on a node with no org.
func TestP305LeaveRemovesTheBudgetAdmission(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, []string{govern.AuthorityDashboardVisibility})
	d, _, cfgPath := testEnrolDashboard(t)
	if _, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "code", OrgURL: org.url, Token: idpTestEnrolCode}); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	path := budgetwarnfile.AdmissionPath(cfg.Observer.DBPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := budgetwarnfile.WriteAdmission(path, budgetwarnfile.Admission{
		WrittenAt: time.Now().UTC(),
		Stops:     []budgetwarnfile.Stop{{RuleID: "B-625", Reason: "unavailable"}},
	}); err != nil {
		t.Fatal(err)
	}
	lv, err := d.Leave(ctx, dashapi.SwitchOptions{})
	if err != nil || !lv.WasEnrolled {
		t.Fatalf("Leave = (%+v, %v)", lv, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("budget-admission.json survived unenrol (err %v)", err)
	}
}
