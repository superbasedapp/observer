package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type nodeInterventionBlockingExitHandle struct {
	waitStarted chan struct{}
	releaseWait chan struct{}
	term        int
	kill        int
	wait        int
	close       int
}

func (h *nodeInterventionBlockingExitHandle) SignalTerminate(context.Context) (intervention.ExitResult, error) {
	h.term++
	return intervention.ExitResult{}, nil
}

func (h *nodeInterventionBlockingExitHandle) SignalKill(context.Context) (intervention.ExitResult, error) {
	h.kill++
	return intervention.ExitResult{}, nil
}

func (h *nodeInterventionBlockingExitHandle) WaitExit(ctx context.Context) (intervention.ExitResult, error) {
	h.wait++
	close(h.waitStarted)
	select {
	case <-h.releaseWait:
		return intervention.ExitResult{Observed: true}, nil
	case <-ctx.Done():
		return intervention.ExitResult{}, ctx.Err()
	}
}

func (h *nodeInterventionBlockingExitHandle) Close() error {
	h.close++
	return nil
}

func TestNodeInterventionBudgetUsesLiveGrantAndFreshCap(t *testing.T) {
	ctx := context.Background()
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-one" })
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("budget identity: active=%v err=%v", active, err)
	}
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil || !durable.Witness.Valid() {
		t.Fatalf("durable budget witness: %+v err=%v", durable.Witness, err)
	}
	pricing, err := st.LoadOrgPricing(ctx)
	if err != nil || !pricing.Witness.Valid() {
		t.Fatalf("durable pricing witness: %+v err=%v", pricing.Witness, err)
	}
	pricingWitness := guard.BudgetDocumentWitness{
		Known: pricing.Witness.Known, Present: pricing.Witness.Present, SHA256: pricing.Witness.SHA256,
	}
	cfg := config.Default()
	cfg.Guard.Enabled, cfg.Guard.Mode = true, "enforce"
	gd, err := guard.New(guard.Options{Config: cfg.Guard, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := gd.ApplyOrgBudgetWithWitness(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false, policy.BudgetProtection{DailyUSD: true}, identity.Binding, guardBudgetDocumentWitness(durable.Witness)); err != nil {
		t.Fatal(err)
	}
	spend := 0.34
	pricingCurrent := true
	gd.SetBudgetLookup(func(string) (guard.BudgetSnapshot, bool) {
		return guard.BudgetSnapshot{DailyUSD: spend, PricingDocumentWitness: pricingWitness, AccountingEvidence: &guard.BudgetAccountingEvidence{Fence: func(_ context.Context, action func() error) error {
			if !pricingCurrent {
				return errors.New("fixture price table changed")
			}
			return action()
		}}}, true
	})
	w := intervention.Workload{SurfaceID: "fixture/cli", Identity: intervention.Identity{UID: 1000}}
	decide := func(ready bool) intervention.PolicyDecision {
		t.Helper()
		d, err := nodeInterventionBudget(ctx, st, cfg, gd, w, nodeInterventionSource{Tool: "fixture", Ready: ready, Reason: "ready"}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := decide(true)
	if !before.Authorized || before.Stop {
		t.Fatalf("under cap=%+v", before)
	}
	spend = 0.35
	if got := decide(true); !got.Stop || got.RuleID != "B-602" {
		t.Fatalf("at cap=%+v", got)
	}
	// The priced decision can become obsolete before its signal. Exercise
	// the complete production fence composition without sending an OS signal.
	pending := decide(true)
	pricingCurrent = false
	actions := 0
	fencedCtx, fencedCancel := context.WithTimeout(ctx, time.Second)
	action := func(context.Context) (intervention.ExitResult, error) {
		actions++
		return intervention.ExitResult{Observed: true}, nil
	}
	fence := nodeInterventionSignalFence(st, gd)
	if _, err := fence(fencedCtx, w, pending, action); err == nil || actions != 0 {
		t.Fatalf("stale accounting reached process: actions=%d err=%v", actions, err)
	}
	pricingCurrent = true
	if _, err := fence(fencedCtx, w, pending, action); err != nil || actions != 1 {
		t.Fatalf("current accounting refused process operation: actions=%d err=%v", actions, err)
	}
	gd.SetBudgetLookup(func(string) (guard.BudgetSnapshot, bool) {
		return guard.BudgetSnapshot{USDUnavailable: policy.BudgetUnavailableWindows{Daily: true}}, true
	})
	unavailable := decide(true)
	if !unavailable.Stop || unavailable.RuleID != "B-602" || unavailable.PricingDocumentRequired {
		t.Fatalf("unknown-rate decision=%+v", unavailable)
	}
	if _, err := fence(fencedCtx, w, unavailable, action); err != nil || actions != 2 {
		t.Fatalf("unknown-rate cutoff refused: actions=%d err=%v", actions, err)
	}
	fencedCancel()
	spend = 0
	if got := decide(false); !got.Stop {
		t.Fatalf("unknown native source admitted: %+v", got)
	}
	if err := gd.ApplyOrgBudget(config.GuardBudgetConfig{}, nil, false, policy.BudgetProtection{}, identity.Binding); err != nil {
		t.Fatal(err)
	}
	if got := decide(false); got.Stop {
		t.Fatalf("removed cap still stopped: %+v", got)
	}
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-two" })
	if got := decide(true); got.Authority == before.Authority || !got.Stop || got.RuleID != "B-625" {
		t.Fatalf("member replacement reused authority or old cap: %+v", got)
	}
	rewriteBudgetLaunchGrant(t, dbPath, func(g *store.EnrolmentGrant) { g.Authority = nil })
	if got := decide(false); got.Authorized || got.Stop {
		t.Fatalf("revoked grant authorizes stop: %+v", got)
	}
}

func TestNodeInterventionAuthorityRequiresManagedMember(t *testing.T) {
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "" })
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := nodeInterventionAuthority(context.Background(), store.New(database), 1000, time.Now()); err == nil {
		t.Fatal("managed identity with no member accepted")
	}
}

func TestNodeInterventionSignalFenceRejectsReplacedAuthority(t *testing.T) {
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-one" })
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	st := store.New(database)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := nodeInterventionAuthority(ctx, st, 1000, time.Now())
	if err != nil || !d.Authorized {
		t.Fatalf("initial authority: %+v err=%v", d, err)
	}
	d.Stop = true
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil || !durable.Witness.Valid() {
		t.Fatalf("durable budget witness: %+v err=%v", durable.Witness, err)
	}
	setPolicyBudgetWitness(&d, guardBudgetDocumentWitness(durable.Witness))
	w := intervention.Workload{Identity: intervention.Identity{UID: 1000}}
	actions := 0
	d.ValidUntil = time.Now().Add(time.Second)
	action := func(actionCtx context.Context) (intervention.ExitResult, error) {
		deadline, ok := actionCtx.Deadline()
		if !ok || !deadline.Equal(d.ValidUntil) {
			t.Fatalf("operation deadline=%v ok=%v, want decision horizon %v", deadline, ok, d.ValidUntil)
		}
		actions++
		return intervention.ExitResult{Observed: true}, nil
	}
	fence := nodeInterventionSignalFence(st, nil)
	if _, err := fence(ctx, w, d, action); err != nil || actions != 1 {
		t.Fatalf("current grant refused: %v actions=%d", err, actions)
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	enr.UserID = "member-two"
	if err := st.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatal(err)
	}
	if _, err := fence(ctx, w, d, action); err == nil || actions != 1 {
		t.Fatalf("replaced identity reached signal: %v actions=%d", err, actions)
	}
	// Restore identity, resolve a fresh permit, then revoke only its budget
	// grant. Identity equality alone must never authorize the pending signal.
	enr.UserID = "member-one"
	if err := st.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatal(err)
	}
	d, err = nodeInterventionAuthority(ctx, st, 1000, time.Now())
	if err != nil || !d.Authorized {
		t.Fatalf("fresh authority: %+v err=%v", d, err)
	}
	d.Stop = true
	setPolicyBudgetWitness(&d, guardBudgetDocumentWitness(durable.Witness))
	key := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	grant, have, err := st.LoadEnrolmentGrant(ctx, key)
	if err != nil || !have {
		t.Fatalf("grant: have=%v err=%v", have, err)
	}
	grant.Authority = nil
	if err := st.WriteEnrolmentGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := fence(ctx, w, d, action); err == nil || actions != 1 {
		t.Fatalf("revoked grant reached signal: %v actions=%d", err, actions)
	}
}

func TestNodeInterventionSupervisorReleasesFenceBeforeExitWait(t *testing.T) {
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-one" })
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	st := store.New(database)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := nodeInterventionAuthority(ctx, st, 1000, time.Now().UTC())
	if err != nil || !d.Authorized {
		t.Fatalf("initial authority: %+v err=%v", d, err)
	}
	d.Stop = true
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil || !durable.Witness.Valid() {
		t.Fatalf("durable budget witness: %+v err=%v", durable.Witness, err)
	}
	setPolicyBudgetWitness(&d, guardBudgetDocumentWitness(durable.Witness))
	h := &nodeInterventionBlockingExitHandle{waitStarted: make(chan struct{}), releaseWait: make(chan struct{})}
	supervisor := intervention.Supervisor{
		Decide:      func(context.Context, intervention.Workload) (intervention.PolicyDecision, error) { return d, nil },
		Acquire:     func(context.Context, intervention.Identity) (intervention.ControlHandle, error) { return h, nil },
		Fence:       nodeInterventionSignalFence(st, nil),
		GracePeriod: 3 * time.Second,
	}
	w := intervention.Workload{SurfaceID: "fixture/cli", Identity: intervention.Identity{
		BootID: "fixture", PID: 123, StartTicks: 1, UID: 1000,
		Executable: intervention.ExecutableIdentity{Device: 1, Inode: 1},
	}}
	done := make(chan []intervention.Outcome, 1)
	go func() { done <- supervisor.Reconcile(ctx, []intervention.Workload{w}) }()
	select {
	case <-h.waitStarted:
	case <-ctx.Done():
		t.Fatalf("exit wait did not start: %v", ctx.Err())
	}

	writeCtx, writeCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_, writeErr := database.ExecContext(writeCtx, `CREATE TABLE intervention_fence_release_probe (id INTEGER PRIMARY KEY)`)
	writeCancel()
	if writeErr != nil {
		close(h.releaseWait)
		t.Fatalf("unrelated SQLite writer blocked by exit observation: %v", writeErr)
	}
	close(h.releaseWait)
	select {
	case outcomes := <-done:
		if len(outcomes) != 1 || outcomes[0].Status != "terminated" || !outcomes[0].Stopped ||
			!outcomes[0].TermAttempted || outcomes[0].KillAttempted || h.term != 1 || h.kill != 0 || h.wait != 1 || h.close != 1 {
			t.Fatalf("outcome=%+v handle=%+v", outcomes, h)
		}
	case <-ctx.Done():
		t.Fatalf("supervisor did not finish: %v", ctx.Err())
	}
}

func TestNodeInterventionSignalFenceRejectsBudgetChangeWithoutGuardApply(t *testing.T) {
	for _, tc := range []struct {
		name string
		body orgcontract.BudgetPolicyBody
	}{
		{name: "signed explicit none", body: orgcontract.EmptyBudgetPolicyBody(7)},
		{name: "same-version higher cap", body: orgcontract.BudgetPolicyBody{
			Version: 7, ResolvedScope: "member:one", CapUSD: 3.50,
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			Caps: []orgcontract.BudgetPolicyCap{{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 3.50,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard, ResolvedScope: "member:one",
			}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-one" })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			database, err := db.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			st := store.New(database)
			identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
			if err != nil || !active {
				t.Fatalf("budget identity: active=%v err=%v", active, err)
			}
			oldDoc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{
				Version: 7, ResolvedScope: "member:one", CapUSD: 0.35,
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, Enforcement: orgcontract.BudgetPolicyEnforcementHard,
				Caps: []orgcontract.BudgetPolicyCap{{
					Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 0.35,
					Enforcement: orgcontract.BudgetPolicyEnforcementHard, ResolvedScope: "member:one",
				}},
			}}
			oldWitness, err := st.SaveOrgBudgetWithWitness(ctx, oldDoc, `"old"`, "fixture-key", identity)
			if err != nil {
				t.Fatal(err)
			}
			pricing, err := st.LoadOrgPricing(ctx)
			if err != nil || !pricing.Witness.Valid() {
				t.Fatalf("durable pricing witness: %+v err=%v", pricing.Witness, err)
			}
			pricingWitness := guard.BudgetDocumentWitness{
				Known: pricing.Witness.Known, Present: pricing.Witness.Present, SHA256: pricing.Witness.SHA256,
			}
			cfg := config.Default()
			cfg.Guard.Enabled, cfg.Guard.Mode, cfg.Guard.Budget.FromOrg = true, "enforce", true
			gd, err := guard.New(guard.Options{Config: cfg.Guard, Home: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			if err := gd.ApplyOrgBudgetWithWitness(
				config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false,
				policy.BudgetProtection{DailyUSD: true}, identity.Binding,
				guardBudgetDocumentWitness(oldWitness),
			); err != nil {
				t.Fatal(err)
			}
			gd.SetBudgetLookup(func(string) (guard.BudgetSnapshot, bool) {
				return guard.BudgetSnapshot{
					DailyUSD: 0.35, PricingDocumentWitness: pricingWitness,
					AccountingEvidence: &guard.BudgetAccountingEvidence{Fence: func(_ context.Context, action func() error) error { return action() }},
				}, true
			})
			w := intervention.Workload{SurfaceID: "fixture/cli", Identity: intervention.Identity{UID: 1000}}
			pending, err := nodeInterventionBudget(ctx, st, cfg, gd, w, nodeInterventionSource{Tool: "fixture", Ready: true, Reason: "ready"}, time.Now().UTC())
			if err != nil || !pending.Stop || pending.RuleID != "B-602" {
				t.Fatalf("old deny=%+v err=%v", pending, err)
			}
			newWitness, err := st.SaveOrgBudgetWithWitness(ctx,
				orgcontract.BudgetPolicyDoc{BudgetPolicyBody: tc.body}, `"new"`, "fixture-key", identity)
			if err != nil || newWitness == oldWitness {
				t.Fatalf("replacement witness=%+v old=%+v err=%v", newWitness, oldWitness, err)
			}
			actions := 0
			_, err = nodeInterventionSignalFence(st, gd)(ctx, w, pending, func(context.Context) (intervention.ExitResult, error) {
				actions++
				return intervention.ExitResult{Observed: true}, nil
			})
			if !errors.Is(err, store.ErrOrgBudgetWitnessChanged) || actions != 0 {
				t.Fatalf("changed durable budget reached callback: actions=%d err=%v", actions, err)
			}
		})
	}
}

func TestNodeInterventionNilGuardClassifiesDurableBudgetState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withBudget bool
		malform    bool
		wantReason string
		present    bool
	}{
		{name: "missing", wantReason: "managed budget document is missing"},
		{name: "malformed", malform: true, wantReason: "managed budget document is malformed or unverified", present: true},
		{name: "unverified", withBudget: true, wantReason: "managed budget document is malformed or unverified", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, dbPath := writeManagedBudgetLaunchFixture(t, tc.withBudget, "enforce")
			rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "member-one" })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			database, err := db.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			if tc.malform {
				if _, err := database.ExecContext(ctx, `UPDATE org_budget_cache SET body_json = '{' WHERE id = 1`); err != nil {
					t.Fatal(err)
				}
			}
			st := store.New(database)
			cfg := config.Default()
			cfg.Guard.Enabled, cfg.Guard.Mode, cfg.Guard.Budget.FromOrg = true, "enforce", true
			w := intervention.Workload{SurfaceID: "fixture/cli", Identity: intervention.Identity{UID: 1000}}
			d, err := nodeInterventionBudget(ctx, st, cfg, nil, w, nodeInterventionSource{Tool: "fixture", Reason: "parse_error"}, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			// The durable-document classification is retained, and the
			// operator-facing cause of THIS stop - the missing guard itself -
			// is stated alongside it (accounting-readiness correction,
			// 2026-09-14).
			want := tc.wantReason + "; " + nodeInterventionGuardUnavailableReason
			if !d.Authorized || !d.Stop || d.RuleID != "B-625" || d.Reason != want ||
				!d.BudgetDocumentKnown || d.BudgetDocumentPresent != tc.present ||
				(tc.present && d.BudgetDocumentSHA256 == "") {
				t.Fatalf("nil-guard durable state=%+v, want reason %q", d, want)
			}
		})
	}
}
