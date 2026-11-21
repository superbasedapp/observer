package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// TestGrantPlanOrgVerbs drives `grant-plan org` (W15-D13) and
// `grant-plan team-orgs` (W15-D12) through their run functions against a
// real PostgreSQL, with the roles the verbs use: the operator store
// (sbci_app) writes, the worker store reads the org's kind, and the worker's
// plan source then puts the org on the granted plan after its launch window.
func TestGrantPlanOrgVerbs(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	app, err := store.NewForRole(pool, store.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	org, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: "internal-w15", DisplayName: "Internal", Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)

	// Required flags.
	var out bytes.Buffer
	for name, req := range map[string]orgGrantRequest{
		"no org":    {Plan: "team", Reason: "x"},
		"no plan":   {OrgID: org.OrgID, Reason: "x"},
		"no reason": {OrgID: org.OrgID, Plan: "team"},
		"bad until": {OrgID: org.OrgID, Plan: "team", Reason: "x", Until: "tomorrow"},
	} {
		if err := runOrgGrant(ctx, &out, worker, app, req, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := runOrgGrant(ctx, &out, worker, app, orgGrantRequest{OrgID: "00000000-0000-4000-8000-000000000009", Plan: "team", Reason: "x"}, now); err == nil || !strings.Contains(err.Error(), "no org") {
		t.Errorf("unknown org: %v", err)
	}
	if err := runOrgGrant(ctx, &out, worker, app, orgGrantRequest{OrgID: org.OrgID, Plan: "plus_beta", Reason: "x"}, now); err == nil {
		t.Error("an account plan was granted to a team org")
	}

	out.Reset()
	if err := runOrgGrant(ctx, &out, worker, app, orgGrantRequest{OrgID: org.OrgID, Plan: "team", Reason: "internal org for the acceptance test"}, now); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if s := out.String(); !strings.Contains(s, "granted plan team v1 with no end") || !strings.Contains(s, "was no grant") {
		t.Fatalf("grant output = %q", s)
	}

	// The worker's plan source keeps the org on the plan after its launch
	// window (the org's create was "acked" 30 days ago here).
	view := store.OrgEntitlementView{OrgID: org.OrgID, Kind: store.OrgTeam, Status: "active", CreatedOnHostAt: now.AddDate(0, 0, -30)}
	pl, rule, err := entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return now }}.Resolve(ctx, view, entitlements.KindTeam)
	if err != nil || rule != "org_grant" || pl.Name != "team" || pl.NotAfter != 0 {
		t.Fatalf("plan after the window = %+v %q %v, want the team grant", pl, rule, err)
	}

	out.Reset()
	if err := runOrgGrantShow(ctx, &out, app, org.OrgID, now); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "in force: team v1 with no end") || !strings.Contains(s, "by operator: internal org for the acceptance test") {
		t.Fatalf("show output = %q", s)
	}

	out.Reset()
	if err := runOrgRevoke(ctx, &out, app, org.OrgID, "", now); err == nil {
		t.Error("a revoke without a reason was accepted")
	}
	if err := runOrgRevoke(ctx, &out, app, org.OrgID, "test over", now.Add(time.Second)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := runOrgRevoke(ctx, &out, app, org.OrgID, "again", now.Add(2*time.Second)); err == nil || !strings.Contains(err.Error(), "no plan grant in force") {
		t.Fatalf("second revoke: %v", err)
	}
	if _, rule, _ := (entitlementwork.SubscriptionPlans{Subs: worker, Now: func() time.Time { return now.Add(3 * time.Second) }}).Resolve(ctx, view, entitlements.KindTeam); rule != "floor" {
		t.Fatalf("after the revoke rule = %q, want floor", rule)
	}

	// team-orgs.
	out.Reset()
	if err := runTeamOrgLimitShow(ctx, &out, app, owner); err != nil || !strings.Contains(out.String(), "default cap of 3") {
		t.Fatalf("show default = %q, %v", out.String(), err)
	}
	if err := runTeamOrgLimit(ctx, &out, app, owner, -1, "x", now); err == nil {
		t.Error("no --max was accepted")
	}
	if err := runTeamOrgLimit(ctx, &out, app, owner, 5, "", now); err == nil {
		t.Error("no --reason was accepted")
	}
	out.Reset()
	if err := runTeamOrgLimit(ctx, &out, app, owner, 5, "customer asked for five", now); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "may hold 5 team orgs (was 3 (the default))") {
		t.Fatalf("team-orgs output = %q", s)
	}
	if a, err := api.TeamOrgAllowance(ctx, owner); err != nil || a.Limit != 5 || a.Used != 1 {
		t.Fatalf("allowance = %+v, %v", a, err)
	}
	out.Reset()
	if err := runTeamOrgLimitShow(ctx, &out, app, owner); err != nil || !strings.Contains(out.String(), "set 5  by operator: customer asked for five") {
		t.Fatalf("show = %q, %v", out.String(), err)
	}
	if err := runTeamOrgLimit(ctx, &out, app, "00000000-0000-4000-8000-000000000009", 5, "x", now); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("unknown account: %v", err)
	}
}

// TestGrantPlanHasOrgAndTeamOrgsVerbs: the two verbs hang off grant-plan, so
// main.go's command list is unchanged.
func TestGrantPlanHasOrgAndTeamOrgsVerbs(t *testing.T) {
	t.Parallel()
	cmd := newGrantPlanCmd()
	for _, path := range [][]string{{"org"}, {"org", "revoke"}, {"org", "show"}, {"team-orgs"}, {"team-orgs", "show"}} {
		c, rest, err := cmd.Find(path)
		if err != nil || len(rest) != 0 || c.Name() != path[len(path)-1] {
			t.Errorf("grant-plan %v: found %v rest %v err %v", path, c.Name(), rest, err)
		}
	}
}
