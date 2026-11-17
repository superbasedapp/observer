package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// portal_orgs_w15_test.go covers the wave 15 console fixes over a real
// PostgreSQL with the server bound to sbci_api: the team cap's 409 and the
// list's team_orgs (W15-D12), the account deletion refused while the account
// pays for a live org on both deletion routes (C2.front-door-5 A), and the
// console plan view naming an operator grant (W15-D13).

type orgsListView struct {
	Orgs []struct {
		OrgID           string `json:"org_id"`
		Kind            string `json:"kind"`
		MachinesPageURL string `json:"machines_page_url"`
	} `json:"orgs"`
	TeamOrgs *struct {
		Used      int `json:"used"`
		Limit     int `json:"limit"`
		Remaining int `json:"remaining"`
	} `json:"team_orgs"`
}

func listOrgsView(t *testing.T, c *portalClient) orgsListView {
	t.Helper()
	resp := c.get("/portal/api/orgs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list orgs status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var v orgsListView
	decode(t, resp, &v)
	return v
}

func TestPortalTeamOrgCap(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "cap-carol")

	if v := listOrgsView(t, c); v.TeamOrgs == nil || v.TeamOrgs.Used != 0 || v.TeamOrgs.Limit != 3 || v.TeamOrgs.Remaining != 3 {
		t.Fatalf("fresh account team_orgs = %+v", v.TeamOrgs)
	}
	for _, slug := range []string{"carol-a", "carol-b", "carol-c"} {
		createTeam(t, c, "Carol "+slug, slug)
	}
	if v := listOrgsView(t, c); v.TeamOrgs == nil || v.TeamOrgs.Used != 3 || v.TeamOrgs.Remaining != 0 {
		t.Fatalf("at the cap team_orgs = %+v", v.TeamOrgs)
	}

	resp := orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": "Carol D", "slug": "carol-d"}, c.csrf, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("fourth create status=%d body=%s, want 409", resp.StatusCode, readAll(resp))
	}
	var e struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	decode(t, resp, &e)
	if e.Code != "team_org_limit" || !strings.Contains(e.Error, "3 team orgs") || !strings.Contains(e.Error, "raise this on request") {
		t.Fatalf("fourth create = %+v, want team_org_limit naming the cap and the raise", e)
	}
	// A repeat of the third create (a double submit) still answers the org it
	// made, not the cap.
	resp = orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": "Carol carol-c", "slug": "carol-c"}, c.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replayed third create status=%d body=%s, want 200", resp.StatusCode, readAll(resp))
	}
	var d orgDetail
	decode(t, resp, &d)
	if !d.Replayed || d.Org.Slug != "carol-c" {
		t.Fatalf("replay = %+v", d)
	}

	// Raised on request (the operator's CLI path): one more goes through.
	if _, err := h.store.SetTeamOrgLimit(context.Background(), c.accountID, 4, "customer asked", time.Now()); err != nil {
		t.Fatal(err)
	}
	createTeam(t, c, "Carol D", "carol-d")
	if v := listOrgsView(t, c); v.TeamOrgs == nil || v.TeamOrgs.Used != 4 || v.TeamOrgs.Limit != 4 || v.TeamOrgs.Remaining != 0 {
		t.Fatalf("after the raise team_orgs = %+v", v.TeamOrgs)
	}
}

func TestPortalOrgListLinksEachTeamsMachinesPage(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "links-lee")
	active := createTeam(t, c, "Lee", "lee-team")
	createTeam(t, c, "Lee Two", "lee-two")
	if _, err := h.pool.Exec(context.Background(), `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, active.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	for _, o := range listOrgsView(t, c).Orgs {
		want := ""
		if o.OrgID == active.Org.OrgID {
			want = "https://lee-team.example.test/me/profile"
		}
		if o.MachinesPageURL != want {
			t.Errorf("org %s machines_page_url = %q, want %q", o.OrgID, o.MachinesPageURL, want)
		}
	}
}

// payForOrg gives the account a live org-scoped subscription for org (the
// webhook's binding is proven in the store and checkout tests).
func payForOrg(t *testing.T, h orgsHarness, account, org, status string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		 VALUES ($1::uuid, $2::uuid, 'ctm_w15', 'sub_w15_'||substr(md5($2::text), 1, 8), 'team', 1, $3)`, account, org, status); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
}

func TestPortalDeletionRefusedWhilePayingForLiveOrg(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "pay-pat")
	d := createTeam(t, c, "Pat's Team", "pat-team")
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	payForOrg(t, h, c.accountID, d.Org.OrgID, "active")

	resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:pay-pat"}`), c.csrf)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deletion while paying status=%d body=%s, want 409", resp.StatusCode, readAll(resp))
	}
	var refusal struct {
		Code  string `json:"code"`
		Error string `json:"error"`
		Orgs  []struct {
			OrgID       string `json:"org_id"`
			Slug        string `json:"slug"`
			DisplayName string `json:"display_name"`
		} `json:"orgs"`
	}
	decode(t, resp, &refusal)
	if refusal.Code != "pays_for_live_org" || len(refusal.Orgs) != 1 || refusal.Orgs[0].OrgID != d.Org.OrgID ||
		refusal.Orgs[0].DisplayName != "Pat's Team" || !strings.Contains(refusal.Error, "Pat's Team") ||
		!strings.Contains(refusal.Error, "cannot be deleted yet") {
		t.Fatalf("refusal = %+v", refusal)
	}
	// The session survives a refused deletion; the device route refuses too.
	if resp := c.get("/portal/api/orgs"); resp.StatusCode != http.StatusOK {
		t.Fatalf("session after the refusal status=%d", resp.StatusCode)
	}
	dev := h.login(t, "pay-pat")
	if resp := dev.do(dev.signedReq("POST", "/v1/deletion-requests", []byte("{}"))); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "pays_for_live_org" {
		t.Fatalf("device deletion while paying status=%d, want 409 pays_for_live_org", resp.StatusCode)
	}
	var status string
	if err := h.pool.QueryRow(ctx, `SELECT status FROM accounts WHERE account_id=$1::uuid`, c.accountID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("account status after the refusals = %q, %v", status, err)
	}

	// The subscription ends: the account is still the team's only owner and
	// billing owner (M6.9), so it is refused again, now naming the team.
	if _, err := h.pool.Exec(ctx, `UPDATE paddle_subscriptions SET status='canceled' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	if resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:pay-pat"}`), c.csrf); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "account_deletion_blocked" {
		t.Fatalf("deletion of the team's only owner after the cancel status=%d, want 409 account_deletion_blocked", resp.StatusCode)
	}
	// Once the team is on its way out the deletion goes through.
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='pending_deletion' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	if resp := c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:pay-pat"}`), c.csrf); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("deletion after the cancel status=%d body=%s, want 202", resp.StatusCode, readAll(resp))
	}
}

func TestPortalOrgPlanShowsOperatorGrant(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "grant-gil")
	d := createTeam(t, c, "Gil", "gil-team")
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	if got := getOrgDetail(t, c, d.Org.OrgID); got.Plan == nil || got.Plan.Source != "floor" {
		t.Fatalf("plan before the grant = %+v, want the floor", got.Plan)
	}
	until := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, _, err := h.store.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: d.Org.OrgID, Kind: store.OrgTeam, Plan: "business", Until: until, Reason: "internal org",
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := getOrgDetail(t, c, d.Org.OrgID)
	if got.Plan == nil || got.Plan.Source != "org_grant" || got.Plan.Name != "business" || got.Plan.NotAfter != until.Format(time.RFC3339) {
		t.Fatalf("plan with the grant = %+v, want business from org_grant until %s", got.Plan, until.Format(time.RFC3339))
	}
}
