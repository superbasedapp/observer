package api_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// portal_deletion_test.go covers the console's org deletion routes and the
// account deletion's org precheck (M6.9 / M7a.1) over a real PostgreSQL with
// the server on the least-privilege sbci_api role.

type orgDeletionView struct {
	Deletion *struct {
		RequestID string `json:"request_id"`
		State     string `json:"state"`
		Step      string `json:"step"`
		Origin    string `json:"origin"`
		CanCancel bool   `json:"can_cancel"`
	} `json:"deletion"`
	Preview struct {
		CanRequest     bool     `json:"can_request"`
		Refusal        string   `json:"refusal"`
		CoolingOffDays int      `json:"cooling_off_days"`
		Members        int      `json:"members"`
		Kept           []string `json:"kept"`
		Reauth         string   `json:"reauth"`
	} `json:"preview"`
}

func getDeletion(t *testing.T, c *portalClient, org string) orgDeletionView {
	t.Helper()
	resp := c.get("/portal/api/orgs/" + org + "/deletion")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get deletion status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var v orgDeletionView
	decode(t, resp, &v)
	return v
}

// TestPortalOrgDeletionRoutes walks an owner's request and cancel, and the
// refusals: a member, a slug that does not match, a second request, CSRF.
func TestPortalOrgDeletionRoutes(t *testing.T) {
	h := newOrgsHarness(t)
	ctx := context.Background()
	owner := h.portalLogin(t, "del-owner")
	member := h.portalLogin(t, "del-member")
	d := createTeam(t, owner, "Delco", "delco-team")
	org := d.Org.OrgID
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status = 'active', host_id = 'h1', lifecycle_gen = 1 WHERE org_id = $1::uuid`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, org, member.accountID); err != nil {
		t.Fatal(err)
	}
	path := "/portal/api/orgs/" + org + "/deletion"

	v := getDeletion(t, owner, org)
	if v.Deletion != nil || !v.Preview.CanRequest || v.Preview.CoolingOffDays != 14 || v.Preview.Members != 2 || len(v.Preview.Kept) == 0 || v.Preview.Reauth != "broker_token" {
		t.Fatalf("owner preview of a free, never-active team = %+v", v)
	}
	if mv := getDeletion(t, member, org); mv.Preview.CanRequest || mv.Preview.Refusal != "not_owner" {
		t.Fatalf("member preview = %+v", mv.Preview)
	}
	confirm := map[string]string{"confirm_slug": "delco-team", "broker_token": "dev:del-owner"}
	if resp := orgReq(t, member, "POST", path, confirm, member.csrf, ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "not_owner" {
		t.Fatalf("member request: want 403 not_owner, got %d", resp.StatusCode)
	}
	if resp := orgReq(t, owner, "POST", path, confirm, "", ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "csrf_failed" {
		t.Fatalf("no CSRF: want 403 csrf_failed, got %d", resp.StatusCode)
	}
	if resp := orgReq(t, owner, "POST", path, map[string]string{"confirm_slug": "nope"}, owner.csrf, ""); resp.StatusCode != http.StatusBadRequest || errCode(t, resp) != "confirm_mismatch" {
		t.Fatalf("wrong slug: want 400 confirm_mismatch, got %d", resp.StatusCode)
	}
	// FR-23: the dev sign-in's re-presented credential is the step-up: none,
	// or another account's, opens nothing.
	if resp := orgReq(t, owner, "POST", path, map[string]string{"confirm_slug": "delco-team"}, owner.csrf, ""); resp.StatusCode != http.StatusUnauthorized || errCode(t, resp) != "reauth_required" {
		t.Fatalf("no credential: want 401 reauth_required, got %d", resp.StatusCode)
	}
	if resp := orgReq(t, owner, "POST", path, map[string]string{"confirm_slug": "delco-team", "broker_token": "dev:del-member"}, owner.csrf, ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "reauth_mismatch" {
		t.Fatalf("another account's credential: want 403 reauth_mismatch, got %d", resp.StatusCode)
	}
	if v := getDeletion(t, owner, org); v.Deletion != nil {
		t.Fatalf("a refused step-up opened a deletion: %+v", v.Deletion)
	}
	resp := orgReq(t, owner, "POST", path, confirm, owner.csrf, "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("request status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	if resp := orgReq(t, owner, "POST", path, confirm, owner.csrf, ""); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "deletion_open" {
		t.Fatalf("second request: want 409 deletion_open, got %d", resp.StatusCode)
	}
	mv := getDeletion(t, member, org)
	if mv.Deletion == nil || mv.Deletion.State != "cooling_off" || mv.Deletion.CanCancel {
		t.Fatalf("member view of the open deletion = %+v", mv.Deletion)
	}
	ov := getDeletion(t, owner, org)
	if ov.Deletion == nil || !ov.Deletion.CanCancel || ov.Preview.Refusal != "deletion_open" {
		t.Fatalf("owner view = %+v", ov)
	}
	if resp := orgReq(t, member, "DELETE", path, nil, member.csrf, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member cancel status=%d", resp.StatusCode)
	}
	resp = orgReq(t, owner, "DELETE", path, nil, owner.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	if v := getDeletion(t, owner, org); v.Deletion == nil || v.Deletion.State != "canceled" || v.Deletion.CanCancel {
		t.Fatalf("after cancel = %+v", v.Deletion)
	}
	stranger := h.portalLogin(t, "del-stranger")
	if resp := stranger.get(path); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stranger read status=%d, want 404", resp.StatusCode)
	}
	// A purging deletion cannot be canceled.
	if _, err := h.pool.Exec(ctx, `UPDATE org_deletion_requests SET state = 'purging', step = 'await_host' WHERE org_id = $1::uuid`, org); err != nil {
		t.Fatal(err)
	}
	if resp := orgReq(t, owner, "DELETE", path, nil, owner.csrf, ""); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "not_cancellable" {
		t.Fatalf("cancel while purging: want 409 not_cancellable, got %d", resp.StatusCode)
	}
}

// TestPortalAccountDeletionPrecheck: the sole owner of a team is blocked, in
// the precheck and at the deletion route before any re-authentication; a
// plain member is not.
func TestPortalAccountDeletionPrecheck(t *testing.T) {
	h := newOrgsHarness(t)
	ctx := context.Background()
	owner := h.portalLogin(t, "pre-owner")
	member := h.portalLogin(t, "pre-member")
	d := createTeam(t, owner, "Preco", "preco-team")
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status = 'active' WHERE org_id = $1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`, d.Org.OrgID, member.accountID); err != nil {
		t.Fatal(err)
	}
	type precheck struct {
		CanDelete bool `json:"can_delete"`
		Blockers  []struct {
			Code  string `json:"code"`
			OrgID string `json:"org_id"`
			Slug  string `json:"slug"`
		} `json:"blockers"`
		MembershipsRemoved []struct {
			OrgID string `json:"org_id"`
		} `json:"memberships_removed"`
	}
	var p precheck
	resp := owner.get("/portal/api/account/deletion-precheck")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("precheck status=%d", resp.StatusCode)
	}
	decode(t, resp, &p)
	if p.CanDelete || len(p.Blockers) != 1 || p.Blockers[0].Code != "billing_owner" || p.Blockers[0].Slug != "preco-team" {
		t.Fatalf("owner precheck = %+v", p)
	}
	resp = orgReq(t, owner, "POST", "/portal/api/deletion-requests", map[string]string{}, owner.csrf, "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("owner deletion status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		Code     string `json:"code"`
		Blockers []struct {
			Code string `json:"code"`
		} `json:"blockers"`
	}
	decode(t, resp, &body)
	if body.Code != "account_deletion_blocked" || len(body.Blockers) != 1 {
		t.Fatalf("409 body = %+v", body)
	}
	resp = member.get("/portal/api/account/deletion-precheck")
	decode(t, resp, &p)
	if !p.CanDelete || len(p.MembershipsRemoved) != 1 || p.MembershipsRemoved[0].OrgID != d.Org.OrgID {
		t.Fatalf("member precheck = %+v", p)
	}
}

// TestPortalOrgDeletionRefusals (FR-11, FR-1): one row per refusal the
// preview and the request route share. A personal org is never deleted from
// the team route; a team with a live subscription is refused when this
// deployment cannot cancel it at Paddle (the harness has no Paddle API key),
// instead of blocking at cancel_billing after the window.
func TestPortalOrgDeletionRefusals(t *testing.T) {
	h := newOrgsHarness(t)
	ctx := context.Background()
	cases := []struct {
		name   string
		setup  func(owner *portalClient, org string)
		kind   string
		status int
		code   string
	}{
		{
			name: "a personal org", kind: "personal", status: http.StatusConflict, code: "personal_org",
		},
		{
			name: "a live subscription with no billing client", kind: "team", status: http.StatusConflict, code: "billing_cancel_unavailable",
			setup: func(owner *portalClient, org string) {
				if _, err := h.pool.Exec(ctx, `INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
					VALUES ($1::uuid, $2::uuid, 'ctm_1', 'sub_live_ref', 'team', 1, 'active')`, owner.accountID, org); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each case has its own owner, with no personal org of its own.
			subject := fmt.Sprintf("ref-owner-%d", i)
			owner := h.portalLogin(t, subject)
			slug := fmt.Sprintf("ref-team-%d", i)
			d := createTeam(t, owner, "Ref", slug)
			org := d.Org.OrgID
			if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status = 'active', host_id = 'h1', lifecycle_gen = 1 WHERE org_id = $1::uuid`, org); err != nil {
				t.Fatal(err)
			}
			if tc.kind == "personal" {
				// Turned into the account's personal org in place: the test
				// is about the deletion route, not how personal orgs start.
				if _, err := h.pool.Exec(ctx, `UPDATE orgs SET kind = 'personal', tenancy = 'individual' WHERE org_id = $1::uuid`, org); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup != nil {
				tc.setup(owner, org)
			}
			v := getDeletion(t, owner, org)
			if v.Preview.CanRequest || v.Preview.Refusal != tc.code {
				t.Fatalf("preview = %+v, want refusal %s", v.Preview, tc.code)
			}
			body := map[string]string{"confirm_slug": slug, "broker_token": "dev:" + subject}
			resp := orgReq(t, owner, "POST", "/portal/api/orgs/"+org+"/deletion", body, owner.csrf, "")
			if resp.StatusCode != tc.status || errCode(t, resp) != tc.code {
				t.Fatalf("request: want %d %s, got %d", tc.status, tc.code, resp.StatusCode)
			}
			if v := getDeletion(t, owner, org); v.Deletion != nil {
				t.Fatal("a refused request opened a deletion")
			}
		})
	}
}
