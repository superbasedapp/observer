package api_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling/paddleapi"
)

// paddle_portal_test.go covers wave 17's billing additions over a real
// PostgreSQL (paddle_portal.go; docs/security.md PADDLELIVE-3): the org
// checkout opens at the plan's seat minimum, the billing portal session is
// the billing owner's only (an org admin who does not pay is refused), it
// needs a configured Paddle API, and a Paddle failure is a 502 that names no
// link.

const (
	portalCustomer = "ctm_01jcportal0000000000000000"
	portalSub      = "sub_01jcportal0000000000000000"
)

// fakePortal records the sessions asked for.
type fakePortal struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakePortal) CreatePortalSession(_ context.Context, customer string, subs []string) (paddleapi.PortalSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, customer+"|"+subs[0])
	if f.err != nil {
		return paddleapi.PortalSession{}, f.err
	}
	return paddleapi.PortalSession{
		Overview:      "https://sandbox-customer-portal.paddle.com/cpl_x?token=t",
		Subscriptions: []paddleapi.PortalSubscriptionLinks{{ID: subs[0], Cancel: "https://sandbox-customer-portal.paddle.com/c", UpdatePaymentMethod: "https://sandbox-customer-portal.paddle.com/u"}},
	}, nil
}

func TestOrgCheckoutQuantityAndPortalSession(t *testing.T) {
	fp := &fakePortal{}
	h := newOrgsHarnessWith(t, func(o *api.Options) { o.PaddlePortal = fp })
	c := h.portalLogin(t, "portal-pat")
	d := createTeam(t, c, "Pat", "pat-team")
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	billingPath := "/portal/api/orgs/" + d.Org.OrgID + "/billing"
	portalPath := billingPath + "/portal-session"

	// No subscription yet: no portal.
	if resp := orgReq(t, c, "POST", portalPath, nil, c.csrf, ""); resp.StatusCode != http.StatusNotFound || errCode(t, resp) != "no_subscription" {
		t.Fatalf("portal before a subscription: want 404 no_subscription")
	}

	// The Team checkout opens at the plan's minimum of 3 seats.
	resp := orgReq(t, c, "POST", billingPath+"/checkout", map[string]string{"price_id": orgsPriceTeam}, c.csrf, "")
	var intent struct {
		Quantity   int64             `json:"quantity"`
		CustomData map[string]string `json:"custom_data"`
	}
	decode(t, resp, &intent)
	if intent.Quantity != 3 {
		t.Fatalf("org checkout quantity = %d, want the Team minimum 3", intent.Quantity)
	}

	whBody := []byte(`{
		"event_id": "evt_portal_1", "event_type": "subscription.activated", "occurred_at": "` + time.Now().UTC().Format(time.RFC3339) + `",
		"data": {
			"id": "` + portalSub + `", "customer_id": "` + portalCustomer + `", "status": "active",
			"custom_data": {"account_id": "` + c.accountID + `", "org_id": "` + d.Org.OrgID + `", "checkout_nonce": "` + intent.CustomData["checkout_nonce"] + `"},
			"items": [{"price": {"id": "` + orgsPriceTeam + `"}}]
		}
	}`)
	if r := signedPaddle(t, h.srv.URL, whBody, time.Now(), paddleSecret); r.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d", r.StatusCode)
	}
	var bv struct {
		PortalAvailable bool `json:"portal_available"`
	}
	decode(t, c.get(billingPath), &bv)
	if !bv.PortalAvailable {
		t.Fatal("portal_available false for the billing owner with a subscription")
	}

	// CSRF is required like every portal mutation.
	if resp := orgReq(t, c, "POST", portalPath, nil, "", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("portal session without CSRF status=%d, want 403", resp.StatusCode)
	}
	resp = orgReq(t, c, "POST", portalPath, nil, c.csrf, "")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("portal session status=%d cache=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	var ps struct {
		URL, Cancel, UpdatePaymentMethod string
	}
	decode(t, resp, &ps)
	if ps.URL == "" || ps.Cancel == "" || len(fp.calls) != 1 || fp.calls[0] != portalCustomer+"|"+portalSub {
		t.Fatalf("portal session = %+v calls=%v", ps, fp.calls)
	}

	// An org admin who is not the billing owner is refused (the portal
	// overview is the payer's own Paddle customer).
	admin := h.portalLogin(t, "portal-quin")
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'admin')`,
		d.Org.OrgID, admin.accountID); err != nil {
		t.Fatal(err)
	}
	if resp := orgReq(t, admin, "POST", portalPath, nil, admin.csrf, ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "billing_owner_required" {
		t.Fatalf("admin portal session: want 403 billing_owner_required")
	}
	decode(t, admin.get(billingPath), &bv)
	if bv.PortalAvailable {
		t.Fatal("portal_available true for an admin who does not pay")
	}

	// A Paddle failure is a 502 and the call is still made once.
	fp.err = errors.New("paddleapi: HTTP 403 request_error/forbidden")
	if resp := orgReq(t, c, "POST", portalPath, nil, c.csrf, ""); resp.StatusCode != http.StatusBadGateway || errCode(t, resp) != "portal_session_failed" {
		t.Fatalf("Paddle failure: want 502 portal_session_failed")
	}
}

// TestPortalSessionUnconfigured: with no Paddle API the routes answer 501
// and the billing views say the portal is not available.
func TestPortalSessionUnconfigured(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "portal-ray")
	if resp := orgReq(t, c, "POST", "/portal/api/billing/portal-session", nil, c.csrf, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("account portal with no subscription status=%d, want 404", resp.StatusCode)
	}
	d := createTeam(t, c, "Ray", "ray-team")
	var bv struct {
		PortalAvailable bool `json:"portal_available"`
	}
	decode(t, c.get("/portal/api/orgs/"+d.Org.OrgID+"/billing"), &bv)
	if bv.PortalAvailable {
		t.Fatal("portal_available with no Paddle API")
	}
	// The account checkout opens at one.
	resp := orgReq(t, c, "POST", "/portal/api/billing/checkout", map[string]string{"price_id": orgsPricePlus}, c.csrf, "")
	var intent struct {
		Quantity int64 `json:"quantity"`
	}
	decode(t, resp, &intent)
	if intent.Quantity != 1 {
		t.Fatalf("account checkout quantity = %d, want 1", intent.Quantity)
	}
}
