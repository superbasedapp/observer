package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
)

// portal_deletion_billing_test.go is ORGDEL-7 at the console and device
// routes: an account deletion with a live account-scope subscription cancels
// it at Paddle first (a fake of the orgdeletion.Billing seam; no Paddle
// call), and each way the cancellation can fail answers its own refusal
// with nothing deleted.

// apiFakeBilling is an orgdeletion.Billing that records the subscriptions it
// was asked to cancel and answers fail.
type apiFakeBilling struct {
	mu    sync.Mutex
	subs  []string
	fail  error
	calls int
}

func (f *apiFakeBilling) CancelOrgSubscription(_ context.Context, req orgdeletion.CancelRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail != nil {
		return f.fail
	}
	f.subs = append(f.subs, req.SubscriptionID)
	return nil
}

// payForAccount gives the account a live account-scope (org_id NULL)
// subscription.
func payForAccount(t *testing.T, h orgsHarness, account, sub string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO paddle_subscriptions (account_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		 VALUES ($1::uuid, 'ctm_o7', $2, 'plus_beta', 1, 'active')`, account, sub); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
}

func TestPortalDeletionCancelsAccountSubscription(t *testing.T) {
	cases := []struct {
		name string
		// wire: the billing seam is wired (false: this deployment has none).
		wire       bool
		fail       error
		status     int
		code       string
		retryAfter string
		msg        string
	}{
		{name: "no billing seam: refused up front", status: http.StatusConflict, code: "billing_cancel_unavailable", msg: "billing page"},
		{
			name: "paddle unreachable", wire: true, fail: orgdeletion.Classed("billing:cancel:transport", errors.New("dial: timeout")),
			status: http.StatusServiceUnavailable, code: "billing_cancel_failed", retryAfter: "60", msg: "Try again",
		},
		{
			name: "paddle refuses", wire: true, fail: orgdeletion.Classed("billing:cancel:http_403", fmt.Errorf("%w: forbidden", orgdeletion.ErrBillingRefused)),
			status: http.StatusConflict, code: "billing_cancel_refused", msg: "contact support",
		},
		{name: "canceled, then deleted", wire: true, status: http.StatusAccepted},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &apiFakeBilling{fail: tc.fail}
			h := newOrgsHarnessWith(t, func(o *api.Options) {
				if tc.wire {
					o.Store.SetDeletionBilling(fake)
				}
			})
			user := fmt.Sprintf("o7-user-%d", i)
			c := h.portalLogin(t, user)
			payForAccount(t, h, c.accountID, "sub_o7")

			// The precheck names the cancellation and whether it can run.
			var pre struct {
				CanDelete              bool `json:"can_delete"`
				SubscriptionsCanceled  int  `json:"subscriptions_canceled"`
				BillingCancelAvailable bool `json:"billing_cancel_available"`
			}
			resp := c.get("/portal/api/account/deletion-precheck")
			decode(t, resp, &pre)
			if !pre.CanDelete || pre.SubscriptionsCanceled != 1 || pre.BillingCancelAvailable != tc.wire {
				t.Fatalf("precheck = %+v", pre)
			}

			resp = c.mutate("POST", "/portal/api/deletion-requests", []byte(`{"broker_token":"dev:`+user+`"}`), c.csrf)
			if resp.StatusCode != tc.status {
				t.Fatalf("deletion status=%d body=%s, want %d", resp.StatusCode, readAll(resp), tc.status)
			}
			var status string
			if err := h.pool.QueryRow(context.Background(), `SELECT status FROM accounts WHERE account_id=$1::uuid`, c.accountID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusAccepted {
				if status != "deleted" || len(fake.subs) != 1 || fake.subs[0] != "sub_o7" {
					t.Fatalf("after the deletion: status %q, canceled %v", status, fake.subs)
				}
				return
			}
			if got := resp.Header.Get("Retry-After"); got != tc.retryAfter {
				t.Fatalf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			var body struct {
				Code  string `json:"code"`
				Error string `json:"error"`
			}
			decode(t, resp, &body)
			if body.Code != tc.code || !strings.Contains(body.Error, "nothing was deleted") || !strings.Contains(body.Error, tc.msg) {
				t.Fatalf("refusal = %+v", body)
			}
			if status != "active" || len(fake.subs) != 0 {
				t.Fatalf("after the refusal: status %q, canceled %v", status, fake.subs)
			}
			if n := countRows(t, h, `SELECT count(*) FROM paddle_subscriptions WHERE account_id=$1::uuid`, c.accountID); n != 1 {
				t.Fatalf("%d subscription rows after the refusal", n)
			}
			if n := countRows(t, h, `SELECT count(*) FROM security_audit_events WHERE account_id=$1::uuid AND event_type='deletion_refused_billing_cancel'`, c.accountID); n != 1 {
				t.Fatalf("%d refusal audit rows, want 1", n)
			}
			// The session survives; the device route answers the same.
			if resp := c.get("/portal/api/orgs"); resp.StatusCode != http.StatusOK {
				t.Fatalf("session after the refusal status=%d", resp.StatusCode)
			}
			dev := h.login(t, user)
			if resp := dev.do(dev.signedReq("POST", "/v1/deletion-requests", []byte("{}"))); resp.StatusCode != tc.status || errCode(t, resp) != tc.code {
				t.Fatalf("device deletion status=%d, want %d %s", resp.StatusCode, tc.status, tc.code)
			}
		})
	}
}
