package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_trialoffer_test.go covers the returning customer once trials are
// on (fu/billing-trial, after FR-10): the checkout offers a scope that has
// had its trial the plan's trial-less sibling price, chosen by the server
// from paddle_trial_uses, never by the browser; the intent records that
// price (FR-2's cross-check); the billing view stops advertising a trial to
// that scope; and the webhook binds the trial-less price to the plan.

const (
	offerPricePlusNoTrial = "pri_test_plus_notrial"
	offerPriceTeamNoTrial = "pri_test_team_notrial"
)

// offerHarness is newOrgsHarnessWith with trialDays advertised and, when
// siblings, a trial-less sibling for both the Plus and the Team price.
func offerHarness(t *testing.T, trialDays int, siblings bool) orgsHarness {
	t.Helper()
	return newOrgsHarnessWith(t, func(o *api.Options) {
		o.PaddleCheckout.TrialDays = trialDays
		env := ""
		if siblings {
			env = orgsPricePlus + "=" + offerPricePlusNoTrial + "," + orgsPriceTeam + "=" + offerPriceTeamNoTrial
		}
		pm, err := store.WithPaddleNoTrialPrices(map[string]store.PaddlePlan{
			orgsPricePlus: {Name: "plus_beta", Version: 1, Interval: "month"},
			orgsPriceTeam: {Name: "team", Version: 1, Interval: "month", Display: "$12/seat"},
		}, env)
		if err != nil {
			t.Fatal(err)
		}
		o.Store.SetPaddlePriceMap(pm)
	})
}

type offerBillingView struct {
	Checkout struct {
		Prices []struct {
			PriceID string `json:"price_id"`
		} `json:"prices"`
		TrialDays int  `json:"trial_days"`
		TrialUsed bool `json:"trial_used"`
	} `json:"checkout"`
}

// TestCheckoutOfferByTrialUse: one row per (path, trial on/off, trial
// used/unused, sibling configured or not, price the browser names).
func TestCheckoutOfferByTrialUse(t *testing.T) {
	type row struct {
		name      string
		org       bool
		trialDays int
		used      bool
		siblings  bool
		request   string // "" = the scope's catalogue price
		status    int
		price     string // the price offered and recorded on the intent
		viewTrial int
		viewUsed  bool
	}
	var rows []row
	for _, org := range []bool{false, true} {
		cat, nt, scope := orgsPricePlus, offerPricePlusNoTrial, "account"
		if org {
			cat, nt, scope = orgsPriceTeam, offerPriceTeamNoTrial, "org"
		}
		rows = append(
			rows,
			row{scope + ": trial off, unused, sibling", org, 0, false, true, "", 200, cat, 0, false},
			row{scope + ": trial off, used, sibling", org, 0, true, true, "", 200, cat, 0, false},
			row{scope + ": trial off, used, no sibling", org, 0, true, false, "", 200, cat, 0, false},
			row{scope + ": trial on, unused, sibling", org, 7, false, true, "", 200, cat, 7, false},
			row{scope + ": trial on, unused, no sibling", org, 7, false, false, "", 200, cat, 7, false},
			row{scope + ": trial on, used, sibling: pays from day one", org, 7, true, true, "", 200, nt, 0, true},
			row{scope + ": trial on, used, no sibling: refused", org, 7, true, false, "", http.StatusConflict, "", 0, true},
			row{scope + ": browser names the sibling, trial unused: the catalogue price", org, 7, false, true, nt, 200, cat, 7, false},
			row{scope + ": browser names the sibling, trial off: the catalogue price", org, 0, false, true, nt, 200, cat, 0, false},
			row{scope + ": browser names the catalogue price, trial used: the sibling", org, 7, true, true, cat, 200, nt, 0, true},
		)
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			h := offerHarness(t, c.trialDays, c.siblings)
			cl := h.portalLogin(t, "offer-buyer")
			ctx := context.Background()
			billingPath, checkoutPath, catalogue := "/portal/api/billing", "/portal/api/billing/checkout", orgsPricePlus
			orgID := ""
			if c.org {
				d := createTeam(t, cl, "Offer", "offer-team")
				orgID = d.Org.OrgID
				if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, orgID); err != nil {
					t.Fatal(err)
				}
				billingPath = "/portal/api/orgs/" + orgID + "/billing"
				checkoutPath, catalogue = billingPath+"/checkout", orgsPriceTeam
			}
			if c.used {
				var orgArg any
				if orgID != "" {
					orgArg = orgID
				}
				if _, err := h.pool.Exec(ctx,
					`INSERT INTO paddle_trial_uses (account_id, org_id, paddle_subscription_id, first_trial_at) VALUES ($1::uuid, $2::uuid, 'sub_first', now())`,
					cl.accountID, orgArg); err != nil {
					t.Fatal(err)
				}
			}
			var bv offerBillingView
			decode(t, cl.get(billingPath), &bv)
			if bv.Checkout.TrialDays != c.viewTrial || bv.Checkout.TrialUsed != c.viewUsed {
				t.Errorf("billing view trial_days=%d trial_used=%v, want %d %v", bv.Checkout.TrialDays, bv.Checkout.TrialUsed, c.viewTrial, c.viewUsed)
			}
			if len(bv.Checkout.Prices) != 1 || bv.Checkout.Prices[0].PriceID != catalogue {
				t.Errorf("billing view prices = %+v, want only %s (a sibling is never listed)", bv.Checkout.Prices, catalogue)
			}

			req := c.request
			if req == "" {
				req = catalogue
			}
			resp := orgReq(t, cl, "POST", checkoutPath, map[string]string{"price_id": req}, cl.csrf, "")
			if resp.StatusCode != c.status {
				t.Fatalf("checkout status=%d body=%s, want %d", resp.StatusCode, readAll(resp), c.status)
			}
			if c.status != http.StatusOK {
				if code := errCode(t, resp); code != "trial_already_used" {
					t.Fatalf("code = %q, want trial_already_used", code)
				}
				var n int
				if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM checkout_intents WHERE account_id=$1::uuid`, cl.accountID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("intents after a refusal = %d err=%v, want 0", n, err)
				}
				return
			}
			var intent struct {
				PriceID string `json:"price_id"`
			}
			decode(t, resp, &intent)
			if intent.PriceID != c.price {
				t.Errorf("offered price = %q, want %q", intent.PriceID, c.price)
			}
			var recorded string
			if err := h.pool.QueryRow(ctx, `SELECT price_id FROM checkout_intents WHERE account_id=$1::uuid ORDER BY created_at DESC LIMIT 1`, cl.accountID).Scan(&recorded); err != nil || recorded != c.price {
				t.Errorf("intent price = %q err=%v, want %q (FR-2 cross-checks the price actually offered)", recorded, err, c.price)
			}
		})
	}
}

// TestReturningCustomerBuysTrialLessEndToEnd: an account that has had its
// trial checks out, is offered the trial-less price, and Paddle's webhook
// for that price binds the subscription to the paid plan.
func TestReturningCustomerBuysTrialLessEndToEnd(t *testing.T) {
	h := offerHarness(t, 7, true)
	cl := h.portalLogin(t, "offer-returning")
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO paddle_trial_uses (account_id, paddle_subscription_id, first_trial_at) VALUES ($1::uuid, 'sub_first', now())`,
		cl.accountID); err != nil {
		t.Fatal(err)
	}
	resp := orgReq(t, cl, "POST", "/portal/api/billing/checkout", map[string]string{"price_id": orgsPricePlus}, cl.csrf, "")
	var intent struct {
		PriceID    string            `json:"price_id"`
		CustomData map[string]string `json:"custom_data"`
	}
	decode(t, resp, &intent)
	if intent.PriceID != offerPricePlusNoTrial {
		t.Fatalf("offered %q, want the trial-less price", intent.PriceID)
	}
	now := time.Now().UTC()
	body := []byte(`{
		"event_id": "evt_nt_1", "event_type": "subscription.activated", "occurred_at": "` + now.Format(time.RFC3339) + `",
		"data": {
			"id": "sub_nt_e2e", "customer_id": "ctm_nt", "status": "active",
			"custom_data": {"account_id": "` + cl.accountID + `", "checkout_nonce": "` + intent.CustomData["checkout_nonce"] + `"},
			"items": [{"quantity": 1, "price": {"id": "` + offerPricePlusNoTrial + `"}}],
			"current_billing_period": {"starts_at": "` + now.Format(time.RFC3339) + `", "ends_at": "` + now.AddDate(0, 1, 0).Format(time.RFC3339) + `"}
		}
	}`)
	if r := signedPaddle(t, h.srv.URL, body, now, paddleSecret); r.StatusCode != http.StatusOK {
		t.Fatalf("webhook status=%d body=%s", r.StatusCode, readAll(r))
	}
	sub, err := h.store.AccountSubscription(ctx, cl.accountID)
	if err != nil || sub.PlanName != "plus_beta" || sub.Status != "active" {
		t.Fatalf("subscription = %+v err=%v, want plus_beta active (no trial)", sub, err)
	}
}
