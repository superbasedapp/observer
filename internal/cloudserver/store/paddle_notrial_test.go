package store_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// paddle_notrial_test.go covers the trial-less sibling prices
// (fu/billing-trial, after FR-10): the SBCI_PADDLE_NO_TRIAL_PRICES parser,
// the lookups the checkout uses, and the webhook binding a subscription on
// either price of a plan, on the account and the org path, with FR-2's
// intent price cross-check still in force.

const (
	testPriceNoTrial        = "pri_test_plus_notrial"
	orgTestPriceTeamNoTrial = "pri_test_team_notrial"
)

func TestWithPaddleNoTrialPrices(t *testing.T) {
	t.Parallel()
	catalogue := map[string]store.PaddlePlan{
		"pri_pro":  {Name: "plus_beta", Version: 5, Interval: "month", Display: "$9/month"},
		"pri_team": {Name: "team", Version: 1, Interval: "month"},
	}
	cases := []struct {
		name    string
		env     string
		want    map[string]store.PaddlePlan // nil: want the catalogue unchanged
		wantErr string
	}{
		{name: "unset: the catalogue unchanged", env: ""},
		{name: "blank entries skipped", env: " , ,"},
		{
			name: "one sibling inherits its primary's plan", env: "pri_pro=pri_pro_nt",
			want: map[string]store.PaddlePlan{
				"pri_pro_nt": {Name: "plus_beta", Version: 5, Interval: "month", Display: "$9/month", NoTrialOf: "pri_pro"},
			},
		},
		{
			name: "two siblings, spaces trimmed", env: " pri_pro = pri_pro_nt , pri_team=pri_team_nt ",
			want: map[string]store.PaddlePlan{
				"pri_pro_nt":  {Name: "plus_beta", Version: 5, Interval: "month", Display: "$9/month", NoTrialOf: "pri_pro"},
				"pri_team_nt": {Name: "team", Version: 1, Interval: "month", NoTrialOf: "pri_team"},
			},
		},
		{name: "no equals sign", env: "pri_pro", wantErr: "malformed entry"},
		{name: "empty sibling", env: "pri_pro=", wantErr: "malformed entry"},
		{name: "empty primary", env: "=pri_x", wantErr: "malformed entry"},
		{name: "a plan spec instead of a price id", env: "pri_pro=pri_x:plus_beta:5:month", wantErr: "bare price id"},
		{name: "primary not in the catalogue", env: "pri_nope=pri_x", wantErr: "not a price in SBCI_PADDLE_PRICES"},
		{name: "sibling equal to its primary", env: "pri_pro=pri_pro", wantErr: "maps to itself"},
		{name: "sibling listed in the catalogue", env: "pri_pro=pri_team", wantErr: "is listed in SBCI_PADDLE_PRICES"},
		{name: "primary given twice", env: "pri_pro=pri_a,pri_pro=pri_b", wantErr: "given twice"},
		{name: "one sibling for two primaries", env: "pri_pro=pri_a,pri_team=pri_a", wantErr: "already the trial-less price of pri_pro"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := store.WithPaddleNoTrialPrices(catalogue, c.env)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			want := map[string]store.PaddlePlan{}
			for k, v := range catalogue {
				want[k] = v
			}
			for k, v := range c.want {
				want[k] = v
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("map = %+v\nwant  %+v", got, want)
			}
		})
	}
	// The input map is never changed.
	if len(catalogue) != 2 {
		t.Fatalf("the catalogue map was modified: %+v", catalogue)
	}
}

func TestPaddleNoTrialLookups(t *testing.T) {
	t.Parallel()
	pm, err := store.WithPaddleNoTrialPrices(map[string]store.PaddlePlan{
		"pri_pro":  {Name: "plus_beta", Version: 5},
		"pri_team": {Name: "team", Version: 1},
		"pri_biz":  {Name: "business", Version: 1},
	}, "pri_pro=pri_pro_nt,pri_team=pri_team_nt")
	if err != nil {
		t.Fatal(err)
	}
	s := store.New(nil)
	s.SetPaddlePriceMap(pm)
	for _, c := range []struct {
		price, sibling, catalogue string
		hasSibling                bool
	}{
		{"pri_pro", "pri_pro_nt", "pri_pro", true},
		{"pri_team", "pri_team_nt", "pri_team", true},
		{"pri_biz", "", "pri_biz", false},
		{"pri_pro_nt", "", "pri_pro", false},
		{"pri_unknown", "", "pri_unknown", false},
		{"", "", "", false},
	} {
		sib, ok := s.PaddleNoTrialPrice(c.price)
		if sib != c.sibling || ok != c.hasSibling {
			t.Errorf("PaddleNoTrialPrice(%q) = %q %v, want %q %v", c.price, sib, ok, c.sibling, c.hasSibling)
		}
		if got := s.PaddleCataloguePrice(c.price); got != c.catalogue {
			t.Errorf("PaddleCataloguePrice(%q) = %q, want %q", c.price, got, c.catalogue)
		}
	}
	if !s.PaddlePriceKnown("pri_pro_nt") {
		t.Error("a trial-less sibling is not a known price; its webhooks would resolve no plan")
	}
	if got := store.PaddleCataloguePricesWithoutNoTrial(pm); !reflect.DeepEqual(got, []string{"pri_biz"}) {
		t.Errorf("PaddleCataloguePricesWithoutNoTrial = %v, want [pri_biz]", got)
	}
}

// TestPaddleWebhookAcceptsEitherPriceOfAPlan: one row per (path, price the
// checkout offered): the subscription binds on the offered price and grants
// the plan; an event on the OTHER price of the same plan is refused by
// FR-2's cross-check, because the intent records the price actually offered.
func TestPaddleWebhookAcceptsEitherPriceOfAPlan(t *testing.T) {
	type row struct {
		name     string
		org      bool
		offered  string // the price the intent records
		eventFor string // the price the webhook reports
		bind     bool
		plan     string
	}
	rows := []row{
		{"account: catalogue price", false, testPrice, testPrice, true, "plus_beta"},
		{"account: trial-less price", false, testPriceNoTrial, testPriceNoTrial, true, "plus_beta"},
		{"account: offered trial-less, event on the trial price", false, testPriceNoTrial, testPrice, false, ""},
		{"account: offered the trial price, event on the trial-less one", false, testPrice, testPriceNoTrial, false, ""},
		{"org: catalogue price", true, orgTestPriceTeam, orgTestPriceTeam, true, "team"},
		{"org: trial-less price", true, orgTestPriceTeamNoTrial, orgTestPriceTeamNoTrial, true, "team"},
		{"org: offered trial-less, event on the trial price", true, orgTestPriceTeamNoTrial, orgTestPriceTeam, false, ""},
		{"org: offered the trial price, event on the trial-less one", true, orgTestPriceTeam, orgTestPriceTeamNoTrial, false, ""},
	}
	pm, err := store.WithPaddleNoTrialPrices(orgTestPrices, testPrice+"="+testPriceNoTrial+","+orgTestPriceTeam+"="+orgTestPriceTeamNoTrial)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			f := newOrgBillingFixture(t)
			f.s.SetPaddlePriceMap(pm)
			ctx := context.Background()
			var nonce, orgID string
			if c.org {
				nonce, orgID = f.orgNonce(t, c.offered), f.org.OrgID
			} else {
				n, _, err := f.s.CreateCheckoutIntent(ctx, f.owner, c.offered, time.Hour, f.now)
				if err != nil {
					t.Fatalf("CreateCheckoutIntent: %v", err)
				}
				nonce = n
			}
			in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
				EventID: "evt_nt", EventType: "subscription.activated", AccountID: f.owner, OrgID: orgID,
				CheckoutNonce: nonce, CustomerID: "ctm_nt", SubscriptionID: "sub_nt", Status: "active",
				PriceID: c.eventFor, OccurredAt: f.now, CurrentPeriodEnd: f.now.AddDate(0, 1, 0), Now: f.now,
				TransactionPaid: true,
			})
			if err != nil {
				t.Fatalf("ProcessPaddleEvent: %v", err)
			}
			if !c.bind {
				if in.Applied || in.Outcome != "binding_refused" {
					t.Fatalf("intake = %+v, want binding_refused (intent price mismatch)", in)
				}
				return
			}
			if !in.Applied {
				t.Fatalf("intake = %+v, want applied", in)
			}
			var sub store.PaddleSubscription
			if c.org {
				sub, err = f.s.OrgSubscription(ctx, f.org.OrgID)
			} else {
				sub, err = f.s.AccountSubscription(ctx, f.owner)
			}
			if err != nil || sub.PlanName != c.plan || sub.Status != "active" {
				t.Fatalf("subscription = %+v err=%v, want %s active", sub, err, c.plan)
			}
			// A trial-less checkout never records a trial use.
			used := false
			if c.org {
				used, err = f.s.OrgTrialUsed(ctx, f.org.OrgID)
			} else {
				used, err = f.s.AccountTrialUsed(ctx, f.owner)
			}
			if err != nil || used {
				t.Errorf("trial used = %v err=%v after a paid activation, want false", used, err)
			}
		})
	}
}
