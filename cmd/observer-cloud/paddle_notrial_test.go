package main

import (
	"strings"
	"testing"
)

// TestPaddlePriceMapNoTrialSiblings: SBCI_PADDLE_NO_TRIAL_PRICES joins the
// one price map (so a webhook for the trial-less price resolves the plan),
// stays out of the portal catalogue, and a bad pair fails startup
// (fu/billing-trial).
func TestPaddlePriceMapNoTrialSiblings(t *testing.T) {
	cases := []struct {
		name    string
		prices  string
		noTrial string
		wantMap int
		wantCat []string
		wantErr string
	}{
		{name: "no siblings", prices: "pri_pro=plus_beta:5:month,pri_team=team:1:month", wantMap: 2, wantCat: []string{"pri_pro", "pri_team"}},
		{name: "one sibling, kept out of the catalogue", prices: "pri_pro=plus_beta:5:month,pri_team=team:1:month", noTrial: "pri_pro=pri_pro_nt", wantMap: 3, wantCat: []string{"pri_pro", "pri_team"}},
		{name: "sibling of an unknown price", prices: "pri_pro=plus_beta:5:month", noTrial: "pri_x=pri_y", wantErr: "not a price in SBCI_PADDLE_PRICES"},
		{name: "sibling also in the catalogue", prices: "pri_pro=plus_beta:5:month,pri_team=team:1:month", noTrial: "pri_pro=pri_team", wantErr: "is listed in SBCI_PADDLE_PRICES"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SBCI_PADDLE_PRICES", c.prices)
			t.Setenv("SBCI_PADDLE_PRICE_PLUS", "")
			t.Setenv("SBCI_PADDLE_NO_TRIAL_PRICES", c.noTrial)
			t.Setenv("SBCI_PADDLE_ENV", "sandbox")
			t.Setenv("SBCI_PADDLE_CLIENT_TOKEN", "")
			t.Setenv("SBCI_PADDLE_TRIAL_DAYS", "7")
			pm, err := paddlePriceMap()
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || len(pm) != c.wantMap {
				t.Fatalf("map = %+v err=%v, want %d prices", pm, err, c.wantMap)
			}
			co, err := paddleCheckoutFromEnv(pm, "http://localhost:8090", paddleSecrets{})
			if err != nil {
				t.Fatalf("paddleCheckoutFromEnv: %v", err)
			}
			got := []string{}
			for _, p := range co.Prices {
				got = append(got, p.PriceID)
			}
			if strings.Join(got, ",") != strings.Join(c.wantCat, ",") {
				t.Fatalf("catalogue = %v, want %v", got, c.wantCat)
			}
		})
	}
}
