package api

import "testing"

// TestCheckoutOfferRules: one case per checkoutOfferRules row, each landing
// on that row, plus the rows a trial switched off makes unreachable.
func TestCheckoutOfferRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   checkoutOfferInput
		row  int
		want checkoutOffer
	}{
		{"trial off, never used", checkoutOfferInput{}, 0, offerCataloguePrice},
		{"trial off, used, sibling configured", checkoutOfferInput{TrialUsed: true, HasNoTrialPrice: true}, 0, offerCataloguePrice},
		{"trial off, used, no sibling", checkoutOfferInput{TrialUsed: true}, 0, offerCataloguePrice},
		{"trial on, unused, no sibling", checkoutOfferInput{TrialAdvertised: true}, 1, offerCataloguePrice},
		{"trial on, unused, sibling configured", checkoutOfferInput{TrialAdvertised: true, HasNoTrialPrice: true}, 1, offerCataloguePrice},
		{"trial on, used, sibling configured", checkoutOfferInput{TrialAdvertised: true, TrialUsed: true, HasNoTrialPrice: true}, 2, offerNoTrialPrice},
		{"trial on, used, no sibling", checkoutOfferInput{TrialAdvertised: true, TrialUsed: true}, 3, offerRefuseTrialUsed},
	}
	hit := make([]bool, len(checkoutOfferRules))
	for _, c := range cases {
		if got := decideCheckoutOffer(c.in); got != c.want {
			t.Errorf("%s: offer = %d, want %d", c.name, got, c.want)
		}
		first := -1
		for i, r := range checkoutOfferRules {
			if r.match(c.in) {
				first = i
				break
			}
		}
		if first != c.row {
			t.Errorf("%s: matched row %d, want row %d (%s)", c.name, first, c.row, checkoutOfferRules[c.row].name)
		}
		if first >= 0 {
			hit[first] = true
		}
	}
	for i, h := range hit {
		if !h {
			t.Errorf("row %d (%s) has no case", i, checkoutOfferRules[i].name)
		}
	}
}
