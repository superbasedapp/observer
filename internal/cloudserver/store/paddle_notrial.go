package store

import (
	"fmt"
	"sort"
	"strings"
)

// Trial-less sibling prices (fu/billing-trial, after FR-10).
//
// Paddle Billing puts a free trial on the PRICE: every checkout of a price
// that carries a trial period starts with that trial, and Paddle.js gives
// the browser no way to drop it for one customer. Paddle's documented way to
// sell the same plan without the trial is a second price on the same product
// with no trial period. SBCI_PADDLE_NO_TRIAL_PRICES maps each catalogue price
// that carries a trial to that sibling:
//
//	SBCI_PADDLE_NO_TRIAL_PRICES=pri_PRO=pri_PRO_NOTRIAL[,pri_X=pri_Y...]
//
// The sibling joins the one price map with its primary's plan (so a webhook
// for either price resolves the same plan, and FR-2's intent cross-check
// compares against whichever price the server actually offered), marked
// NoTrialOf so the checkout catalogue never lists it. The checkout handler
// (api checkoutOfferRules) offers it, never the browser, when the scope's
// trial is recorded as used (paddle_trial_uses, FR-10).

// WithPaddleNoTrialPrices parses SBCI_PADDLE_NO_TRIAL_PRICES (raw; "" means
// none) against an already-parsed catalogue (ParsePaddlePriceEntries) and
// returns a NEW map holding the catalogue plus one entry per sibling, which
// carries its primary's plan and NoTrialOf = the primary. Pure. Every rule
// below is a startup error, never a silently dropped pair: a primary that is
// not a catalogue price, a sibling that is itself a catalogue price (it would
// be offered to everyone, trial or not), a sibling equal to its primary, a
// primary given twice, or one sibling shared by two primaries.
func WithPaddleNoTrialPrices(prices map[string]PaddlePlan, noTrialEnv string) (map[string]PaddlePlan, error) {
	out := make(map[string]PaddlePlan, len(prices))
	for id, p := range prices {
		out[id] = p
	}
	noTrialEnv = strings.TrimSpace(noTrialEnv)
	if noTrialEnv == "" {
		return out, nil
	}
	seenPrimary := map[string]bool{}
	for _, entry := range strings.Split(noTrialEnv, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		primary, sibling, ok := strings.Cut(entry, "=")
		primary, sibling = strings.TrimSpace(primary), strings.TrimSpace(sibling)
		if !ok || primary == "" || sibling == "" {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: malformed entry %q (want pri_TRIAL=pri_NOTRIAL)", entry)
		}
		if strings.ContainsAny(sibling, ":= ") {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s: the trial-less price is a bare price id, got %q", primary, sibling)
		}
		plan, known := prices[primary]
		if !known {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s is not a price in SBCI_PADDLE_PRICES", primary)
		}
		if sibling == primary {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s maps to itself", primary)
		}
		if _, inCatalogue := prices[sibling]; inCatalogue {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s is listed in SBCI_PADDLE_PRICES; a trial-less price is listed only here", sibling)
		}
		if seenPrimary[primary] {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s is given twice", primary)
		}
		if prior, dup := out[sibling]; dup {
			return nil, fmt.Errorf("cloudserver/store.WithPaddleNoTrialPrices: %s is already the trial-less price of %s", sibling, prior.NoTrialOf)
		}
		seenPrimary[primary] = true
		plan.NoTrialOf = primary
		out[sibling] = plan
	}
	return out, nil
}

// PaddleNoTrialPrice returns the trial-less sibling of catalogue price
// priceID, and false when none is configured.
func (s *Store) PaddleNoTrialPrice(priceID string) (string, bool) {
	if priceID == "" {
		return "", false
	}
	for id, p := range s.paddlePrices {
		if p.NoTrialOf == priceID {
			return id, true
		}
	}
	return "", false
}

// PaddleCataloguePrice is the catalogue price a requested price stands for:
// a trial-less sibling's primary, otherwise the price itself. The checkout
// handlers decide from it, so a browser that names the sibling directly
// still gets the server's choice.
func (s *Store) PaddleCataloguePrice(priceID string) string {
	if p, ok := s.paddlePlanForPrice(priceID); ok && p.NoTrialOf != "" {
		return p.NoTrialOf
	}
	return priceID
}

// PaddleCataloguePricesWithoutNoTrial lists the catalogue prices (NoTrialOf
// empty) of m that have no trial-less sibling, sorted. Startup logs it when
// a trial is advertised: a scope that has had its trial cannot buy those
// plans by itself (409 trial_already_used).
func PaddleCataloguePricesWithoutNoTrial(m map[string]PaddlePlan) []string {
	has := map[string]bool{}
	for _, p := range m {
		if p.NoTrialOf != "" {
			has[p.NoTrialOf] = true
		}
	}
	out := []string{}
	for id, p := range m {
		if p.NoTrialOf == "" && !has[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
