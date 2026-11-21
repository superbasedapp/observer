package api

import (
	"context"
)

// Which price a checkout offers (fu/billing-trial, after FR-10).
//
// Paddle puts the trial on the price, so the server chooses the price: the
// catalogue price (with whatever trial Paddle gives it) for a scope that has
// not had a trial, and its trial-less sibling (store.WithPaddleNoTrialPrices,
// SBCI_PADDLE_NO_TRIAL_PRICES) for one that has, so a returning customer pays
// from the first day instead of being refused. The browser names a plan's
// price; it never picks the trial or the sibling: a sibling it names is
// folded back to its catalogue price before the rules run.

// checkoutOffer is the outcome of checkoutOfferRules.
type checkoutOffer int

const (
	// offerCataloguePrice: open the checkout on the catalogue price.
	offerCataloguePrice checkoutOffer = iota
	// offerNoTrialPrice: open it on the catalogue price's trial-less sibling.
	offerNoTrialPrice
	// offerRefuseTrialUsed: 409 trial_already_used (no sibling configured).
	offerRefuseTrialUsed
)

// checkoutOfferInput is what the rules read. TrialUsed is meaningful only
// when TrialAdvertised (the trial use is not read otherwise).
type checkoutOfferInput struct {
	TrialAdvertised bool // SBCI_PADDLE_TRIAL_DAYS > 0
	TrialUsed       bool // paddle_trial_uses holds the scope (FR-10)
	HasNoTrialPrice bool // the catalogue price has a trial-less sibling
}

// checkoutOfferRules is walked top-down; the first match decides (CLAUDE.md
// #5). One test case per row: TestCheckoutOfferRules.
var checkoutOfferRules = []struct {
	name  string
	match func(checkoutOfferInput) bool
	offer checkoutOffer
}{
	{"no trial advertised: the catalogue price", func(in checkoutOfferInput) bool { return !in.TrialAdvertised }, offerCataloguePrice},
	{"trial not yet used: the catalogue price and its trial", func(in checkoutOfferInput) bool { return !in.TrialUsed }, offerCataloguePrice},
	{"trial used, a trial-less price: pay from the first day", func(in checkoutOfferInput) bool { return in.HasNoTrialPrice }, offerNoTrialPrice},
	{"trial used, no trial-less price: refused", func(checkoutOfferInput) bool { return true }, offerRefuseTrialUsed},
}

// decideCheckoutOffer walks checkoutOfferRules.
func decideCheckoutOffer(in checkoutOfferInput) checkoutOffer {
	for _, r := range checkoutOfferRules {
		if r.match(in) {
			return r.offer
		}
	}
	return offerRefuseTrialUsed
}

// resolveCheckoutPrice is the checkout handlers' one call: the price the
// checkout opens with for requested, or refused=true for 409
// trial_already_used. trialUsed is called only while a trial is advertised.
// A price this deployment does not sell comes back unchanged; the handler's
// own unknown-price refusal still applies to it.
func (s *Server) resolveCheckoutPrice(ctx context.Context, requested string, trialUsed func(context.Context) (bool, error)) (price string, refused bool, err error) {
	price = requested
	if s.store == nil {
		return price, false, nil
	}
	price = s.store.PaddleCataloguePrice(requested)
	in := checkoutOfferInput{TrialAdvertised: s.paddleCheckout.TrialDays > 0}
	if in.TrialAdvertised {
		if in.TrialUsed, err = trialUsed(ctx); err != nil {
			return "", false, err
		}
	}
	sibling, ok := s.store.PaddleNoTrialPrice(price)
	in.HasNoTrialPrice = ok
	switch decideCheckoutOffer(in) {
	case offerNoTrialPrice:
		return sibling, false, nil
	case offerRefuseTrialUsed:
		return "", true, nil
	default:
		return price, false, nil
	}
}

// checkoutTrialDays is the trial a scope's billing view advertises: none
// once the scope has had its trial (its checkout is then trial-less, or
// refused), the deployment's otherwise. A failed read keeps the advertised
// value; the checkout itself decides from a fresh read.
func (s *Server) checkoutTrialDays(ctx context.Context, trialUsed func(context.Context) (bool, error)) (days int, used bool) {
	days = s.paddleCheckout.TrialDays
	if days <= 0 || s.store == nil {
		return days, false
	}
	u, err := trialUsed(ctx)
	if err != nil {
		s.log.Error("cloudserver/api: billing view: trial use", "err", err)
		return days, false
	}
	if u {
		return 0, true
	}
	return days, false
}
