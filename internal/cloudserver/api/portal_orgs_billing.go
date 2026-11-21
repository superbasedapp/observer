package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// portal_orgs_billing.go is billing per org (lead decision W14-D3; plan 07
// M6.5; docs/security.md PORTALORG-3 and PORTALORG-6). There is one
// subscription store: the org-scoped rows of paddle_subscriptions, written
// only by the Paddle webhook's org branch (store/paddle_org.go). This file
// reads them back for the console and mints the org checkout's intent; it
// writes no subscription itself.
//
// The plan shown is the plan the entitlements worker issues the org's signed
// document from: the same rule table (entitlementwork.SubscriptionPlans:
// subscription, then the launch window, then the floor), fed the
// subscription this file read, so the console and the host never disagree
// about which plan an org is on.

// orgPlanJSON is the plan an org's document carries.
type orgPlanJSON struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Label   string `json:"label"`
	// Source is the plan rule that decided (entitlementwork.PlanRuleNames):
	// subscription | org_grant | launch | floor.
	Source string `json:"source"`
	// NotAfter is a launch plan's end, or an operator grant's end.
	NotAfter string `json:"not_after,omitempty"`
	// SeatsMin is the plan's minimum seat count (0: none).
	SeatsMin int64 `json:"seats_min,omitempty"`
}

// fixedOrgSubscription hands entitlementwork the subscription this request
// already read (or its error).
type fixedOrgSubscription struct {
	sub store.PaddleSubscription
	err error
}

func (f fixedOrgSubscription) OrgSubscription(context.Context, string) (store.PaddleSubscription, error) {
	return f.sub, f.err
}

// fixedOrgGrant hands entitlementwork the operator grant this request
// already read (or its error).
type fixedOrgGrant struct {
	grant store.OrgPlanGrant
	err   error
}

func (f fixedOrgGrant) OrgPlanGrant(context.Context, string) (store.OrgPlanGrant, error) {
	return f.grant, f.err
}

// orgPlan composes the org's plan through the worker's rule table, so the
// console names the plan the issued document carries (PORTALORG-6), an
// operator grant included (W15-D13).
func (s *Server) orgPlan(r *http.Request, accountID string, o store.MyOrg, createdOnHost time.Time) (*orgPlanJSON, error) {
	kind, ok := store.OrgEntitlementsKind(o.Kind)
	if !ok {
		return nil, errors.New("api.orgPlan: org kind has no entitlements kind")
	}
	sub, subErr := s.store.PortalOrgSubscription(r.Context(), accountID, o.OrgID)
	if subErr != nil && !errors.Is(subErr, store.ErrNotFound) {
		return nil, subErr
	}
	grant, grantErr := s.store.PortalOrgPlanGrant(r.Context(), accountID, o.OrgID)
	if grantErr != nil && !errors.Is(grantErr, store.ErrNotFound) {
		return nil, grantErr
	}
	view := store.OrgEntitlementView{OrgID: o.OrgID, Kind: o.Kind, Status: string(o.Status), CreatedOnHostAt: createdOnHost}
	pl, rule, err := entitlementwork.SubscriptionPlans{
		Subs:         fixedOrgSubscription{sub: sub, err: subErr},
		Grants:       fixedOrgGrant{grant: grant, err: grantErr},
		Now:          s.now,
		PastDueGrace: s.paddlePastDueGrace,
	}.Resolve(r.Context(), view, kind)
	if err != nil {
		return nil, err
	}
	out := &orgPlanJSON{Name: pl.Name, Version: pl.Version, Source: rule}
	if pl.NotAfter != 0 {
		out.NotAfter = rfc3339(time.Unix(pl.NotAfter, 0))
	}
	if b, ok := entitlements.Plan(pl.Name, pl.Version); ok {
		out.Label = b.Plan.Label
		out.SeatsMin = b.Caps[entitlements.CapSeatsMin]
	}
	return out, nil
}

// checkoutPricesFor returns the configured checkout prices whose plan is of
// kind (entitlements.KindAccount for the personal Billing page, an org kind
// for an org's page), in the catalogue's order. Never nil.
func (s *Server) checkoutPricesFor(kind entitlements.Kind) []PaddlePriceEntry {
	out := []PaddlePriceEntry{}
	if s.store == nil {
		return out
	}
	for _, p := range s.paddleCheckout.Prices {
		if k, ok := s.store.PaddlePriceKind(p.PriceID); ok && k == kind {
			out = append(out, p)
		}
	}
	return out
}

// checkoutCatalogForScope is the "checkout" slice of a billing view for
// kind, for the scope trialUsed reads: trial_days is the trial this scope
// would get (0 once it has had one, checkoutTrialDays) and trial_used says
// why. The prices are the catalogue's; a trial-less sibling is never listed
// (the server offers it at checkout).
func (s *Server) checkoutCatalogForScope(ctx context.Context, kind entitlements.Kind, trialUsed func(context.Context) (bool, error)) map[string]any {
	prices := s.checkoutPricesFor(kind)
	days, used := s.checkoutTrialDays(ctx, trialUsed)
	return map[string]any{
		"available":    s.paddleCheckout.ClientToken != "" && len(prices) > 0,
		"environment":  s.paddleCheckout.Environment,
		"client_token": s.paddleCheckout.ClientToken,
		"prices":       prices,
		"trial_days":   days,
		"trial_used":   used,
	}
}

// handlePortalOrgBilling is GET /portal/api/orgs/{id}/billing: the org's
// subscription, its plan and the checkout catalogue of its kind, for an org
// owner or admin or its billing owner.
func (s *Server) handlePortalOrgBilling(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	org, err := s.store.GetOrg(r.Context(), p.AccountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: org billing: get org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	caps := orgCaps(org)
	if !caps.ViewBilling {
		writeErr(w, http.StatusForbidden, "forbidden", "only an org owner, admin or billing owner can see billing")
		return
	}
	kind, _ := store.OrgEntitlementsKind(org.Kind)
	view := map[string]any{"has_subscription": false, "checkout": s.checkoutCatalogForScope(r.Context(), kind, func(ctx context.Context) (bool, error) {
		return s.orgTrialUsed(ctx, p.AccountID, org)
	})}
	sub, err := s.store.PortalOrgSubscription(r.Context(), p.AccountID, org.OrgID)
	live := false
	switch {
	case err == nil:
		view["has_subscription"] = true
		view["subscription"] = sub
		live = store.SubscriptionIsLive(sub.Status)
	case errors.Is(err, store.ErrNotFound):
	default:
		s.log.Error("cloudserver/api: org billing: subscription", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	var createdOnHost time.Time
	if cs, err := s.store.OrgCreateStatus(r.Context(), p.AccountID, org.OrgID); err == nil && cs.State == "acked" && cs.DoneAt != nil {
		createdOnHost = *cs.DoneAt
	}
	if pl, err := s.orgPlan(r, p.AccountID, org, createdOnHost); err == nil {
		view["plan"] = pl
	} else {
		s.log.Error("cloudserver/api: org billing: plan", "err", err)
	}
	view["can_checkout"] = caps.Checkout && !live && orgCanStartCheckout(org.Status)
	view["is_billing_owner"] = org.IsBillingOwner
	// Wave 17: the billing owner can open Paddle's customer portal
	// (invoices, payment method) when the deployment holds an API key.
	view["portal_available"] = s.paddlePortal != nil && org.IsBillingOwner && view["has_subscription"] == true
	writeJSON(w, http.StatusOK, view)
}

// orgTrialUsed reports whether an org checkout would repeat a free trial
// (FR-10): the org has had one, or it is the caller's personal org and the
// caller's own account has had one.
func (s *Server) orgTrialUsed(ctx context.Context, accountID string, org store.MyOrg) (bool, error) {
	used, err := s.store.OrgTrialUsed(ctx, org.OrgID)
	if err != nil || used {
		return used, err
	}
	if org.Kind != store.OrgPersonal {
		return false, nil
	}
	return s.store.AccountTrialUsed(ctx, accountID)
}

// orgCanStartCheckout mirrors store.CreateOrgCheckoutIntent's billable
// statuses (provisioning, active, suspended).
func orgCanStartCheckout(st platformcontract.TenantState) bool {
	switch st {
	case platformcontract.StateProvisioning, platformcontract.StateActive, platformcontract.StateSuspended:
		return true
	}
	return false
}

// orgCheckoutErrors maps a refused org checkout intent to the console's
// answer.
var orgCheckoutErrors = []struct {
	err    error
	status int
	code   string
	msg    string
}{
	{store.ErrNotFound, http.StatusNotFound, "not_found", "org not found"},
	{store.ErrOrgBillingForbidden, http.StatusForbidden, "billing_owner_required", "only the team's billing owner can start a checkout"},
	{store.ErrOrgNotBillable, http.StatusConflict, "org_not_billable", "this org cannot take a subscription"},
	{store.ErrBillingUnknownPrice, http.StatusNotImplemented, "checkout_unavailable", "that price is not a plan this org can buy on this deployment"},
}

// handlePortalOrgCheckout is POST /portal/api/orgs/{id}/billing/checkout: the
// org twin of handlePortalCheckout. It mints a single-use nonce bound to the
// authenticated billing owner AND the org (checkout_intents.org_id); the
// webhook's org branch binds the resulting subscription to that org only.
// Like the account checkout it creates no Paddle transaction itself:
// Paddle.js opens the checkout in the browser with the returned custom_data.
func (s *Server) handlePortalOrgCheckout(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, err := s.store.GetOrg(r.Context(), p.AccountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: org checkout: get org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start checkout")
		return
	}
	if !org.IsBillingOwner {
		writeErr(w, http.StatusForbidden, "billing_owner_required", "only the team's billing owner can start a checkout")
		return
	}
	if sub, serr := s.store.PortalOrgSubscription(r.Context(), p.AccountID, org.OrgID); serr == nil {
		if store.SubscriptionIsLive(sub.Status) {
			writeErr(w, http.StatusConflict, "already_subscribed",
				"this team already holds a live subscription; manage or cancel it before starting a new checkout")
			return
		}
	} else if !errors.Is(serr, store.ErrNotFound) {
		s.log.Error("cloudserver/api: org checkout: existing subscription", "err", serr)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the existing subscription")
		return
	}
	var req struct {
		PriceID string `json:"price_id"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	price := strings.TrimSpace(req.PriceID)
	// FR-10: one free trial per org; a personal org also counts its owner's
	// own trial (the same person moved onto the org by migrate-personal).
	// An org that has had one is offered the plan's trial-less price
	// (paddle_trialoffer.go), or refused when none is configured; the
	// intent records the price actually offered (FR-2's cross-check).
	price, refused, terr := s.resolveCheckoutPrice(r.Context(), price, func(ctx context.Context) (bool, error) {
		return s.orgTrialUsed(ctx, p.AccountID, org)
	})
	if terr != nil {
		s.log.Error("cloudserver/api: org checkout: trial use", "err", terr)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start checkout")
		return
	}
	if refused {
		writeErr(w, http.StatusConflict, "trial_already_used", trialAlreadyUsedMessage)
		return
	}
	nonce, expiresAt, err := s.store.CreateOrgCheckoutIntent(r.Context(), p.AccountID, org.OrgID, price, checkoutIntentTTL, s.now())
	if err != nil {
		for _, m := range orgCheckoutErrors {
			if errors.Is(err, m.err) {
				writeErr(w, m.status, m.code, m.msg)
				return
			}
		}
		s.log.Error("cloudserver/api: org checkout intent", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start checkout")
		return
	}
	s.audit(r.Context(), p.AccountID, "paddle_org_checkout_intent_created")
	writeJSON(w, http.StatusOK, map[string]any{
		"price_id":   price,
		"quantity":   s.checkoutQuantity(price),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"custom_data": map[string]string{
			"account_id":     p.AccountID,
			"org_id":         org.OrgID,
			"checkout_nonce": nonce,
		},
	})
}
