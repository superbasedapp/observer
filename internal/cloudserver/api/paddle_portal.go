package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling/paddleapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// paddle_portal.go is the Paddle customer portal link (wave 17 paddle-live;
// docs/security.md PADDLELIVE-3). Paddle is the merchant of record: the
// invoices, receipts, tax details, payment method and cancellation live in
// Paddle's hosted customer portal, never in this one. These routes mint a
// short-lived authenticated portal session for the signed-in payer and
// return its link; nothing is stored and the link is never logged.
//
//   - POST /portal/api/billing/portal-session: the account's own
//     subscription (Personal Pro).
//   - POST /portal/api/orgs/{id}/billing/portal-session: an org's
//     subscription, for its BILLING OWNER only. The Paddle customer is the
//     billing owner's own Paddle customer, and the portal's overview lists
//     every subscription and invoice of that customer, so an org admin who
//     is not the payer must not be handed it (they see the plan and the
//     subscription's own links on the org page instead).
//
// Both need the server-side Paddle API key (SBCI_PADDLE_API_KEY_FILE, with
// the customer portal session write permission); without one they answer
// 501 portal_unavailable and the portal keeps the subscription's own
// management links (cloud 0034).

// PaddlePortalAPI mints Paddle customer portal sessions. *paddleapi.Client
// implements it; tests use a fake.
type PaddlePortalAPI interface {
	CreatePortalSession(ctx context.Context, customerID string, subscriptionIDs []string) (paddleapi.PortalSession, error)
}

// portalSessionJSON is the route's answer.
type portalSessionJSON struct {
	// URL is the portal's overview (subscriptions, payment methods,
	// invoices).
	URL string `json:"url"`
	// Cancel and UpdatePaymentMethod are the subscription's deep links, when
	// Paddle returned them.
	Cancel              string `json:"cancel,omitempty"`
	UpdatePaymentMethod string `json:"update_payment_method,omitempty"`
}

// writePortalSession mints the session for sub and answers it.
func (s *Server) writePortalSession(w http.ResponseWriter, r *http.Request, accountID string, sub store.PaddleSubscription, audit string) {
	if s.paddlePortal == nil {
		writeErr(w, http.StatusNotImplemented, "portal_unavailable",
			"the billing portal is not configured on this deployment; use the links on the subscription, or the receipt email Paddle sent")
		return
	}
	if !paddleapi.ValidCustomerID(sub.CustomerID) || !paddleapi.ValidSubscriptionID(sub.SubscriptionID) {
		writeErr(w, http.StatusConflict, "no_paddle_customer", "this subscription has no Paddle customer to open a portal for")
		return
	}
	ps, err := s.paddlePortal.CreatePortalSession(r.Context(), sub.CustomerID, []string{sub.SubscriptionID})
	if err != nil {
		// The error names no key and no link (paddleapi); it may name
		// Paddle's request id, which support needs.
		s.log.Error("cloudserver/api: paddle portal session", "err", err)
		writeErr(w, http.StatusBadGateway, "portal_session_failed", "Paddle could not open the billing portal; try again shortly")
		return
	}
	out := portalSessionJSON{URL: ps.Overview}
	for _, l := range ps.Subscriptions {
		if l.ID == sub.SubscriptionID {
			out.Cancel, out.UpdatePaymentMethod = l.Cancel, l.UpdatePaymentMethod
		}
	}
	s.audit(r.Context(), accountID, audit)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

// handlePortalBillingPortalSession is POST /portal/api/billing/portal-session.
func (s *Server) handlePortalBillingPortalSession(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	sub, err := s.store.AccountSubscription(r.Context(), p.AccountID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "no_subscription", "this account has no subscription")
		return
	case err != nil:
		s.log.Error("cloudserver/api: portal session: subscription", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	s.writePortalSession(w, r, p.AccountID, sub, "paddle_portal_session_created")
}

// handlePortalOrgBillingPortalSession is POST
// /portal/api/orgs/{id}/billing/portal-session, for the org's billing owner.
func (s *Server) handlePortalOrgBillingPortalSession(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, err := s.store.GetOrg(r.Context(), p.AccountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: org portal session: get org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	if !org.IsBillingOwner {
		writeErr(w, http.StatusForbidden, "billing_owner_required", "only the team's billing owner can open the billing portal")
		return
	}
	sub, err := s.store.PortalOrgSubscription(r.Context(), p.AccountID, org.OrgID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "no_subscription", "this team has no subscription")
		return
	case err != nil:
		s.log.Error("cloudserver/api: org portal session: subscription", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read billing")
		return
	}
	s.writePortalSession(w, r, p.AccountID, sub, "paddle_org_portal_session_created")
}

// checkoutQuantity is the quantity a checkout for priceID opens with: the
// plan's seat minimum (entitlements CapSeatsMin, the only caps authority),
// never below one. A Team price sold per active developer with a minimum
// of 3 opens at 3; a Personal Pro price opens at 1. The seat sync pass
// (cmd/observer-cloud seatsync.go) moves it to the period's real seat count
// later; the checkout never guesses a number above the minimum.
func (s *Server) checkoutQuantity(priceID string) int64 {
	if s.store == nil {
		return 1
	}
	pl, ok := s.store.PaddlePricePlan(priceID)
	if !ok {
		return 1
	}
	if b, ok := entitlements.Plan(pl.Name, pl.Version); ok {
		if m := b.Caps[entitlements.CapSeatsMin]; m > 1 {
			return m
		}
	}
	return 1
}
