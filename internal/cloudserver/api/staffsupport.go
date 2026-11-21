package api

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// The staff console's support sign-in (managed-SaaS plan 07 M7a.2; plan 06
// 5.8.7; design m6.0 4.9 "The support claim").
//
// GET /staff/oauth2/authorize is the platform issuer's authorize endpoint for
// SUPPORT sign-ins, advertised to tenants in discovery as
// sb_support_authorization_endpoint. It is served by the staff process on the
// staff host, behind staffAuth with staffauth.ActionSupportSignIn, whose row
// requires a passkey assertion within the fresh window: the staff session
// cookie (host-only on the staff host) is the only credential that reaches
// it, and a customer portal session never does. The handler hands the
// request and the staff member's id and assertion time to
// oidcissuer.SupportAuthorizer, which validates the client and the exact
// redirect URI, writes a support code with its staff_actions row (one
// transaction, as sbci_staff), and redirects to the tenant's callback. The
// token endpoint (serve) turns the code into an id_token with support: true.
// Whether the org lets this staff member in is the tenant's own grant.

// staffSupportAuthorizer builds the support authorizer from o; nil when no
// issuer is configured or the identifier is unusable (logged).
func (s *Server) staffSupportAuthorizer(o Options) *oidcissuer.SupportAuthorizer {
	if o.StaffSupportIssuer == "" {
		return nil
	}
	codes := o.StaffSupportStore
	if codes == nil {
		if o.Store == nil {
			return nil
		}
		codes = o.Store.StaffOIDC()
	}
	a, err := oidcissuer.NewSupportAuthorizer(oidcissuer.SupportAuthorizerConfig{
		Issuer: o.StaffSupportIssuer, Store: codes, Now: s.now,
	})
	if err != nil {
		s.log.Error("cloudserver/api: support authorize is off: the issuer identifier is unusable", "err", err)
		return nil
	}
	return a
}

// handleStaffSupportAuthorize serves GET /staff/oauth2/authorize.
func (s *Server) handleStaffSupportAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.staff.support == nil {
		writeErr(w, http.StatusNotImplemented, "not_available", "support sign-in is not configured on this staff console")
		return
	}
	p, ok := staffPrincipalFrom(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in to the staff console")
		return
	}
	res := s.staff.support.Authorize(r.Context(), oidcissuer.ParseAuthorizeQuery(r.URL.Query()),
		oidcissuer.StaffSession{StaffID: p.StaffID, AssertedAt: p.AssertedAt})
	switch res.Outcome {
	case oidcissuer.OutcomeRedirect:
		if res.Err != nil {
			s.log.Info("cloudserver/api: support authorize refused", "rule", res.Err.RuleID, "code", res.Err.Code)
		}
		http.Redirect(w, r, res.Location, http.StatusFound)
	default:
		e := res.Err
		if e == nil {
			e = &oidcissuer.Error{Code: oidcissuer.ErrCodeServerError, Description: "support sign-in failed", Status: http.StatusInternalServerError, RuleID: "no-outcome"}
		}
		s.log.Info("cloudserver/api: support authorize refused in place", "rule", e.RuleID, "code", e.Code)
		status := e.Status
		if status < 400 || status > 599 {
			status = http.StatusBadRequest
		}
		writeErr(w, status, e.Code, e.Description)
	}
}
