package api

import (
	"net/http"
)

// portal_personal.go is the console's trigger of the lazy personal org
// (managed-SaaS individuals workstream, D-IND-1; docs/security.md IND-1):
//
//	POST /portal/api/orgs/personal   find or create the caller's personal org
//
// It sits behind portalAuth exactly like POST /portal/api/orgs: the session
// cookie, the per-account rate limit, the exact portal Origin and the
// double-submit X-SBCI-CSRF check. It takes no body: the display name, the
// slug and the tenancy of a personal org are not the caller's to choose
// (store.EnsurePersonalOrg). It answers 201 when this call created the org and
// 200 when it already existed, with the same org detail body a team create
// writes (writeOrgDetail). It never writes a membership row, and a personal
// org does not count against the team org cap; team creation is unchanged.

// handlePortalEnsurePersonal is POST /portal/api/orgs/personal.
func (s *Server) handlePortalEnsurePersonal(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, created, err := s.store.EnsurePersonalOrg(r.Context(), p.AccountID, s.tenantDomain)
	if err != nil {
		s.log.Error("cloudserver/api: ensure personal org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not set up your personal org")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_personal_org_ensured")
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	s.writeOrgDetail(w, r, p.AccountID, org, status, false)
}
