package api

import (
	"net/http"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// device_orgs.go is the node's organization discovery (managed-SaaS plan 06
// 19.3 rows 7-9; plan 07 M8.4, M8.7; individuals workstream D-IND-1, D-IND-2;
// docs/security.md IND-1): the two device-authenticated calls
// `observer connect` makes when it is given no server address.
//
//	GET  /v1/orgs                   cloudcontract.DeviceOrgList
//	POST /v1/orgs/personal:ensure   cloudcontract.EnsurePersonalOrgResponse
//
// Both sit behind authenticate (bearer, proof of possession, jti replay, and
// the per-IP, per-account and per-device rate limits) like every /v1 device
// route. The account is the verified principal's, never a request field;
// ensure takes no body. Every host is built here from the org's slug and the
// configured tenant domain (the node only checks its shape), and every answer
// passes the cloudcontract Validate the node runs before it is written.

// mountDeviceOrgs registers the discovery routes on mux. Go's ServeMux takes
// the literal "personal:ensure" segment as written (a colon is not a
// wildcard), and URL.EscapedPath keeps the colon, so the proof-of-possession
// htu the node signs is the path the server rebuilds; no slash alias is
// registered (device_orgs_test.go pins both).
func (s *Server) mountDeviceOrgs(mux *http.ServeMux) {
	mux.Handle("GET /v1/orgs", s.authenticate(http.HandlerFunc(s.handleDeviceListOrgs)))
	mux.Handle("POST /v1/orgs/personal:ensure", s.authenticate(http.HandlerFunc(s.handleDeviceEnsurePersonal)))
}

// deviceOrg is org o on the discovery wire. ServerURL is set only for an
// active org with a tenant domain configured; Stage only while the org is
// being created, from the same provisioning reader the console uses.
func (s *Server) deviceOrg(r *http.Request, accountID string, o store.MyOrg) cloudcontract.DeviceOrg {
	d := cloudcontract.DeviceOrg{
		OrgID: o.OrgID, Slug: o.Slug, DisplayName: o.DisplayName,
		Kind:    cloudcontract.DeviceOrgKind(o.Kind),
		Status:  cloudcontract.DeviceOrgStatus(o.Status),
		Tenancy: string(o.Tenancy),
	}
	if host := s.tenantHost(o.Slug); host != "" && o.Status == platformcontract.StateActive {
		d.ServerURL = "https://" + host
	}
	if o.Status == platformcontract.StateProvisioning {
		prov, _, _ := s.provisioning(r, accountID, o)
		d.Stage = prov.Stage
	}
	return d
}

// deviceOrgOrder sorts the list: the personal org first, then team orgs
// oldest first (ListMyOrgs' own order, kept by the stable sort).
func deviceOrgOrder(orgs []store.MyOrg) {
	sort.SliceStable(orgs, func(i, j int) bool {
		return orgs[i].Kind == store.OrgPersonal && orgs[j].Kind != store.OrgPersonal
	})
}

// handleDeviceListOrgs is GET /v1/orgs: every org the account belongs to,
// personal first. An org whose row would fail the node's validation is left
// out (and logged) rather than failing the whole list; the list is bounded by
// cloudcontract.MaxDeviceOrgs, keeping the personal org.
func (s *Server) handleDeviceListOrgs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := principalFrom(r.Context())
	orgs, err := s.store.ListMyOrgs(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: device list orgs", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list orgs")
		return
	}
	deviceOrgOrder(orgs)
	out := cloudcontract.DeviceOrgList{Orgs: make([]cloudcontract.DeviceOrg, 0, len(orgs))}
	for _, o := range orgs {
		if len(out.Orgs) == cloudcontract.MaxDeviceOrgs {
			s.log.Warn("cloudserver/api: device org list truncated", "max", cloudcontract.MaxDeviceOrgs, "orgs", len(orgs))
			break
		}
		d := s.deviceOrg(r, p.AccountID, o)
		if err := d.Validate(); err != nil {
			s.log.Error("cloudserver/api: device org left out of the list", "org_id", o.OrgID, "err", err)
			continue
		}
		out.Orgs = append(out.Orgs, d)
	}
	if err := out.Validate(); err != nil {
		s.log.Error("cloudserver/api: device org list", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list orgs")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeviceEnsurePersonal is POST /v1/orgs/personal:ensure: the account's
// personal org, created lazily (201) or already there (200).
func (s *Server) handleDeviceEnsurePersonal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := principalFrom(r.Context())
	org, created, err := s.store.EnsurePersonalOrg(r.Context(), p.AccountID, s.tenantDomain)
	if err != nil {
		s.log.Error("cloudserver/api: device ensure personal org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not set up your personal org")
		return
	}
	s.audit(r.Context(), p.AccountID, "device_personal_org_ensured")
	resp := cloudcontract.EnsurePersonalOrgResponse{Org: s.deviceOrg(r, p.AccountID, org), Created: created}
	if err := resp.Validate(); err != nil {
		s.log.Error("cloudserver/api: device ensure personal org answer", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not set up your personal org")
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, resp)
}
