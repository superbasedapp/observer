package api

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestTenantLink is one case per tenant page, plus the two empty answers (no
// tenant domain, no slug).
func TestTenantLink(t *testing.T) {
	t.Parallel()
	s := &Server{tenantDomain: "superbased.app"}
	cases := []struct {
		name string
		srv  *Server
		slug string
		page tenantPage
		want string
	}{
		{"dashboard", s, "acme", tenantPageDashboard, "https://acme.superbased.app/"},
		{"machines", s, "acme", tenantPageMachines, "https://acme.superbased.app/me/profile"},
		{"invites", s, "acme", tenantPageInvites, "https://acme.superbased.app/people-access?tab=invites"},
		{"install", s, "acme", tenantPageInstall, "https://acme.superbased.app/me/install"},
		{"origin", s, "acme", tenantPageOrigin, "https://acme.superbased.app"},
		{"personal dashboard", s, "u-3f9a2c1d", tenantPageDashboard, "https://u-3f9a2c1d.superbased.app/"},
		{"no tenant domain", &Server{}, "acme", tenantPageDashboard, ""},
		{"no slug", s, "", tenantPageDashboard, ""},
	}
	for _, tc := range cases {
		if got := tc.srv.tenantLink(tc.slug, tc.page); got != tc.want {
			t.Errorf("%s: tenantLink(%q, %q) = %q, want %q", tc.name, tc.slug, tc.page, got, tc.want)
		}
	}
}

// TestOrgJSONLinks pins which links an org row carries per state and kind:
// every link comes from tenantLink, open_url and its deprecated twin
// dashboard_url agree, and only an active org with a host gets any.
func TestOrgJSONLinks(t *testing.T) {
	t.Parallel()
	s := &Server{tenantDomain: "superbased.app"}
	org := func(slug string, kind store.OrgKind, st pc.TenantState) store.MyOrg {
		return store.MyOrg{Org: store.Org{Slug: slug, Kind: kind, Status: st}}
	}
	cases := []struct {
		name                         string
		srv                          *Server
		o                            store.MyOrg
		open, machines, invite, host string
	}{
		{
			"active team", s, org("acme", store.OrgTeam, pc.StateActive),
			"https://acme.superbased.app/", "https://acme.superbased.app/me/profile", "https://acme.superbased.app/people-access?tab=invites", "acme.superbased.app",
		},
		{
			"active personal (no invite)", s, org("u-1a2b", store.OrgPersonal, pc.StateActive),
			"https://u-1a2b.superbased.app/", "https://u-1a2b.superbased.app/me/profile", "", "u-1a2b.superbased.app",
		},
		{"provisioning team", s, org("acme", store.OrgTeam, pc.StateProvisioning), "", "", "", "acme.superbased.app"},
		{"suspended team", s, org("acme", store.OrgTeam, pc.StateSuspended), "", "", "", "acme.superbased.app"},
		{"no tenant domain", &Server{}, org("acme", store.OrgTeam, pc.StateActive), "", "", "", ""},
	}
	for _, tc := range cases {
		v := tc.srv.orgJSON(tc.o)
		if v.OpenURL != tc.open || v.MachinesPageURL != tc.machines || v.InviteURL != tc.invite || v.Host != tc.host {
			t.Errorf("%s: open=%q machines=%q invite=%q host=%q, want %q %q %q %q",
				tc.name, v.OpenURL, v.MachinesPageURL, v.InviteURL, v.Host, tc.open, tc.machines, tc.invite, tc.host)
		}
		if v.DashboardURL != v.OpenURL {
			t.Errorf("%s: dashboard_url %q must equal open_url %q for one release", tc.name, v.DashboardURL, v.OpenURL)
		}
	}
}

// TestConnectOpenURL: the connect views open the chosen dashboard's home, and
// nothing without a target.
func TestConnectOpenURL(t *testing.T) {
	t.Parallel()
	s := &Server{tenantDomain: "superbased.app"}
	if got := s.connectOpenURL(nil); got != "" {
		t.Errorf("no target: %q, want empty", got)
	}
	if got, want := s.connectOpenURL(&store.ConnectTarget{Slug: "u-9f"}), "https://u-9f.superbased.app/"; got != want {
		t.Errorf("target: %q, want %q", got, want)
	}
}
