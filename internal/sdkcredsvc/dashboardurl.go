package sdkcredsvc

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// The discovery body's online.dashboard_url (SDK quickstart plan 3.8): the
// base of the organization's own dashboard for the key this machine hands
// the SDKs, so an SDK can print a link to an app's first trace that went
// online (<dashboard_url>/trajectories?trace=<id>). It is a place for a
// person to look, never a place the key goes (the key goes only to its
// file's gateway_url line). Additive: api_version stays 1.
//
// The machine never guesses a host: the address comes from the enrolment
// row it already holds (settingslink.DashboardAddress: the online address
// `observer connect` recorded, else the org server address), and it is
// offered only when that organization is the key's.

// OrgDashboard is what the machine's enrolment says about its
// organization's own dashboard. The zero value is "not enrolled".
type OrgDashboard struct {
	// OrgID is the enrolled organization's id.
	OrgID string
	// Base is the dashboard's origin (scheme://host[:port], no trailing
	// slash), "" when the enrolment names no address a link may open.
	Base string
}

// OrgDashboardFrom builds the enrolment facts from the enrolment row's
// fields: its organization, the online address `observer connect` recorded
// and the org server address.
func OrgDashboardFrom(orgID, onlineURL, serverURL string) OrgDashboard {
	return OrgDashboard{
		OrgID: strings.TrimSpace(orgID),
		Base:  settingslink.OrgDashboardBase(settingslink.DashboardAddress(onlineURL, serverURL)),
	}
}

// dashboardURLFacts are the inputs of the dashboard_url rule table.
type dashboardURLFacts struct {
	keyUsable   bool
	adminIssued bool
	keyOrgID    string
	keyGateway  string // the key file's gateway_url line
	org         OrgDashboard
}

// dashboardURLRules decides whether the enrolment's dashboard is the key's,
// walked top-down; the first row that applies answers (true offers
// org.Base). One test case per row (dashboardurl_test.go).
var dashboardURLRules = []struct {
	name    string
	applies func(f dashboardURLFacts) bool
	offer   bool
}{
	// No key is offered to the SDKs (none held, its file does not read
	// back, or it expired): there is no online trace of this machine's key
	// to link to.
	{"no usable key", func(f dashboardURLFacts) bool { return !f.keyUsable }, false},
	// Not enrolled, or the enrolment names no address a link may open.
	{"no dashboard address", func(f dashboardURLFacts) bool { return f.org.Base == "" }, false},
	// The contract field is https only (destination.md section 4.1): a
	// loopback http org server (a local test organization) gets no link.
	{"dashboard address is not https", func(f dashboardURLFacts) bool { return !strings.HasPrefix(f.org.Base, "https://") }, false},
	// A sign-in key was minted by the enrolled organization; one the
	// machine kept from an earlier enrolment in another organization is not
	// that dashboard's.
	{"sign-in key of another organization", func(f dashboardURLFacts) bool {
		return !f.adminIssued && f.keyOrgID != "" && f.org.OrgID != "" && f.keyOrgID != f.org.OrgID
	}, false},
	{"sign-in key of the enrolled organization", func(f dashboardURLFacts) bool { return !f.adminIssued }, true},
	// An admin-issued key names no organization; it is the enrolled one's
	// only when the key goes to the dashboard's own host (a hosted
	// organization serves its dashboard and its ingest gateway on one host).
	{"admin-issued key sent to the dashboard's host", func(f dashboardURLFacts) bool {
		return settingslink.OrgDashboardBase(f.keyGateway) == f.org.Base
	}, true},
	{"admin-issued key sent elsewhere", func(dashboardURLFacts) bool { return true }, false},
}

// discoveryDashboardURL is online.dashboard_url for the key st describes.
func discoveryDashboardURL(st Status, org OrgDashboard) string {
	f := dashboardURLFacts{
		keyUsable:   st.Usable(),
		adminIssued: st.AdminIssued(),
		keyOrgID:    strings.TrimSpace(st.OrgID),
		keyGateway:  strings.TrimSpace(st.KeyGatewayURL),
		org:         org,
	}
	for _, r := range dashboardURLRules {
		if r.applies(f) {
			if r.offer {
				return org.Base
			}
			return ""
		}
	}
	return ""
}

// BuildDiscoveryWithOrg is BuildDiscovery with the enrolment's dashboard
// facts, which fill online.dashboard_url. The dashboard's discovery route
// and `observer sdk status` both build through it, so the two agree.
func BuildDiscoveryWithOrg(cfg config.Config, st Status, dashboardBase string, org OrgDashboard) Discovery {
	d := BuildDiscovery(cfg, st, dashboardBase)
	d.Online.DashboardURL = discoveryDashboardURL(st, org)
	return d
}
