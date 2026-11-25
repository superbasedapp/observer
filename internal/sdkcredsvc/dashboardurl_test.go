package sdkcredsvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestDiscoveryDashboardURLRows is one case per dashboardURLRules row, plus
// the address forms OrgDashboardFrom accepts and refuses.
func TestDiscoveryDashboardURLRows(t *testing.T) {
	t.Parallel()
	signIn := func(orgID string) Status {
		return Status{SignedIn: true, Meta: Meta{KeyID: "ik_1", OrgID: orgID, Origin: KeyOriginSignIn}, KeyGatewayURL: "https://gw.acme.example"}
	}
	admin := func(gw string) Status {
		return Status{SignedIn: true, Meta: Meta{KeyID: "ik_2", Origin: KeyOriginAdminIssued}, KeyGatewayURL: gw}
	}
	acme := OrgDashboardFrom("o1", "", "https://observer-org.acme.example/")
	hosted := OrgDashboardFrom("o2", "https://u-sam.superbased.app/", "https://u-sam.superbased.app")
	cases := []struct {
		name string
		st   Status
		org  OrgDashboard
		want string
	}{
		{"no key held", Status{}, acme, ""},
		{"key file does not read back", Status{Meta: Meta{KeyID: "ik_1"}, Problem: "moved"}, acme, ""},
		{"key expired", func() Status { s := signIn("o1"); s.Expired = true; return s }(), acme, ""},
		{"not enrolled", signIn("o1"), OrgDashboard{}, ""},
		{"enrolment address is plain http to a remote host", signIn("o1"), OrgDashboardFrom("o1", "", "http://observer-org.acme.example"), ""},
		{"enrolment address carries credentials", signIn("o1"), OrgDashboardFrom("o1", "", "https://u:p@observer-org.acme.example"), ""},
		{"sign-in key of another organization", signIn("o9"), acme, ""},
		{"sign-in key of the enrolled organization", signIn("o1"), acme, "https://observer-org.acme.example"},
		{"sign-in key without an organization id", signIn(""), acme, "https://observer-org.acme.example"},
		{"description from before origins were recorded", Status{SignedIn: true, Meta: Meta{KeyID: "ik_1", OrgID: "o1"}}, acme, "https://observer-org.acme.example"},
		{"dashboard address is not https: loopback test org over http", signIn("o1"), OrgDashboardFrom("o1", "", "http://127.0.0.1:8443"), ""},
		{"online address recorded by connect wins", signIn("o2"), hosted, "https://u-sam.superbased.app"},
		{"admin-issued key sent to the dashboard's host", admin("https://u-sam.superbased.app"), hosted, "https://u-sam.superbased.app"},
		{"admin-issued key sent to the dashboard's host with a path", admin("https://u-sam.superbased.app/"), hosted, "https://u-sam.superbased.app"},
		{"admin-issued key sent elsewhere", admin("https://gw.other.example:4318"), hosted, ""},
		{"admin-issued key with no gateway", admin(""), hosted, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := discoveryDashboardURL(tc.st, tc.org); got != tc.want {
				t.Fatalf("dashboard_url = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDiscoveryCarriesDashboardURL pins the wire field: always present (""
// when unknown), never the key, and built the same way by
// BuildDiscoveryWithOrg; BuildDiscovery alone knows no enrolment.
func TestDiscoveryCarriesDashboardURL(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	st := Status{SignedIn: true, Meta: Meta{KeyID: "ik_1", OrgID: "o1"}, KeyGatewayURL: "https://gw.acme.example", CredentialFile: "/x"}
	org := OrgDashboardFrom("o1", "", "https://observer-org.acme.example")
	d := BuildDiscoveryWithOrg(cfg, st, "http://127.0.0.1:8081", org)
	if d.Online.DashboardURL != "https://observer-org.acme.example" || d.APIVersion != 1 {
		t.Fatalf("with enrolment: %+v", d.Online)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"dashboard_url":"https://observer-org.acme.example"`) {
		t.Fatalf("wire body: %s", raw)
	}
	if d := BuildDiscovery(cfg, st, "http://127.0.0.1:8081"); d.Online.DashboardURL != "" {
		t.Fatalf("without enrolment facts: %q", d.Online.DashboardURL)
	}
	raw, _ = json.Marshal(BuildDiscoveryWithOrg(cfg, Status{}, "http://127.0.0.1:8081", org))
	if !strings.Contains(string(raw), `"dashboard_url":""`) {
		t.Fatalf("an unknown dashboard must still carry the field: %s", raw)
	}
}
