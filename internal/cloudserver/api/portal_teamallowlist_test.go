package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestPortalTeamCreateAllowlist covers the W17 gate end to end over a real
// PostgreSQL with the server bound to sbci_api: with the switch on, a
// stranger's team create is a 403 in plain words carrying the account
// reference, the list says invite_only and create_allowed=false, and once the
// account is allow-listed the same create succeeds. With the switch off the
// list says invite_only=false.
func TestPortalTeamCreateAllowlist(t *testing.T) {
	h := newOrgsHarnessWith(t, func(o *api.Options) { o.TeamCreateAllowlist = true })
	c := h.portalLogin(t, "allow-ann")

	type flags struct {
		TeamOrgs *struct {
			InviteOnly    bool `json:"invite_only"`
			CreateAllowed bool `json:"create_allowed"`
		} `json:"team_orgs"`
	}
	readFlags := func() flags {
		t.Helper()
		resp := c.get("/portal/api/orgs")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list status=%d", resp.StatusCode)
		}
		var f flags
		decode(t, resp, &f)
		if f.TeamOrgs == nil {
			t.Fatal("no team_orgs")
		}
		return f
	}
	if f := readFlags(); !f.TeamOrgs.InviteOnly || f.TeamOrgs.CreateAllowed {
		t.Fatalf("stranger flags = %+v", *f.TeamOrgs)
	}

	resp := orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": "Ann", "slug": "ann-team"}, c.csrf, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger create status=%d body=%s, want 403", resp.StatusCode, readAll(resp))
	}
	var e struct {
		Code       string `json:"code"`
		Error      string `json:"error"`
		AccountRef string `json:"account_ref"`
	}
	decode(t, resp, &e)
	if e.Code != "team_create_invite_only" || !strings.Contains(e.Error, "by invitation") || e.AccountRef != c.accountID {
		t.Fatalf("refusal = %+v (account %s)", e, c.accountID)
	}

	// Staff (here the operator path) adds the account.
	if _, err := h.store.AddTeamAllowlistEntry(context.Background(),
		staffauth.AllowlistEntry{Kind: staffauth.AllowlistAccount, Value: c.accountID},
		store.TeamAllowlistChange{Reason: "canary", Now: time.Now()}); err != nil {
		t.Fatalf("allow-list: %v", err)
	}
	if f := readFlags(); !f.TeamOrgs.InviteOnly || !f.TeamOrgs.CreateAllowed {
		t.Fatalf("invited flags = %+v", *f.TeamOrgs)
	}
	createTeam(t, c, "Ann", "ann-team")

	off := newOrgsHarness(t)
	oc := off.portalLogin(t, "allow-bob")
	resp = oc.get("/portal/api/orgs")
	var f flags
	decode(t, resp, &f)
	if f.TeamOrgs == nil || f.TeamOrgs.InviteOnly || !f.TeamOrgs.CreateAllowed {
		t.Fatalf("switch off flags = %+v", f.TeamOrgs)
	}
}
