package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// TestStaffTeamAllowlistRoutes covers the staff console's W17 routes over
// Postgres: ops adds and removes entries (each with a staff_actions row),
// support reads but is refused a change, input and reason are validated, a
// duplicate is 409 and an unknown entry 404.
func TestStaffTeamAllowlistRoutes(t *testing.T) {
	t.Parallel()
	h := newStaffPGHarness(t)
	_, _, ops, opsCSRF := h.staff(staffauth.RoleOps, api.NewStaffTestAuthenticator(41))
	_, _, sup, supCSRF := h.staff(staffauth.RoleSupport, api.NewStaffTestAuthenticator(42))
	opsH := map[string]string{"X-SBCI-Staff-CSRF": opsCSRF}

	add := h.do("POST", "/staff/api/team-allowlist",
		map[string]string{"kind": "email_domain", "value": "@Marmut.App", "reason": "our own domain"}, []*http.Cookie{ops}, opsH)
	if add.Code != http.StatusCreated {
		t.Fatalf("add = %d %s", add.Code, add.Body)
	}
	var entry struct {
		EntryID string `json:"entry_id"`
		Value   string `json:"value"`
	}
	if err := json.Unmarshal(add.Body.Bytes(), &entry); err != nil || entry.Value != "marmut.app" || entry.EntryID == "" {
		t.Fatalf("added entry = %s (%v)", add.Body, err)
	}
	if rec := h.do("POST", "/staff/api/team-allowlist",
		map[string]string{"kind": "email_domain", "value": "marmut.app", "reason": "again"}, []*http.Cookie{ops}, opsH); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate add = %d %s", rec.Code, rec.Body)
	}
	for name, body := range map[string]map[string]string{
		"an address":   {"kind": "email_domain", "value": "a@b.com", "reason": "x"},
		"not a uuid":   {"kind": "account", "value": "bob", "reason": "x"},
		"no reason":    {"kind": "email_domain", "value": "example.com"},
		"unknown kind": {"kind": "email", "value": "example.com", "reason": "x"},
	} {
		if rec := h.do("POST", "/staff/api/team-allowlist", body, []*http.Cookie{ops}, opsH); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, rec.Code, rec.Body)
		}
	}

	// Support reads; a change is refused by the authorization table.
	list := h.do("GET", "/staff/api/team-allowlist", nil, []*http.Cookie{sup}, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"value":"marmut.app"`) {
		t.Fatalf("support list = %d %s", list.Code, list.Body)
	}
	if rec := h.do("DELETE", "/staff/api/team-allowlist/"+entry.EntryID, map[string]string{"reason": "x"},
		[]*http.Cookie{sup}, map[string]string{"X-SBCI-Staff-CSRF": supCSRF}); rec.Code != http.StatusForbidden {
		t.Fatalf("support remove = %d %s, want 403", rec.Code, rec.Body)
	}

	if rec := h.do("DELETE", "/staff/api/team-allowlist/"+entry.EntryID, map[string]string{"reason": "domain retired"},
		[]*http.Cookie{ops}, opsH); rec.Code != http.StatusOK {
		t.Fatalf("remove = %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("DELETE", "/staff/api/team-allowlist/"+entry.EntryID, map[string]string{"reason": "again"},
		[]*http.Cookie{ops}, opsH); rec.Code != http.StatusNotFound {
		t.Fatalf("second remove = %d %s, want 404", rec.Code, rec.Body)
	}
	if list := h.do("GET", "/staff/api/team-allowlist", nil, []*http.Cookie{ops}, nil); strings.Contains(list.Body.String(), "marmut.app") {
		t.Fatalf("active list still has the removed entry: %s", list.Body)
	}
	if list := h.do("GET", "/staff/api/team-allowlist?include_removed=1", nil, []*http.Cookie{ops}, nil); !strings.Contains(list.Body.String(), `"removed_reason":"domain retired"`) {
		t.Fatalf("full list = %s", list.Body)
	}

	log := h.do("GET", "/staff/api/log?limit=100", nil, []*http.Cookie{ops}, nil)
	for _, verb := range []string{"team_allowlist.added", "team_allowlist.removed"} {
		if !strings.Contains(log.Body.String(), `"verb":"`+verb+`"`) {
			t.Errorf("log lacks %s", verb)
		}
	}
	if !strings.Contains(log.Body.String(), `"target":"team_allowlist.write"`) {
		t.Error("log lacks support's refused change")
	}
}
