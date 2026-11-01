//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityOrgNotice (lane SEC-E3, ruling P-089): inactive with nothing
// shared and no floor; while a floor or sharing is on it names what is
// shared, the stored purpose's label (never server text), what the org's
// views can see under its settings, and the "Not for evaluating" line only
// when the org shows it.
func TestSecurityOrgNotice(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	get := func() securityOrgNoticeJS {
		w := httptest.NewRecorder()
		s.handleSecurityOrgNotice(w, httptest.NewRequest(http.MethodGet, "/api/security/org-notice", nil))
		var out securityOrgNoticeJS
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if n := get(); n.Active {
		t.Fatalf("no seam must be inactive: %+v", n)
	}
	share := dashapi.SecurityOrgShare{Level: "off"}
	s.opts.SecurityOrgShare = func(context.Context) (dashapi.SecurityOrgShare, bool) { return share, true }
	if n := get(); n.Active {
		t.Fatalf("nothing shared and no floor must be inactive: %+v", n)
	}
	share = dashapi.SecurityOrgShare{Level: "findings", Managed: true, FloorsInForce: true}
	if err := store.New(s.db()).SetSecurityOrgPurpose(context.Background(), "audit_evidence"); err != nil {
		t.Fatal(err)
	}
	n := get()
	if !n.Active || len(n.Shared) != 4 || n.Purpose != "Audit evidence" || !n.PurposeStated || n.NotFor != "" ||
		len(n.OrgSees) != 1 || !strings.Contains(n.OrgSees[0], "not yet told") {
		t.Fatalf("notice before the settings are heard: %+v", n)
	}
	// The org's defaults (P-089): every field, no group hidden, no statement.
	if err := store.New(s.db()).SetSecurityOrgVisibility(context.Background(), orgcontract.SecurityVisibility{MinGroup: 1, HiddenFields: []string{}}); err != nil {
		t.Fatal(err)
	}
	n = get()
	all := strings.Join(n.OrgSees, " ")
	if n.NotFor != "" || len(n.OrgSees) != len(orgcontract.SecurityVisibilityFields)+2 ||
		!strings.Contains(all, "traced to the person") || !strings.Contains(all, "singled out") || !strings.Contains(all, "not a privacy promise") {
		t.Fatalf("notice under the defaults: %+v", n)
	}
	// A raised minimum, the drill-down off and the statement on.
	if err := store.New(s.db()).SetSecurityOrgVisibility(context.Background(), orgcontract.SecurityVisibility{MinGroup: 5, HiddenFields: []string{"drill_down"}, PurposeStatement: true}); err != nil {
		t.Fatal(err)
	}
	n = get()
	all = strings.Join(n.OrgSees, " ")
	if !strings.Contains(n.NotFor, "Not for evaluating") || strings.Contains(all, "traced to the person") || !strings.Contains(all, "fewer than 5 members") {
		t.Fatalf("notice under raised settings: %+v", n)
	}
	if err := store.New(s.db()).SetSecurityOrgPurpose(context.Background(), "unset"); err != nil {
		t.Fatal(err)
	}
	share = dashapi.SecurityOrgShare{Level: "posture"}
	if n := get(); !n.Active || n.PurposeStated || len(n.Shared) != 1 || len(n.OrgSees) != 2 {
		t.Fatalf("posture, no purpose (no per-finding lines at posture): %+v", n)
	}
}
