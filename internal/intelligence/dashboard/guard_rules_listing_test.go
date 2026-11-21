package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// guardRulesListing fetches /api/guard/rules with query and returns its rows
// keyed by id (the first row of a multi-row id).
func guardRulesListing(t *testing.T, s *Server, query string) map[string]guardRuleJSON {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/guard/rules"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/guard/rules%s = %d: %s", query, rec.Code, rec.Body.String())
	}
	var resp struct {
		Rules []guardRuleJSON `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[string]guardRuleJSON{}
	for _, r := range resp.Rules {
		if _, ok := out[r.ID]; !ok {
			out[r.ID] = r
		}
	}
	return out
}

// TestAPIGuardRulesListsOrgCustomRules (round-3 finding): GET
// /api/guard/rules serves the one listing (guard.Guard.RuleListing) the
// Rules tab and `observer guard rules` read, so an org bundle's own [[rule]]
// entries appear with source "org" by default; ?catalog=1 is the built-in
// table.
func TestAPIGuardRulesListsOrgCustomRules(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "guard", "org-custom-rules-bundle.toml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	s, _, _ := newTrustedPolicyServer(t, string(raw))

	cases := []struct {
		name    string
		query   string
		present map[string]string // id -> want source
		absent  []string
	}{
		{"default", "", map[string]string{"ORG-1": "org", "ORG-2": "org", "R-101": "builtin"}, nil},
		{"effective=1, the old spelling", "?effective=1", map[string]string{"ORG-1": "org", "ORG-2": "org"}, nil},
		{"catalog=1 is the built-in table", "?catalog=1", map[string]string{"R-101": ""}, []string{"ORG-1", "ORG-2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := guardRulesListing(t, s, tc.query)
			for id, src := range tc.present {
				r, ok := rows[id]
				if !ok {
					t.Errorf("%s missing from the listing", id)
					continue
				}
				if src != "" && r.Source != src {
					t.Errorf("%s source = %q, want %q", id, r.Source, src)
				}
				if r.Project != "" {
					t.Errorf("%s project = %q, want an org-wide rule", id, r.Project)
				}
			}
			for _, id := range tc.absent {
				if _, ok := rows[id]; ok {
					t.Errorf("%s listed, want it absent", id)
				}
			}
		})
	}
}
