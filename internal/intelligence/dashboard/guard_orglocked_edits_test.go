package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
)

// orgLockBundle names R-172 (an org [[override]]), defines ORG-2 and marks
// R-110 overridable.
const orgLockBundle = `[[rule]]
id         = "ORG-2"
category   = "exfil"
severity   = "warn"
decision   = "ask"
match.url_domain = "paste.example.com"

[[override]]
rule = "R-172"
decision = "deny"
enforce = true

[[override]]
rule = "R-110"
overridable = true
`

// TestOrgLockedRulesRefuseLocalEdits (round-3 finding): the save paths that
// could disable or override a rule refuse one the organization sets on this
// node - every rule but an overridable one on a managed node, the rules its
// bundle names on an individual node - and accept anything else. The rule
// listing marks the same rules org_locked. The handlers are called directly:
// the governance guard in front of them (which on a managed node with no
// node.governance policy hides these pages altogether) is pinned elsewhere,
// and this test is about the gate behind it.
func TestOrgLockedRulesRefuseLocalEdits(t *testing.T) {
	type edit struct {
		path string // "user" | "trusted" | "config"
		kind string // "override" | "disable"
		id   string
	}
	cases := []struct {
		name    string
		managed bool
		e       edit
		refused bool
	}{
		{"managed: user override of a built-in", true, edit{"user", "override", "R-101"}, true},
		{"managed: user override of an overridable rule", true, edit{"user", "override", "R-110"}, false},
		{"managed: trusted disable of a built-in", true, edit{"trusted", "disable", "R-101"}, true},
		{"managed: trusted override of a named rule", true, edit{"trusted", "override", "R-172"}, true},
		{"managed: config disable of a built-in", true, edit{"config", "disable", "R-101"}, true},
		{"managed: config disable of an overridable rule", true, edit{"config", "disable", "R-110"}, false},
		{"individual: user override of an unnamed built-in", false, edit{"user", "override", "R-101"}, false},
		{"individual: user override of a named rule", false, edit{"user", "override", "R-172"}, true},
		{"individual: trusted disable of a named rule", false, edit{"trusted", "disable", "R-172"}, true},
		{"individual: trusted disable of an org-layer rule", false, edit{"trusted", "disable", "ORG-2"}, true},
		{"individual: trusted disable of an unnamed built-in", false, edit{"trusted", "disable", "R-101"}, false},
		{"individual: config disable of a named rule", false, edit{"config", "disable", "R-172"}, true},
		{"individual: config disable of an unnamed built-in", false, edit{"config", "disable", "R-101"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, tdir := newTrustedPolicyServer(t, orgLockBundle)
			managed := tc.managed
			s.opts.Governance = func(context.Context) govern.Effective { return govern.Effective{Managed: managed} }
			root := addKnownProject(t, s, tdir, "proj")

			var rec *httptest.ResponseRecorder
			switch tc.e.path {
			case "user":
				rec = callHandler(s.handleGuardPolicy, http.MethodPut, "/api/guard/policy", policyBody("[[override]]\nrule = \""+tc.e.id+"\"\ndecision = \"deny\"\n"))
			case "trusted":
				content := "[[override]]\nrule = \"" + tc.e.id + "\"\ndecision = \"allow\"\n"
				if tc.e.kind == "disable" {
					content = "disable = [\"" + tc.e.id + "\"]\n"
				}
				rec = callHandler(s.handleGuardProjectPolicy, http.MethodPut, "/api/guard/policy/project", projectBody(root, content))
			case "config":
				cfgPath := filepath.Join(tdir, "config.toml")
				cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
				if err != nil {
					t.Fatal(err)
				}
				cfg.Guard.Rules.Disable = []string{tc.e.id}
				body, err := json.Marshal(cfg.Guard)
				if err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				s.handleConfigSection(rec, confirmedReq(t, s, httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(string(body)))))
			}
			// A refusal is a 422 listing the rule (the trusted layer's own
			// org-floor lint already refuses a disable of an org-floored rule;
			// the org-lock gate refuses the rest).
			gotRefused := rec.Code == http.StatusUnprocessableEntity && strings.Contains(rec.Body.String(), tc.e.id)
			if gotRefused != tc.refused {
				t.Fatalf("%+v: status %d body %s; refused = %v, want %v", tc.e, rec.Code, rec.Body.String(), gotRefused, tc.refused)
			}
			if !tc.refused && rec.Code != http.StatusOK {
				t.Fatalf("%+v: status %d body %s, want 200", tc.e, rec.Code, rec.Body.String())
			}
			if tc.refused && tc.e.path == "user" {
				if _, err := os.Stat(filepath.Join(tdir, "guard-policy.toml")); err == nil {
					t.Errorf("a refused save wrote the user policy file")
				}
			}

			// The listing marks the same rules org_locked.
			lrec := callHandler(s.handleGuardRules, http.MethodGet, "/api/guard/rules", "")
			var listing struct {
				Rules []guardRuleJSON `json:"rules"`
			}
			if err := json.Unmarshal(lrec.Body.Bytes(), &listing); err != nil {
				t.Fatal(err)
			}
			rows := map[string]guardRuleJSON{}
			for _, r := range listing.Rules {
				rows[r.ID] = r
			}
			if r, ok := rows[tc.e.id]; ok && r.OrgLocked != tc.refused {
				t.Errorf("listing %s org_locked = %v, want %v", tc.e.id, r.OrgLocked, tc.refused)
			}
		})
	}
}

// TestGuardRulesListingSeparatesSetFromLocked (2026-11-12 operator report):
// on a managed node every rule is org_locked, but only the rules the org's
// bundle sets itself are org_named; the dashboard labels the rest "Locked by
// your organization", not "Set by your organization". One case per row kind.
func TestGuardRulesListingSeparatesSetFromLocked(t *testing.T) {
	cases := []struct {
		managed       bool
		id            string
		locked, named bool
	}{
		{true, "R-121", true, false},   // a built-in the bundle never names
		{true, "R-172", true, true},    // a built-in the bundle overrides
		{true, "ORG-2", true, true},    // a rule the bundle defines
		{true, "R-110", false, true},   // named only to mark it overridable
		{false, "R-121", false, false}, // individual: the lock reaches named rules only
		{false, "R-172", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			s, _, _ := newTrustedPolicyServer(t, orgLockBundle)
			managed := tc.managed
			s.opts.Governance = func(context.Context) govern.Effective { return govern.Effective{Managed: managed} }
			lrec := callHandler(s.handleGuardRules, http.MethodGet, "/api/guard/rules", "")
			var listing struct {
				Rules []guardRuleJSON `json:"rules"`
			}
			if err := json.Unmarshal(lrec.Body.Bytes(), &listing); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range listing.Rules {
				if r.ID != tc.id {
					continue
				}
				found = true
				if r.OrgLocked != tc.locked || r.OrgNamed != tc.named {
					t.Errorf("managed=%v %s: org_locked %v org_named %v; want %v %v", tc.managed, tc.id, r.OrgLocked, r.OrgNamed, tc.locked, tc.named)
				}
			}
			if !found {
				t.Fatalf("%s not listed", tc.id)
			}
		})
	}
}

// callHandler runs one handler directly with a JSON body (or none).
func callHandler(h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}
