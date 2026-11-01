package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// postureProvider resolves a real posture through govern.Resolve: consent is
// the grant's consent mode (managed / interactive), body is the org's
// node.governance input (nil = nothing published).
func postureProvider(t *testing.T, consent string, body *nodegov.PolicyInput, authority ...string) GovernanceProvider {
	t.Helper()
	var delivered govern.Delivered
	if body != nil {
		spec, err := nodegov.Compile(*body)
		if err != nil {
			t.Fatalf("nodegov.Compile: %v", err)
		}
		delivered = govern.Delivered{Present: true, Version: 21, BodyHash: "bh", Spec: spec}
	}
	now := time.Now().UTC()
	grant := &govern.Grant{
		OrgKey: "ok", Generation: 1, OrgName: "Acme", KeyPinSHA256: "pin",
		Authority: authority, ConsentMode: consent, ExpiresAt: now.Add(24 * time.Hour),
	}
	live := govern.LiveIdentity{Enrolled: true, OrgKey: "ok", Generation: 1, KeyPinSHA256: "pin"}
	eff := govern.Resolve(delivered, grant, live, now)
	return func(context.Context) govern.Effective { return eff }
}

func governanceRefusalCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusConflict {
		return ""
	}
	var refusal governanceRefusal
	if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err != nil || refusal.Family != "node.governance" {
		return ""
	}
	return refusal.Error
}

// TestManagedDefaultsRefusedAtTheAPI: a managed machine with NOTHING
// published refuses the defaulted pages and Settings sections at the API, on
// the loopback chain the developer's own browser uses, and leaves the
// developer's own pages alone.
func TestManagedDefaultsRefusedAtTheAPI(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		Governance: postureProvider(t, govern.ConsentManaged, nil, govern.AuthoritySettingsPin),
	})
	h := s.guardedHandler("127.0.0.1:8081")
	cases := []struct {
		name, method, path, want string
	}{
		{"security page hidden", http.MethodGet, "/api/guard/summary", "governance_hidden"},
		{"guard policy hidden", http.MethodPut, "/api/guard/policy", "governance_hidden"},
		{"routing page hidden", http.MethodGet, "/api/routing/status", "governance_hidden"},
		// Code security is hidden by default (lane gov-tabs); its trust READ
		// stays for the New Terminal dialog because Terminals is shown, and
		// accepting trust stays with the hidden page.
		{"code security page hidden", http.MethodGet, "/api/security/status", "governance_hidden"},
		{"code security findings hidden", http.MethodGet, "/api/security/findings", "governance_hidden"},
		{"trust chip read shared with terminals", http.MethodGet, "/api/security/trust", ""},
		{"trust accept stays code security", http.MethodPost, "/api/security/trust", "governance_hidden"},
		{"compression read: allowed", http.MethodGet, "/api/compression/events", ""},
		{"compression experiment write: read-only", http.MethodPost, "/api/experiments", "governance_read_only"},
		{"remote read: allowed", http.MethodGet, "/api/remote/config", ""},
		{"remote enable: read-only", http.MethodPost, "/api/remote/enable", "governance_read_only"},
		{"guard settings hidden", http.MethodPut, "/api/config/section/guard", "governance_hidden"},
		{"proxy settings read-only", http.MethodPut, "/api/config/section/proxy", "governance_read_only"},
		{"pricing write outside the section route", http.MethodPut, "/api/config/pricing", "governance_read_only"},
		{"hook setup writer", http.MethodPost, "/api/setup/hooks", "governance_read_only"},
		{"mcp setup writer", http.MethodPost, "/api/setup/mcp", "governance_read_only"},
		{"telemetry export writer", http.MethodPost, "/api/setup/telemetry", "governance_read_only"},
		{"windows-home init writer", http.MethodPost, "/api/setup/windows-homes/apply", "governance_read_only"},
		// Personal Cloud Intelligence is HIDDEN on a managed machine since the
		// CI parity arc (design Q8); the org plane is the `intel` section,
		// read-only, whose Enrich action the org's own setting decides.
		{"cloud sign-in (personal plane hidden)", http.MethodPost, "/api/cloud/login", "governance_hidden"},
		{"org plane accept: read-only", http.MethodPost, "/api/intel/accept", "governance_read_only"},
		{"org plane session read: allowed", http.MethodGet, "/api/intel/session/s1", ""},
		{"process capture toggle", http.MethodPost, "/api/process/enable-capture", "governance_read_only"},
		{"whole-config restore", http.MethodPost, "/api/config/backup", "governance_read_only"},
		{"whole-config backup preview (guard settings hidden)", http.MethodGet, "/api/config/backup", "governance_hidden"},
		{"compression profiles", http.MethodPut, "/api/config/profiles", "governance_read_only"},
		// T-369: the per-tool assignment control shares the profiles guard.
		{"per-tool profile assignment write", http.MethodPut, "/api/config/profile-assignments", "governance_read_only"},
		{"per-tool profile assignment removal", http.MethodDelete, "/api/config/profile-assignments", "governance_read_only"},
		{"per-tool profile assignment read", http.MethodGet, "/api/config/profile-assignments", ""},
		// T-421 item 1: the per-project assignment control shares it too.
		{"per-project profile assignment write", http.MethodPut, "/api/config/project-profiles", "governance_read_only"},
		{"per-project profile assignment removal", http.MethodDelete, "/api/config/project-profiles", "governance_read_only"},
		{"per-project profile assignment read", http.MethodGet, "/api/config/project-profiles", ""},
		{"own sessions", http.MethodGet, "/api/sessions", ""},
		{"own cost", http.MethodGet, "/api/cost", ""},
		{"own budget warnings", http.MethodGet, "/api/budget/status", ""},
		{"advisor settings stay writable", http.MethodPut, "/api/config/section/advisor", ""},
		{"enrolment (floor)", http.MethodGet, "/api/enrolment/status", ""},
		{"governance endpoint", http.MethodGet, "/api/governance", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(tc.method, tc.path))
			if got := governanceRefusalCode(t, rec); got != tc.want {
				t.Fatalf("%s %s refusal = %q, want %q (status %d, body %s)", tc.method, tc.path, got, tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestManagedExposeLiftsTheDefault: the org's schema-3 expose list brings a
// defaulted page and Settings section back, and nothing else.
func TestManagedExposeLiftsTheDefault(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		Governance: postureProvider(t, govern.ConsentManaged,
			&nodegov.PolicyInput{VisibleSections: []string{"security"}, VisibleSettings: []string{"guard"}}),
	})
	h := s.guardedHandler("127.0.0.1:8081")
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/api/guard/summary", ""},
		{http.MethodPut, "/api/config/section/guard", ""},
		{http.MethodGet, "/api/routing/status", "governance_hidden"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(tc.method, tc.path))
		if got := governanceRefusalCode(t, rec); got != tc.want {
			t.Errorf("%s %s refusal = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestIndividualNodeHasNoDefaults: the same routes on an individual
// (interactive-consent) enrolment are untouched.
func TestIndividualNodeHasNoDefaults(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		Governance: postureProvider(t, govern.ConsentInteractive, nil, govern.AuthorityDashboardVisibility),
	})
	h := s.guardedHandler("127.0.0.1:8081")
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/guard/summary"},
		{http.MethodGet, "/api/routing/status"},
		{http.MethodPost, "/api/experiments"},
		{http.MethodPut, "/api/config/section/guard"},
		{http.MethodPut, "/api/config/pricing"},
		{http.MethodPost, "/api/config/backup"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(tc.method, tc.path))
		if got := governanceRefusalCode(t, rec); got != "" {
			t.Errorf("%s %s refused (%s) on an individual node", tc.method, tc.path, got)
		}
	}
}

// TestGovernanceEndpointVisibilityBlock: GET /api/governance carries the
// resolved visibility the SPA filters on, for both tenancies.
func TestGovernanceEndpointVisibilityBlock(t *testing.T) {
	for _, tc := range []struct {
		name        string
		consent     string
		wantManaged bool
		wantHidden  bool
	}{
		{"managed", govern.ConsentManaged, true, true},
		{"individual", govern.ConsentInteractive, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRemoteTestServer(t, Options{Governance: postureProvider(t, tc.consent, nil)})
			rec := httptest.NewRecorder()
			s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			var resp struct {
				Visibility govern.DashboardVisibility `json:"visibility"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			v := resp.Visibility
			if v.ManagedDefaults != tc.wantManaged {
				t.Fatalf("managed_defaults = %v", v.ManagedDefaults)
			}
			if containsID(v.HiddenSections, "security") != tc.wantHidden {
				t.Fatalf("hidden_sections = %v", v.HiddenSections)
			}
			if len(v.Sections) != len(nodegov.NavSectionIDs) || len(v.Settings) != len(nodegov.SettingsSectionIDs) {
				t.Fatalf("visibility block does not cover the vocabulary: %d/%d", len(v.Sections), len(v.Settings))
			}
			if v.HiddenSections == nil || v.ReadOnlySettings == nil {
				t.Fatal("visibility lists must be [] not null")
			}
		})
	}
}

func containsID(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// TestSettingsSubsectionForRoute resolves a request path through the REAL mux
// and the registered route metadata, exactly as governanceGuard does.
func TestSettingsSubsectionForRoute(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	mux, _, sections := s.registerRoutes(nil)
	for _, tc := range []struct{ path, want string }{
		{"/api/config/section/guard", "guard"},
		{"/api/config/pricing", "pricing"},
		{"/api/config/pricing/defaults", "pricing"},
		{"/api/setup/codex-hooks", "hooks"},
		{"/api/setup/mcp", "mcp"},
		{"/api/setup/telemetry", "hooks"},
		{"/api/setup/windows-homes", "hooks"},
		{"/api/setup/windows-homes/apply", "hooks"},
		{"/api/process/etw/register", "process"},
		{"/api/process/findings", ""},
		{"/api/cloud/login/state", "cloud"},
		{"/api/cloud/session/abc", "cloud"},
		{"/api/reprice/apply", "pricing"},
		{"/api/prune/run", "retention"},
		{"/api/backfill/jobs", "backfill"},
		{"/api/scan/run", "backfill"},
		{"/api/storage", "storage"},
		{"/api/storage/vacuum", "storage"},
		{"/api/tools/launch", "tools"},
		{"/api/terminal/installs/forget", "tools"},
		{"/api/health/doctor", "health"},
		{"/api/jobs/doctor-integrity", "health"},
		{"/api/jobs/doctor-integrity/cancel", "health"},
		{"/api/jobs/reclaim-cleanup", "storage"},
		{"/api/jobs/reclaim-cleanup/cancel", "storage"},
		{"/api/health/doctor/tool", "tools"},
		{"/api/shell-wrap/apply", "terminal"},
		{"/api/config/profiles/fast", "profiles"},
		{"/api/config/profile-assignments", "profiles"},
		{"/api/config/project-profiles", "profiles"},
		{"/api/config", ""},
		{"/api/update/status", ""},
	} {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, tc.path, nil))
		_, sub := sections[pattern].Split()
		if got := settingsSubsectionFor(sub, tc.path); got != tc.want {
			t.Errorf("%s (route %q) resolves to subsection %q, want %q", tc.path, pattern, got, tc.want)
		}
	}
}
