package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// loopbackRequest builds a request the loopback browserGuard accepts: same
// Host as the bind, and an Origin matching it so the CSRF check passes for
// unsafe methods. The governance guard must be provably reached through the
// REAL loopback chain, not around it.
func loopbackRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:8081"
	r.Header.Set("Origin", "http://127.0.0.1:8081")
	return r
}

// governedProvider builds a GovernanceProvider that returns an ACTIVE
// posture hiding/locking the given ids — the shape a real node resolves when
// its grant carries dashboard.visibility and the org published a body.
func governedProvider(t *testing.T, hidden, readOnly, settingsHidden, settingsReadOnly []string) GovernanceProvider {
	t.Helper()
	spec, err := nodegov.Compile(nodegov.PolicyInput{
		HiddenSections:   hidden,
		ReadOnlySections: readOnly,
		HiddenSettings:   settingsHidden,
		ReadOnlySettings: settingsReadOnly,
		Notice:           nodegov.Notice{OrgDisplayName: "Acme Platform Engineering"},
	})
	if err != nil {
		t.Fatalf("nodegov.Compile: %v", err)
	}
	now := time.Now().UTC()
	grant := &govern.Grant{
		OrgKey: "ok", Generation: 1, OrgName: "Acme", KeyPinSHA256: "pin",
		Authority: []string{govern.AuthorityDashboardVisibility},
		ExpiresAt: now.Add(24 * time.Hour),
	}
	live := govern.LiveIdentity{Enrolled: true, OrgKey: "ok", Generation: 1, KeyPinSHA256: "pin"}
	delivered := govern.Delivered{Present: true, Version: 14, BodyHash: "bh", Spec: spec}
	eff := govern.Resolve(delivered, grant, live, now)
	if !eff.Active || eff.State != govern.StateApplied {
		t.Fatalf("test fixture did not resolve to an applied posture: %+v", eff)
	}
	return func(context.Context) govern.Effective { return eff }
}

// TestGovernanceAPIRefusesHiddenRoutes is THE load-bearing test of Phase 1a.
//
// It drives the LOOPBACK listener chain — s.guardedHandler on a loopback
// address, with no RemoteController — which is exactly where the adversarial
// review found the enforcement would have been missing: capMap (the obvious
// place to hang a second predicate) is consulted only by remoteAuthz, and
// Server.Handler() discards it. A UI-only hide, or a guard installed only on
// the remote branch, fails here.
func TestGovernanceAPIRefusesHiddenRoutes(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		Governance: governedProvider(
			t,
			[]string{"benchmarks", "terminals"}, // hidden nav sections
			[]string{"policies"},                // read-only nav section
			[]string{"process"},                 // hidden settings section
			[]string{"guard"},                   // read-only settings section
		),
	})
	// The loopback branch: no remote controller, a loopback bind.
	h := s.guardedHandler("127.0.0.1:8081")

	cases := []struct {
		name   string
		method string
		path   string
		want   int
		code   string
	}{
		{"hidden section GET is 404", http.MethodGet, "/api/benchmarks", http.StatusNotFound, "governance_hidden"},
		{"hidden section subtree GET is 404", http.MethodGet, "/api/benchmarks/x", http.StatusNotFound, "governance_hidden"},
		{"hidden terminals route is 404", http.MethodGet, "/api/terminal/sessions", http.StatusNotFound, "governance_hidden"},
		{"read-only section mutation is 409", http.MethodPut, "/api/guard/policy", http.StatusConflict, "governance_read_only"},
		{"hidden settings section write is 404", http.MethodPut, "/api/config/section/process", http.StatusNotFound, "governance_hidden"},
		{"read-only settings section write is 409", http.MethodPut, "/api/config/section/guard", http.StatusConflict, "governance_read_only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(tc.method, tc.path))
			if rec.Code != tc.want {
				t.Fatalf("%s %s = %d, want %d (body %s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
			}
			var refusal governanceRefusal
			if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err != nil {
				t.Fatalf("refusal body is not JSON: %v (%s)", err, rec.Body.String())
			}
			if refusal.Error != tc.code {
				t.Fatalf("refusal code = %q, want %q", refusal.Error, tc.code)
			}
			if refusal.Message == "" || refusal.OrgName == "" {
				t.Fatalf("refusal must NAME its cause and the organization, got %+v", refusal)
			}
		})
	}
}

// TestGovernanceAPIAllowsUngovernedRoutes is the other half: governance
// refuses what it was told to refuse and NOTHING else. Without it the guard
// could pass the test above by refusing everything.
func TestGovernanceAPIAllowsUngovernedRoutes(t *testing.T) {
	s := newRemoteTestServer(t, Options{
		Governance: governedProvider(t, []string{"benchmarks"}, []string{"policies"}, nil, nil),
	})
	h := s.guardedHandler("127.0.0.1:8081")

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/status"},                  // secNone, never hidden
		{http.MethodGet, "/api/sessions"},                // a governed-but-visible section
		{http.MethodGet, "/api/guard/policy"},            // read-only section: READS still work
		{http.MethodGet, "/api/governance"},              // the honesty endpoint itself
		{http.MethodPut, "/api/config/section/observer"}, // an ungoverned settings section
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(tc.method, tc.path))
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusConflict {
			var refusal governanceRefusal
			if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err == nil && refusal.Family == "node.governance" {
				t.Fatalf("%s %s was refused by governance (%s) but is not governed", tc.method, tc.path, refusal.Error)
			}
		}
	}
}

// TestGovernanceCannotHideItsOwnEvidence is T8 at the ROUTE level: even if a
// posture somehow named them, the routes a developer needs in order to see
// what is happening to them keep working. (The compiler refuses such a body
// outright — this is the second, independent line.)
func TestGovernanceCannotHideItsOwnEvidence(t *testing.T) {
	eff := govern.Effective{
		Active: true, State: govern.StateApplied, Version: 9,
		HiddenSections:   []string{"settings", "privacy", "benchmarks"},
		HiddenSettings:   []string{"enrolment", "org"},
		ReadOnlySections: []string{},
		ReadOnlySettings: []string{},
	}
	s := newRemoteTestServer(t, Options{Governance: func(context.Context) govern.Effective { return eff }})
	h := s.guardedHandler("127.0.0.1:8081")

	for _, path := range []string{
		"/api/enrolment/status",   // secSettings — the unhideable enrolment view
		"/api/privacy/scrub-test", // secPrivacy — the unhideable privacy page
		"/api/governance",         // how the SPA learns it is managed at all
		"/api/config",             // secSettings — the settings page's own read
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(http.MethodGet, path))
		if rec.Code == http.StatusNotFound {
			var refusal governanceRefusal
			if err := json.Unmarshal(rec.Body.Bytes(), &refusal); err == nil && refusal.Error == "governance_hidden" {
				t.Fatalf("%s was hidden by governance - a developer could not see what their organization configured", path)
			}
		}
	}
}

// TestEveryDashboardRouteHasASection is the coverage gate (adversarial
// review A9): every registered route carries an EXPLICIT section decision,
// so a new route cannot silently inherit membership in a hidden page — or
// silently leak one.
func TestEveryDashboardRouteHasASection(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, sections := s.registerRoutes(nil)
	if len(capMap) < 50 {
		t.Fatalf("suspiciously few routes registered (%d) - the registry may not be wired", len(capMap))
	}
	known := map[Section]bool{SectionNone: true}
	for _, sec := range AllSections {
		known[sec] = true
	}
	for pattern := range capMap {
		reg, ok := sections[pattern]
		if !ok {
			t.Errorf("route %q has no section entry - every reg() must name a Section (or SectionNone)", pattern)
			continue
		}
		sec, _ := reg.Split()
		if !known[sec] {
			t.Errorf("route %q names section %q, which is not in the closed vocabulary", pattern, sec)
		}
	}
	if len(sections) != len(capMap) {
		t.Errorf("section map has %d entries, capability map has %d - the two registries have diverged", len(sections), len(capMap))
	}
}

// TestDashboardSectionsMatchNodegovVocabulary pins the route-side section
// vocabulary to the POLICY-side one. Without it, an admin could publish a
// perfectly valid body naming a page whose routes no guard would ever match.
func TestDashboardSectionsMatchNodegovVocabulary(t *testing.T) {
	policy := map[string]bool{}
	for _, id := range nodegov.NavSectionIDs {
		policy[id] = true
	}
	dash := map[string]bool{}
	for _, sec := range AllSections {
		dash[string(sec)] = true
	}
	for id := range policy {
		if !dash[id] {
			t.Errorf("nodegov knows nav section %q but internal/intelligence/dashboard does not - a published directive for it would enforce nothing", id)
		}
	}
	for id := range dash {
		if !policy[id] {
			t.Errorf("dashboard knows section %q but nodegov does not - no org could ever address it", id)
		}
	}
}

// TestGovernanceEndpointDormantWithoutProvider pins the solo shape at the
// HTTP layer: the route exists, answers, and says nothing is governed.
func TestGovernanceEndpointDormantWithoutProvider(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/governance = %d, want 200", rec.Code)
	}
	var eff govern.Effective
	if err := json.Unmarshal(rec.Body.Bytes(), &eff); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if eff.Active {
		t.Fatalf("a node with no governance provider reported Active: %+v", eff)
	}
	if len(eff.HiddenSections)+len(eff.ReadOnlySections)+len(eff.HiddenSettings)+len(eff.ReadOnlySettings) != 0 {
		t.Fatalf("dormant posture carries directives: %+v", eff)
	}
	if eff.HiddenSections == nil {
		t.Fatal("hidden_sections is null rather than [] - the SPA would have to null-check every list")
	}
}

// writeShareConfig writes a config.toml carrying only an [org_client.share]
// block and returns its path — the node's OWN sharing settings, the `local`
// half of every row the governance endpoint resolves.
func writeShareConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[org_client.share]\n"+body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestGovernanceShareBlockIsObjectShaped is the regression for the T8
// serialization defect.
//
// The handler used to serialize govern.Effective verbatim, so `share` went
// out as the org's raw directives — bare booleans. web/src/lib/governance.ts
// declares each entry as {effective, local, source}, and Privacy.tsx reads
// .source and .effective off it, so every row rendered a raised tier as "not
// shared" and looked its label up under `undefined`. This asserts the object
// shape at the BYTE level (not just that a tolerant decode succeeds), because
// a bare `true` decodes into the struct without error — as null fields.
func TestGovernanceShareBlockIsObjectShaped(t *testing.T) {
	eff := govern.Effective{
		Active: true, State: govern.StateApplied, Version: 21, Managed: true,
		// extract.cache is the per-tier authority W-8's ExtractionAuthorized
		// gate requires before cache_detail's raise below is honest — see
		// internal/govern/sharetiers.go. Without it MergeBoolGated leaves
		// cache_detail lowered, which is exactly the over-report bug this
		// gate exists to close.
		Authority:      []string{govern.AuthorityExtractCache},
		HiddenSections: []string{}, ReadOnlySections: []string{},
		HiddenSettings: []string{}, ReadOnlySettings: []string{},
		Share: map[string]any{
			"cache_detail":            true,  // local false + managed + extract.cache ⇒ RAISED
			"full_content":            false, // local true                            ⇒ LOWERED
			"routing_summary":         true,  // local true                            ⇒ PINNED
			"target_action_allowlist": []string{"bash", "read"},
		},
	}
	cfgPath := writeShareConfig(t, "full_content = true\nrouting_summary = true\ncache_detail = false\ntarget_action_allowlist = [\"bash\", \"write\"]\n")
	s := newRemoteTestServer(t, Options{
		ConfigPath: cfgPath,
		Governance: func(context.Context) govern.Effective { return eff },
	})

	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/governance = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// Byte-level: every entry must be a JSON object, never a bare scalar.
	var envelope struct {
		Share map[string]json.RawMessage `json:"share"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (%s)", err, rec.Body.String())
	}
	if len(envelope.Share) != len(eff.Share) {
		t.Fatalf("share has %d rows, want %d (%s)", len(envelope.Share), len(eff.Share), rec.Body.String())
	}
	for key, raw := range envelope.Share {
		if len(raw) == 0 || raw[0] != '{' {
			t.Errorf("share[%q] = %s - the SPA reads .source/.effective off this and would render undefined", key, raw)
		}
	}

	var got struct {
		Share map[string]governanceShareKey `json:"share"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode share block: %v", err)
	}
	cases := []struct {
		key       string
		effective any
		local     any
		source    govern.ShareSource
	}{
		{"cache_detail", true, false, govern.ShareSourceOrgRaised},
		{"full_content", false, true, govern.ShareSourceOrg},
		{"routing_summary", true, true, govern.ShareSourceBoth},
		{"target_action_allowlist", []any{"bash"}, []any{"bash", "write"}, govern.ShareSourceOrg},
	}
	for _, tc := range cases {
		row, ok := got.Share[tc.key]
		if !ok {
			t.Errorf("share is missing %q", tc.key)
			continue
		}
		if !reflect.DeepEqual(row.Effective, tc.effective) {
			t.Errorf("share[%q].effective = %#v, want %#v", tc.key, row.Effective, tc.effective)
		}
		if !reflect.DeepEqual(row.Local, tc.local) {
			t.Errorf("share[%q].local = %#v, want %#v", tc.key, row.Local, tc.local)
		}
		if row.Source != tc.source {
			t.Errorf("share[%q].source = %q, want %q", tc.key, row.Source, tc.source)
		}
		if row.PolicyVersion != eff.Version {
			t.Errorf("share[%q].policy_version = %d, want %d", tc.key, row.PolicyVersion, eff.Version)
		}
	}
}

// TestGovernanceShareRaiseIsInertOnAnIndividualNode pins the tenancy half at
// the HTTP layer: the SAME org body on an UNMANAGED node raises nothing and
// is attributed to nobody but the developer.
func TestGovernanceShareRaiseIsInertOnAnIndividualNode(t *testing.T) {
	eff := govern.Effective{
		Active: true, State: govern.StateApplied, Version: 21,
		HiddenSections: []string{}, ReadOnlySections: []string{},
		HiddenSettings: []string{}, ReadOnlySettings: []string{},
		Share: map[string]any{"cache_detail": true},
	}
	s := newRemoteTestServer(t, Options{
		ConfigPath: writeShareConfig(t, "cache_detail = false\n"),
		Governance: func(context.Context) govern.Effective { return eff },
	})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
	var got struct {
		Share map[string]governanceShareKey `json:"share"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	row := got.Share["cache_detail"]
	if row.Effective != false || row.Source != govern.ShareSourceLocal {
		t.Fatalf("individual node reported effective=%v source=%q, want false/you - raising is managed-only", row.Effective, row.Source)
	}
}

// TestGovernanceShareBlockAbsentWithoutDirectives keeps the solo/dormant wire
// shape byte-identical: no org directives ⇒ no `share` key at all, which is
// what governance.ts documents as "no org sharing directives".
func TestGovernanceShareBlockAbsentWithoutDirectives(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	rec := httptest.NewRecorder()
	s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["share"]; present {
		t.Fatalf("dormant posture emitted a share block: %s", rec.Body.String())
	}
}

// TestShareLocalTableCoversNodegovVocabulary pins the dashboard's
// key → local-setting table to the POLICY-side vocabulary. nodegov.Compile
// refuses any share key outside ShareKeys, so covering that table is exactly
// what makes resolveShareBlock's unknown-key fallback unreachable — and what
// stops a newly added share key from silently reporting the wrong `local`.
func TestShareLocalTableCoversNodegovVocabulary(t *testing.T) {
	for _, k := range nodegov.ShareKeys {
		if _, ok := shareLocalTable[k.Key]; !ok {
			t.Errorf("share key %q is org-directable but shareLocalTable has no local counterpart - the Privacy page would mis-report it", k.Key)
		}
	}
	vocab := map[string]bool{}
	for _, k := range nodegov.ShareKeys {
		vocab[k.Key] = true
	}
	for key := range shareLocalTable {
		if !vocab[key] {
			t.Errorf("shareLocalTable knows %q but no org can direct it - dead row", key)
		}
	}
}

// TestGovernanceShareScopeRaiseRows pins R3-85 on the Privacy card: the two
// scope raise directives are rendered from the same govern RaiseScope the
// push seam applies, labelled the org's raise on a managed node holding
// extract.scope, and the developer's own lists everywhere else.
func TestGovernanceShareScopeRaiseRows(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	body := "[org_client.scope]\nproject_root_allowlist = [\"/w/a\"]\nproject_root_denylist = [\"/w/secret\", \"/w/vendor\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	share := map[string]any{
		govern.ScopeUnrestrictedShareKey:   true,
		govern.ScopeDenylistRemoveShareKey: []string{"/w/vendor"},
	}
	cases := []struct {
		name      string
		eff       govern.Effective
		wantAllow bool
		wantDeny  []any
		source    govern.ShareSource
	}{
		{
			"managed with extract.scope",
			govern.Effective{Active: true, State: govern.StateApplied, Version: 4, Managed: true, Authority: []string{govern.AuthorityExtractScope}, Share: share},
			true,
			[]any{"/w/secret"},
			govern.ShareSourceOrgRaised,
		},
		{
			"individual node",
			govern.Effective{Active: true, State: govern.StateApplied, Version: 4, Authority: []string{govern.AuthorityExtractScope}, Share: share},
			false,
			[]any{"/w/secret", "/w/vendor"},
			govern.ShareSourceLocal,
		},
		{
			"managed without extract.scope",
			govern.Effective{Active: true, State: govern.StateApplied, Version: 4, Managed: true, Share: share},
			false,
			[]any{"/w/secret", "/w/vendor"},
			govern.ShareSourceLocal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff := tc.eff
			s := newRemoteTestServer(t, Options{
				ConfigPath: cfg,
				Governance: func(context.Context) govern.Effective { return eff },
			})
			rec := httptest.NewRecorder()
			s.guardedHandler("127.0.0.1:8081").ServeHTTP(rec, loopbackRequest(http.MethodGet, "/api/governance"))
			var got struct {
				Share map[string]governanceShareKey `json:"share"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v (%s)", err, rec.Body.String())
			}
			allow := got.Share[govern.ScopeUnrestrictedShareKey]
			if allow.Effective != tc.wantAllow || allow.Local != false || allow.Source != tc.source {
				t.Errorf("scope.unrestricted = %+v, want effective %v local false source %q", allow, tc.wantAllow, tc.source)
			}
			deny := got.Share[govern.ScopeDenylistRemoveShareKey]
			if !reflect.DeepEqual(deny.Effective, tc.wantDeny) || deny.Source != tc.source {
				t.Errorf("scope.denylist_remove = %+v, want effective %v source %q", deny, tc.wantDeny, tc.source)
			}
		})
	}
}
