package invariant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B, Phase 1a invariants
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §10, as amended by
// the 2026-08-15 adversarial review).
//
// The claim these tests exist to keep true: a node that holds no enrolment
// grant is UNCHANGED, and a node that holds one applies the INTERSECTION of
// what the org published and what the machine granted — never more.

const governanceMaxBody = 1 << 20

func governanceTestSpec(t *testing.T, body string) nodegov.PolicySpec {
	t.Helper()
	spec, _, err := nodegov.CompileBody([]byte(body), governanceMaxBody)
	if err != nil {
		t.Fatalf("nodegov.CompileBody(%s): %v", body, err)
	}
	return spec
}

func governanceLiveGrant(now time.Time) *govern.Grant {
	return &govern.Grant{
		OrgKey: "ok", Generation: 2, OrgName: "Acme", KeyPinSHA256: "pin",
		Authority: []string{govern.AuthorityDashboardVisibility},
		GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

func governanceLiveIdentity() govern.LiveIdentity {
	return govern.LiveIdentity{Enrolled: true, OrgKey: "ok", Generation: 2, KeyPinSHA256: "pin"}
}

func governanceDelivered(t *testing.T) govern.Delivered {
	return govern.Delivered{
		Present: true, Version: 14, BodyHash: "bh",
		Spec: governanceTestSpec(t, `{"schema":1,"sections":{"hidden":["benchmarks"],"read_only":["policies"]}}`),
	}
}

// TestGovernanceIgnoredWithoutGrant is the dormancy invariant: a fully
// valid, correctly signed body delivered to a node with NO grant applies
// nothing at all. It kills the "apply if delivered" mutation.
func TestGovernanceIgnoredWithoutGrant(t *testing.T) {
	now := time.Now().UTC()
	eff := govern.Resolve(governanceDelivered(t), nil, governanceLiveIdentity(), now)
	if eff.Active {
		t.Fatalf("a node with no grant reported Active: %+v", eff)
	}
	if eff.State != govern.StateNoGrant {
		t.Fatalf("State = %q, want no_grant", eff.State)
	}
	if len(eff.HiddenSections)+len(eff.ReadOnlySections)+len(eff.HiddenSettings)+len(eff.ReadOnlySettings) != 0 {
		t.Fatalf("directives applied without a grant: %+v", eff)
	}
}

// TestGovernanceIntersectsGrantAuthority: the delivered body is applied only
// where the grant authorises it, and a dropped class is RECORDED — which is
// what forces accepted_inert / not_preauthorized instead of effective, so a
// partial application can never masquerade as convergence.
func TestGovernanceIntersectsGrantAuthority(t *testing.T) {
	now := time.Now().UTC()

	withAuthority := govern.Resolve(governanceDelivered(t), governanceLiveGrant(now), governanceLiveIdentity(), now)
	if withAuthority.State != govern.StateApplied || len(withAuthority.HiddenSections) != 1 {
		t.Fatalf("granted node did not apply the body: %+v", withAuthority)
	}
	if len(withAuthority.Dropped) != 0 {
		t.Fatalf("fully-authorised body reported drops: %+v", withAuthority.Dropped)
	}

	narrow := governanceLiveGrant(now)
	narrow.Authority = []string{govern.AuthorityCaptureRaise} // NOT dashboard.visibility
	inert := govern.Resolve(governanceDelivered(t), narrow, governanceLiveIdentity(), now)
	if len(inert.HiddenSections) != 0 {
		t.Fatalf("a directive class the grant does not authorise was applied: %+v", inert)
	}
	if inert.State != govern.StateInert || len(inert.Dropped) != 1 ||
		inert.Dropped[0].Reason != govern.ReasonNotPreauthorized {
		t.Fatalf("dropped class not reported as not_preauthorized: %+v", inert)
	}
	if inert.Hash == withAuthority.Hash {
		t.Fatal("the inert posture hashes like the applied one — fleet state could not tell them apart")
	}
}

// TestGovernanceKeyPinMismatchRejected is the adversarial review's A2 row 3b:
// a grant bound to an org signing key this node no longer pins is a
// substitution attempt, not authority. It is the one check that generalizes
// the MDM flow's out-of-band key commitment onto the flows that ship today.
func TestGovernanceKeyPinMismatchRejected(t *testing.T) {
	now := time.Now().UTC()
	grant := governanceLiveGrant(now)
	live := governanceLiveIdentity()
	live.KeyPinSHA256 = "a-different-key"

	eff := govern.Resolve(governanceDelivered(t), grant, live, now)
	if eff.Active || eff.State != govern.StateKeyPinMismatch {
		t.Fatalf("a grant bound to an unpinned key was honoured: %+v", eff)
	}
	if len(eff.HiddenSections) != 0 {
		t.Fatalf("directives applied under a mismatched key pin: %+v", eff)
	}
}

// TestGovernanceIdentityChangeReverts: a raced unenrol / re-enrol wins
// immediately, without waiting for the grant's TTL.
func TestGovernanceIdentityChangeReverts(t *testing.T) {
	now := time.Now().UTC()
	for name, live := range map[string]govern.LiveIdentity{
		"unenrolled":       {},
		"newer generation": {Enrolled: true, OrgKey: "ok", Generation: 3, KeyPinSHA256: "pin"},
		"different org":    {Enrolled: true, OrgKey: "other", Generation: 2, KeyPinSHA256: "pin"},
	} {
		t.Run(name, func(t *testing.T) {
			eff := govern.Resolve(governanceDelivered(t), governanceLiveGrant(now), live, now)
			if eff.Active || eff.State != govern.StateIdentityChanged {
				t.Fatalf("stale grant still governing: %+v", eff)
			}
		})
	}
}

// TestGovernanceExpiredGrantReverts is the offboarding backstop (§5.3): once
// the TTL lapses the node reverts to local settings WITHOUT needing the org
// to be reachable. It kills the perpetual-lock mutation.
func TestGovernanceExpiredGrantReverts(t *testing.T) {
	now := time.Now().UTC()
	expired := governanceLiveGrant(now)
	expired.ExpiresAt = now.Add(-time.Minute)

	eff := govern.Resolve(governanceDelivered(t), expired, governanceLiveIdentity(), now)
	if eff.Active || eff.State != govern.StateGrantExpired {
		t.Fatalf("expired grant still governing: %+v", eff)
	}
	if len(eff.HiddenSections) != 0 {
		t.Fatalf("expired grant still hiding pages: %+v", eff)
	}
}

// TestGovernanceCannotHideEnrolmentOrPrivacy is threat T8: the surfaces
// through which a developer sees what their employer configured and receives
// are structurally unhideable. Enforced in the family COMPILER, which is the
// same code the server's publish lint runs — so an admin cannot publish such
// a body, and an agent would refuse one that arrived anyway.
func TestGovernanceCannotHideEnrolmentOrPrivacy(t *testing.T) {
	bodies := []string{
		`{"schema":1,"sections":{"hidden":["settings"]}}`,
		`{"schema":1,"sections":{"hidden":["privacy"]}}`,
		`{"schema":1,"sections":{"read_only":["settings"]}}`,
		`{"schema":1,"sections":{"read_only":["privacy"]}}`,
		`{"schema":1,"sections":{"settings_hidden":["enrolment"]}}`,
		`{"schema":1,"sections":{"settings_hidden":["org"]}}`,
		`{"schema":1,"sections":{"settings_read_only":["enrolment"]}}`,
		`{"schema":1,"sections":{"settings_read_only":["org"]}}`,
	}
	for _, body := range bodies {
		if _, _, err := nodegov.CompileBody([]byte(body), governanceMaxBody); err == nil {
			t.Fatalf("the compiler accepted %s — an org could hide the evidence of its own governance", body)
		}
	}
}

// TestGovernanceAPIRefusesHiddenRoutesOnLoopback is the second, independent
// statement of the dashboard package's own loopback test, from OUTSIDE the
// package and through the EXPORTED handler: Server.Handler() is the loopback
// listener's chain, and it must carry the governance guard.
//
// This is the review's headline defect: capMap — the obvious place to hang a
// governance predicate — is consulted only by remoteAuthz, and Handler()
// discards it, so a guard installed "beside capMap" would be absent from
// every normal developer node.
func TestGovernanceAPIRefusesHiddenRoutesOnLoopback(t *testing.T) {
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "gov.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	now := time.Now().UTC()
	eff := govern.Resolve(
		govern.Delivered{
			Present: true, Version: 3, BodyHash: "bh",
			Spec: governanceTestSpec(t, `{"schema":1,"sections":{"hidden":["benchmarks"]}}`),
		},
		governanceLiveGrant(now), governanceLiveIdentity(), now,
	)
	if !eff.Active {
		t.Fatalf("fixture is not governed: %+v", eff)
	}

	srv, err := dashboard.New(dashboard.Options{
		DB:         database,
		Governance: func(context.Context) govern.Effective { return eff },
	})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/benchmarks", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/benchmarks on the LOOPBACK handler = %d, want 404 — a hidden section must be refused at the API, not merely hidden in the SPA", rec.Code)
	}
	// And a route in a visible section is untouched.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("governance refused an ungoverned route")
	}
}

// TestSoloNodeUnchangedByGovernance is the review's A15 rewrite: the solo
// claim stated as BEHAVIOUR that can actually hold, rather than as a
// route-table DeepEqual that cannot (GET /api/governance and the SPA changes
// are unconditional; dormancy is a RUNTIME property gated on
// Effective.Active).
//
// Asserted here: with no grant, (i) the resolved posture is dormant and
// carries no directive, (ii) GET /api/governance answers 200 with
// active:false, (iii) every nav section is visible, and (iv) no route is
// refused.
func TestSoloNodeUnchangedByGovernance(t *testing.T) {
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "solo.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	_ = store.New(database)

	// (i) the posture a solo node resolves.
	dormant := govern.Resolve(govern.Delivered{}, nil, govern.LiveIdentity{}, time.Now().UTC())
	if dormant.Active || dormant.State != govern.StateNoGrant {
		t.Fatalf("solo posture = %+v, want dormant", dormant)
	}

	// A solo node has NO provider wired at all — that is the shape
	// cmd/observer produces when nothing constructed an install seam.
	srv, err := dashboard.New(dashboard.Options{DB: database})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	h := srv.Handler()

	// (ii) the endpoint exists and answers honestly.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/governance", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/governance = %d, want 200", rec.Code)
	}
	var got govern.Effective
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if got.Active {
		t.Fatalf("solo node reported governed: %+v", got)
	}
	if !reflect.DeepEqual(got.HiddenSections, []string{}) ||
		!reflect.DeepEqual(got.ReadOnlySections, []string{}) ||
		!reflect.DeepEqual(got.HiddenSettings, []string{}) ||
		!reflect.DeepEqual(got.ReadOnlySettings, []string{}) {
		t.Fatalf("solo posture carries directives: %+v", got)
	}

	// (iii) every nav section is visible to the resolved posture.
	for _, id := range nodegov.NavSectionIDs {
		if got.IsNavSectionHidden(id) || got.IsNavSectionReadOnly(id) {
			t.Fatalf("solo node hides or locks nav section %q", id)
		}
	}

	// (iv) nothing is refused. A route whose component this build compiled
	// out (a published edition: the minimal one has no benchmark) answers
	// the build's own 404 "not in this build" (reason not_compiled), which
	// is the build, not governance; every other 404 or 409 is a refusal.
	for _, path := range []string{"/api/status", "/api/benchmarks", "/api/sessions", "/api/config"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var body componentstate.NotActiveBody
		if rec.Code == http.StatusNotFound && json.Unmarshal(rec.Body.Bytes(), &body) == nil &&
			body.Error == componentstate.NotActiveError && body.Reason == components.ReasonNotCompiled {
			continue
		}
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusConflict {
			t.Fatalf("solo node refused %s with %d", path, rec.Code)
		}
	}
}

// TestPrivacySentinelUnchangedByGovernance: the grant table is node-local,
// and the ONE privacy-test edit Phase 1a makes is an ADDITION to the
// forbidden set (strictly tightening). The sentinel itself
// (TestSelectUnpushedSinceExcludesCacheTables) does the enforcing; this
// asserts the name is actually in the list, so the enforcement covers it.
func TestPrivacySentinelUnchangedByGovernance(t *testing.T) {
	var found bool
	for _, name := range forbiddenCacheTables {
		if name == "org_enrolment_grant" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("org_enrolment_grant is not in forbiddenCacheTables — the org-push seam could name the node's own consent record")
	}
}
