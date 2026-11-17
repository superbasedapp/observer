package hostapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

func testDoc() pc.EntitlementDocument {
	return pc.EntitlementDocument{Version: 7, Body: []byte("doc"), Signature: []byte("sig"), KeyID: "ent-1"}
}

func queuedOf(t *testing.T, in Intent, err error) Queued {
	t.Helper()
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	return Queued{OrgID: in.OrgID, Verb: in.Verb, IdempotencyKey: in.IdempotencyKey, LifecycleGen: in.LifecycleGen, Payload: in.Payload}
}

// TestBuildEveryVerb is one case per verbTable row: the intent constructor's
// row builds the contract request on the contract's route, and the request
// validates on the host side.
func TestBuildEveryVerb(t *testing.T) {
	t.Parallel()
	qo := func(in Intent, err error) Queued { return queuedOf(t, in, err) }
	extras := CreateExtras{
		OwnerSub: "user_01", OwnerEmail: "owner@example.test", Entitlements: testDoc(),
		Slug: "acme", Kind: pc.OrgKindTeam,
	}
	cases := []struct {
		verb   Verb
		q      Queued
		method string
		path   string
		check  func(t *testing.T, body []byte)
	}{
		{
			verb: VerbCreateTenant, q: qo(CreateTenantIntent(testOrg, "Acme")), method: "POST", path: pc.PathTenants,
			check: func(t *testing.T, b []byte) {
				var r pc.CreateTenantRequest
				decodeStrict(t, b, &r)
				if r.IdempotencyKey != testOrg || r.TenantID != testOrg || r.OwnerSub != "user_01" || r.Entitlements.Version != 7 ||
					r.Slug != "acme" || r.Kind != pc.OrgKindTeam || r.OwnerEmailVerified {
					t.Fatalf("create request = %+v", r)
				}
				// The address hint is unverified: the wire carries no
				// owner_email_verified at all (absent means unverified).
				if strings.Contains(string(b), "owner_email_verified") {
					t.Fatalf("create request vouches for the address: %s", b)
				}
			},
		},
		{
			verb: VerbSetState, q: qo(SetStateIntent(testOrg, pc.StateSuspended, 4)), method: "PUT", path: pc.PathTenantState(testOrg),
			check: func(t *testing.T, b []byte) {
				var r pc.SetStateRequest
				decodeStrict(t, b, &r)
				if r.State != pc.StateSuspended || r.LifecycleGen != 4 || r.TenantID != testOrg {
					t.Fatalf("state request = %+v", r)
				}
			},
		},
		{
			verb: VerbSetEntitlements, q: qo(SetEntitlementsIntent(testOrg, testDoc())), method: "PUT", path: pc.PathTenantEntitlements(testOrg),
			check: func(t *testing.T, b []byte) {
				var r pc.SetEntitlementsRequest
				decodeStrict(t, b, &r)
				if r.Document.Version != 7 || string(r.Document.Body) != "doc" {
					t.Fatalf("entitlements request = %+v", r)
				}
			},
		},
		{
			verb: VerbMembersDeactivate, q: qo(DeactivateMemberIntent(testOrg, "user_02")), method: "POST", path: pc.PathTenantMembersDeactivate(testOrg),
			check: func(t *testing.T, b []byte) {
				var r pc.DeactivateMemberRequest
				decodeStrict(t, b, &r)
				if r.Sub != "user_02" || r.IdempotencyKey != "deact:"+testOrg+":user_02" {
					t.Fatalf("deactivate request = %+v", r)
				}
			},
		},
		{
			verb: VerbEvict, q: qo(EvictIntent(testOrg, 9)), method: "POST", path: pc.PathTenantEvict(testOrg),
			check: func(t *testing.T, b []byte) {
				var r pc.EvictRequest
				decodeStrict(t, b, &r)
				if r.LifecycleGen != 9 {
					t.Fatalf("evict request = %+v", r)
				}
			},
		},
	}
	if len(cases) != len(verbTable) {
		t.Fatalf("%d cases for %d verbs", len(cases), len(verbTable))
	}
	for i, tc := range cases {
		if verbTable[i].verb != tc.verb {
			t.Fatalf("case %d is %s, table row %d is %s", i, tc.verb, i, verbTable[i].verb)
		}
		t.Run(string(tc.verb), func(t *testing.T) {
			t.Parallel()
			r, err := Build(tc.q, extras)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if r.Method != tc.method || r.Path != tc.path || r.RawQuery != "" {
				t.Fatalf("route = %s %s?%s, want %s %s", r.Method, r.Path, r.RawQuery, tc.method, tc.path)
			}
			tc.check(t, r.Body)
		})
	}
}

func decodeStrict(t *testing.T, b []byte, v interface{ Validate() error }) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := v.Validate(); err != nil {
		t.Fatalf("host-side Validate: %v", err)
	}
}

// TestBuildRefusesBadIntents: a row that cannot become a valid request is a
// bad intent (parked, never sent).
func TestBuildRefusesBadIntents(t *testing.T) {
	t.Parallel()
	qo := func(in Intent, err error) Queued { return queuedOf(t, in, err) }
	good := qo(CreateTenantIntent(testOrg, "Acme"))
	extras := CreateExtras{OwnerSub: "u", OwnerEmail: "o@example.test", Entitlements: testDoc()}
	cases := []struct {
		name   string
		mutate func(*Queued)
		extras CreateExtras
	}{
		{"unknown verb", func(q *Queued) { q.Verb = "export" }, extras},
		{"payload for another tenant", func(q *Queued) { q.Payload = []byte(`{"tenant_id":"other","name":"x"}`) }, extras},
		{"payload not json", func(q *Queued) { q.Payload = []byte(`{`) }, extras},
		{"org id with a slash", func(q *Queued) { q.OrgID = "a/b" }, extras},
		{"empty key", func(q *Queued) { q.IdempotencyKey = "" }, extras},
		{"missing owner", func(*Queued) {}, CreateExtras{Entitlements: testDoc()}},
		{"missing entitlements", func(*Queued) {}, CreateExtras{OwnerSub: "u", OwnerEmail: "o@example.test"}},
		{"unknown org kind", func(*Queued) {}, CreateExtras{OwnerSub: "u", OwnerEmail: "o@example.test", Entitlements: testDoc(), Kind: "dedicated"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			q := good
			tc.mutate(&q)
			if _, err := Build(q, tc.extras); !errors.Is(err, ErrBadIntent) {
				t.Fatalf("Build = %v, want ErrBadIntent", err)
			}
		})
	}
}

// TestIntentKeys: keys are deterministic in the intent's identity, so the
// same intent is one key and different intents never share one.
func TestIntentKeys(t *testing.T) {
	t.Parallel()
	mk := func(in Intent, err error) string {
		if err != nil {
			t.Fatalf("intent: %v", err)
		}
		return in.IdempotencyKey
	}
	keys := []string{
		mk(CreateTenantIntent(testOrg, "Acme")),
		mk(SetStateIntent(testOrg, pc.StateSuspended, 2)),
		mk(SetStateIntent(testOrg, pc.StateActive, 2)),
		mk(SetStateIntent(testOrg, pc.StateSuspended, 3)),
		mk(SetEntitlementsIntent(testOrg, testDoc())),
		mk(DeactivateMemberIntent(testOrg, "user_a")),
		mk(DeactivateMemberIntent(testOrg, "user_b")),
		mk(EvictIntent(testOrg, 3)),
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Fatalf("two different intents share key %q", k)
		}
		seen[k] = true
	}
	if keys[0] != testOrg {
		t.Errorf("create key = %q, want the org id (M6.1a's provisioning key)", keys[0])
	}
	if a, b := mk(SetStateIntent(testOrg, pc.StateSuspended, 2)), keys[1]; a != b {
		t.Errorf("the same intent built twice has keys %q and %q", a, b)
	}
	st, _ := SetStateIntent(testOrg, pc.StateSuspended, 2)
	if c := st.AsCorrection(); c.IdempotencyKey != KeyPrefixReconcile+st.IdempotencyKey {
		t.Errorf("correction key = %q", c.IdempotencyKey)
	}
	cr, _ := CreateTenantIntent(testOrg, "Acme")
	if cr.AsCorrection().IdempotencyKey != testOrg {
		t.Errorf("a create correction must keep the org id key, got %q", cr.AsCorrection().IdempotencyKey)
	}
}

// TestIntentConstructorsRefuseBadInput: blank ids, unknown states, negative
// generations and invalid documents never become intents.
func TestIntentConstructorsRefuseBadInput(t *testing.T) {
	t.Parallel()
	bad := []struct {
		name string
		err  error
	}{
		{"create blank org", second(CreateTenantIntent("", "x"))},
		{"create blank name", second(CreateTenantIntent(testOrg, " "))},
		{"state unknown", second(SetStateIntent(testOrg, "weird", 1))},
		{"state negative gen", second(SetStateIntent(testOrg, pc.StateActive, -1))},
		{"entitlements invalid doc", second(SetEntitlementsIntent(testOrg, pc.EntitlementDocument{}))},
		{"deactivate blank sub", second(DeactivateMemberIntent(testOrg, ""))},
		{"deactivate newline sub", second(DeactivateMemberIntent(testOrg, "a\nb"))},
		{"evict negative gen", second(EvictIntent(testOrg, -1))},
	}
	for _, tc := range bad {
		if !errors.Is(tc.err, ErrBadIntent) {
			t.Errorf("%s: err = %v, want ErrBadIntent", tc.name, tc.err)
		}
	}
}

func second(_ Intent, err error) error { return err }

// TestProbes: the reconciler's two read requests and their readers, which
// accept only a verified, well-formed answer.
func TestProbes(t *testing.T) {
	t.Parallel()
	rc, err := RouteCheckProbe(testOrg)
	if err != nil || rc.Method != "POST" || rc.Path != pc.PathRouteCheck {
		t.Fatalf("RouteCheckProbe = %+v, %v", rc, err)
	}
	h, err := HealthProbe(testOrg)
	if err != nil || h.Method != "GET" || h.Path != pc.PathTenantHealth(testOrg) || len(h.Body) != 0 {
		t.Fatalf("HealthProbe = %+v, %v", h, err)
	}
	if _, err := HealthProbe("../x"); !errors.Is(err, ErrBadIntent) {
		t.Errorf("HealthProbe(../x) = %v", err)
	}

	served := mustJSON(t, pc.RouteCheckResponse{Served: true, State: pc.StateActive, LifecycleGen: 2})
	if r, ok := ReadRouteCheck(verified(served)); !ok || !r.Served || r.LifecycleGen != 2 {
		t.Errorf("ReadRouteCheck(verified) = %+v, %v", r, ok)
	}
	for name, a := range map[string]Answer{
		"unverified":  {Kind: AnswerUnverified, Body: served},
		"refusal":     verified(mustJSON(t, pc.ErrorResponse{Code: pc.CodeUnavailable})),
		"bad state":   verified([]byte(`{"served":true,"state":"weird"}`)),
		"not an obj":  verified([]byte(`true`)),
		"neg gen":     verified([]byte(`{"served":false,"lifecycle_gen":-1}`)),
		"transport":   {Kind: AnswerTransport},
		"not sent":    {Kind: AnswerNotSent},
		"zero answer": {},
	} {
		if _, ok := ReadRouteCheck(a); ok {
			t.Errorf("ReadRouteCheck(%s) accepted", name)
		}
	}

	health := pc.HealthResponse{TenantID: testOrg, Status: pc.HealthDegraded, LastPush: pc.PushRecent, Backlog: pc.BacklogClear, Quota: pc.QuotaOK, Error: pc.ErrNone}
	if r, ok := ReadHealth(verified(mustJSON(t, health)), testOrg); !ok || r.Status != pc.HealthDegraded {
		t.Errorf("ReadHealth(verified) = %+v, %v", r, ok)
	}
	if _, ok := ReadHealth(verified(mustJSON(t, health)), "another"); ok {
		t.Error("ReadHealth accepted another tenant's answer")
	}
	if _, ok := ReadHealth(Answer{Kind: AnswerUnverified, Body: mustJSON(t, health)}, testOrg); ok {
		t.Error("ReadHealth accepted an unverified answer")
	}
}
