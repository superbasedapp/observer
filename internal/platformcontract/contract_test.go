package platformcontract

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func doc() EntitlementDocument {
	return EntitlementDocument{Version: 3, Body: []byte("body"), Signature: []byte("sig"), KeyID: "k1"}
}

func goldenCases() map[string]any {
	return map[string]any{
		"create_request":        CreateTenantRequest{IdempotencyKey: "idem-1", TenantID: "org_1", Name: "Acme", OwnerSub: "user_1", OwnerEmail: "o@acme.test", Entitlements: doc(), Slug: "acme", Kind: OrgKindTeam},
		"create_request_v1_0":   CreateTenantRequest{IdempotencyKey: "idem-1", TenantID: "org_1", Name: "Acme", OwnerSub: "user_1", OwnerEmail: "o@acme.test", Entitlements: doc()},
		"create_response":       CreateTenantResponse{TenantID: "org_1", Outcome: CreateReady, State: StateActive, LifecycleGen: 1},
		"state_request":         SetStateRequest{TenantID: "org_1", State: StateSuspended, LifecycleGen: 2},
		"state_response":        SetStateResponse{State: StateSuspended, LifecycleGen: 2, Applied: true},
		"entitlements_request":  SetEntitlementsRequest{TenantID: "org_1", Document: doc()},
		"entitlements_response": SetEntitlementsResponse{Version: 3, Applied: true},
		"availability_request":  SetAvailabilityRequest{Document: AvailabilityDocument{Version: 7, Body: []byte("body"), Signature: []byte("sig"), KeyID: "k1"}},
		"availability_response": SetAvailabilityResponse{Version: 7, Applied: true},
		"deactivate_request":    DeactivateMemberRequest{TenantID: "org_1", Sub: "user_2", IdempotencyKey: "idem-2"},
		"deactivate_response":   DeactivateMemberResponse{Deactivated: true},
		"evict_request":         EvictRequest{TenantID: "org_1", LifecycleGen: 4},
		"evict_response":        EvictResponse{Evicted: true},
		"usage_request":         UsageRequest{Day: "2026-11-12"},
		"usage_response": UsageResponse{Day: "2026-11-12", Tenants: []TenantUsage{
			{TenantID: "org_1", ActiveSeatMemberIDs: []string{"m1", "m2"}, MachineIdentities: 1, Sessions: 40, Members: 5},
		}},
		"route_check_request":  RouteCheckRequest{TenantID: "org_1"},
		"route_check_response": RouteCheckResponse{Served: true, State: StateActive, LifecycleGen: 1},
		"health_response":      HealthResponse{TenantID: "org_1", Status: HealthDegraded, LastPush: PushStale, Backlog: BacklogParked, Quota: QuotaNear, Error: ErrDatabase},
		"envelope":             Envelope{KeyID: "k1", Timestamp: 1700000000, Nonce: "n1", BodyDigest: BodyDigest([]byte("x")), Signature: "c2ln"},
	}
}

func TestGolden(t *testing.T) {
	t.Parallel()
	for name, v := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join("testdata", name+".golden.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.ReplaceAll(string(want), "\r\n", "\n") != string(got) {
				t.Fatalf("golden mismatch for %s:\n got %s\nwant %s", name, got, want)
			}
		})
	}
}

// TestUnknownFieldsIgnored pins the v1 rule that readers tolerate additive fields.
func TestUnknownFieldsIgnored(t *testing.T) {
	t.Parallel()
	for name, v := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, _ := json.Marshal(v)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["future_field"] = map[string]any{"a": 1}
			raw, _ = json.Marshal(m)
			back := newLike(v)
			if err := json.Unmarshal(raw, back); err != nil {
				t.Fatalf("unknown field rejected: %v", err)
			}
		})
	}
}

func newLike(v any) any {
	switch v.(type) {
	case CreateTenantRequest:
		return &CreateTenantRequest{}
	case CreateTenantResponse:
		return &CreateTenantResponse{}
	case SetStateRequest:
		return &SetStateRequest{}
	case SetStateResponse:
		return &SetStateResponse{}
	case SetEntitlementsRequest:
		return &SetEntitlementsRequest{}
	case SetEntitlementsResponse:
		return &SetEntitlementsResponse{}
	case DeactivateMemberRequest:
		return &DeactivateMemberRequest{}
	case DeactivateMemberResponse:
		return &DeactivateMemberResponse{}
	case EvictRequest:
		return &EvictRequest{}
	case EvictResponse:
		return &EvictResponse{}
	case UsageRequest:
		return &UsageRequest{}
	case UsageResponse:
		return &UsageResponse{}
	case RouteCheckRequest:
		return &RouteCheckRequest{}
	case RouteCheckResponse:
		return &RouteCheckResponse{}
	case HealthResponse:
		return &HealthResponse{}
	default:
		return &Envelope{}
	}
}

func TestEnumTables(t *testing.T) {
	t.Parallel()
	type tbl struct {
		name  string
		known []string
		valid func(string) bool
	}
	conv := func(n int, f func(i int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	tables := []tbl{
		{"state", conv(len(KnownTenantStates), func(i int) string { return string(KnownTenantStates[i]) }), func(s string) bool { return TenantState(s).Valid() }},
		{"health", conv(len(KnownHealthStatuses), func(i int) string { return string(KnownHealthStatuses[i]) }), func(s string) bool { return HealthStatus(s).Valid() }},
		{"push", conv(len(KnownPushRecencies), func(i int) string { return string(KnownPushRecencies[i]) }), func(s string) bool { return PushRecency(s).Valid() }},
		{"backlog", conv(len(KnownBacklogLevels), func(i int) string { return string(KnownBacklogLevels[i]) }), func(s string) bool { return BacklogLevel(s).Valid() }},
		{"quota", conv(len(KnownQuotaStates), func(i int) string { return string(KnownQuotaStates[i]) }), func(s string) bool { return QuotaState(s).Valid() }},
		{"error", conv(len(KnownErrorClasses), func(i int) string { return string(KnownErrorClasses[i]) }), func(s string) bool { return ErrorClass(s).Valid() }},
		{"create", conv(len(KnownCreateOutcomes), func(i int) string { return string(KnownCreateOutcomes[i]) }), func(s string) bool { return CreateOutcome(s).Valid() }},
		{"org kind", conv(len(KnownOrgKinds), func(i int) string { return string(KnownOrgKinds[i]) }), func(s string) bool { return OrgKind(s).Valid() }},
	}
	for _, tb := range tables {
		t.Run(tb.name, func(t *testing.T) {
			t.Parallel()
			seen := map[string]bool{}
			for _, k := range tb.known {
				if !tb.valid(k) || seen[k] || k == "" || k != strings.ToLower(k) {
					t.Errorf("bad known value %q", k)
				}
				seen[k] = true
			}
			for _, bad := range []string{"", "ACTIVE", "nope", " active"} {
				if tb.valid(bad) {
					t.Errorf("%q must be invalid", bad)
				}
			}
		})
	}
	want := []string{"provisioning", "active", "suspended", "pending_deletion", "purging", "purged"}
	for i, s := range KnownTenantStates {
		if string(s) != want[i] {
			t.Errorf("state %d = %s want %s", i, s, want[i])
		}
	}
}

func TestPaths(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		PathTenants:                      "/platform/v1/tenants",
		PathUsage:                        "/platform/v1/usage",
		PathRouteCheck:                   "/platform/v1/route-check",
		PathAvailability:                 "/platform/v1/availability",
		PathTenantState("a"):             "/platform/v1/tenants/a/state",
		PathTenantEntitlements("a"):      "/platform/v1/tenants/a/entitlements",
		PathTenantMembersDeactivate("a"): "/platform/v1/tenants/a/members/deactivate",
		PathTenantEvict("a"):             "/platform/v1/tenants/a/evict",
		PathTenantHealth("a"):            "/platform/v1/tenants/a/health",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s want %s", got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	good := goldenCases()
	cases := []struct {
		name string
		err  error
		ok   bool
	}{
		{"create ok", good["create_request"].(CreateTenantRequest).Validate(), true},
		{"create no idem", CreateTenantRequest{TenantID: "t"}.Validate(), false},
		{"create bad doc", func() error {
			r := good["create_request"].(CreateTenantRequest)
			r.Entitlements.Body = nil
			return r.Validate()
		}(), false},
		{"state ok", good["state_request"].(SetStateRequest).Validate(), true},
		{"state bad enum", SetStateRequest{TenantID: "t", State: "x"}.Validate(), false},
		{"state neg gen", SetStateRequest{TenantID: "t", State: StateActive, LifecycleGen: -1}.Validate(), false},
		{"state no id", SetStateRequest{State: StateActive}.Validate(), false},
		{"ent ok", good["entitlements_request"].(SetEntitlementsRequest).Validate(), true},
		{"ent zero version", SetEntitlementsRequest{TenantID: "t", Document: EntitlementDocument{Body: []byte("b"), Signature: []byte("s"), KeyID: "k"}}.Validate(), false},
		{"ent no key", SetEntitlementsRequest{TenantID: "t", Document: EntitlementDocument{Version: 1, Body: []byte("b"), Signature: []byte("s")}}.Validate(), false},
		{"deact ok", good["deactivate_request"].(DeactivateMemberRequest).Validate(), true},
		{"deact blank sub", DeactivateMemberRequest{TenantID: "t", Sub: "  ", IdempotencyKey: "i"}.Validate(), false},
		{"evict ok", good["evict_request"].(EvictRequest).Validate(), true},
		{"evict neg", EvictRequest{TenantID: "t", LifecycleGen: -2}.Validate(), false},
		{"usage ok", UsageRequest{Day: "2026-02-28"}.Validate(), true},
		{"usage leap bad", UsageRequest{Day: "2026-02-29"}.Validate(), false},
		{"usage format", UsageRequest{Day: "2026-2-3"}.Validate(), false},
		{"usage empty", UsageRequest{}.Validate(), false},
		{"route ok", RouteCheckRequest{TenantID: "t"}.Validate(), true},
		{"route empty", RouteCheckRequest{}.Validate(), false},
		{"health ok", good["health_response"].(HealthResponse).Validate(), true},
		{"health bad", HealthResponse{TenantID: "t", Status: "x"}.Validate(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if c.ok && c.err != nil {
				t.Fatalf("unexpected %v", c.err)
			}
			if !c.ok && (c.err == nil || !IsValidation(c.err)) {
				t.Fatalf("want typed validation error, got %v", c.err)
			}
		})
	}
}

func testKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("platformcontract-test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func TestEnvelope(t *testing.T) {
	t.Parallel()
	pub, priv := testKey()
	otherPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"a":1}`)
	target := PathTenantState("org_1")
	env, err := NewEnvelope(priv, "k1", "nonce-1", "put", target, body, now)
	if err != nil {
		t.Fatal(err)
	}
	if env.BodyDigest != BodyDigest(body) {
		t.Fatal("digest not set")
	}
	cases := []struct {
		name   string
		mutate func(e *Envelope)
		pub    ed25519.PublicKey
		method string
		target string
		body   []byte
		at     time.Time
		want   error
	}{
		{"ok", nil, pub, "PUT", target, body, now, nil},
		{"ok lower-case method", nil, pub, "put", target, body, now, nil},
		{"edge past", nil, pub, "PUT", target, body, now.Add(ReplayWindow), nil},
		{"edge future", nil, pub, "PUT", target, body, now.Add(-ReplayWindow), nil},
		{"stale past", nil, pub, "PUT", target, body, now.Add(ReplayWindow + time.Second), ErrStale},
		{"stale future", nil, pub, "PUT", target, body, now.Add(-ReplayWindow - time.Second), ErrStale},
		{"body tamper", nil, pub, "PUT", target, []byte(`{"a":2}`), now, ErrDigestMismatch},
		{"method tamper", nil, pub, "POST", target, body, now, ErrBadSignature},
		{"target tamper", nil, pub, "PUT", PathTenantState("org_2"), body, now, ErrBadSignature},
		{"wrong key", nil, otherPub, "PUT", target, body, now, ErrBadSignature},
		{"nonce tamper", func(e *Envelope) { e.Nonce = "n2" }, pub, "PUT", target, body, now, ErrBadSignature},
		{"keyid tamper", func(e *Envelope) { e.KeyID = "k2" }, pub, "PUT", target, body, now, ErrBadSignature},
		{"ts tamper", func(e *Envelope) { e.Timestamp++ }, pub, "PUT", target, body, now, ErrBadSignature},
		{"garbage sig", func(e *Envelope) { e.Signature = "!!!" }, pub, "PUT", target, body, now, ErrBadSignature},
		{"short pub", nil, pub[:5], "PUT", target, body, now, ErrBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := env
			if c.mutate != nil {
				c.mutate(&e)
			}
			err := e.Verify(c.pub, c.method, c.target, c.body, c.at)
			if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
				t.Fatalf("got %v want %v", err, c.want)
			}
		})
	}
}

func TestSigningInput(t *testing.T) {
	t.Parallel()
	e := Envelope{KeyID: "k", Timestamp: 5, Nonce: "n", BodyDigest: "d"}
	got, err := SigningInput("get", "/x?day=1", e)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sbo-platform-host-api-v1\nGET\n/x?day=1\n5\nn\nk\nd"; string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
	bad := []Envelope{{Timestamp: 5, Nonce: "n", BodyDigest: "d"}, {KeyID: "k\nx", Nonce: "n", BodyDigest: "d"}, {KeyID: "k", BodyDigest: "d"}}
	for i, b := range bad {
		if _, err := SigningInput("GET", "/x", b); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	if _, err := SigningInput("", "/x", e); err == nil {
		t.Error("empty method must fail")
	}
	if _, err := NewEnvelope(nil, "k", "n", "GET", "/x", nil, time.Unix(1, 0)); err == nil {
		t.Error("nil key must fail")
	}
}
