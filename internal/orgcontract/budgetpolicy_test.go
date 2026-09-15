package orgcontract

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testBudgetBody() BudgetPolicyBody {
	return BudgetPolicyBody{
		Version:       41,
		ResolvedScope: "team:eng",
		CapTokens:     40_000_000,
		Period:        BudgetPolicyPeriodCalendarMonth,
		Timezone:      "UTC",
		Enforcement:   BudgetPolicyEnforcementHard,
		Thresholds:    []float64{0.75, 0.9, 1},
		Caps: []BudgetPolicyCap{{
			Period: BudgetPolicyPeriodCalendarMonth, Timezone: "UTC",
			CapTokens: 40_000_000, Enforcement: BudgetPolicyEnforcementHard,
			Thresholds:    []float64{0.75, 0.9, 1},
			ResolvedScope: "team:eng", ScopeTokens: "team:eng",
		}},
	}
}

// TestBudgetPolicySignatureVerifiesUnderTheOrgKey is the base case: the body
// the org signs is the body the node verifies, with the org's public key.
func TestBudgetPolicySignatureVerifiesUnderTheOrgKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	doc, err := SignBudgetPolicy(priv, "org-1", "u1", testBudgetBody())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if doc.Signature == "" {
		t.Fatal("no signature")
	}
	if err := VerifyBudgetPolicy(pub, "org-1", "u1", doc); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestBudgetPolicySignatureIsBoundToTheCaller is the property this rail needs
// and the resource rail does not: the body is resolved PER CALLER, so a
// genuinely signed body replayed at a DIFFERENT member (or a different tenant)
// must not verify — otherwise one developer's cap could be served to another.
func TestBudgetPolicySignatureIsBoundToTheCaller(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	doc, err := SignBudgetPolicy(priv, "org-1", "u1", testBudgetBody())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for _, tc := range []struct{ name, org, sub string }{
		{"another member", "org-1", "u2"},
		{"another tenant", "org-2", "u1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyBudgetPolicy(pub, tc.org, tc.sub, doc); !errors.Is(err, ErrBudgetPolicySignature) {
				t.Fatalf("verify(%s/%s) = %v, want ErrBudgetPolicySignature", tc.org, tc.sub, err)
			}
		})
	}
}

// TestBudgetPolicySignatureIsBoundToTheVersionAndTheCaps closes the
// ROUTING-SIG-1 class on this rail: an old body cannot be re-served under an
// inflated version, and no cap can be edited in flight.
func TestBudgetPolicySignatureIsBoundToTheVersionAndTheCaps(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	doc, _ := SignBudgetPolicy(priv, "org-1", "u1", testBudgetBody())

	inflated := doc
	inflated.Version = 999
	if err := VerifyBudgetPolicy(pub, "org-1", "u1", inflated); !errors.Is(err, ErrBudgetPolicySignature) {
		t.Errorf("an inflated version verified: %v", err)
	}

	raised := doc
	raised.CapTokens = 1 << 40
	if err := VerifyBudgetPolicy(pub, "org-1", "u1", raised); !errors.Is(err, ErrBudgetPolicySignature) {
		t.Errorf("a raised cap verified: %v", err)
	}

	relaxed := doc
	relaxed.Enforcement = BudgetPolicyEnforcementReport
	if err := VerifyBudgetPolicy(pub, "org-1", "u1", relaxed); !errors.Is(err, ErrBudgetPolicySignature) {
		t.Errorf("a downgraded enforcement mode verified: %v", err)
	}
}

// TestBudgetPolicySignatureIsDomainSeparated: one org key signs several rails,
// so a routing-policy signature must never verify as a budget policy.
func TestBudgetPolicySignatureIsDomainSeparated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := testBudgetBody()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A routing-policy v2 signature over the same version + bytes.
	doc := BudgetPolicyDoc{BudgetPolicyBody: body, Signature: SignRoutingPolicyV2(priv, body.Version, string(raw))}
	if err := VerifyBudgetPolicy(pub, "org-1", "u1", doc); !errors.Is(err, ErrBudgetPolicySignature) {
		t.Fatalf("a routing-policy signature verified as a budget policy: %v", err)
	}
}

// TestBudgetPolicyDocIsFlatOnTheWire pins the documented JSON shape (plan
// §3.3b): the body's fields are top-level beside "signature", not nested.
func TestBudgetPolicyDocIsFlatOnTheWire(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	doc, _ := SignBudgetPolicy(priv, "org-1", "u1", testBudgetBody())
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"version":`, `"resolved_scope":`, `"cap_tokens":`, `"period":`,
		`"timezone":`, `"enforcement":`, `"thresholds":`, `"caps":`, `"signature":`,
	} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("wire body is missing %s: %s", key, raw)
		}
	}
	if strings.Contains(string(raw), `"BudgetPolicyBody"`) {
		t.Errorf("the body is nested rather than flat: %s", raw)
	}
	// An unset USD cap must be ABSENT, not rendered as 0 — a node reading a
	// zero cap as a cap would deny every request.
	if strings.Contains(string(raw), `"cap_usd"`) {
		t.Errorf("an unset cap_usd was serialized: %s", raw)
	}
}

// TestBudgetPolicyDigestChangesWithMembership is why the ETag hashes the
// DOCUMENT and not merely Version: a caller's effective body also changes when
// their team membership does, which no budget mutation records.
func TestBudgetPolicyDigestChangesWithMembership(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	teamBody := testBudgetBody()
	orgBody := testBudgetBody()
	orgBody.ResolvedScope = "org"
	orgBody.Caps[0].ResolvedScope = "org"
	orgBody.Caps[0].ScopeTokens = "org"

	a, _ := SignBudgetPolicy(priv, "org-1", "u1", teamBody)
	b, _ := SignBudgetPolicy(priv, "org-1", "u1", orgBody)
	da, err := BudgetPolicyDigest(a)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	db, err := BudgetPolicyDigest(b)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if da == db {
		t.Fatal("the digest did not change when the resolved scope did — a node would be told 304 for a cap that moved")
	}
	again, _ := BudgetPolicyDigest(a)
	if again != da {
		t.Fatal("the digest is not stable for an unchanged document")
	}
}
