package cloudsession

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// testSigner is a deterministic Ed25519 key for policy fixtures.
func testSigner(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	return ed25519.NewKeyFromSeed(seed)
}

// testGuardTOML denies one command (a policy-file rule in the §4.4 format).
const testGuardTOML = `[[rule]]
id = 'U-900'
category = 'boundary'
decision = 'deny'
applies_to = ['shell_exec']
match.command_base = 'curl'
match.arg_contains = 'example.invalid'
`

// signedPolicy builds a policy file signed by priv, with an optional budget.
func signedPolicy(t *testing.T, priv ed25519.PrivateKey, version int64, budget *orgcontract.BudgetPolicyBody) ([]byte, PolicyPin) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	p := SandboxPolicy{
		Origin:    OriginOrg,
		KeyPin:    orgcontract.PublicKeyPinHash(pub),
		FetchedAt: "2026-11-01T10:00:00Z",
		Guard: orgcontract.PolicyBundle{
			Version: version, BundleTOML: testGuardTOML,
			Signature: orgcontract.SignPolicyBundle(priv, version, []byte(testGuardTOML)),
			PublicKey: base64.RawURLEncoding.EncodeToString(pub), SignedAt: "2026-11-01T10:00:00Z",
		},
	}
	if budget != nil {
		doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "user-1", *budget)
		if err != nil {
			t.Fatal(err)
		}
		p.Budget = &SandboxBudget{OrgID: "org-1", Subject: "user-1", Document: doc}
	}
	raw, err := EncodePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw, PolicyPin{KeyPin: p.KeyPin, Digest: PolicyDigest(raw)}
}

// TestVerifyPolicy walks the verification table: one case per refusal row,
// plus the accepted file.
func TestVerifyPolicy(t *testing.T) {
	priv := testSigner(7)
	budget := &orgcontract.BudgetPolicyBody{Version: 3, Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapUSD: 10, Enforcement: "soft"}
	good, pin := signedPolicy(t, priv, 5, budget)
	older, _ := signedPolicy(t, priv, 4, nil)
	forged, forgedPin := signedPolicy(t, testSigner(9), 5, nil)

	// A file whose digest is pinned but whose guard signature was broken
	// after signing (the pin then covers bad bytes; the signature catches it).
	var p SandboxPolicy
	if err := json.Unmarshal(good, &p); err != nil {
		t.Fatal(err)
	}
	p.Guard.BundleTOML = strings.Replace(p.Guard.BundleTOML, "decision = 'deny'", "decision = 'flag'", 1)
	weakened, _ := EncodePolicy(p)

	var pb SandboxPolicy
	_ = json.Unmarshal(good, &pb)
	pb.Budget.Document.CapUSD = 1000
	budgetEdited, _ := EncodePolicy(pb)

	cases := []struct {
		name   string
		raw    []byte
		exists bool
		pin    PolicyPin
		want   PolicyFailure
	}{
		{"accepted", good, true, pin, ""},
		{"missing file", nil, false, pin, PolicyMissing},
		{"edited after commit", append(append([]byte(nil), good...), ' '), true, pin, PolicyDigestMismatch},
		{"older signed copy swapped in from git history", older, true, pin, PolicyDigestMismatch},
		{"not JSON", []byte("{"), true, PolicyPin{KeyPin: pin.KeyPin, Digest: PolicyDigest([]byte("{"))}, PolicyMalformed},
		{"weakened rule with a matching digest", weakened, true, PolicyPin{KeyPin: pin.KeyPin, Digest: PolicyDigest(weakened)}, PolicySignature},
		{"another key with a matching digest", forged, true, PolicyPin{KeyPin: pin.KeyPin, Digest: forgedPin.Digest}, PolicyKeyPin},
		{"raised budget cap with a matching digest", budgetEdited, true, PolicyPin{KeyPin: pin.KeyPin, Digest: PolicyDigest(budgetEdited)}, PolicyBudgetSignature},
		{"bad pin shape", good, true, PolicyPin{KeyPin: "nope", Digest: pin.Digest}, PolicyMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := VerifyPolicy(tc.raw, tc.exists, tc.pin)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if v.Budget == nil || v.Budget.CapUSD != 10 || len(v.GuardEnvelope) == 0 {
					t.Fatalf("verified policy = %+v", v)
				}
				return
			}
			pe, ok := AsPolicyError(err)
			if !ok {
				t.Fatalf("err = %v, want a PolicyError %s", err, tc.want)
			}
			if pe.Failure != tc.want {
				t.Fatalf("failure = %s (%s), want %s", pe.Failure, pe.Detail, tc.want)
			}
			if !strings.Contains(pe.Reason(), "blocked because guard enforcement is on") {
				t.Errorf("reason does not say why the call is blocked: %s", pe.Reason())
			}
		})
	}
}

// TestNodePolicyCarriesNoBudget: a node-signed file with a budget is refused.
func TestNodePolicyCarriesNoBudget(t *testing.T) {
	priv := testSigner(3)
	raw, pin := signedPolicy(t, priv, 1, &orgcontract.BudgetPolicyBody{Version: 1, Period: "calendar_day", CapUSD: 1, Enforcement: "soft"})
	var p SandboxPolicy
	_ = json.Unmarshal(raw, &p)
	p.Origin = OriginNode
	raw, _ = EncodePolicy(p)
	_, err := VerifyPolicy(raw, true, PolicyPin{KeyPin: pin.KeyPin, Digest: PolicyDigest(raw)})
	if pe, ok := AsPolicyError(err); !ok || pe.Failure != PolicyMalformed {
		t.Fatalf("err = %v, want malformed", err)
	}
}

// TestEncodePolicyIsStable: the encoding is deterministic, two-space JSON
// ending in a newline, and recognised as Observer's file.
func TestEncodePolicyIsStable(t *testing.T) {
	a, _ := signedPolicy(t, testSigner(1), 1, nil)
	b, _ := signedPolicy(t, testSigner(1), 1, nil)
	if string(a) != string(b) {
		t.Fatal("encoding is not deterministic")
	}
	if !strings.HasSuffix(string(a), "}\n") || !strings.Contains(string(a), "\n  \"format\": \""+PolicyFormat+"\"") {
		t.Fatalf("unexpected layout:\n%s", a)
	}
	if !isPolicyFile(string(a)) || isPolicyFile(`{"format":"other"}`) || isPolicyFile("x") {
		t.Fatal("ownership test wrong")
	}
}
