package pricingfeed

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestGoldenEnvelope_CrossModuleCanonicalAgreement pins BYTE-FOR-BYTE agreement
// between this module's canonicalizer/verifier and the Tokenomics publisher's
// (finding F3, consumer half). The golden envelope + its test public key are
// committed by the publisher side (model-pricing) at
// testdata/golden-envelope-v1.{json,pub} and are READ-ONLY here: if the two
// modules' CanonicalRows ever diverge by a single byte, the digest check below
// stops matching and a signed feed the publisher emits would be refused by every
// node — exactly the silent cross-module drift this test exists to catch.
func TestGoldenEnvelope_CrossModuleCanonicalAgreement(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden-envelope-v1.json")
	if err != nil {
		t.Fatalf("read golden envelope: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal golden envelope: %v", err)
	}

	// (1) Re-canonicalise with OUR canonicalizer and assert the resulting digest
	// equals the digest the publisher stamped into the file. This is the
	// byte-for-byte agreement assertion: a different field order, number
	// rendering, or nil-vs-quoted-zero handling on either side would change the
	// digest.
	canonical, err := CanonicalRows(env.Rows)
	if err != nil {
		t.Fatalf("CanonicalRows: %v", err)
	}
	if got := digestOf(canonical); got != env.Digest {
		t.Fatalf("recomputed digest %q != golden digest %q — the two modules' canonicalizers disagree byte-for-byte", got, env.Digest)
	}

	// (2) Build a KeySet from the committed .pub (keyed by the envelope's own
	// key_id) and assert Verify passes end to end.
	pubHex, err := os.ReadFile("testdata/golden-envelope-v1.pub")
	if err != nil {
		t.Fatalf("read golden pub: %v", err)
	}
	keys, err := NewKeySet(map[string]string{env.KeyID: strings.TrimSpace(string(pubHex))})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if err := Verify(env, keys); err != nil {
		t.Fatalf("Verify(golden) = %v, want nil — the committed signature must verify under the committed key", err)
	}

	// (3) Flip one byte of the canonical body (bump a rate) and assert Verify now
	// fails. The digest is recomputed so the refusal is ErrBadSignature, not a
	// digest mismatch — pinning that the Ed25519 signature binds the canonical
	// BODY, so no consumer can accept a tampered feed.
	//
	// Verify now checks the digest/signature over the envelope's RAW RECEIVED
	// bytes when it has them (verify-over-received-bytes, §3.4), so the tamper
	// must happen at the WIRE-BYTES level — exactly what a real attacker
	// controls — rather than on the already-decoded typed Rows field (mutating
	// that leaves the untouched original raw bytes behind, which would make
	// this a digest-mismatch test instead of a signature test). Re-marshal the
	// mutated typed envelope to get tampered wire bytes, then re-decode so
	// tampered.rawRows reflects them, exactly like a real received body would.
	tamperedRows := make([]Row, len(env.Rows))
	copy(tamperedRows, env.Rows)
	r0 := tamperedRows[0]
	if r0.InputPerMTok == nil {
		t.Fatalf("golden row 0 (%s) unexpectedly has a nil input rate; cannot flip a byte of it", r0.Model)
	}
	bumped := *r0.InputPerMTok + 1
	r0.InputPerMTok = &bumped
	tamperedRows[0] = r0

	preTamper := env
	preTamper.Rows = tamperedRows
	tamperedJSON, err := json.Marshal(preTamper)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}
	var tampered Envelope
	if err := json.Unmarshal(tamperedJSON, &tampered); err != nil {
		t.Fatalf("unmarshal tampered envelope: %v", err)
	}
	reDigest, err := Digest(tampered.Rows)
	if err != nil {
		t.Fatalf("Digest(tampered): %v", err)
	}
	tampered.Digest = reDigest
	if err := Verify(tampered, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify(tampered) = %v, want ErrBadSignature — the signature must cover the canonical body", err)
	}
}
