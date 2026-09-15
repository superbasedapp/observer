package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSealKeyAdvertisementRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	adv := SignSealKeyAdvertisement(priv, "org-1", "scim-42", "x25519-hkdf-sha256-aes256gcm-v1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	parsed, ok, err := ParseSealKeyHeader(adv.HeaderValue())
	if err != nil || !ok || parsed != adv {
		t.Fatalf("parse: %+v ok=%v err=%v", parsed, ok, err)
	}
	if err := VerifySealKeyAdvertisement(pub, "org-1", "scim-42", parsed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Bound to org + node: the same advertisement does not verify for another
	// node, and a different agent key never verifies it.
	if err := VerifySealKeyAdvertisement(pub, "org-1", "scim-99", parsed); err == nil {
		t.Fatal("verified for a different node")
	}
	if err := VerifySealKeyAdvertisement(pub, "org-2", "scim-42", parsed); err == nil {
		t.Fatal("verified for a different org")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySealKeyAdvertisement(other, "org-1", "scim-42", parsed); err == nil {
		t.Fatal("verified under a different agent key")
	}
	swapped := parsed
	swapped.PublicKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := VerifySealKeyAdvertisement(pub, "org-1", "scim-42", swapped); err == nil {
		t.Fatal("verified with a swapped public key")
	}
}

func TestParseSealKeyHeaderShapes(t *testing.T) {
	if _, ok, err := ParseSealKeyHeader("  "); ok || err != nil {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	for _, bad := range []string{"scheme:key", "a:b:c:d", ":key:sig", "scheme::sig"} {
		if _, _, err := ParseSealKeyHeader(bad); err == nil {
			t.Errorf("%q parsed, want error", bad)
		}
	}
}
