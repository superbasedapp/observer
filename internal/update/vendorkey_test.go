package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestVendorKeyIsRealAndAccepted is the W6 requirement: the compiled-in
// vendor key slot holds REAL key material that this build accepts, so
// the two-signature claim of §2.2 is true rather than aspirational.
func TestVendorKeyIsRealAndAccepted(t *testing.T) {
	key, err := ParseVendorKey(VendorPublicKeyV1)
	if err != nil {
		t.Fatalf("ParseVendorKey: %v", err)
	}
	if len(key) != ed25519.PublicKeySize {
		t.Fatalf("key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	if VendorKeyIsPlaceholder() {
		t.Error("VendorKeyIsPlaceholder() = true — this build carries no usable vendor key")
	}
	accepted := VendorPublicKeys()
	if len(accepted) == 0 {
		t.Fatal("VendorPublicKeys() is empty — no artifact signature could ever verify")
	}
	if string(accepted[0]) != string(key) {
		t.Error("VendorPublicKeyV1 is not the first accepted key")
	}
	if _, err := ParseVendorKey("not base64"); err == nil {
		t.Error("ParseVendorKey accepted a non-base64 key")
	}
	if _, err := ParseVendorKey("YWJj"); err == nil {
		t.Error("ParseVendorKey accepted a short key")
	}
}

// TestVendorKeyIDIsStable pins the key id the release pipeline stamps
// into `update-manifest-<channel>.json` (and that the operator README
// beside the private key records) to the compiled-in public key. A
// silent key swap that kept the same id, or an id recomputed a
// different way, would make the manifest's key_id field a lie.
func TestVendorKeyIDIsStable(t *testing.T) {
	key, err := ParseVendorKey(VendorPublicKeyV1)
	if err != nil {
		t.Fatalf("ParseVendorKey: %v", err)
	}
	sum := sha256.Sum256(key)
	const want = "7595a73e343e517a07c8d944ba75be91"
	if got := hex.EncodeToString(sum[:])[:32]; got != want {
		t.Errorf("key id = %s, want %s — the compiled-in key changed; "+
			"rotate through VendorPublicKeyV0Previous and update this pin", got, want)
	}
}

// TestPlaceholderKeyIsNotAccepted is why the all-zero placeholder is
// kept as a REFUSED sentinel rather than deleted, demonstrated rather
// than asserted: an all-zero Ed25519 public key VERIFIES an all-zero
// signature, because the identity point satisfies the verification
// equation trivially. Letting those bytes back into the accepted set —
// by a bad merge, or by a half-finished rotation that blanks V1 — would
// let 64 zero bytes pass vendor verification.
func TestPlaceholderKeyIsNotAccepted(t *testing.T) {
	zero, err := ParseVendorKey(vendorPlaceholderKey)
	if err != nil {
		t.Fatalf("ParseVendorKey: %v", err)
	}
	if !ed25519.Verify(zero, []byte("anything"), make([]byte, ed25519.SignatureSize)) {
		t.Skip("this Go release rejects the all-zero key outright; the exclusion is still correct")
	}
	for _, k := range VendorPublicKeys() {
		if string(k) == string(zero) {
			t.Fatal("the all-zero placeholder is in the ACCEPTED key set — 64 zero bytes would verify")
		}
	}
}

// TestVendorKeySlotsFailClosed walks the accepted-set builder over the
// slot shapes a rotation can produce. It is table-driven because the
// EMPTY rotation slot is the case a reader most easily reads as
// "accept anything": an unused slot must contribute no key, and a build
// with nothing but empty and placeholder slots must accept nothing at
// all rather than falling back to some default.
func TestVendorKeySlotsFailClosed(t *testing.T) {
	realKey := VendorPublicKeyV1
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherB64 := base64.StdEncoding.EncodeToString(other)

	cases := []struct {
		name        string
		slots       []string
		wantKeys    int
		wantNoUsage bool // VendorKeyIsPlaceholder()
	}{
		{"current only", []string{realKey, ""}, 1, false},
		{"rotation overlap", []string{otherB64, realKey}, 2, false},
		{"empty slots only", []string{"", ""}, 0, true},
		{"placeholder only", []string{vendorPlaceholderKey, ""}, 0, true},
		{"malformed current", []string{"not base64", ""}, 0, false},
		{"malformed current with real previous", []string{"not base64", realKey}, 1, false},
	}
	saved := vendorPublicKeysB64
	t.Cleanup(func() { vendorPublicKeysB64 = saved })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vendorPublicKeysB64 = tc.slots
			if got := len(VendorPublicKeys()); got != tc.wantKeys {
				t.Errorf("VendorPublicKeys() = %d keys, want %d", got, tc.wantKeys)
			}
			if got := VendorKeyIsPlaceholder(); got != tc.wantNoUsage {
				t.Errorf("VendorKeyIsPlaceholder() = %t, want %t", got, tc.wantNoUsage)
			}
		})
	}
}
