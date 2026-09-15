package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testReplacement(t *testing.T, pub ed25519.PublicKey) GrantReplacement {
	t.Helper()
	return GrantReplacement{
		OrgID:        "org-1",
		OrgServerURL: "https://org.example.com",
		KeyPinSHA256: PublicKeyPinHash(pub),
		Generation:   1,
		PublicKey:    base64.RawURLEncoding.EncodeToString(pub),
		Authority:    []string{"dashboard.visibility"},
		GrantedAt:    "2026-08-15T10:00:00Z",
		ExpiresAt:    "2026-09-14T10:00:00Z",
	}
}

func TestGrantReplacementSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	r := testReplacement(t, pub)
	r.Signature = SignGrantReplacement(priv, r)

	gotPub, err := VerifyGrantReplacement(r)
	if err != nil {
		t.Fatalf("VerifyGrantReplacement: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatalf("VerifyGrantReplacement returned a different key than the message embedded")
	}

	// Authority order must not change the signature — same canonicalization
	// as EnrolmentGrant.
	r2 := r
	r2.Authority = []string{"settings.pin", "dashboard.visibility"}
	r2.Signature = SignGrantReplacement(priv, r2)
	r3 := r2
	r3.Authority = []string{"dashboard.visibility", "settings.pin", "dashboard.visibility"}
	if _, err := VerifyGrantReplacement(r3); err != nil {
		t.Fatalf("reordered/duplicated authority broke verification: %v", err)
	}
}

// TestGrantReplacementTamperDetected walks every semantic field, mirroring
// TestEnrolmentGrantTamperDetected: a replacement that claims more authority,
// a different generation, org, server, or key pin than what was signed must
// fail — the self-contained PublicKey field must not weaken this.
func TestGrantReplacementTamperDetected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	base := testReplacement(t, pub)
	base.Signature = SignGrantReplacement(priv, base)

	mutate := map[string]func(*GrantReplacement){
		"widened authority": func(r *GrantReplacement) {
			r.Authority = append(r.Authority, "capture.raise")
		},
		"different org":     func(r *GrantReplacement) { r.OrgID = "org-2" },
		"different server":  func(r *GrantReplacement) { r.OrgServerURL = "https://evil.example" },
		"different key pin": func(r *GrantReplacement) { r.KeyPinSHA256 = "cafe" },
		"lower generation":  func(r *GrantReplacement) { r.Generation = 0 },
		"higher generation": func(r *GrantReplacement) { r.Generation = 99 },
		"extended TTL":      func(r *GrantReplacement) { r.ExpiresAt = "2099-01-01T00:00:00Z" },
		"backdated grant":   func(r *GrantReplacement) { r.GrantedAt = "2020-01-01T00:00:00Z" },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Authority = append([]string(nil), base.Authority...)
			m(&r)
			if _, err := VerifyGrantReplacement(r); err == nil {
				t.Fatalf("tampered replacement (%s) verified", name)
			}
		})
	}

	// The PublicKey field itself is NOT part of the signed bytes (mirrors
	// PolicyBundle) — but swapping it to a DIFFERENT key must still fail,
	// because verification runs against whatever key the message now claims,
	// and the original signature was minted under the original key.
	t.Run("public key swapped for an unrelated key", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		r := base
		r.PublicKey = base64.RawURLEncoding.EncodeToString(otherPub)
		if _, err := VerifyGrantReplacement(r); err == nil {
			t.Fatal("replacement verified after its embedded public key was swapped")
		}
	})

	t.Run("no public key at all", func(t *testing.T) {
		r := base
		r.PublicKey = ""
		_, err := VerifyGrantReplacement(r)
		if err == nil || !strings.Contains(err.Error(), "no public key") {
			t.Fatalf("err = %v, want a NAMED no-key error", err)
		}
	})

	t.Run("public key does not base64-decode", func(t *testing.T) {
		r := base
		r.PublicKey = "not valid base64url!!"
		if _, err := VerifyGrantReplacement(r); err == nil {
			t.Fatal("replacement verified with an undecodable public key")
		}
	})

	t.Run("public key wrong length", func(t *testing.T) {
		r := base
		r.PublicKey = base64.RawURLEncoding.EncodeToString([]byte("too-short"))
		if _, err := VerifyGrantReplacement(r); err == nil {
			t.Fatal("replacement verified with a wrong-length public key")
		}
	})

	t.Run("no signature", func(t *testing.T) {
		r := base
		r.Signature = ""
		if _, err := VerifyGrantReplacement(r); err == nil {
			t.Fatal("unsigned replacement verified")
		}
	})

	t.Run("signature does not base64-decode", func(t *testing.T) {
		r := base
		r.Signature = "not valid base64url!!"
		if _, err := VerifyGrantReplacement(r); err == nil {
			t.Fatal("replacement verified with an undecodable signature")
		}
	})
}

// TestGrantReplacementSigningIsDomainSeparated proves a replacement
// signature cannot be replayed from another rail signed by the same org
// key, and specifically that it cannot be replayed AS an EnrolmentGrant or
// vice versa — the two share every other field shape.
func TestGrantReplacementSigningIsDomainSeparated(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	r := testReplacement(t, pub)
	msg := string(GrantReplacementSigningMessage(r))
	if msg == string(PolicyBundleSigningMessage(1, []byte(r.OrgID))) {
		t.Fatal("replacement and policy-bundle signing messages collide")
	}
	if msg == string(AnnouncementSigningMessage(1, r.OrgID)) {
		t.Fatal("replacement and announcement signing messages collide")
	}

	g := EnrolmentGrant{
		OrgID: r.OrgID, OrgServerURL: r.OrgServerURL, KeyPinSHA256: r.KeyPinSHA256,
		Authority: r.Authority, GrantedAt: r.GrantedAt, ExpiresAt: r.ExpiresAt,
	}
	sig := SignEnrolmentGrant(priv, g)
	r2 := r
	r2.Signature = sig
	if _, err := VerifyGrantReplacement(r2); err == nil {
		t.Fatal("an EnrolmentGrant signature verified as a GrantReplacement signature")
	}
}

func TestGrantReplacementReceiptHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	r := testReplacement(t, pub)
	r.Signature = SignGrantReplacement(priv, r)

	h1 := GrantReplacementReceiptHash(r)
	h2 := GrantReplacementReceiptHash(r)
	if h1 == "" || h1 != h2 {
		t.Fatalf("GrantReplacementReceiptHash not stable: %q vs %q", h1, h2)
	}
	r2 := r
	r2.Generation = 2
	r2.Signature = SignGrantReplacement(priv, r2)
	if GrantReplacementReceiptHash(r2) == h1 {
		t.Fatal("receipt hash did not change for a different generation")
	}
}
