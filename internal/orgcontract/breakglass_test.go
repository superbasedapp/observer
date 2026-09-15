package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testLease(t *testing.T, pub ed25519.PublicKey) BreakGlassLease {
	t.Helper()
	return BreakGlassLease{
		LeaseID:          "bgl-1",
		RequestID:        "bgr-1",
		OrgID:            "org-1",
		OrgServerURL:     "https://org.example.com",
		KeyPinSHA256:     PublicKeyPinHash(pub),
		UserID:           "scim-42",
		UpstreamID:       "anthropic-prod",
		Rung:             "break_glass",
		SealScheme:       "opaque-v1",
		SealedCredential: base64.StdEncoding.EncodeToString([]byte("sealed-secret-bytes")),
		PublicKey:        base64.RawURLEncoding.EncodeToString(pub),
		ApprovedBy:       "super-admin-1",
		GrantedAt:        "2026-08-30T10:00:00Z",
		ExpiresAt:        "2026-08-30T11:00:00Z",
	}
}

func TestBreakGlassLeaseSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	l := testLease(t, pub)
	l.Signature = SignBreakGlassLease(priv, l)

	gotPub, err := VerifyBreakGlassLease(l)
	if err != nil {
		t.Fatalf("VerifyBreakGlassLease: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatalf("VerifyBreakGlassLease returned a different key than the message embedded")
	}
}

// TestBreakGlassLeaseTamperDetected walks every semantic field: a lease that
// claims a different target, upstream, sealed credential, expiry, or approver
// than what was signed must fail. The sealed credential and its scheme are
// signed so a lease can never be re-pointed at a different sealed blob.
func TestBreakGlassLeaseTamperDetected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	base := testLease(t, pub)
	base.Signature = SignBreakGlassLease(priv, base)

	mutate := map[string]func(*BreakGlassLease){
		"different lease id":  func(l *BreakGlassLease) { l.LeaseID = "bgl-2" },
		"different request":   func(l *BreakGlassLease) { l.RequestID = "bgr-2" },
		"different org":       func(l *BreakGlassLease) { l.OrgID = "org-2" },
		"different server":    func(l *BreakGlassLease) { l.OrgServerURL = "https://evil.example" },
		"different key pin":   func(l *BreakGlassLease) { l.KeyPinSHA256 = "cafe" },
		"different target":    func(l *BreakGlassLease) { l.UserID = "scim-99" },
		"different upstream":  func(l *BreakGlassLease) { l.UpstreamID = "openai-prod" },
		"swapped seal scheme": func(l *BreakGlassLease) { l.SealScheme = "other" },
		"swapped credential":  func(l *BreakGlassLease) { l.SealedCredential = base64.StdEncoding.EncodeToString([]byte("attacker")) },
		"different approver":  func(l *BreakGlassLease) { l.ApprovedBy = "plain-admin" },
		"extended TTL":        func(l *BreakGlassLease) { l.ExpiresAt = "2099-01-01T00:00:00Z" },
		"backdated grant":     func(l *BreakGlassLease) { l.GrantedAt = "2020-01-01T00:00:00Z" },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			l := base
			m(&l)
			if _, err := VerifyBreakGlassLease(l); err == nil {
				t.Fatalf("tampered lease (%s) verified", name)
			}
		})
	}

	t.Run("public key swapped for an unrelated key", func(t *testing.T) {
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		l := base
		l.PublicKey = base64.RawURLEncoding.EncodeToString(otherPub)
		if _, err := VerifyBreakGlassLease(l); err == nil {
			t.Fatal("lease verified after its embedded public key was swapped")
		}
	})

	t.Run("no public key at all", func(t *testing.T) {
		l := base
		l.PublicKey = ""
		_, err := VerifyBreakGlassLease(l)
		if err == nil || !strings.Contains(err.Error(), "no public key") {
			t.Fatalf("err = %v, want a NAMED no-key error", err)
		}
	})

	t.Run("no signature", func(t *testing.T) {
		l := base
		l.Signature = ""
		if _, err := VerifyBreakGlassLease(l); err == nil {
			t.Fatal("unsigned lease verified")
		}
	})
}

// TestBreakGlassLeaseSigningIsDomainSeparated proves a lease signature cannot
// be replayed as a GrantReplacement (or any other rail) signed by the same key.
func TestBreakGlassLeaseSigningIsDomainSeparated(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	l := testLease(t, pub)
	msg := string(BreakGlassLeaseSigningMessage(l))

	// A GrantReplacement whose fields overlap the lease must not collide.
	r := GrantReplacement{
		OrgID: l.OrgID, OrgServerURL: l.OrgServerURL, KeyPinSHA256: l.KeyPinSHA256,
		Generation: 1, PublicKey: l.PublicKey, GrantedAt: l.GrantedAt, ExpiresAt: l.ExpiresAt,
	}
	if msg == string(GrantReplacementSigningMessage(r)) {
		t.Fatal("break-glass lease and grant-replacement signing messages collide")
	}
	rsig := SignGrantReplacement(priv, r)
	l2 := l
	l2.Signature = rsig
	if _, err := VerifyBreakGlassLease(l2); err == nil {
		t.Fatal("a GrantReplacement signature verified as a BreakGlassLease signature")
	}
}

func TestBreakGlassLeaseReceiptHash(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	l := testLease(t, pub)
	l.Signature = SignBreakGlassLease(priv, l)

	h1 := BreakGlassLeaseReceiptHash(l)
	h2 := BreakGlassLeaseReceiptHash(l)
	if h1 == "" || h1 != h2 {
		t.Fatalf("BreakGlassLeaseReceiptHash not stable: %q vs %q", h1, h2)
	}
	l2 := l
	l2.LeaseID = "bgl-2"
	l2.Signature = SignBreakGlassLease(priv, l2)
	if BreakGlassLeaseReceiptHash(l2) == h1 {
		t.Fatal("receipt hash did not change for a different lease")
	}
}
