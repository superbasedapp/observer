package store_test

import (
	"context"
	"testing"
	"time"
)

// TestVerifiedEmailFeedsTheIssuerMember is A4 at the store seam, one case per
// row: what the last sign-in recorded is exactly what the issuer's member
// lookup reads. A missing flag reaches the store as false (the API layer's
// rule); an empty address clears the row, so no stale verified address
// survives; and the display profile is never read for the claim.
func TestVerifiedEmailFeedsTheIssuerMember(t *testing.T) {
	f := newOIDCFixture(t)
	ctx := context.Background()
	oidc := newAPIStore(t, f.pool).OIDC()
	// A display profile with a different address: the issuer must ignore it.
	if err := f.app.UpsertAccountProfile(ctx, f.owner, "display@example.com", "Owner", time.Now()); err != nil {
		t.Fatalf("UpsertAccountProfile: %v", err)
	}
	for _, tc := range []struct {
		name         string
		address      string
		verified     bool
		wantEmail    string
		wantVerified bool
	}{
		{"verified", "owner@example.com", true, "owner@example.com", true},
		{"unverified", "owner@example.com", false, "owner@example.com", false},
		{"flag missing (stored false)", "owner@example.com", false, "owner@example.com", false},
		{"verified again, new address", "new@example.com", true, "new@example.com", true},
		{"no address clears the row", "", true, "", false},
		{"over-long address clears the row", string(make([]byte, 255)), true, "", false},
	} {
		if err := f.app.UpsertVerifiedEmail(ctx, f.owner, tc.address, tc.verified, time.Now()); err != nil {
			t.Fatalf("%s: UpsertVerifiedEmail: %v", tc.name, err)
		}
		m, err := oidc.Member(ctx, f.owner, f.org.OrgID)
		if err != nil {
			t.Fatalf("%s: Member: %v", tc.name, err)
		}
		if !m.IsMember || m.Email != tc.wantEmail || m.EmailVerified != tc.wantVerified {
			t.Fatalf("%s: member email %q verified %v (member %v), want %q %v", tc.name, m.Email, m.EmailVerified, m.IsMember, tc.wantEmail, tc.wantVerified)
		}
	}
}
