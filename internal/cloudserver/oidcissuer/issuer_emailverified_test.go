package oidcissuer_test

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// TestIssuerEnforcesProviderEmailVerified is operator item A4 through both
// legs: an address the identity provider verified is signed with
// email_verified=true; an unverified one, and one whose flag the provider did
// not send (stored as false by the API layer), is refused at authorize and,
// when the flag drops between authorize and token, at token too. No token is
// ever issued carrying email_verified=false.
func TestIssuerEnforcesProviderEmailVerified(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		verified bool
		wantRule string
	}{
		{"verified", true, ""},
		{"unverified", false, "email-verified"},
		{"flag missing", false, "email-verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			w := newWorld(t)
			iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
			p := newRP(orgA)
			m := member()
			m.EmailVerified = tc.verified
			w.store.SetMember(alice, orgA, m)

			res := iss.Authorize(ctx, p.authorize(), oidcissuer.Session{AccountID: alice, AuthTime: start, AMR: []string{"pwd"}})
			if tc.wantRule == "" {
				resp, err := iss.Token(ctx, p.token(codeFrom(t, p, res)))
				if err != nil {
					t.Fatalf("Token: %v", err)
				}
				if c := verifyWithJWKS(t, iss, resp.IDToken); !c.EmailVerified || c.Email != "alice@example.com" {
					t.Fatalf("claims = %+v, want the verified email", c)
				}
				return
			}
			if res.Err == nil || res.Err.RuleID != tc.wantRule || res.Err.Code != oidcissuer.ErrCodeAccessDenied {
				t.Fatalf("authorize = %+v, want refusal %s", res, tc.wantRule)
			}
			// Verified at authorize, no longer verified at token time.
			w.store.SetMember(alice, orgA, member())
			code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), oidcissuer.Session{AccountID: alice, AuthTime: start, AMR: []string{"pwd"}}))
			w.store.SetMember(alice, orgA, m)
			_, err := iss.Token(ctx, p.token(code))
			if e := wantGrantErr(t, err, oidcissuer.ErrCodeInvalidGrant); e.RuleID != tc.wantRule {
				t.Fatalf("token refused by %s, want %s", e.RuleID, tc.wantRule)
			}
			if issued := w.store.Issued(); len(issued) != 0 {
				t.Fatalf("issued %d tokens for an unverified email", len(issued))
			}
		})
	}
}

// TestBuildClaimsCarriesTheMemberFlag: the claim is the flag the member
// carried, never a constant, and the signer's own claim rule refuses false.
func TestBuildClaimsCarriesTheMemberFlag(t *testing.T) {
	t.Parallel()
	for _, verified := range []bool{true, false} {
		code := oidcissuer.CodeRecord{
			ClientID: oidcissuer.ClientIDForOrg(orgA), OrgID: orgA, Sub: "user_alice",
			Email: "alice@example.com", EmailVerified: verified, AuthTime: start,
		}
		c := oidcissuer.BuildClaims(testIssuer, code, "jti-0123456789abcdef", start)
		if c.EmailVerified != verified {
			t.Fatalf("verified=%v: claim %v", verified, c.EmailVerified)
		}
		err := oidcissuer.ValidateClaims(c, testIssuer, start)
		if verified && err != nil {
			t.Fatalf("verified claims refused: %v", err)
		}
		if !verified && err == nil {
			t.Fatal("the signer's claim rules accepted email_verified=false")
		}
	}
}
