package oidcissuer_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
)

// TestIssuerSecondFactor covers C2 at the issuer: a session whose account
// holds a passkey it has not used is sent to the second-factor page, an org
// that requires a second factor issues only to a multi-factor session (at
// authorize and again at token time), prompt=none answers
// interaction_required, and the amr reaches the id_token unchanged.
func TestIssuerSecondFactor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mfa := []string{"hwk", "mfa"}

	t.Run("pending passkey is sent to the second factor", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
		s := signedIn(alice)
		s.SecondFactorPending = true
		if res := iss.Authorize(ctx, newRP(orgA).authorize(), s); res.Outcome != oidcissuer.OutcomeSecondFactor {
			t.Fatalf("outcome = %+v", res)
		}
	})

	t.Run("org requirement", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
		m := member()
		m.RequireSecondFactor = true
		w.store.SetMember(alice, orgA, m)
		p := newRP(orgA)
		if res := iss.Authorize(ctx, p.authorize(), signedIn(alice)); res.Outcome != oidcissuer.OutcomeSecondFactor {
			t.Fatalf("single-factor outcome = %+v", res)
		}
		// A recovery-code session carries no amr: still not enough.
		if res := iss.Authorize(ctx, p.authorize(), oidcissuer.Session{AccountID: alice, AuthTime: start, AMR: nil}); res.Outcome != oidcissuer.OutcomeSecondFactor {
			t.Fatalf("no-amr outcome = %+v", res)
		}
		none := p.authorize()
		none.Prompt = "none"
		res := iss.Authorize(ctx, none, signedIn(alice))
		u, _ := url.Parse(res.Location)
		if res.Outcome != oidcissuer.OutcomeRedirect || u == nil || u.Query().Get("error") != oidcissuer.ErrCodeInteractionRequired {
			t.Fatalf("prompt=none = %+v", res)
		}
		s := signedIn(alice)
		s.AMR = mfa
		code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), s))
		resp, err := iss.Token(ctx, p.token(code))
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if c := verifyWithJWKS(t, iss, resp.IDToken); len(c.AMR) != 2 || c.AMR[0] != "hwk" || c.AMR[1] != "mfa" {
			t.Fatalf("amr = %v", c.AMR)
		}
	})

	t.Run("requirement turned on between authorize and token", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
		p := newRP(orgA)
		code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
		m := member()
		m.RequireSecondFactor = true
		w.store.SetMember(alice, orgA, m)
		_, err := iss.Token(ctx, p.token(code))
		if e := wantGrantErr(t, err, oidcissuer.ErrCodeInvalidGrant); e.RuleID != "org-requires-second-factor" {
			t.Fatalf("rule = %s", e.RuleID)
		}
	})

	t.Run("no requirement, no passkey: issued without amr", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		iss, _ := w.replica(t, oidctest.NewKey(t), "vm-a")
		p := newRP(orgA)
		code := codeFrom(t, p, iss.Authorize(ctx, p.authorize(), signedIn(alice)))
		resp, err := iss.Token(ctx, p.token(code))
		if err != nil {
			t.Fatal(err)
		}
		if c := verifyWithJWKS(t, iss, resp.IDToken); len(c.AMR) != 0 {
			t.Fatalf("amr = %v, want none", c.AMR)
		}
	})
}
