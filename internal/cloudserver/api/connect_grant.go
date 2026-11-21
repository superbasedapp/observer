package api

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// connect_grant.go mints the one-step attach grant an approved connect
// request with a target carries (docs/plans/onboarding-v2-connect-flow.md
// section 11; internal/attachgrant; docs/security.md ONB-8).
//
// The grant rides in the poll answer beside sign_in, under exactly sign_in's
// delivery rules: it is minted only on a poll that delivers a sign-in (the
// first poll after the approval and at most two more within ten minutes),
// never after. It is anchored to the approval, not to the poll: issued at
// the approval time with a ten-minute lifetime and a jti derived from the
// request id, and Ed25519 is deterministic, so every delivery of one approval
// carries the same bytes and the tenant host admits one attach per approval.
//
// No grant is minted (the machine then falls back to the dashboard's own
// sign-in) when no key is configured, when the approval chose no target
// ("Not now"), when the approval is older than the grant's lifetime, or when
// the account has no identity-provider subject the host could bind it by.

// connectGrantMember is the account facts a grant needs, read through the
// OIDC issuer's membership seam (the same subject and verified address the
// platform issuer signs into the tenant host's id tokens).
type connectGrantMember = oidcissuer.Member

// connectGrantClaims builds the grant's claims for an approved request and
// the approving account's membership facts. It reports false when no grant
// may be minted. Pure: the caller passes now and the facts.
func connectGrantClaims(c store.ConnectRequest, m connectGrantMember, now time.Time) (attachgrant.Claims, bool) {
	t := c.Target
	switch {
	case t == nil, c.AccountID == "", c.ResolvedAt.IsZero(), len(c.PublicKey) != ed25519.PublicKeySize:
		return attachgrant.Claims{}, false
	case !m.IsMember, m.Sub == "":
		return attachgrant.Claims{}, false
	}
	iat := c.ResolvedAt.UTC().Truncate(time.Second)
	exp := iat.Add(attachgrant.Lifetime)
	if !now.Before(exp) {
		return attachgrant.Claims{}, false
	}
	email := ""
	if m.EmailVerified {
		email = m.Email
	}
	return attachgrant.Claims{
		OrgID:            t.OrgID,
		Slug:             t.Slug,
		Kind:             string(t.Kind),
		AccountID:        c.AccountID,
		Subject:          m.Sub,
		Email:            email,
		DeviceThumbprint: attachgrant.Thumbprint(ed25519.PublicKey(c.PublicKey)),
		RequestID:        c.RequestID,
		ShareLevel:       string(t.ShareLevel),
		IssuedAt:         iat.Unix(),
		ExpiresAt:        exp.Unix(),
		JTI:              attachgrant.JTIFor(c.RequestID),
	}, true
}

// connectAttachGrant returns the grant for a delivering poll, or "" when none
// may be minted. A failure is logged and answers "" (the sign-in is still
// delivered; the machine falls back), never an error to the machine.
func (s *Server) connectAttachGrant(ctx context.Context, c store.ConnectRequest, now time.Time) string {
	if s.attachGrantKey == nil || c.Target == nil || c.AccountID == "" {
		return ""
	}
	m, err := s.store.OIDC().Member(ctx, c.AccountID, c.Target.OrgID)
	if err != nil {
		s.log.Error("cloudserver/api: attach grant: read membership", "err", err)
		return ""
	}
	claims, ok := connectGrantClaims(c, m, now)
	if !ok {
		return ""
	}
	grant, err := attachgrant.Mint(s.attachGrantKey, claims)
	if err != nil {
		s.log.Error("cloudserver/api: attach grant: mint", "err", err)
		return ""
	}
	return grant
}
