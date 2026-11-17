package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/connectflow"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestConnectGrantClaims is the mint rule table (connect_grant.go): which
// approvals carry a grant, and that what is minted verifies on a tenant host
// pinning the key, for the approved org only.
func TestConnectGrantClaims(t *testing.T) {
	devPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approved := time.Unix(1_800_000_000, 0).UTC()
	team := &store.ConnectTarget{OrgID: "org-team", Slug: "acme", Kind: store.OrgKind(connectflow.KindTeam), ShareLevel: connectflow.ShareFull}
	personal := &store.ConnectTarget{OrgID: "org-me", Slug: "u-abc123", Kind: store.OrgKind(connectflow.KindPersonal), ShareLevel: connectflow.ShareSummary}
	req := func(tg *store.ConnectTarget) store.ConnectRequest {
		return store.ConnectRequest{RequestID: "req-1", PublicKey: devPub, AccountID: "acct-1", ResolvedAt: approved, Target: tg}
	}
	member := connectGrantMember{IsMember: true, Sub: "user_01X", Email: "a@example.test", EmailVerified: true}

	cases := []struct {
		name   string
		c      store.ConnectRequest
		m      connectGrantMember
		now    time.Time
		want   bool
		wantEm string
	}{
		{name: "team", c: req(team), m: member, now: approved.Add(time.Second), want: true, wantEm: "a@example.test"},
		{name: "personal", c: req(personal), m: member, now: approved.Add(time.Second), want: true, wantEm: "a@example.test"},
		{name: "not now (no target)", c: req(nil), m: member, now: approved.Add(time.Second)},
		{name: "the approval is older than the grant's lifetime", c: req(team), m: member, now: approved.Add(attachgrant.Lifetime)},
		{name: "no subject to bind by", c: req(team), m: connectGrantMember{IsMember: true}, now: approved.Add(time.Second)},
		{name: "not a member of the target", c: req(team), m: connectGrantMember{Sub: "user_01X"}, now: approved.Add(time.Second)},
		{name: "an unverified email is left out", c: req(team), m: connectGrantMember{IsMember: true, Sub: "user_01X", Email: "a@example.test"}, now: approved.Add(time.Second), want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, ok := connectGrantClaims(tc.c, tc.m, tc.now)
			if ok != tc.want {
				t.Fatalf("ok = %v, want %v", ok, tc.want)
			}
			if !ok {
				return
			}
			if claims.Email != tc.wantEm {
				t.Fatalf("email = %q, want %q", claims.Email, tc.wantEm)
			}
			grant, err := attachgrant.Mint(signPriv, claims)
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			keys := platformcontract.KeySet{platformcontract.NewDocumentKey(signPub)}
			got, err := attachgrant.Verify(grant, attachgrant.Facts{Keys: keys, OrgID: tc.c.Target.OrgID, Now: tc.now})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got.DeviceThumbprint != attachgrant.Thumbprint(devPub) || got.JTI != attachgrant.JTIFor("req-1") ||
				got.IssuedAt != approved.Unix() || got.Kind != string(tc.c.Target.Kind) {
				t.Fatalf("claims = %+v", got)
			}
			if _, err := attachgrant.Verify(grant, attachgrant.Facts{Keys: keys, OrgID: "another-org", Now: tc.now}); err == nil {
				t.Fatal("a grant verified for another org")
			}
		})
	}
}
