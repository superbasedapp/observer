package orgclient

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// replacementWithConsent is validReplacement carrying a consent mode, signed
// after the mode is set so the signature covers it.
func replacementWithConsent(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, orgURL, orgID, mode string) orgcontract.GrantReplacement {
	t.Helper()
	r := validReplacementWithAuthority(t, priv, pub, orgURL, orgID, 1, []string{"dashboard.visibility", "enforce.budget"})
	r.ConsentMode = mode
	r.ConsentActor = "fleet"
	r.Signature = orgcontract.SignGrantReplacement(priv, r)
	return r
}

// TestGrantReplacementTenancy (OSH-R-013, operator ruling P-204): a
// verified fleet grant replacement from the node's OWN org is accepted on
// either tenancy, because a managed-consent replacement from that org IS
// the org switching its members to enterprise; a replacement naming a
// different org than the enrolment is refused whole and leaves no grant
// behind, whatever its consent mode.
func TestGrantReplacementTenancy(t *testing.T) {
	cases := []struct {
		name    string
		tenancy string
		mode    string
		org     string
		accept  bool
	}{
		{"switch: managed consent, individual node, own org", orgcontract.TenancyIndividual, govern.ConsentManaged, "org-1", true},
		{"switch: idp consent, individual node, own org", orgcontract.TenancyIndividual, govern.ConsentIdP, "org-1", true},
		{"managed consent, managed node, own org", orgcontract.TenancyManaged, govern.ConsentManaged, "org-1", true},
		{"managed consent from org B on an org A node", orgcontract.TenancyManaged, govern.ConsentManaged, "org-2", false},
		{"managed consent from org B on an individual org A node", orgcontract.TenancyIndividual, govern.ConsentManaged, "org-2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newAgentStore(t)
			c := newTestClient(t, s, &memBearerStore{})
			const orgURL = "https://org.example.com"
			pub, priv := seedEnrolledNode(t, s, orgURL, "org-1")
			enr, err := s.LoadEnrolment(ctx)
			if err != nil || enr == nil {
				t.Fatalf("LoadEnrolment: %v", err)
			}
			enr.Tenancy = tc.tenancy
			if err := s.WriteEnrolment(ctx, *enr); err != nil {
				t.Fatal(err)
			}
			accepted, err := c.AcceptGrantReplacement(ctx, replacementWithConsent(t, priv, pub, orgURL, tc.org, tc.mode))
			if err != nil {
				t.Fatalf("AcceptGrantReplacement: %v", err)
			}
			if accepted != tc.accept {
				t.Fatalf("accepted = %v, want %v", accepted, tc.accept)
			}
			row, stored, err := s.LoadEnrolmentGrant(ctx, OrgKey(orgURL, "org-1"))
			if err != nil {
				t.Fatal(err)
			}
			if stored != tc.accept {
				t.Fatalf("grant stored = %v, want %v", stored, tc.accept)
			}
			if !stored {
				return
			}
			// End to end: the stored grant, read through the same facts the
			// cmd boundary fills (grantFromStore), resolves managed and
			// honours its managed authority on either tenancy.
			g := &govern.Grant{
				OrgID: row.OrgID, ConsentMode: row.ConsentMode, Authority: row.Authority,
				Tenancy: enr.Tenancy, EnrolmentOrgID: enr.OrgID, ReplacementGeneration: row.ReplacementGeneration,
			}
			if !govern.GrantIsManaged(g) {
				t.Fatalf("accepted replacement does not resolve managed: %+v", g)
			}
			honoured := false
			for _, a := range govern.HonoredAuthority(g) {
				if a == govern.AuthorityEnforceBudget {
					honoured = true
				}
			}
			if !honoured {
				t.Fatal("enforce.budget from the accepted replacement is not honoured")
			}
		})
	}
}
