package projectmatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// familyMember is a security.scanning section published for the given
// projects.
func familyMember(version int64, body string, projects ...string) orgcontract.ProjectFamilyMember {
	return orgcontract.ProjectFamilyMember{
		Family: "security.scanning", Version: version, Projects: projects,
		Body: body, BodyHash: orgcontract.ProjectFamilyBodyHash(body),
	}
}

// familyDelivery is delivery() with X's envelope carrying members.
func familyDelivery(t *testing.T, priv ed25519.PrivateKey, epoch int64, members ...orgcontract.ProjectFamilyMember) orgcontract.PolicyBundle {
	t.Helper()
	b := delivery(t, priv, epoch)
	env := b.Projects.Envelopes[0]
	env.Families = members
	pb := *env.ProjectBinding
	pb.FamiliesDigest = orgcontract.ProjectFamiliesDigest(members)
	env.ProjectBinding = &pb
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	b.Projects.Envelopes = []orgcontract.PolicyBundle{env}
	return b
}

// TestFamilyMemberGate is lane sec-p3 milestone 1: a project envelope's
// family member is covered by the envelope's signature, so a forged member
// (body or audience changed), a stripped or added member, a member moved to
// another project's envelope, another member's or org's envelope, and an
// envelope replayed from an older epoch are refused; the composed bundle
// never carries members.
func TestFamilyMemberGate(t *testing.T) {
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{OrgID: "org", Subject: "u-dana"}
	floor := `{"allow":{"online_checks":"forbidden"},"version":1}`
	good := familyDelivery(t, priv, 3, familyMember(4, floor, "X"))
	if _, err := AcceptDelivery(Held{}, good, want, pubKey); err != nil {
		t.Fatalf("a good delivery with a family member: %v", err)
	}
	resign := func(e *orgcontract.PolicyBundle) { e.Signature = orgcontract.SignPolicyBundleEnvelope(priv, *e) }

	rows := []struct {
		name   string
		mutate func(b *orgcontract.PolicyBundle)
		want   error
	}{
		{"forged body, signature kept", func(b *orgcontract.PolicyBundle) {
			b.Projects.Envelopes[0].Families[0].Body = `{"version":1}`
		}, ErrEnvelope},
		{"forged body and hash, signature kept", func(b *orgcontract.PolicyBundle) {
			m := familyMember(4, `{"version":1}`, "X")
			b.Projects.Envelopes[0].Families = []orgcontract.ProjectFamilyMember{m}
		}, ErrEnvelope},
		{"member stripped, digest kept", func(b *orgcontract.PolicyBundle) {
			b.Projects.Envelopes[0].Families = nil
		}, ErrEnvelope},
		{"member stripped with its digest", func(b *orgcontract.PolicyBundle) {
			e := &b.Projects.Envelopes[0]
			e.Families = nil
			pb := *e.ProjectBinding
			pb.FamiliesDigest = ""
			e.ProjectBinding = &pb
		}, ErrEnvelope},
		{"member added to a P1 envelope", func(b *orgcontract.PolicyBundle) {
			*b = delivery(t, priv, 3)
			b.Projects.Envelopes[0].Families = []orgcontract.ProjectFamilyMember{familyMember(4, floor, "X")}
		}, ErrEnvelope},
		{"member published for another project, re-signed", func(b *orgcontract.PolicyBundle) {
			e := &b.Projects.Envelopes[0]
			e.Families = []orgcontract.ProjectFamilyMember{familyMember(4, floor, "Y")}
			pb := *e.ProjectBinding
			pb.FamiliesDigest = orgcontract.ProjectFamiliesDigest(e.Families)
			e.ProjectBinding = &pb
			resign(e)
		}, ErrEnvelope},
		{"envelope moved to another project", func(b *orgcontract.PolicyBundle) {
			e := &b.Projects.Envelopes[0]
			pb := *e.ProjectBinding
			pb.OrgProjectID = "Y"
			e.ProjectBinding = &pb
		}, ErrEnvelope},
		{"envelope of another member", func(b *orgcontract.PolicyBundle) {
			e := &b.Projects.Envelopes[0]
			pb := *e.ProjectBinding
			pb.Subject = "u-sam"
			e.ProjectBinding = &pb
			resign(e)
		}, ErrEnvelope},
		{"envelope of another org", func(b *orgcontract.PolicyBundle) {
			e := &b.Projects.Envelopes[0]
			pb := *e.ProjectBinding
			pb.OrgID = "other-org"
			e.ProjectBinding = &pb
			resign(e)
		}, ErrEnvelope},
		{"envelope replayed from an older epoch", func(b *orgcontract.PolicyBundle) {
			b.Projects.Envelopes = familyDelivery(t, priv, 2, familyMember(4, floor, "X")).Projects.Envelopes
		}, ErrEnvelope},
		{"members on the composed bundle", func(b *orgcontract.PolicyBundle) {
			b.Families = []orgcontract.ProjectFamilyMember{familyMember(4, floor, "X")}
		}, ErrMalformed},
		{"families digest on the composed bundle", func(b *orgcontract.PolicyBundle) {
			pb := *b.ProjectBinding
			pb.FamiliesDigest = "00"
			b.ProjectBinding = &pb
		}, ErrMalformed},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			b := familyDelivery(t, priv, 3, familyMember(4, floor, "X"))
			r.mutate(&b)
			if _, err := AcceptDelivery(Held{}, b, want, pubKey); !errors.Is(err, r.want) {
				t.Fatalf("err = %v, want %v", err, r.want)
			}
		})
	}

	// The cached envelope check (what the guard and the read seam run)
	// refuses the same forged member.
	env := good.Projects.Envelopes[0]
	if err := CheckEnvelope(env, good, "X", pubKey); err != nil {
		t.Fatalf("CheckEnvelope on the good envelope: %v", err)
	}
	env.Families = []orgcontract.ProjectFamilyMember{familyMember(4, `{"version":1}`, "X")}
	if err := CheckEnvelope(env, good, "X", pubKey); !errors.Is(err, ErrEnvelope) {
		t.Fatalf("CheckEnvelope on a forged member: %v", err)
	}
}
