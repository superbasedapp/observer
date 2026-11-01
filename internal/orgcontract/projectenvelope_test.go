package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestPolicyBundleV3SignatureIsDomainSeparated(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := PolicyBundle{Version: 7, BundleTOML: "[[override]]\nrule = \"R-110\"\n", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}
	b.ProjectBinding = &ProjectBinding{OrgID: "org", Subject: "u-dana", Epoch: 3, MappingDigest: "abc"}
	b.Signature = SignPolicyBundleEnvelope(priv, b)
	if _, err := VerifyPolicyBundle(b); err != nil {
		t.Fatalf("v3 round trip: %v", err)
	}
	for name, mutate := range map[string]func(*PolicyBundle){
		"epoch":    func(x *PolicyBundle) { x.ProjectBinding.Epoch = 2 },
		"digest":   func(x *PolicyBundle) { x.ProjectBinding.MappingDigest = "abd" },
		"project":  func(x *PolicyBundle) { x.ProjectBinding.OrgProjectID = "X" },
		"subject":  func(x *PolicyBundle) { x.ProjectBinding.Subject = "u-sam" },
		"stripped": func(x *PolicyBundle) { x.ProjectBinding = nil },
		"as v2": func(x *PolicyBundle) {
			x.Binding = &PolicyBinding{OrgID: "org", Subject: "u-dana"}
			x.ProjectBinding = nil
		},
		"body edit": func(x *PolicyBundle) { x.BundleTOML += "#" },
	} {
		c := b
		pb := *b.ProjectBinding
		c.ProjectBinding = &pb
		mutate(&c)
		if _, err := VerifyPolicyBundle(c); err == nil {
			t.Errorf("%s: a changed v3 envelope still verified", name)
		}
	}
}

func TestProjectMappingDigestAndSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := ProjectMapping{OrgID: "org", Subject: "u-dana", Epoch: 4, MaxAgeSeconds: DefaultProjectMappingMaxAge, Projects: []ProjectMappingEntry{
		{OrgProjectID: "Y", Repos: []ProjectRepoHashes{{RemoteHash: "r2"}, {RemoteHash: "r1", RootCommitHash: "c1"}}},
		{OrgProjectID: "X", Repos: []ProjectRepoHashes{{RemoteHash: "r3"}}},
	}}
	reordered := ProjectMapping{OrgID: "org", Subject: "u-dana", Epoch: 4, MaxAgeSeconds: DefaultProjectMappingMaxAge, Projects: []ProjectMappingEntry{
		{OrgProjectID: "X", Repos: []ProjectRepoHashes{{RemoteHash: "r3"}}},
		{OrgProjectID: "Y", Repos: []ProjectRepoHashes{{RemoteHash: "r1", RootCommitHash: "c1"}, {RemoteHash: "r2"}}},
	}}
	if ProjectMappingDigest(m) != ProjectMappingDigest(reordered) {
		t.Fatal("the digest depends on list order")
	}
	signed := SignProjectMapping(priv, m)
	if _, err := VerifyProjectMapping(signed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ProjectMappingDigest(signed) != ProjectMappingDigest(m) {
		t.Fatal("signing changed the digest")
	}
	signed.Epoch = 5
	if _, err := VerifyProjectMapping(signed); err == nil {
		t.Fatal("a mapping with a changed epoch still verified")
	}
}
