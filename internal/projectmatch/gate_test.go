package projectmatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// delivery builds a valid signed v3 delivery for org/u-dana at epoch 3 with
// one envelope for X.
func delivery(t *testing.T, priv ed25519.PrivateKey, epoch int64) orgcontract.PolicyBundle {
	t.Helper()
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u-dana", Epoch: epoch, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh"}}}},
	})
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	env := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "[[override]]\nrule = \"R-110\"\n", PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: "X", Epoch: epoch},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	b := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "# composed\n", PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", Epoch: epoch, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	b.Projects = &orgcontract.ProjectDelivery{Mapping: m, Envelopes: []orgcontract.PolicyBundle{env}}
	return b
}

// TestV3AcceptGate is JSP-10's prototype gate, made real: a v2 envelope after
// a v3 one, a lower epoch, and a mapping whose digest or epoch differs from
// the signed one are refused; so is any envelope of another delivery.
func TestV3AcceptGate(t *testing.T) {
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	want := Identity{OrgID: "org", Subject: "u-dana"}
	good := delivery(t, priv, 3)

	held, err := AcceptDelivery(Held{}, good, want, pubKey)
	if err != nil || !held.HadV3 || held.Epoch != 3 {
		t.Fatalf("a good delivery: held=%+v err=%v", held, err)
	}
	if _, err := AcceptDelivery(Held{}, orgcontract.PolicyBundle{Version: 1}, want, pubKey); err != nil {
		t.Fatalf("a v2 bundle before any v3 one must pass: %v", err)
	}

	rows := []struct {
		name   string
		held   Held
		mutate func(b *orgcontract.PolicyBundle)
		want   error
	}{
		{"v2 after v3", held, func(b *orgcontract.PolicyBundle) {
			*b = orgcontract.PolicyBundle{Version: 10, Binding: &orgcontract.PolicyBinding{OrgID: "org", Subject: "u-dana"}}
		}, ErrDowngrade},
		{"v1 after v3", held, func(b *orgcontract.PolicyBundle) { *b = orgcontract.PolicyBundle{Version: 10} }, ErrDowngrade},
		{"lower epoch", Held{HadV3: true, Epoch: 4}, func(*orgcontract.PolicyBundle) {}, ErrEpochLower},
		{"another member", held, func(b *orgcontract.PolicyBundle) { b.ProjectBinding.Subject = "u-sam" }, ErrBindingOwner},
		{"no mapping", held, func(b *orgcontract.PolicyBundle) { b.Projects = nil }, ErrMalformed},
		{"also a v2 binding", held, func(b *orgcontract.PolicyBundle) { b.Binding = &orgcontract.PolicyBinding{} }, ErrMalformed},
		{"mapping digest differs", held, func(b *orgcontract.PolicyBundle) { b.ProjectBinding.MappingDigest = "00" }, ErrMappingDigest},
		{"mapping epoch differs", held, func(b *orgcontract.PolicyBundle) {
			b.Projects.Mapping = orgcontract.SignProjectMapping(priv, withEpoch(b.Projects.Mapping, 2))
		}, ErrMappingDigest},
		{"mapping signed by another key", held, func(b *orgcontract.PolicyBundle) {
			b.Projects.Mapping = orgcontract.SignProjectMapping(other, b.Projects.Mapping)
		}, ErrMappingDigest},
		{"envelope of an older epoch", held, func(b *orgcontract.PolicyBundle) {
			b.Projects.Envelopes = delivery(t, priv, 2).Projects.Envelopes
		}, ErrEnvelope},
		{"envelope for an unlisted project", held, func(b *orgcontract.PolicyBundle) {
			e := b.Projects.Envelopes[0]
			pb := *e.ProjectBinding
			pb.OrgProjectID = "Z"
			e.ProjectBinding = &pb
			e.Signature = orgcontract.SignPolicyBundleEnvelope(priv, e)
			b.Projects.Envelopes = []orgcontract.PolicyBundle{e}
		}, ErrEnvelope},
		{"envelope listed twice", held, func(b *orgcontract.PolicyBundle) {
			b.Projects.Envelopes = append(b.Projects.Envelopes, b.Projects.Envelopes[0])
		}, ErrEnvelope},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			b := delivery(t, priv, 3)
			r.mutate(&b)
			got, err := AcceptDelivery(r.held, b, want, pubKey)
			if !errors.Is(err, r.want) {
				t.Fatalf("err = %v, want %v", err, r.want)
			}
			if got != r.held {
				t.Fatalf("a refusal changed the held state: %+v", got)
			}
		})
	}
}

func withEpoch(m orgcontract.ProjectMapping, e int64) orgcontract.ProjectMapping {
	m.Epoch = e
	return m
}
