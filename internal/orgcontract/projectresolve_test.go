package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestProjectResolveDigestAndSignature: the request digest ignores hash order
// and duplicates but binds every hash, the root commit and the nonce; the
// answer's signature covers every bound field and its id order does not
// matter; a signature from another domain never verifies as a resolve answer.
func TestProjectResolveDigestAndSignature(t *testing.T) {
	a := ProjectResolveRequest{RemoteHashes: []string{"b", "a", "a"}, RootCommitHash: "r", Nonce: "n"}
	b := ProjectResolveRequest{RemoteHashes: []string{"a", "b"}, RootCommitHash: "r", Nonce: "n"}
	if ProjectResolveRequestDigest(a) != ProjectResolveRequestDigest(b) {
		t.Fatal("hash order or duplicates changed the digest")
	}
	for name, c := range map[string]ProjectResolveRequest{
		"another hash":  {RemoteHashes: []string{"a", "c"}, RootCommitHash: "r", Nonce: "n"},
		"another root":  {RemoteHashes: []string{"a", "b"}, RootCommitHash: "s", Nonce: "n"},
		"another nonce": {RemoteHashes: []string{"a", "b"}, RootCommitHash: "r", Nonce: "m"},
	} {
		if ProjectResolveRequestDigest(c) == ProjectResolveRequestDigest(b) {
			t.Errorf("%s: same digest", name)
		}
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ans := SignProjectResolveAnswer(priv, ProjectResolveAnswer{
		OrgID: "org", Subject: "u", Epoch: 2, BundleVersion: 7, RequestDigest: "d", Nonce: "n",
		OrgProjectIDs: []string{"Y", "X"}, IssuedAt: 10, ExpiresAt: 20,
	})
	if _, err := VerifyProjectResolveAnswer(ans); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ans.OrgProjectIDs[0] != "X" {
		t.Fatalf("ids not sorted: %v", ans.OrgProjectIDs)
	}
	for name, mut := range map[string]func(*ProjectResolveAnswer){
		"org":     func(x *ProjectResolveAnswer) { x.OrgID = "o2" },
		"subject": func(x *ProjectResolveAnswer) { x.Subject = "v" },
		"epoch":   func(x *ProjectResolveAnswer) { x.Epoch = 3 },
		"version": func(x *ProjectResolveAnswer) { x.BundleVersion = 8 },
		"digest":  func(x *ProjectResolveAnswer) { x.RequestDigest = "e" },
		"nonce":   func(x *ProjectResolveAnswer) { x.Nonce = "m" },
		"ids":     func(x *ProjectResolveAnswer) { x.OrgProjectIDs = []string{"X"} },
		"issued":  func(x *ProjectResolveAnswer) { x.IssuedAt = 11 },
		"expiry":  func(x *ProjectResolveAnswer) { x.ExpiresAt = 99 },
	} {
		c := ans
		c.OrgProjectIDs = append([]string(nil), ans.OrgProjectIDs...)
		mut(&c)
		if _, err := VerifyProjectResolveAnswer(c); err == nil {
			t.Errorf("changing %s kept the signature valid", name)
		}
	}
	m := SignProjectMapping(priv, ProjectMapping{OrgID: "org", Subject: "u", Epoch: 2})
	forged := ans
	forged.Signature = m.Signature
	if _, err := VerifyProjectResolveAnswer(forged); err == nil {
		t.Fatal("a mapping signature verified as a resolve answer")
	}
}
