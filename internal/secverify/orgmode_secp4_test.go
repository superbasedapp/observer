package secverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// signRecordWith signs a record for (sha, tree, fp) with key on machine.
func (f *orgFixture) signRecordWith(key ed25519.PrivateKey, machine, sha, tree, fp string) (string, string) {
	f.t.Helper()
	pub, _ := key.Public().(ed25519.PublicKey)
	r := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFP: fp, PatchFPState: "ok", OrgID: f.orgID, MachineIdentity: machine},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationOrg, Storage: secchange.StorageKeychain},
		CommittedAt: "2026-10-21T10:00:00Z", RecordedAt: "2026-10-21T10:01:00Z",
	}
	env, err := secchange.Sign(r, key)
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := env.Marshal()
	if err != nil {
		f.t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	return string(b), secchange.Digest(payload)
}

// TestOrgModeX13MemberClaim (lane SEC-P4 decision 8, SECP-31): an
// insider's certified key records a colleague's sha first and the
// colleague's own verified record arrives second (the org stores it as a
// claim conflict). CI picks the record whose certified member is the
// commit's committer or author and reports the other as
// claim_by_another_member; no match, two matches, or a lookup that names
// no member stay records_from_two_keys, never a pass.
func TestOrgModeX13MemberClaim(t *testing.T) {
	f := newOrgFixture(t)
	insider := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
	insiderMachine := strings.Repeat("b", 64)
	ipub, _ := insider.Public().(ed25519.PublicKey)
	ic, err := secchange.SignCertificate(secchange.Certificate{
		KeyID: secchange.KeyID(ipub), PublicKey: base64.StdEncoding.EncodeToString(ipub), MachineIdentity: insiderMachine,
		OrgID: f.orgID, NotBefore: "2026-10-01T00:00:00Z", NotAfter: "2026-12-30T00:00:00Z",
	}, f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.extra = []secchange.Certificate{ic}

	colleagueEnv, colleagueDigest := f.record(oSHA1, oTree1, oFP1)
	insiderEnv, insiderDigest := f.signRecordWith(insider, insiderMachine, oSHA1, oTree1, oFP1)
	colleagueHash := orgcontract.ChangeMemberEmailHash("colleague@example.com")
	insiderHash := orgcontract.ChangeMemberEmailHash("insider@example.com")
	rec := func(env, digest, keyID, state, member string) orgcontract.CILookupRecord {
		return orgcontract.CILookupRecord{RecordDigest: digest, KeyID: keyID, MatchedBy: orgcontract.CIMatchCommitSHA, State: state, Envelope: env, MemberHash: member}
	}
	answer := func(members bool) []byte {
		ch, ih := colleagueHash, insiderHash
		if !members {
			ch, ih = "", ""
		}
		return f.lookupDoc(f.now.Add(-time.Minute), commitAnswer(oSHA1, oFP1,
			rec(insiderEnv, insiderDigest, ic.KeyID, orgcontract.ChangeIngestPending, ih),
			rec(colleagueEnv, colleagueDigest, f.cert.KeyID, orgcontract.ChangeIngestClaimConflict, ch),
		))
	}
	commit := func(emails ...string) ProvenanceCommit {
		c := ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}}
		for _, e := range emails {
			c.IdentityHashes = append(c.IdentityHashes, orgcontract.ChangeMemberEmailHash(e))
		}
		return c
	}
	cases := []struct {
		name    string
		lookup  []byte
		commit  ProvenanceCommit
		prov    secchange.Provenance
		reason  string
		digest  string
		claimed bool
	}{
		{"committer is the colleague", answer(true), commit("Colleague@Example.com ", "colleague@example.com"), secchange.ProvenanceVerified, secchange.ReasonExact, colleagueDigest, true},
		{"author is the insider", answer(true), commit("insider@example.com", "ci-bot@example.com"), secchange.ProvenanceVerified, secchange.ReasonExact, insiderDigest, true},
		{"no member matches", answer(true), commit("someone@example.com"), secchange.ProvenanceFailed, secchange.ReasonReplay, "", false},
		{"both members match, no committer read", answer(true), commit("colleague@example.com", "insider@example.com"), secchange.ProvenanceFailed, secchange.ReasonReplay, "", false},
		{"insider authored, colleague committed", answer(true), withCommitter(commit("insider@example.com", "colleague@example.com"), "colleague@example.com"), secchange.ProvenanceVerified, secchange.ReasonExact, colleagueDigest, true},
		{"colleague authored, insider committed", answer(true), withCommitter(commit("colleague@example.com", "insider@example.com"), "insider@example.com"), secchange.ProvenanceVerified, secchange.ReasonExact, insiderDigest, true},
		{"committer matches no member", answer(true), withCommitter(commit("colleague@example.com", "insider@example.com"), "bot@example.com"), secchange.ProvenanceFailed, secchange.ReasonReplay, "", false},
		{"the lookup names no member", answer(false), commit("colleague@example.com"), secchange.ProvenanceFailed, secchange.ReasonReplay, "", false},
		{"no identity read", answer(true), commit(), secchange.ProvenanceFailed, secchange.ReasonReplay, "", false},
	}
	for _, c := range cases {
		got := f.run(ModeEnforce, c.lookup, c.commit).Provenance.Commits[0]
		if got.Provenance != c.prov || got.Reason != c.reason || (c.digest != "" && got.Digest != c.digest) {
			t.Errorf("%s: got %s %s %s errors=%v", c.name, got.Provenance, got.Reason, got.Digest, got.Errors)
		}
		if containsStr(got.Errors, ReasonClaimByAnotherMember) != c.claimed {
			t.Errorf("%s: errors %v, claim_by_another_member reported = %v", c.name, got.Errors, !c.claimed)
		}
	}
}

// withCommitter sets the commit's committer hash.
func withCommitter(c ProvenanceCommit, email string) ProvenanceCommit {
	c.CommitterHash = orgcontract.ChangeMemberEmailHash(email)
	return c
}
