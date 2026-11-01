package secverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// TestOrgModeReplayYieldsToOwnVerifiedRecord (SEC-F2B merge audit finding
// 2): an insider's record naming the victim's commit, signed by a key the org
// never certified, does not fail the victim's commit in CI. Whether the org
// stored the victim's own record as countersigned (a fixed server) or refused
// it as a replay (an older one), the victim's record verifies and binds, so
// the commit verifies in every mode. A replay refusal whose record does NOT
// bind the commit still fails it (P-059).
func TestOrgModeReplayYieldsToOwnVerifiedRecord(t *testing.T) {
	f := newOrgFixture(t)
	env1, dig1 := f.record(oSHA1, oTree1, oFP1)
	insider := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize))
	insiderPub, _ := insider.Public().(ed25519.PublicKey)
	rec := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: oSHA1, TreeSHA: oTree1, PatchFP: oFP1, PatchFPState: "ok", OrgID: f.orgID, MachineIdentity: f.machine},
		Key:         secchange.KeyRef{ID: secchange.KeyID(insiderPub), Attestation: secchange.AttestationOrg, Storage: secchange.StorageKeychain},
		CommittedAt: "2026-10-21T09:00:00Z", RecordedAt: "2026-10-21T09:01:00Z",
	}
	ienv, err := secchange.Sign(rec, insider)
	if err != nil {
		t.Fatal(err)
	}
	ib, _ := ienv.Marshal()
	ipayload, _ := base64.StdEncoding.DecodeString(ienv.Payload)
	idig := secchange.Digest(ipayload)
	ics := orgcontract.SignChangeCountersign(orgcontract.ChangeCountersign{
		OrgID: f.orgID, KeyID: secchange.KeyID(insiderPub), RecordDigest: idig, ReceivedAt: "2026-10-21T09:02:00Z",
		KeyStatus: orgcontract.CountersignKeyNotEnrolled, Envelope: "unverified",
	}, f.root)
	insiderRec := orgcontract.CILookupRecord{RecordDigest: idig, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestCountersigned, Envelope: string(ib), Countersign: &ics}
	victimCountersigned := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestCountersigned, Envelope: env1, Countersign: f.countersign(dig1, f.root)}
	victimRefused := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestReplay, Envelope: env1}
	commit := ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}}
	for _, c := range []struct {
		name string
		recs []orgcontract.CILookupRecord
		want secchange.Provenance
	}{
		{"fixed server: the victim's record countersigned", []orgcontract.CILookupRecord{insiderRec, victimCountersigned}, secchange.ProvenanceVerified},
		{"older server: the victim's record refused as a replay", []orgcontract.CILookupRecord{insiderRec, victimRefused}, secchange.ProvenanceVerified},
		{"the insider's record alone", []orgcontract.CILookupRecord{insiderRec}, secchange.ProvenanceFailed},
	} {
		for _, mode := range []Mode{ModeEnforce, ModeObserve} {
			rep := f.run(mode, f.lookupDoc(f.now.Add(-time.Minute), commitAnswer(oSHA1, oFP1, c.recs...)), commit)
			got := rep.Provenance.Commits[0]
			if got.Provenance != c.want {
				t.Errorf("%s/%s: %s %s errors=%v", c.name, mode, got.Provenance, got.Reason, got.Errors)
			}
			if c.want == secchange.ProvenanceVerified && (rep.Verdict != VerdictPass || got.Digest != dig1) {
				t.Errorf("%s/%s: verdict %s digest %s, want a pass decided by the victim's record", c.name, mode, rep.Verdict, got.Digest)
			}
			if c.want == secchange.ProvenanceFailed && rep.Verdict != VerdictFail {
				t.Errorf("%s/%s: verdict %s, want fail (P-059)", c.name, mode, rep.Verdict)
			}
		}
	}
	// A replay refusal whose record binds another commit stays a failure.
	other := ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree3, PatchFP: oFP2}}
	refusedElsewhere := victimRefused
	rep := f.run(ModeObserve, f.lookupDoc(f.now.Add(-time.Minute), commitAnswer(oSHA2, oFP2, refusedElsewhere)), other)
	if got := rep.Provenance.Commits[0]; got.Provenance != secchange.ProvenanceFailed || !containsStr(got.Errors, "org_refused_replay") {
		t.Fatalf("an unbound replay refusal: %s %v", got.Provenance, got.Errors)
	}
}
