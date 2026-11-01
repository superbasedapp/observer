package secverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// orgFixture is one org: its root key, a node key it certified, and the
// clock the documents are checked at.
type orgFixture struct {
	t       *testing.T
	orgID   string
	root    ed25519.PrivateKey
	node    ed25519.PrivateKey
	machine string
	cert    secchange.Certificate
	now     time.Time
	revoked []secchange.Revocation
	floor   string
	version int64
	// extra are further certificates the policy's keys file carries.
	extra []secchange.Certificate
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := &orgFixture{
		t: t, orgID: "org-1",
		root:    ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)),
		node:    provKey(),
		machine: strings.Repeat("a", 64),
		now:     time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC),
		floor:   string(secchange.FloorLabel),
		version: 4,
	}
	pub, _ := f.node.Public().(ed25519.PublicKey)
	c, err := secchange.SignCertificate(secchange.Certificate{
		KeyID: secchange.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: f.machine,
		OrgID: f.orgID, NotBefore: "2026-10-01T00:00:00Z", NotAfter: "2026-12-30T00:00:00Z",
	}, f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.cert = c
	return f
}

func (f *orgFixture) rootPub() ed25519.PublicKey {
	pub, _ := f.root.Public().(ed25519.PublicKey)
	return pub
}

// record signs a record the certified node key made for (sha, tree, fp).
func (f *orgFixture) record(sha, tree, fp string) (string, string) {
	f.t.Helper()
	pub, _ := f.node.Public().(ed25519.PublicKey)
	r := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFP: fp, PatchFPState: "ok", OrgID: f.orgID, MachineIdentity: f.machine},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationOrg, Storage: secchange.StorageKeychain},
		CommittedAt: "2026-10-21T10:00:00Z", RecordedAt: "2026-10-21T10:01:00Z",
	}
	env, err := secchange.Sign(r, f.node)
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

// policyDoc is the org's signed CI policy.
func (f *orgFixture) policyDoc(mut func(*orgcontract.CIPolicy)) []byte {
	f.t.Helper()
	r := secchange.TrustKey{KeyID: secchange.KeyID(f.rootPub()), PublicKey: base64.StdEncoding.EncodeToString(f.rootPub())}
	kb, err := json.Marshal(secchange.TrustFile{Version: 1, Keys: []secchange.TrustKey{}, OrgRoots: []secchange.TrustKey{r}, Certificates: append([]secchange.Certificate{f.cert}, f.extra...), Revoked: append([]secchange.Revocation{}, f.revoked...)})
	if err != nil {
		f.t.Fatal(err)
	}
	p := orgcontract.CIPolicy{
		OrgID: f.orgID, Version: f.version, IssuedAt: f.now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: f.now.Add(23 * time.Hour).Format(time.RFC3339), ProvenanceFloor: f.floor, WaitSeconds: 180, Keys: kb,
	}
	if mut != nil {
		mut(&p)
	}
	body, err := json.Marshal(p)
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(orgcontract.SignCIDocument(orgcontract.CIPolicyDomain, f.orgID, p.Version, body, f.root))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// countersign is the org's receipt of a record.
func (f *orgFixture) countersign(digest string, key ed25519.PrivateKey) *orgcontract.ChangeCountersign {
	pub, _ := f.node.Public().(ed25519.PublicKey)
	c := orgcontract.SignChangeCountersign(orgcontract.ChangeCountersign{
		OrgID: f.orgID, KeyID: secchange.KeyID(pub), RecordDigest: digest, ReceivedAt: "2026-10-21T10:02:00Z",
		KeyStatus: orgcontract.CountersignKeyCertified, Envelope: orgcontract.CountersignEnvelopeChecked,
	}, key)
	return &c
}

// lookupDoc is the org's signed lookup answer.
func (f *orgFixture) lookupDoc(answeredAt time.Time, commits ...orgcontract.CILookupCommitAnswer) []byte {
	f.t.Helper()
	body, err := json.Marshal(orgcontract.CILookupAnswer{OrgID: f.orgID, AnsweredAt: answeredAt.Format(time.RFC3339), Commits: commits})
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(orgcontract.SignCIDocument(orgcontract.CILookupDomain, f.orgID, 0, body, f.root))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// run verifies commits in org mode under mode, with the lookup doc (nil:
// none came).
func (f *orgFixture) run(mode Mode, lookup []byte, commits ...ProvenanceCommit) Report {
	f.t.Helper()
	op, err := ParseOrgPolicy(f.policyDoc(nil), f.orgID, f.rootPub(), 0, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	org := &OrgProvenance{OrgID: f.orgID, OrgKey: f.rootPub(), PolicyVersion: op.Version}
	if lookup != nil {
		if org.Lookup, err = ParseOrgLookup(lookup, f.orgID, f.rootPub(), f.now); err != nil {
			f.t.Fatal(err)
		}
	}
	pol := op.Policy
	pol.Mode = mode
	return Verify(context.Background(), Request{Policy: pol, Provenance: &ProvenanceInput{Trust: op.Trust, Commits: commits, Org: org}}, []Detector{})
}

var (
	oSHA1  = strings.Repeat("1", 40)
	oSHA2  = strings.Repeat("4", 40)
	oSHA3  = strings.Repeat("5", 40)
	oTree1 = strings.Repeat("2", 40)
	oTree3 = strings.Repeat("6", 40)
	oFP1   = strings.Repeat("3", 40)
	oFP2   = strings.Repeat("7", 40)
)

func commitAnswer(sha, fp string, recs ...orgcontract.CILookupRecord) orgcontract.CILookupCommitAnswer {
	return orgcontract.CILookupCommitAnswer{SHA: sha, PatchFPHash: orgcontract.ChangePatchFPHash(fp), Records: recs}
}

// TestOrgModeX13 is the X13 case table run in process, in org mode: each
// case under both modes and both floors. A present record that fails
// verification fails the check in every mode (decision log P-059); a
// commit with no record, or only a trailer, is unknown_provenance.
func TestOrgModeX13(t *testing.T) {
	f := newOrgFixture(t)
	env1, dig1 := f.record(oSHA1, oTree1, oFP1)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	countersigned := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestCountersigned, Envelope: env1, Countersign: f.countersign(dig1, f.root)}
	viaPatch := countersigned
	viaPatch.MatchedBy = orgcontract.CIMatchPatchFP
	forgedCS := countersigned
	forgedCS.Countersign = f.countersign(dig1, other)
	noEnvelope := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestPending}
	replayed := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestReplay, Envelope: env1}
	pending := orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestPending, Envelope: env1}

	type want struct {
		prov          secchange.Provenance
		reason, code  string
		countersigned bool
	}
	cases := []struct {
		name    string
		revoke  bool
		commit  ProvenanceCommit
		answers []orgcontract.CILookupCommitAnswer
		want    want
	}{
		{
			"forged trailer, no record", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree1, PatchFP: oFP2}, Trailer: "claude-code"},
			nil,
			want{prov: secchange.ProvenanceUnknown, reason: secchange.ReasonMissing},
		},
		{
			"no record at the org either", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree1, PatchFP: oFP2}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA2, oFP2)},
			want{prov: secchange.ProvenanceUnknown, reason: secchange.ReasonMissing},
		},
		{
			"countersigned record by commit sha", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA1, oFP1, countersigned)},
			want{prov: secchange.ProvenanceVerified, reason: secchange.ReasonExact, countersigned: true},
		},
		{
			"note and org copy of one record are one candidate", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}, Notes: [][]byte{[]byte(env1)}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA1, oFP1, countersigned)},
			want{prov: secchange.ProvenanceVerified, reason: secchange.ReasonExact, countersigned: true},
		},
		{
			"rebase found through the patch fingerprint", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA3, Tree: oTree3, PatchFP: oFP1}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA3, oFP1, viaPatch)},
			want{prov: secchange.ProvenanceRebased, reason: secchange.ReasonPatch, countersigned: true},
		},
		{
			"pending countersign still verifies", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA1, oFP1, pending)},
			want{prov: secchange.ProvenanceVerified, reason: secchange.ReasonExact},
		},
		{
			"record replayed onto another commit (note)", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree3, PatchFP: oFP2}, Notes: [][]byte{[]byte(env1)}},
			nil,
			want{prov: secchange.ProvenanceFailed, reason: secchange.ReasonUnbound, code: "record_for_another_commit"},
		},
		{
			"record the org refused as a replay", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree3, PatchFP: oFP2}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA2, oFP2, replayed)},
			want{prov: secchange.ProvenanceFailed, reason: secchange.ReasonInvalid, code: "org_refused_replay"},
		},
		{
			"revoked key", true,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}, Notes: [][]byte{[]byte(env1)}},
			nil,
			want{prov: secchange.ProvenanceFailed, reason: secchange.ReasonInvalid, code: "key_revoked"},
		},
		{
			"forged countersign", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA1, oFP1, forgedCS)},
			want{prov: secchange.ProvenanceFailed, reason: secchange.ReasonInvalid, code: "countersign_invalid"},
		},
		{
			"org record without its envelope", false,
			ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}},
			[]orgcontract.CILookupCommitAnswer{commitAnswer(oSHA1, oFP1, noEnvelope)},
			want{prov: secchange.ProvenanceUnknown, reason: ReasonEnvelopeMissing, code: ReasonEnvelopeMissing},
		},
	}
	for _, c := range cases {
		for _, mode := range []Mode{ModeEnforce, ModeObserve} {
			for _, floor := range []string{string(secchange.FloorLabel), string(secchange.FloorFail)} {
				f.floor, f.revoked = floor, nil
				if c.revoke {
					f.revoked = []secchange.Revocation{{KeyID: f.cert.KeyID, RevokedAt: "2026-10-21T12:00:00Z"}}
				}
				var lookup []byte
				if c.answers != nil {
					lookup = f.lookupDoc(f.now.Add(-time.Minute), c.answers...)
				}
				rep := f.run(mode, lookup, c.commit)
				name := c.name + "/" + string(mode) + "/" + floor
				got := rep.Provenance.Commits[0]
				if got.Provenance != c.want.prov || got.Reason != c.want.reason || got.Countersigned != c.want.countersigned {
					t.Errorf("%s: got %s %s countersigned=%v errors=%v", name, got.Provenance, got.Reason, got.Countersigned, got.Errors)
				}
				if c.want.code != "" && !containsStr(got.Errors, c.want.code) {
					t.Errorf("%s: errors %v lack %s", name, got.Errors, c.want.code)
				}
				if c.commit.Trailer != "" && got.Trailer != c.commit.Trailer {
					t.Errorf("%s: trailer not reported", name)
				}
				switch {
				case c.want.prov == secchange.ProvenanceFailed:
					if rep.Verdict != VerdictFail || rep.Rule != "provenance_failed" {
						t.Errorf("%s: a failing record must fail in every mode, got %s (%s)", name, rep.Verdict, rep.Rule)
					}
				case c.want.prov == secchange.ProvenanceUnknown && mode == ModeEnforce && floor == string(secchange.FloorFail):
					if rep.Verdict != VerdictFail || rep.Rule != "provenance_floor" {
						t.Errorf("%s: unknown under a fail floor, got %s (%s)", name, rep.Verdict, rep.Rule)
					}
				default:
					if rep.Verdict != VerdictPass {
						t.Errorf("%s: got %s (%s)", name, rep.Verdict, rep.Rule)
					}
				}
				if rep.Provenance.Org == nil || rep.Provenance.Org.OrgID != f.orgID {
					t.Fatalf("%s: org report missing", name)
				}
				wantLookup := OrgLookupAnswered
				if lookup == nil {
					wantLookup = OrgLookupUnavailable
				}
				if rep.Provenance.Org.Lookup != wantLookup {
					t.Errorf("%s: lookup %s", name, rep.Provenance.Org.Lookup)
				}
			}
		}
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestOrgModeSquashStatement: the squash statement a squash merge would
// carry is derived from the verified records only (X13): two verified
// commits are its inputs, an unknown one is counted, never an input.
func TestOrgModeSquashStatement(t *testing.T) {
	f := newOrgFixture(t)
	env1, dig1 := f.record(oSHA1, oTree1, oFP1)
	env3, dig3 := f.record(oSHA3, oTree3, oFP2)
	lookup := f.lookupDoc(f.now.Add(-time.Minute),
		commitAnswer(oSHA1, oFP1, orgcontract.CILookupRecord{RecordDigest: dig1, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestCountersigned, Envelope: env1, Countersign: f.countersign(dig1, f.root)}),
		commitAnswer(oSHA3, oFP2, orgcontract.CILookupRecord{RecordDigest: dig3, MatchedBy: orgcontract.CIMatchCommitSHA, State: orgcontract.ChangeIngestCountersigned, Envelope: env3, Countersign: f.countersign(dig3, f.root)}),
	)
	rep := f.run(ModeEnforce, lookup,
		ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA3, Tree: oTree3, PatchFP: oFP2}},
		ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA2, Tree: oTree1, PatchFP: strings.Repeat("9", 40)}},
		ProvenanceCommit{Facts: secchange.CommitFacts{SHA: oSHA1, Tree: oTree1, PatchFP: oFP1}},
	)
	sq := rep.Provenance.Squash
	if sq.CommitSHA != oSHA3 || sq.Unverified != 1 || len(sq.Inputs) != 2 || !containsStr(sq.Inputs, dig1) || !containsStr(sq.Inputs, dig3) {
		t.Fatalf("squash = %+v", sq)
	}
	if o := rep.Provenance.Org; o.Countersigned != 2 || o.Pending != 0 {
		t.Fatalf("org report = %+v", o)
	}
}

// TestOrgDocumentRefusals: a policy or lookup answer that is not this
// org's, not signed by the pinned key, tampered, stale or below the pinned
// version floor is refused (the step then exits unknown).
func TestOrgDocumentRefusals(t *testing.T) {
	f := newOrgFixture(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, ed25519.SeedSize))
	otherPub, _ := other.Public().(ed25519.PublicKey)
	good := f.policyDoc(nil)
	if _, err := ParseOrgPolicy(good, f.orgID, f.rootPub(), 4, f.now); err != nil {
		t.Fatalf("good policy refused: %v", err)
	}
	var tampered orgcontract.CISignedDocument
	if err := json.Unmarshal(good, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Body = json.RawMessage(strings.Replace(string(tampered.Body), `"provenance_floor":"label"`, `"provenance_floor":"fail" `, 1))
	tamperedB, _ := json.Marshal(tampered)
	policyCases := []struct {
		name  string
		doc   []byte
		org   string
		key   ed25519.PublicKey
		min   int64
		now   time.Time
		match string
	}{
		{"another key", good, f.orgID, otherPub, 0, f.now, "issued by another key"},
		{"another org", good, "org-2", f.rootPub(), 0, f.now, ""},
		{"tampered body", tamperedB, f.orgID, f.rootPub(), 0, f.now, ""},
		{"below the version floor", good, f.orgID, f.rootPub(), 5, f.now, "below the pinned floor"},
		{"expired", good, f.orgID, f.rootPub(), 0, f.now.Add(48 * time.Hour), "not valid now"},
		{"not yet issued", good, f.orgID, f.rootPub(), 0, f.now.Add(-2 * time.Hour), "not valid now"},
		{"bad floor", f.policyDoc(func(p *orgcontract.CIPolicy) { p.ProvenanceFloor = "ignore" }), f.orgID, f.rootPub(), 0, f.now, "provenance floor"},
		{"bad verify policy", f.policyDoc(func(p *orgcontract.CIPolicy) { p.VerifyPolicy = "version = 1\nmode = \"loose\"\n" }), f.orgID, f.rootPub(), 0, f.now, "mode"},
		{"not a document", []byte(`{"body":{}}x`), f.orgID, f.rootPub(), 0, f.now, ""},
	}
	for _, c := range policyCases {
		_, err := ParseOrgPolicy(c.doc, c.org, c.key, c.min, c.now)
		if err == nil || (c.match != "" && !strings.Contains(err.Error(), c.match)) {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
	if op, err := ParseOrgPolicy(f.policyDoc(func(p *orgcontract.CIPolicy) {
		p.VerifyPolicy = "version = 1\nmode = \"observe\"\n"
		p.ProvenanceFloor = "fail"
	}), f.orgID, f.rootPub(), 0, f.now); err != nil || op.Policy.Mode != ModeObserve || op.Policy.Provenance != secchange.FloorFail || op.Policy.Source != SourceOrg {
		t.Errorf("verify policy text not applied: %+v %v", op.Policy, err)
	}

	fresh := f.lookupDoc(f.now.Add(-time.Minute))
	if _, err := ParseOrgLookup(fresh, f.orgID, f.rootPub(), f.now); err != nil {
		t.Fatalf("fresh lookup refused: %v", err)
	}
	for name, c := range map[string]struct {
		doc []byte
		org string
		key ed25519.PublicKey
	}{
		"stale":       {f.lookupDoc(f.now.Add(-25 * time.Hour)), f.orgID, f.rootPub()},
		"another key": {fresh, f.orgID, otherPub},
		"another org": {fresh, "org-2", f.rootPub()},
		// A policy document is not a lookup answer: the domains differ.
		"policy as lookup": {good, f.orgID, f.rootPub()},
	} {
		if _, err := ParseOrgLookup(c.doc, c.org, c.key, f.now); !errors.Is(err, ErrOrgDocument) {
			t.Errorf("lookup %s: err = %v", name, err)
		}
	}
}
