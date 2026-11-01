package secchange

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// testKey is a fixed Ed25519 key from a fixed seed, so the vectors below
// never change.
func testKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey {
	p, _ := k.Public().(ed25519.PublicKey)
	return p
}

const (
	sha1A  = "1111111111111111111111111111111111111111"
	tree1A = "2222222222222222222222222222222222222222"
	fpA    = "3333333333333333333333333333333333333333"
	projH  = "4444444444444444444444444444444444444444444444444444444444444444"
)

func fixedRecord(k ed25519.PrivateKey) Record {
	return Record{
		Binding: Binding{
			CommitSHA: sha1A, TreeSHA: tree1A, PatchFP: fpA, PatchFPState: "ok",
			ProjectHash: projH, PolicyVersion: "pack-1",
		},
		Key:         KeyRef{ID: KeyID(pub(k)), Attestation: AttestationSelf, Storage: StorageKeychain},
		CommittedAt: "2026-10-21T10:00:00Z",
		RecordedAt:  "2026-10-21T10:02:00Z",
		Lines:       Lines{AI: 12, Human: 0, Unknown: 3, HumanCapture: HumanCaptureNone},
		Files:       []File{{PathHash: "bbbbbbbbbbbbbbbb", AI: 2, Unknown: 3}, {PathHash: "aaaaaaaaaaaaaaaa", AI: 10}},
		Sessions:    []string{"sess-2", "sess-1", "sess-1"},
		Agents:      []string{"claude-code"},
		Models:      []string{"claude-opus-5-5"},
		PromptIDs:   []string{"41", "40"},
		Guard:       Guard{Events: 3, Asks: 1, ApprovedAsks: 1},
		Scanners:    []string{"secrets@1"},
	}
}

// The fixed vectors: the key id of the 0x01 seed key, and the digest of
// the fixed record's canonical payload. A change to the canonical form,
// the field names or the digest domain changes these and must be a
// deliberate shape change (a new Version).
const (
	vectorKeyID  = "34750f98bd59fcfc946da45aaabe933b"
	vectorDigest = "73844e8b7a96483e2eb0c3ab33363a64ae29c979fce7f4b6203919d0fec19747"
)

func TestFixedVectors(t *testing.T) {
	k := testKey(1)
	if got := KeyID(pub(k)); got != vectorKeyID {
		t.Fatalf("KeyID = %s, want %s", got, vectorKeyID)
	}
	payload, err := fixedRecord(k).Payload()
	if err != nil {
		t.Fatal(err)
	}
	if got := Digest(payload); got != vectorDigest {
		t.Fatalf("Digest = %s, want %s\npayload: %s", got, vectorDigest, payload)
	}
	if bytes.ContainsAny(payload, " \n\t") {
		t.Fatalf("canonical payload has whitespace: %s", payload)
	}
	if !bytes.HasPrefix(payload, []byte(`{"agents":["claude-code"],`)) {
		t.Fatalf("keys not sorted: %s", payload)
	}
	// Ed25519 is deterministic: the same key and payload sign the same.
	e1, _ := Sign(fixedRecord(k), k)
	e2, _ := Sign(fixedRecord(k), k)
	if e1.Signatures[0].Sig != e2.Signatures[0].Sig {
		t.Fatal("signature is not deterministic")
	}
}

func TestPAE(t *testing.T) {
	got := string(PAE("a/b", []byte("hello")))
	if got != "DSSEv1 3 a/b 5 hello" {
		t.Fatalf("PAE = %q", got)
	}
}

func selfTrust(t *testing.T, keys ...ed25519.PrivateKey) TrustSet {
	t.Helper()
	f := TrustFile{Version: TrustVersion}
	for _, k := range keys {
		f.Keys = append(f.Keys, SelfKeyEntry(pub(k), "", ""))
	}
	ts, err := NewTrustSet(f)
	if err != nil || len(ts.Issues) > 0 {
		t.Fatalf("trust: %v %v", err, ts.Issues)
	}
	return ts
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k := testKey(1)
	env, err := Sign(fixedRecord(k), k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(back, selfTrust(t, k))
	if err != nil {
		t.Fatal(err)
	}
	if v.Digest != vectorDigest || v.Attestation != AttestationSelf || len(v.Record.Sessions) != 2 {
		t.Fatalf("verified = %+v", v)
	}
}

// TestOneByteTamperRefused flips every byte of the payload and of the
// signature in turn: no single change verifies.
func TestOneByteTamperRefused(t *testing.T) {
	k := testKey(1)
	env, _ := Sign(fixedRecord(k), k)
	ts := selfTrust(t, k)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	for i := range payload {
		p := append([]byte(nil), payload...)
		p[i] ^= 0x01
		e := env
		e.Payload = base64.StdEncoding.EncodeToString(p)
		if _, err := Verify(e, ts); err == nil {
			t.Fatalf("payload byte %d flipped and the record verified", i)
		}
	}
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	for i := range sig {
		s := append([]byte(nil), sig...)
		s[i] ^= 0x80
		e := env
		e.Signatures = []Signature{{KeyID: env.Signatures[0].KeyID, Sig: base64.StdEncoding.EncodeToString(s)}}
		if _, err := Verify(e, ts); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("signature byte %d flipped: err = %v", i, err)
		}
	}
}

func TestVerifyRefusals(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	env, _ := Sign(fixedRecord(k1), k1)
	cases := []struct {
		name string
		env  func() Envelope
		ts   func() TrustSet
		want error
	}{
		{"unknown key", func() Envelope { return env }, func() TrustSet { return selfTrust(t, k2) }, ErrUnknownKey},
		{"wrong payload type", func() Envelope { e := env; e.PayloadType = "application/json"; return e }, func() TrustSet { return selfTrust(t, k1) }, ErrPayloadType},
		{"two signatures", func() Envelope { e := env; e.Signatures = append(e.Signatures, e.Signatures[0]); return e }, func() TrustSet { return selfTrust(t, k1) }, ErrMalformed},
		{"revoked", func() Envelope { return env }, func() TrustSet {
			ts, _ := NewTrustSet(TrustFile{Version: 1, Keys: []TrustKey{SelfKeyEntry(pub(k1), "", "")}, Revoked: []Revocation{{KeyID: KeyID(pub(k1)), RevokedAt: "2026-10-22T00:00:00Z"}}})
			return ts
		}, ErrRevoked},
		{"expired", func() Envelope { return env }, func() TrustSet {
			e := SelfKeyEntry(pub(k1), "", "")
			e.NotAfter = "2026-10-01T00:00:00Z"
			ts, _ := NewTrustSet(TrustFile{Version: 1, Keys: []TrustKey{e}})
			return ts
		}, ErrKeyExpired},
		{"signed by another key under this id", func() Envelope {
			e, _ := Sign(fixedRecord(k1), k1)
			sig := ed25519.Sign(k2, PAE(PayloadType, mustB64(e.Payload)))
			e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
			return e
		}, func() TrustSet { return selfTrust(t, k1) }, ErrBadSignature},
		{"not canonical", func() Envelope {
			p := append([]byte(" "), mustB64(env.Payload)...)
			sig := ed25519.Sign(k1, PAE(PayloadType, p))
			return Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(p), Signatures: []Signature{{KeyID: KeyID(pub(k1)), Sig: base64.StdEncoding.EncodeToString(sig)}}}
		}, func() TrustSet { return selfTrust(t, k1) }, ErrInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Verify(c.env(), c.ts()); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func mustB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func TestSignRefusesKeyMismatchAndInvalid(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	if _, err := Sign(fixedRecord(k1), k2); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
	r := fixedRecord(k1)
	r.Binding.CommitSHA = "not-a-sha"
	if _, err := Sign(r, k1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	r = fixedRecord(k1)
	r.Sessions = []string{"has space"}
	if _, err := Sign(r, k1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestCertificates(t *testing.T) {
	node, root, other := testKey(1), testKey(9), testKey(8)
	cert := Certificate{KeyID: KeyID(pub(node)), PublicKey: base64.StdEncoding.EncodeToString(pub(node)), MachineIdentity: "m-1", OrgID: "org-1", NotBefore: "2026-10-01T00:00:00Z", NotAfter: "2026-12-30T00:00:00Z"}
	signed, err := SignCertificate(cert, root)
	if err != nil {
		t.Fatal(err)
	}
	rootEntry := SelfKeyEntry(pub(root), "", "")
	ts, _ := NewTrustSet(TrustFile{Version: 1, OrgRoots: []TrustKey{rootEntry}, Certificates: []Certificate{signed}})
	rec := fixedRecord(node)
	rec.Binding.OrgID, rec.Binding.MachineIdentity = "org-1", "m-1"
	rec.Key.Attestation = AttestationOrg
	env, _ := Sign(rec, node)
	v, err := Verify(env, ts)
	if err != nil || v.Attestation != AttestationOrg {
		t.Fatalf("certified verify: %+v %v", v, err)
	}
	// A record for another org from the certified key is refused.
	rec.Binding.OrgID = "org-2"
	env2, _ := Sign(rec, node)
	if _, err := Verify(env2, ts); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("other org: %v", err)
	}
	// A certificate signed by a key that is not an org root is dropped.
	forged, _ := SignCertificate(cert, other)
	ts2, _ := NewTrustSet(TrustFile{Version: 1, OrgRoots: []TrustKey{rootEntry}, Certificates: []Certificate{forged}})
	if ts2.Len() != 0 || len(ts2.Issues) != 1 || !strings.Contains(ts2.Issues[0], "issuer") {
		t.Fatalf("forged cert kept: %d %v", ts2.Len(), ts2.Issues)
	}
	// A tampered certificate (machine changed after signing) is dropped.
	bad := signed
	bad.MachineIdentity = "m-2"
	ts3, _ := NewTrustSet(TrustFile{Version: 1, OrgRoots: []TrustKey{rootEntry}, Certificates: []Certificate{bad}})
	if ts3.Len() != 0 {
		t.Fatal("tampered certificate trusted")
	}
	// A revoked org root vouches for nothing.
	ts4, _ := NewTrustSet(TrustFile{Version: 1, OrgRoots: []TrustKey{rootEntry}, Certificates: []Certificate{signed}, Revoked: []Revocation{{KeyID: KeyID(pub(root))}}})
	if ts4.Len() != 0 {
		t.Fatal("revoked root vouched")
	}
}

func TestTrustFileRefusals(t *testing.T) {
	k := testKey(1)
	e := SelfKeyEntry(pub(k), "", "")
	e.KeyID = strings.Repeat("0", 32)
	ts, _ := NewTrustSet(TrustFile{Version: 1, Keys: []TrustKey{e}})
	if ts.Len() != 0 || len(ts.Issues) != 1 {
		t.Fatal("key id mismatch accepted")
	}
	if _, err := ParseTrustFile([]byte(`{"version":1,"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseTrustFile([]byte(`{"version":2}`)); err == nil {
		t.Fatal("future version accepted")
	}
}

func TestCheckBindingTable(t *testing.T) {
	b := fixedRecord(testKey(1)).Binding
	cases := []struct {
		name string
		c    CommitFacts
		want Match
	}{
		{"exact", CommitFacts{SHA: sha1A, Tree: tree1A}, MatchExact},
		{"exact with matching facts", CommitFacts{SHA: sha1A, Tree: tree1A, ProjectHash: projH}, MatchExact},
		{"rebase keeps the patch", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: fpA}, MatchPatch},
		{"amend changed the patch", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: strings.Repeat("7", 40)}, MatchNone},
		{"same sha other tree", CommitFacts{SHA: sha1A, Tree: strings.Repeat("6", 40)}, MatchNone},
		{"other org", CommitFacts{SHA: sha1A, Tree: tree1A, OrgID: "org-x"}, MatchNone},
		{"other project", CommitFacts{SHA: sha1A, Tree: tree1A, ProjectHash: strings.Repeat("9", 64)}, MatchNone},
	}
	for _, c := range cases {
		if got, row := CheckBinding(b, c.c); got != c.want {
			t.Errorf("%s: %s (row %s), want %s", c.name, got, row, c.want)
		}
	}
	nofp := b
	nofp.PatchFP, nofp.PatchFPState = "", "binary_only"
	if got, _ := CheckBinding(nofp, CommitFacts{SHA: strings.Repeat("5", 40), PatchFP: ""}); got != MatchNone {
		t.Errorf("a binary-only patch must never bind through the fingerprint, got %s", got)
	}
}

func TestDecideIngestTable(t *testing.T) {
	a := Stored{KeyID: "k1", CommitSHA: sha1A, PatchFP: fpA, Digest: "d1"}
	cases := []struct {
		name     string
		existing []Stored
		n        Stored
		want     Ingest
	}{
		{"first", nil, a, IngestAccept},
		{"same record", []Stored{a}, a, IngestDuplicate},
		{"replay from another key", []Stored{a}, Stored{KeyID: "k2", CommitSHA: sha1A, Digest: "d2"}, IngestReplay},
		{"same key rebuilt", []Stored{a}, Stored{KeyID: "k1", CommitSHA: sha1A, Digest: "d3"}, IngestUpdate},
		{"amend: a new commit", []Stored{a}, Stored{KeyID: "k1", CommitSHA: strings.Repeat("5", 40), Digest: "d4"}, IngestAccept},
		{"replay beats update", []Stored{a, {KeyID: "k2", CommitSHA: sha1A, Digest: "d5"}}, Stored{KeyID: "k1", CommitSHA: sha1A, Digest: "d6"}, IngestReplay},
	}
	for _, c := range cases {
		if got := DecideIngest(c.existing, c.n); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func verifiedFor(t *testing.T, k ed25519.PrivateKey, mut func(*Record)) Verified {
	t.Helper()
	r := fixedRecord(k)
	if mut != nil {
		mut(&r)
	}
	env, err := Sign(r, k)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(env, selfTrust(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDecideCommitAndSquash(t *testing.T) {
	k1, k2 := testKey(1), testKey(2)
	v1 := verifiedFor(t, k1, nil)
	v2 := verifiedFor(t, k2, nil)
	exact := CommitFacts{SHA: sha1A, Tree: tree1A}
	rebased := CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: fpA}
	cases := []struct {
		name   string
		c      CommitFacts
		cands  []Candidate
		want   Provenance
		reason string
	}{
		{"missing", exact, nil, ProvenanceUnknown, ReasonMissing},
		{"exact", exact, []Candidate{{Verified: v1}}, ProvenanceVerified, ReasonExact},
		{"rebase", rebased, []Candidate{{Verified: v1}}, ProvenanceRebased, ReasonPatch},
		// Decision log P-059: a record that is present and fails is a
		// failure; only a missing record is unknown.
		{"invalid only", exact, []Candidate{{Err: ErrBadSignature}}, ProvenanceFailed, ReasonInvalid},
		{"revoked key", exact, []Candidate{{Err: ErrRevoked}}, ProvenanceFailed, ReasonInvalid},
		{"unknown key", exact, []Candidate{{Err: ErrUnknownKey}}, ProvenanceFailed, ReasonInvalid},
		{"outside the key's validity", exact, []Candidate{{Err: ErrKeyExpired}}, ProvenanceFailed, ReasonInvalid},
		{"payload does not match the commit", CommitFacts{SHA: sha1A, Tree: strings.Repeat("6", 40)}, []Candidate{{Verified: v1}}, ProvenanceFailed, ReasonUnbound},
		{"invalid beside a good one", exact, []Candidate{{Err: ErrBadSignature}, {Verified: v1}}, ProvenanceVerified, ReasonExact},
		{"replay: two keys", exact, []Candidate{{Verified: v1}, {Verified: v2}}, ProvenanceFailed, ReasonReplay},
		{"replayed onto another commit", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: strings.Repeat("8", 40)}, []Candidate{{Verified: v1}}, ProvenanceFailed, ReasonUnbound},
		{"amend: no record for the new commit", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: strings.Repeat("8", 40)}, nil, ProvenanceUnknown, ReasonMissing},
	}
	for _, c := range cases {
		got := DecideCommit(c.c, c.cands)
		if got.Provenance != c.want || got.Reason != c.reason {
			t.Errorf("%s: %+v, want %s/%s", c.name, got, c.want, c.reason)
		}
	}
	st, out := DeriveSquash(strings.Repeat("e", 40), []CommitOutcome{DecideCommit(exact, []Candidate{{Verified: v1}}), DecideCommit(rebased, nil)})
	if out.Provenance != ProvenanceDerived || len(st.Inputs) != 1 || st.Inputs[0] != v1.Digest || st.Unverified != 1 {
		t.Fatalf("squash = %+v %+v", st, out)
	}
	if _, out := DeriveSquash(strings.Repeat("e", 40), []CommitOutcome{DecideCommit(rebased, nil)}); out.Provenance != ProvenanceUnknown {
		t.Fatalf("squash with no verified input = %+v", out)
	}
}

// TestBindingRefusalCodes pins the closed code of every binding row that
// does not match (decision log P-059 names each failure).
func TestBindingRefusalCodes(t *testing.T) {
	b := Binding{CommitSHA: sha1A, TreeSHA: tree1A, PatchFP: fpA, PatchFPState: "ok", OrgID: "org-a", MachineIdentity: "m-a", ProjectHash: "p-a"}
	cases := []struct {
		name string
		c    CommitFacts
		want string
	}{
		{"exact", CommitFacts{SHA: sha1A, Tree: tree1A}, ""},
		{"rebased through the patch", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), PatchFP: fpA}, ""},
		{"other org", CommitFacts{SHA: sha1A, Tree: tree1A, OrgID: "org-b"}, "record_for_another_org"},
		{"other machine", CommitFacts{SHA: sha1A, Tree: tree1A, MachineIdentity: "m-b"}, "record_for_another_machine"},
		{"other project", CommitFacts{SHA: sha1A, Tree: tree1A, ProjectHash: "p-b"}, "record_for_another_project"},
		{"payload does not match the commit", CommitFacts{SHA: sha1A, Tree: strings.Repeat("6", 40)}, "payload_does_not_match_commit"},
		{"replayed onto another commit", CommitFacts{SHA: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40)}, "record_for_another_commit"},
	}
	for _, c := range cases {
		if got := BindingRefusal(b, c.c); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRotationTable(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		k    KeyState
		want Rotation
	}{
		{"no key", KeyState{}, RotationGenerate},
		{"retired", KeyState{Exists: true, Retired: true, CreatedAt: now}, RotationGenerate},
		{"re-enrolled", KeyState{Exists: true, CreatedAt: now, Enrolment: "e1", CurrentEnrolment: "e2"}, RotationReEnrolment},
		{"enrolled for the first time", KeyState{Exists: true, CreatedAt: now, CurrentEnrolment: "e1"}, RotationReEnrolment},
		{"89 days", KeyState{Exists: true, CreatedAt: now.Add(-89 * 24 * time.Hour)}, RotationKeep},
		{"90 days", KeyState{Exists: true, CreatedAt: now.Add(-90 * 24 * time.Hour)}, RotationAge},
	}
	for _, c := range cases {
		if got := RotationDue(c.k, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestEvidenceOptional(t *testing.T) {
	k := testKey(1)
	v := verifiedFor(t, k, func(r *Record) {
		r.Evidence = &Evidence{RunID: "run-1", Digest: strings.Repeat("a", 64), IsolationClass: "container"}
	})
	if v.Record.Evidence == nil || v.Digest == vectorDigest {
		t.Fatal("evidence must change the digest and survive the round trip")
	}
}

func TestBuildLineSplit(t *testing.T) {
	k := testKey(1)
	base := BuildInput{
		Binding:     fixedRecord(k).Binding,
		Key:         KeyRef{ID: KeyID(pub(k)), Attestation: AttestationSelf, Storage: StorageFileKey},
		CommittedAt: time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
		RecordedAt:  time.Date(2026, 10, 21, 10, 2, 0, 500, time.UTC),
		Files: []FileInput{
			{PathHash: "aaaaaaaaaaaaaaaa", Added: 10, AI: 14, Human: 3},
			{PathHash: "bbbbbbbbbbbbbbbb", Added: 6, AI: 2, Human: 3},
			{PathHash: "not hex", Added: 5},
		},
		Models:   []string{"claude-opus-5-5", "a model with spaces"},
		Sessions: []string{"s1"},
	}
	cases := []struct {
		name              string
		hc                string
		ai, human, unknow int64
	}{
		{"no human capture: unmeasured, never zero human", "none", 12, 0, 4},
		{"vscode capture", "vscode", 12, 3, 1},
		{"unknown capture value reads as none", "jetbrains", 12, 0, 4},
	}
	for _, c := range cases {
		in := base
		in.HumanCapture = c.hc
		r := Build(in)
		if r.Lines.AI != c.ai || r.Lines.Human != c.human || r.Lines.Unknown != c.unknow || len(r.Files) != 2 {
			t.Errorf("%s: lines %+v files %d", c.name, r.Lines, len(r.Files))
		}
		if len(r.Models) != 1 || r.RecordedAt != "2026-10-21T10:02:00Z" {
			t.Errorf("%s: models %v recorded %s", c.name, r.Models, r.RecordedAt)
		}
		if _, err := Sign(r, k); err != nil {
			t.Errorf("%s: built record does not sign: %v", c.name, err)
		}
	}
}

// TestTrustMergeKeepsRevocation: a key one set trusts and the other revokes
// reads as revoked in the union, and keys from both sets are trusted.
func TestTrustMergeKeepsRevocation(t *testing.T) {
	a, b := testKey(1), testKey(2)
	env, err := Sign(fixedRecord(a), a)
	if err != nil {
		t.Fatal(err)
	}
	trustA := selfTrust(t, a)
	revoked, err := NewTrustSet(TrustFile{Version: TrustVersion, Revoked: []Revocation{{KeyID: KeyID(pub(a)), RevokedAt: "2026-10-01T00:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, trustA.Merge(selfTrust(t, b))); err != nil {
		t.Fatalf("union lost a key: %v", err)
	}
	for _, m := range []TrustSet{trustA.Merge(revoked), revoked.Merge(trustA)} {
		if _, err := Verify(env, m); !errors.Is(err, ErrRevoked) {
			t.Fatalf("merge lost the revocation: %v", err)
		}
	}
	if trustA.Merge(selfTrust(t, b)).Len() != 2 {
		t.Fatal("union size")
	}
}
