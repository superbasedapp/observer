package secverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

func provKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

// provNote signs a record for (sha, tree, fp) and returns its envelope line.
func provNote(t *testing.T, sha, tree, fp string) []byte {
	t.Helper()
	k := provKey()
	pub, _ := k.Public().(ed25519.PublicKey)
	r := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFP: fp, PatchFPState: "ok"},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationSelf, Storage: secchange.StorageKeychain},
		CommittedAt: "2026-10-21T10:00:00Z", RecordedAt: "2026-10-21T10:01:00Z",
	}
	env, err := secchange.Sign(r, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func provTrust(t *testing.T) secchange.TrustSet {
	t.Helper()
	pub, _ := provKey().Public().(ed25519.PublicKey)
	ts, err := secchange.NewTrustSet(secchange.TrustFile{Version: 1, Keys: []secchange.TrustKey{secchange.SelfKeyEntry(pub, "", "")}})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

var (
	pSHA1 = strings.Repeat("1", 40)
	pTree = strings.Repeat("2", 40)
	pFP   = strings.Repeat("3", 40)
	pSHA2 = strings.Repeat("4", 40)
)

// provTrustFile builds a trust set over the test key with the given
// changes to its entry and revocation list.
func provTrustFile(t *testing.T, mut func(*secchange.TrustFile)) secchange.TrustSet {
	t.Helper()
	pub, _ := provKey().Public().(ed25519.PublicKey)
	f := secchange.TrustFile{Version: 1, Keys: []secchange.TrustKey{secchange.SelfKeyEntry(pub, "", "")}}
	if mut != nil {
		mut(&f)
	}
	ts, err := secchange.NewTrustSet(f)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// TestVerifyProvenanceFailures is decision log P-059, one row per kind: a
// record that is present and fails verification is verification_failed,
// named by its closed code, and fails the check whatever the floor and the
// mode; a commit with no record stays unknown_provenance (a label).
func TestVerifyProvenanceFailures(t *testing.T) {
	good := provNote(t, pSHA1, pTree, pFP)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	otherPub, _ := other.Public().(ed25519.PublicKey)
	provPub, _ := provKey().Public().(ed25519.PublicKey)
	id := secchange.KeyID(provPub)
	// The trusted key's id over a signature another key made.
	env, err := secchange.ParseEnvelope(good)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(other, secchange.PAE(env.PayloadType, payload)))
	badSig, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		trust  secchange.TrustSet
		commit ProvenanceCommit
		failed bool
		code   string
	}{
		{"no record stays unknown", provTrust(t), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}}, false, ""},
		{"bad signature", provTrust(t), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{badSig}}, true, "bad_signature"},
		{"unknown key", provTrustFile(t, func(f *secchange.TrustFile) { f.Keys = []secchange.TrustKey{secchange.SelfKeyEntry(otherPub, "", "")} }), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{good}}, true, "key_unknown"},
		{"revoked key", provTrustFile(t, func(f *secchange.TrustFile) {
			f.Revoked = []secchange.Revocation{{KeyID: id, RevokedAt: "2026-10-21T11:00:00Z", Reason: "rotated_by_hand"}}
		}), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{good}}, true, "key_revoked"},
		{"outside the key's validity", provTrustFile(t, func(f *secchange.TrustFile) { f.Keys[0].NotAfter = "2026-10-21T10:00:30Z" }), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{good}}, true, "key_expired"},
		{"payload does not match the commit", provTrust(t), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: strings.Repeat("6", 40)}, Notes: [][]byte{good}}, true, "payload_does_not_match_commit"},
		{"replayed onto another commit", provTrust(t), ProvenanceCommit{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree, PatchFP: strings.Repeat("8", 40)}, Notes: [][]byte{good}}, true, "record_for_another_commit"},
	}
	for _, c := range cases {
		for _, mode := range []Mode{ModeEnforce, ModeObserve} {
			for _, floor := range []secchange.FloorAction{secchange.FloorLabel, secchange.FloorFail} {
				pol := DefaultPolicy()
				pol.Provenance, pol.Mode = floor, mode
				rep := Verify(context.Background(), Request{Policy: pol, Provenance: &ProvenanceInput{Trust: c.trust, Commits: []ProvenanceCommit{c.commit}}}, []Detector{})
				p := rep.Provenance
				name := c.name + "/" + string(mode) + "/" + string(floor)
				if !c.failed {
					if p.Failed != 0 || p.Unknown != 1 || p.Commits[0].Provenance != secchange.ProvenanceUnknown || rep.Rule == "provenance_failed" {
						t.Errorf("%s: %+v (%s)", name, p, rep.Rule)
					}
					continue
				}
				if p.Failed != 1 || p.Unknown != 0 || p.Commits[0].Provenance != secchange.ProvenanceFailed {
					t.Errorf("%s: provenance %+v", name, p)
				}
				if rep.Verdict != VerdictFail || rep.Rule != "provenance_failed" || rep.Verdict.ExitCode() == ExitPass {
					t.Errorf("%s: verdict %s (%s)", name, rep.Verdict, rep.Rule)
				}
				if c.code != "" && !strings.Contains(strings.Join(p.Commits[0].Errors, ","), c.code) {
					t.Errorf("%s: errors %v, want %s", name, p.Commits[0].Errors, c.code)
				}
				var buf bytes.Buffer
				_ = WriteSummary(&buf, rep)
				if !strings.Contains(buf.String(), "1 verification_failed") || !strings.Contains(buf.String(), "verification_failed") {
					t.Errorf("%s: summary does not name the failure:\n%s", name, buf.String())
				}
			}
		}
	}
}

func TestVerifyProvenance(t *testing.T) {
	good := provNote(t, pSHA1, pTree, pFP)
	tampered := bytes.Replace(good, []byte(`"payload":"`), []byte(`"payload":"A`), 1)
	cases := []struct {
		name     string
		floor    secchange.FloorAction
		mode     Mode
		commits  []ProvenanceCommit
		verdict  Verdict
		verified int
		unknown  int
		label    string
	}{
		{"verified", "", ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{good}}}, VerdictPass, 1, 0, ""},
		{"rebased: verified through the patch", "", ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: strings.Repeat("5", 40), PatchFP: pFP}, Notes: [][]byte{good}}}, VerdictPass, 1, 0, ""},
		{"missing: a label, never a failure by default", "", ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree}}}, VerdictPass, 0, 1, "unknown_provenance"},
		{"missing under a fail floor", secchange.FloorFail, ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree}}}, VerdictFail, 0, 1, "unknown_provenance"},
		{"missing under a fail floor in observe mode", secchange.FloorFail, ModeObserve, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree}}}, VerdictPass, 0, 1, "unknown_provenance"},
		// Decision log P-059: a tampered note is a verification failure (not
		// an unknown), and it fails under the default floor too.
		{"tampered note fails", "", ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{tampered}}}, VerdictFail, 0, 0, ""},
		{"a trailer alone verifies nothing", "", ModeEnforce, []ProvenanceCommit{{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree}, Trailer: "claude-code:x"}}, VerdictPass, 0, 1, "unknown_provenance"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol := DefaultPolicy()
			pol.Provenance, pol.Mode = c.floor, c.mode
			rep := Verify(context.Background(), Request{Policy: pol, Provenance: &ProvenanceInput{Trust: provTrust(t), Commits: c.commits}}, []Detector{})
			p := rep.Provenance
			if rep.Verdict != c.verdict || p.Verified != c.verified || p.Unknown != c.unknown || p.Label != c.label {
				t.Fatalf("verdict %s (%s), provenance %+v", rep.Verdict, rep.Rule, p)
			}
			var buf bytes.Buffer
			if err := WriteSummary(&buf, rep); err != nil || !strings.Contains(buf.String(), "provenance: ") {
				t.Fatalf("summary: %v\n%s", err, buf.String())
			}
		})
	}
	// The squash statement lists the verified records only.
	pol := DefaultPolicy()
	rep := Verify(context.Background(), Request{Policy: pol, Provenance: &ProvenanceInput{Trust: provTrust(t), Commits: []ProvenanceCommit{
		{Facts: secchange.CommitFacts{SHA: pSHA1, Tree: pTree}, Notes: [][]byte{good}},
		{Facts: secchange.CommitFacts{SHA: pSHA2, Tree: pTree}},
	}}}, []Detector{})
	if len(rep.Provenance.Squash.Inputs) != 1 || rep.Provenance.Squash.Unverified != 1 {
		t.Fatalf("squash = %+v", rep.Provenance.Squash)
	}
	// A truncated range reads unknown.
	rep = Verify(context.Background(), Request{Policy: pol, Provenance: &ProvenanceInput{Trust: provTrust(t), Truncated: true}}, []Detector{})
	if rep.Provenance.Label == "" {
		t.Fatal("a truncated range must carry the label")
	}
	// No keys file: not checked, and said so.
	rep = Verify(context.Background(), Request{Policy: pol}, []Detector{})
	var buf bytes.Buffer
	_ = WriteSummary(&buf, rep)
	if rep.Provenance.Checked || !strings.Contains(buf.String(), "not checked") {
		t.Fatalf("unchecked provenance: %+v\n%s", rep.Provenance, buf.String())
	}
}

func TestPolicyProvenanceFloor(t *testing.T) {
	p, err := ParsePolicy([]byte("version = 1\nprovenance = \"fail\"\n"), SourceProtected)
	if err != nil || p.Provenance != secchange.FloorFail {
		t.Fatalf("%+v %v", p.Provenance, err)
	}
	if _, err := ParsePolicy([]byte("version = 1\nprovenance = \"block\"\n"), SourceProtected); err == nil {
		t.Fatal("an unknown floor was accepted")
	}
}

func TestPathArgRefusal(t *testing.T) {
	cases := []struct {
		v       string
		windows bool
		refused bool
	}{
		{"/home/runner/policy.toml", false, false},
		{"policy.toml", false, false},
		{"", false, false},
		{"file:///etc/policy.toml", false, true},
		{"FILE:policy.toml", true, true},
		{"C:/policy.toml", false, true},
		{"c:policy.toml", false, true},
		{`C:\work\policy.toml`, true, false},
		{"ab:c.toml", false, false},
	}
	for _, c := range cases {
		if got := PathArgRefusal("--policy", c.v, c.windows) != ""; got != c.refused {
			t.Errorf("%q windows=%v: refused %v, want %v", c.v, c.windows, got, c.refused)
		}
	}
}
