//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secverify"
)

// signForVerify signs a record for a commit of r and writes it as the
// commit's note under refs/notes/observer, the way the node's writer does.
func signForVerify(t *testing.T, r *verifyRepo, k ed25519.PrivateKey, sha string) {
	t.Helper()
	pub, _ := k.Public().(ed25519.PublicKey)
	tree := r.git("rev-parse", sha+"^{tree}")
	diff := r.git("diff-tree", "-p", "--no-renames", "-r", "--no-commit-id", "--root", sha)
	fp, st := commitlogFingerprint(diff + "\n")
	rec := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFP: fp, PatchFPState: st},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationSelf, Storage: secchange.StorageFileKey},
		CommittedAt: "2026-10-21T10:00:00Z", RecordedAt: "2026-10-21T10:01:00Z",
	}
	env, err := secchange.Sign(rec, k)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := env.Marshal()
	r.git("notes", "--ref="+secchange.NotesRef, "add", "-m", string(b), sha)
}

func writeKeysFile(t *testing.T, k ed25519.PrivateKey) string {
	t.Helper()
	pub, _ := k.Public().(ed25519.PublicKey)
	f := secchange.TrustFile{Version: secchange.TrustVersion, Keys: []secchange.TrustKey{secchange.SelfKeyEntry(pub, "", "")}}
	b, _ := json.Marshal(f)
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSecurityVerifyChangeRecords drives verify over a real repository:
// a commit with a signed note verifies, one without is unknown_provenance
// (a label, the check passes), a fail floor fails it, a keys file inside
// the repository is refused (exit 2), and the outcomes and the squash
// statement are written as JSON.
func TestSecurityVerifyChangeRecords(t *testing.T) {
	r := newVerifyRepo(t)
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	r.write("a.go", "package a\n")
	signed := r.commit("feat: a")
	signForVerify(t, r, k, signed)
	r.write("b.go", "package b\n")
	head := r.commit("feat: b")
	keys := writeKeysFile(t, k)
	out := filepath.Join(t.TempDir(), "prov.json")

	code, stdout, stderr := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, keys: keys, provenanceJSON: out})
	if code != 0 || !strings.Contains(stdout, "provenance: 1 verified, 1 unknown_provenance") || !strings.Contains(stdout, "label unknown_provenance") {
		t.Fatalf("label run: code %d\n%s\n%s", code, stdout, stderr)
	}
	var rep secverify.ProvenanceReport
	b, _ := os.ReadFile(out)
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Squash.Inputs) != 1 || rep.Squash.Unverified != 1 {
		t.Fatalf("provenance json: %v %s", err, b)
	}

	pol := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(pol, []byte("version = 1\nprovenance = \"fail\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, keys: keys, policyFile: pol}); code != 1 || !strings.Contains(stdout, "provenance_floor") {
		t.Fatalf("fail floor: code %d\n%s", code, stdout)
	}
	// Both commits signed: the floor is met.
	signForVerify(t, r, k, head)
	if code, stdout, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, keys: keys, policyFile: pol}); code != 0 {
		t.Fatalf("floor met: code %d\n%s", code, stdout)
	}
	// A keys file the PR controls is refused.
	r.write("keys.json", "{}")
	if code, _, stderr := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, keys: filepath.Join(r.dir, "keys.json")}); code != 2 || !strings.Contains(stderr, "inside the repository") {
		t.Fatalf("keys inside the repo: code %d %s", code, stderr)
	}
	// Decision log P-059: a note signed by a key the keys file does not
	// trust is a verification failure, named, and fails under the default
	// floor.
	r.write("c.go", "package c\n")
	forged := r.commit("feat: c")
	signForVerify(t, r, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize)), forged)
	if code, stdout, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: forged, keys: keys}); code != 1 ||
		!strings.Contains(stdout, "verification_failed") || !strings.Contains(stdout, "key_unknown") || !strings.Contains(stdout, "provenance_failed") {
		t.Fatalf("forged record: code %d\n%s", code, stdout)
	}
	// Without --keys the step says it did not run.
	if _, stdout, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head}); !strings.Contains(stdout, "provenance: not checked") {
		t.Fatalf("no keys: %s", stdout)
	}
}

// TestSecurityVerifySARIFProvenanceLocations: with --keys, every
// provenance result in the SARIF file carries a physical location code
// scanning accepts, beside its commit/<sha> logical location: the first
// path the commit changes in sorted order, the root README for a commit
// that changes nothing, and the template's policy path when there is no
// README either.
func TestSecurityVerifySARIFProvenanceLocations(t *testing.T) {
	r := newVerifyRepo(t)
	k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	r.write("z.go", "package z\n")
	r.write("m/a.go", "package a\n")
	twoFiles := r.commit("feat: two files")
	empty := r.commit("chore: empty")
	r.git("rm", "-q", "README.md")
	noReadme := r.commit("chore: drop the readme")
	head := r.commit("chore: empty without a readme")
	sarifPath := filepath.Join(t.TempDir(), "out.sarif")
	code, stdout, stderr := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, keys: writeKeysFile(t, k), sarif: sarifPath})
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout, stderr)
	}
	b, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"commit/" + twoFiles: "m/a.go",
		"commit/" + empty:    "README.md",
		"commit/" + noReadme: "README.md",
		"commit/" + head:     secverify.ProvenanceFallbackPath,
	}
	got := map[string]string{}
	for _, res := range log.Runs[0].Results {
		if res.RuleID != secverify.RuleProvenanceUnknown || len(res.Locations) != 1 {
			t.Fatalf("result %+v", res)
		}
		l := res.Locations[0]
		if l.PhysicalLocation == nil || l.PhysicalLocation.ArtifactLocation.URIBaseID != "%SRCROOT%" || l.PhysicalLocation.Region.StartLine != 1 || len(l.LogicalLocations) != 1 {
			t.Fatalf("location %+v", l)
		}
		got[l.LogicalLocations[0].FullyQualifiedName] = l.PhysicalLocation.ArtifactLocation.URI
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for c, uri := range want {
		if got[c] != uri {
			t.Fatalf("%s: located at %q, want %q (all: %v)", c, got[c], uri, got)
		}
	}
}

// TestSecurityVerifyPathArgsExit2 is PT-10: a file: URI or (off Windows) a
// drive-letter form on any path argument exits 2 with a reason, before any
// file is opened.
func TestSecurityVerifyPathArgsExit2(t *testing.T) {
	r := newVerifyRepo(t)
	head := r.base
	cases := []securityVerifyOpts{
		{policyFile: "file:///etc/policy.toml"},
		{sarif: "file:out.sarif"},
		{keys: "FILE:keys.json"},
		{installIndex: "file:/idx"},
		{repo: "file:" + r.dir},
		{policyFile: "C:/policy.toml"},
		{provenanceJSON: "c:out.json"},
	}
	for _, o := range cases {
		if o.repo == "" {
			o.repo = r.dir
		}
		o.base, o.head = r.base, head
		code, _, stderr := runVerifyForTest(t, o)
		if strings.HasPrefix(o.policyFile, "C:") || strings.HasPrefix(o.provenanceJSON, "c:") {
			if isWindowsHost() {
				continue
			}
		}
		if code != 2 || !strings.Contains(stderr, "UNKNOWN") {
			t.Errorf("%+v: code %d %s", o, code, stderr)
		}
	}
}

func isWindowsHost() bool { return filepath.Separator == '\\' }

func commitlogFingerprint(diff string) (string, string) {
	fp, st := commitlog.PatchFingerprint([]byte(diff))
	return fp, string(st)
}
