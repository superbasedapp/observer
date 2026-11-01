//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// ciOrg is a stand-in org server for the CI routes: it signs the CI policy
// and answers lookups from the records it holds, the way org.security.ci
// does (the server half is tested in internal/orgserver/secci).
type ciOrg struct {
	t       *testing.T
	orgID   string
	root    ed25519.PrivateKey
	node    ed25519.PrivateKey
	machine string
	cert    secchange.Certificate
	// records by commit sha.
	records map[string][]orgcontract.CILookupRecord
}

func newCIOrg(t *testing.T) *ciOrg {
	t.Helper()
	o := &ciOrg{
		t: t, orgID: "org-ci", machine: strings.Repeat("b", 64),
		root:    ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, ed25519.SeedSize)),
		node:    ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, ed25519.SeedSize)),
		records: map[string][]orgcontract.CILookupRecord{},
	}
	pub, _ := o.node.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	c, err := secchange.SignCertificate(secchange.Certificate{
		KeyID: secchange.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: o.machine,
		OrgID: o.orgID, NotBefore: now.Add(-30 * 24 * time.Hour).Format(time.RFC3339), NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
	}, o.root)
	if err != nil {
		t.Fatal(err)
	}
	o.cert = c
	return o
}

func (o *ciOrg) rootPub64() string {
	pub, _ := o.root.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(pub)
}

// ship records what the node would ship for a commit of r: the signed
// envelope, received and countersigned by the org.
func (o *ciOrg) ship(r *verifyRepo, sha string) {
	o.t.Helper()
	pub, _ := o.node.Public().(ed25519.PublicKey)
	tree := r.git("rev-parse", sha+"^{tree}")
	fp, st := commitlogFingerprint(r.git("diff-tree", "-p", "--no-renames", "-r", "--no-commit-id", "--root", sha) + "\n")
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	env, err := secchange.Sign(secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree, PatchFP: fp, PatchFPState: st, OrgID: o.orgID, MachineIdentity: o.machine},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationOrg, Storage: secchange.StorageKeychain},
		CommittedAt: now, RecordedAt: now,
	}, o.node)
	if err != nil {
		o.t.Fatal(err)
	}
	b, _ := env.Marshal()
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	dig := secchange.Digest(payload)
	cs := orgcontract.SignChangeCountersign(orgcontract.ChangeCountersign{
		OrgID: o.orgID, KeyID: secchange.KeyID(pub), RecordDigest: dig, ReceivedAt: now,
		KeyStatus: orgcontract.CountersignKeyCertified, Envelope: orgcontract.CountersignEnvelopeChecked,
	}, o.root)
	o.records[sha] = append(o.records[sha], orgcontract.CILookupRecord{
		RecordDigest: dig, KeyID: secchange.KeyID(pub), MatchedBy: orgcontract.CIMatchCommitSHA,
		State: orgcontract.ChangeIngestCountersigned, Envelope: string(b), Countersign: &cs,
	})
}

func (o *ciOrg) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ci-secret" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		now := time.Now().UTC()
		var doc orgcontract.CISignedDocument
		switch r.URL.Path {
		case orgcontract.CIPolicyPath:
			kb, _ := json.Marshal(secchange.TrustFile{
				Version: 1, Keys: []secchange.TrustKey{}, OrgRoots: []secchange.TrustKey{{KeyID: o.cert.IssuerKeyID, PublicKey: o.rootPub64()}},
				Certificates: []secchange.Certificate{o.cert}, Revoked: []secchange.Revocation{},
			})
			body, _ := json.Marshal(orgcontract.CIPolicy{
				OrgID: o.orgID, Version: 3, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
				ProvenanceFloor: "label", WaitSeconds: 0, Keys: kb,
			})
			doc = orgcontract.SignCIDocument(orgcontract.CIPolicyDomain, o.orgID, 3, body, o.root)
		case orgcontract.CILookupPath:
			var req orgcontract.CILookupRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
				return
			}
			ans := orgcontract.CILookupAnswer{OrgID: o.orgID, AnsweredAt: now.Format(time.RFC3339)}
			for _, c := range req.Commits {
				ans.Commits = append(ans.Commits, orgcontract.CILookupCommitAnswer{SHA: c.SHA, PatchFPHash: c.PatchFPHash, Records: append([]orgcontract.CILookupRecord{}, o.records[c.SHA]...)})
			}
			body, _ := json.Marshal(ans)
			doc = orgcontract.SignCIDocument(orgcontract.CILookupDomain, o.orgID, 0, body, o.root)
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

// TestSecurityVerifyOrgModeThreeJobs drives the org mode as the protected
// workflow runs it: `verify commits` with no secret, `verify fetch` with
// the CI credential and no checkout, then verify against the pinned org
// key. A commit the org countersigned verifies, one it holds nothing for
// is unknown_provenance; a wrong pinned key or a stale answer is exit 2; a
// lookup that never came leaves the commits to their notes.
func TestSecurityVerifyOrgModeThreeJobs(t *testing.T) {
	r := newVerifyRepo(t)
	org := newCIOrg(t)
	r.write("a.go", "package a\n")
	shipped := r.commit("feat: a")
	org.ship(r, shipped)
	r.write("b.go", "package b\n")
	head := r.commit("feat: b")
	srv := org.server()
	defer srv.Close()
	work := t.TempDir()
	commits := filepath.Join(work, "commits.json")
	policy := filepath.Join(work, "policy.json")
	lookup := filepath.Join(work, "lookup.json")

	// Job 1: the lookup request, no secrets.
	c := newSecurityVerifyCommitsCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs([]string{"--repo", r.dir, "--base", r.base, "--head", head, "--out", commits})
	if err := c.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("verify commits: %v\n%s", err, out.String())
	}
	var req orgcontract.CILookupRequest
	b, _ := os.ReadFile(commits)
	if err := json.Unmarshal(b, &req); err != nil || len(req.Commits) != 2 || req.Commits[0].PatchFPHash == "" {
		t.Fatalf("lookup request: %v %s", err, b)
	}

	// Job 2: the fetch, with the credential in its variable.
	t.Setenv(verifyOrgCredentialEnv, "ci-secret")
	var fo, fe bytes.Buffer
	if err := runSecurityVerifyFetch(context.Background(), &fo, &fe, securityVerifyFetchOpts{
		orgURL: srv.URL, commits: commits, policyOut: policy, lookupOut: lookup, credentialEnv: verifyOrgCredentialEnv, wait: -1,
	}); err != nil {
		t.Fatalf("verify fetch: %v\n%s\n%s", err, fo.String(), fe.String())
	}

	// Job 3: verify against the pinned key.
	o := securityVerifyOpts{repo: r.dir, base: r.base, head: head, orgPolicy: policy, orgLookup: lookup, orgKey: org.rootPub64(), orgID: org.orgID}
	code, stdout, stderr := runVerifyForTest(t, o)
	if code != 0 || !strings.Contains(stdout, "provenance: 1 verified, 1 unknown_provenance") || !strings.Contains(stdout, "(org countersigned)") ||
		!strings.Contains(stdout, "lookup answered: 1 countersigned") || !strings.Contains(stdout, "org_signed_policy") {
		t.Fatalf("org run: code %d\n%s\n%s", code, stdout, stderr)
	}

	// A key the workflow did not pin: exit 2.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	op, _ := other.Public().(ed25519.PublicKey)
	bad := o
	bad.orgKey = base64.StdEncoding.EncodeToString(op)
	if code, _, stderr := runVerifyForTest(t, bad); code != 2 || !strings.Contains(stderr, "org policy") {
		t.Fatalf("wrong key: code %d %s", code, stderr)
	}
	// A rollback floor above the policy's version: exit 2.
	floor := o
	floor.minPolicyVersion = 4
	if code, _, stderr := runVerifyForTest(t, floor); code != 2 || !strings.Contains(stderr, "below the pinned floor") {
		t.Fatalf("version floor: code %d %s", code, stderr)
	}
	// No lookup answer came: the commits read only their notes.
	if err := os.Remove(lookup); err != nil {
		t.Fatal(err)
	}
	if code, stdout, _ := runVerifyForTest(t, o); code != 0 || !strings.Contains(stdout, "0 verified, 2 unknown_provenance") || !strings.Contains(stdout, "lookup unavailable") {
		t.Fatalf("no lookup: code %d\n%s", code, stdout)
	}
	// Combinations refused up front.
	for _, mut := range []func(*securityVerifyOpts){
		func(x *securityVerifyOpts) { x.orgKey = "" },
		func(x *securityVerifyOpts) { x.policyFile = policy },
		func(x *securityVerifyOpts) { x.orgKey = "not-base64" },
		func(x *securityVerifyOpts) { x.orgPolicy = ""; x.orgKey = org.rootPub64() },
	} {
		x := o
		mut(&x)
		if code, _, stderr := runVerifyForTest(t, x); code != 2 {
			t.Errorf("refusal: code %d %s", code, stderr)
		}
	}
}

// TestSecurityVerifyFetchRefusals: a wrong credential or no org CI check
// fails the fetch closed (exit 2), and a stale lookup answer from an
// earlier run is removed before the new lookup.
func TestSecurityVerifyFetchRefusals(t *testing.T) {
	org := newCIOrg(t)
	srv := org.server()
	defer srv.Close()
	work := t.TempDir()
	policy := filepath.Join(work, "policy.json")
	t.Setenv(verifyOrgCredentialEnv, "wrong")
	err := runSecurityVerifyFetch(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, securityVerifyFetchOpts{orgURL: srv.URL, policyOut: policy, credentialEnv: verifyOrgCredentialEnv, wait: -1})
	var ec exitErr
	if !errors.As(err, &ec) || int(ec) != 2 {
		t.Fatalf("wrong credential: %v", err)
	}
	t.Setenv(verifyOrgCredentialEnv, "ci-secret")
	err = runSecurityVerifyFetch(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, securityVerifyFetchOpts{orgURL: "http://org.example.com", policyOut: policy, credentialEnv: verifyOrgCredentialEnv, wait: -1})
	if !errors.As(err, &ec) || int(ec) != 2 {
		t.Fatalf("plain http to a remote host: %v", err)
	}
	commits := filepath.Join(work, "commits.json")
	lookup := filepath.Join(work, "lookup.json")
	if err := os.WriteFile(commits, []byte(`{"commits":[{"sha":"`+strings.Repeat("c", 40)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookup, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runSecurityVerifyFetch(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, securityVerifyFetchOpts{
		orgURL: srv.URL, commits: commits, policyOut: policy, lookupOut: lookup, credentialEnv: verifyOrgCredentialEnv, wait: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(lookup); bytes.Equal(b, []byte("stale")) {
		t.Fatal("stale lookup answer kept")
	}
}
