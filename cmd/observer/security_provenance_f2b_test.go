//go:build !sbo_omit_security

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// provenanceCommitEvent is the shell event of an agent's commit line run
// in dir.
func provenanceCommitEvent(dir, line string) *policy.Event {
	return &policy.Event{Kind: policy.KindShellExec, Target: line, Dialect: policy.DialectPosix, Cwd: dir, SessionID: "sess-a"}
}

// provenanceSnapshotHook replaces the repository's prepare-commit-msg hook
// with one that copies the index the commit is being made from (git's
// GIT_INDEX_FILE) and aborts the commit, so HEAD stays where the marker
// saw it and the trailer step can be run over exactly that index.
func provenanceSnapshotHook(t *testing.T, root, snap string) {
	t.Helper()
	hook := filepath.Join(root, ".git", "hooks", "prepare-commit-msg")
	script := "#!/bin/sh\ncp \"${GIT_INDEX_FILE:-.git/index}\" '" + filepath.Join(snap, "index") + "'\nexit 1\n"
	if err := os.WriteFile(hook, []byte(script), 0o700); err != nil { //nolint:gosec // G306: a test hook must be executable.
		t.Fatal(err)
	}
}

// provenanceRunLine runs a shell line in root the way an agent's shell
// tool does; the commit it makes is aborted by the snapshot hook.
func provenanceRunLine(t *testing.T, root, line string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", line)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_NOSYSTEM=1", "HOME="+root, "F=x.txt")
	_ = cmd.Run() // the snapshot hook aborts the commit on purpose
}

// TestProvenanceTrailerPlannedStagingRealGit is P-078 ruling 2 (lane
// SEC-F2B) against real git: an agent's one-line `git add X && git
// commit`, `git add -A; git commit`, `git commit -a`, `git commit -am` and
// a pathspec commit each keep the trailer, judged over the very index git
// hands the prepare-commit-msg hook; an unreadable `git add $F` gets none,
// and a line that stages more than it says gets none.
func TestProvenanceTrailerPlannedStagingRealGit(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	cases := []struct {
		name string
		// planned is the line the hook saw; ran is what the shell ran
		// ("" = the same).
		planned, ran string
		want         string
	}{
		{"add then commit", "git add x.txt && git commit -m m", "", "agent_commit"},
		{"add -A then commit", "git add -A; git commit -m m", "", "agent_commit"},
		{"commit -a", "git commit -a -m m", "", "agent_commit"},
		{"commit -am", "git commit -am m", "", "agent_commit"},
		{"pathspec commit", "git commit -m m -- a.go", "", "agent_commit"},
		{"unreadable add", "git add $F && git commit -m m", "", "not_an_agent_commit"},
		{"stages more than planned", "git add x.txt && git commit -m m", "git add x.txt y.txt && git commit -m m", "marker_other_tree"},
		{"commit -a never covers a new file", "git commit -a -m m", "git add y.txt && git commit -a -m m", "marker_other_tree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, layout, step := provenanceTrailerRepo(t)
			for name, body := range map[string]string{"x.txt": "x\n", "y.txt": "y\n", "a.go": "package a\n\nchanged := 1\n"} {
				if err := os.WriteFile(filepath.Join(n.root, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			snap := t.TempDir()
			provenanceSnapshotHook(t, n.root, snap)
			provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, tc.planned), "claude-code", true, nil)
			provenanceAgentCommitAllowed()
			ran := tc.ran
			if ran == "" {
				ran = tc.planned
			}
			provenanceRunLine(t, n.root, ran)
			if _, err := os.Stat(filepath.Join(snap, "index")); err != nil {
				t.Fatalf("the commit never reached prepare-commit-msg: %v", err)
			}
			t.Setenv("GIT_INDEX_FILE", filepath.Join(snap, "index"))
			reason, out := step("feat: c\n", time.Now())
			if reason != tc.want {
				t.Fatalf("%q: %s, want %s", ran, reason, tc.want)
			}
			if (tc.want == "agent_commit") != strings.Contains(out, "Assisted-by: claude-code") {
				t.Fatalf("trailer state wrong for %s: %q", reason, out)
			}
		})
	}
}

// TestProvenanceMarkerRefusesPathOutsideTree: a pathspec leaving the
// working tree writes no marker (fail safe).
func TestProvenanceMarkerRefusesPathOutsideTree(t *testing.T) {
	n, layout, _ := provenanceTrailerRepo(t)
	marker := provenancePendingPath(layout, secposture.ProjectRootHash(n.root))
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git add ../out && git commit -m m"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a marker was written for a pathspec outside the working tree")
	}
}

// TestProvenanceOrgProject: the record's org project id and policy
// version come from facts the node holds (lane SEC-F2B): the cached bundle
// and a current, single-project match record; anything else leaves the
// project id empty.
func TestProvenanceOrgProject(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.json")
	root := "/work/repo"
	if id, pv := provenanceOrgProject(bundle, root); id != "" || pv != "" {
		t.Fatalf("no bundle: %q %q", id, pv)
	}
	b := orgcontract.PolicyBundle{Version: 12, ProjectBinding: &orgcontract.ProjectBinding{OrgID: "o", Epoch: 3, MappingDigest: "md"}}
	raw, _ := json.Marshal(b)
	if err := os.WriteFile(bundle, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if id, pv := provenanceOrgProject(bundle, root); id != "" || pv != "guard-bundle:12" {
		t.Fatalf("bundle, no match: %q %q", id, pv)
	}
	write := func(m projectmatch.MatchFile) {
		t.Helper()
		path := projectmatch.LayoutFor(bundle).MatchPath(projectmatch.RootHash(root))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(m)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(projectmatch.MatchFile{OrgProjectIDs: []string{"proj-1"}, Epoch: 3, MappingDigest: "md"})
	if id, _ := provenanceOrgProject(bundle, root); id != "proj-1" {
		t.Fatalf("current single match: %q", id)
	}
	for _, m := range []projectmatch.MatchFile{
		{OrgProjectIDs: []string{"proj-1", "proj-2"}, Epoch: 3, MappingDigest: "md"},
		{OrgProjectIDs: []string{"proj-1"}, Epoch: 2, MappingDigest: "md"},
		{Unknown: true, Epoch: 3, MappingDigest: "md"},
	} {
		write(m)
		if id, _ := provenanceOrgProject(bundle, root); id != "" {
			t.Fatalf("%+v gave %q", m, id)
		}
	}
}

// TestProvenanceWithdrawAllTeardown: the security.provenance teardown step
// withdraws consent in every repository through the one consent seam, so
// each trailer block goes byte-exactly and the hook a person wrote stays.
func TestProvenanceWithdrawAllTeardown(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := t.Context()
	layout := t.TempDir()
	hook := filepath.Join(n.root, ".git", "hooks", "prepare-commit-msg")
	const mine = "#!/bin/sh\necho mine\n"
	if err := os.WriteFile(hook, []byte(mine), 0o700); err != nil { //nolint:gosec // G306: a hook is executable.
		t.Fatal(err)
	}
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, true, true, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(hook); string(b) == mine {
		t.Fatal("consent did not install the block")
	}
	done, failed, err := provenanceWithdrawAll(ctx, n.st, layout, gitview.RunReadOnlyTimeout)
	if err != nil || len(done) != 1 || len(failed) != 0 {
		t.Fatalf("withdraw-all: %+v %v %v", done, failed, err)
	}
	if b, _ := os.ReadFile(hook); string(b) != mine {
		t.Fatalf("teardown left %q", b)
	}
	if _, err := os.Stat(provenanceTrailerFlag(layout, secposture.ProjectRootHash(n.root))); err == nil {
		t.Fatal("the trailer flag stayed")
	}
	if done, _, _ := provenanceWithdrawAll(ctx, n.st, layout, gitview.RunReadOnlyTimeout); len(done) != 0 {
		t.Fatal("a second teardown found consent again")
	}
}

// TestProvenanceEnrolKey (lane SEC-F2B): a managed node enrols its active
// key once, keeps the org's certificate, marks the key org_certified and
// exports the certificate with its org root; a server without the CI check
// leaves the key self-attested and is not asked again at once.
func TestProvenanceEnrolKey(t *testing.T) {
	if _, err := machineid.ForOrg("org-1"); err != nil {
		t.Skipf("no machine identity here: %v", err)
	}
	n := newProvenanceNode(t)
	ctx := t.Context()
	n.svc.keyDir = t.TempDir()
	n.svc.enrolment = func(context.Context) (*store.Enrolment, error) {
		return &store.Enrolment{OrgID: "org-1", EnrolledAt: "2026-10-01T00:00:00Z", Tenancy: orgcontract.TenancyManaged}, nil
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	calls := 0
	n.svc.enrol = func(_ context.Context, priv ed25519.PrivateKey, machine string, now time.Time) (orgclient.ChangeKeyCertificate, error) {
		calls++
		pub, _ := priv.Public().(ed25519.PublicKey)
		c, err := secchange.SignCertificate(secchange.Certificate{
			KeyID: secchange.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: machine, OrgID: "org-1",
			NotBefore: now.UTC().Add(-time.Minute).Format(time.RFC3339), NotAfter: now.UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
		}, root)
		rp, _ := root.Public().(ed25519.PublicKey)
		cb, _ := json.Marshal(c)
		return orgclient.ChangeKeyCertificate{Certificate: cb, OrgRoot: orgcontract.ChangeKeyOrgRoot{KeyID: secchange.KeyID(rp), PublicKey: base64.StdEncoding.EncodeToString(rp)}}, err
	}
	if err := n.svc.enrolKey(ctx); err != nil || calls != 1 {
		t.Fatalf("enrol: %v (calls %d)", err, calls)
	}
	if err := n.svc.enrolKey(ctx); err != nil || calls != 1 {
		t.Fatalf("a held certificate was enrolled again: %v (calls %d)", err, calls)
	}
	k, ok, err := n.st.ActiveChangeKey(ctx)
	if err != nil || !ok || k.Attestation != secchange.AttestationOrg {
		t.Fatalf("key %+v %v", k, err)
	}
	f, err := provenanceKeysFile(ctx, n.st)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := n.st.ChangeKeys(ctx)
	provenanceAddCertificates(&f, n.svc.keyDir, keys)
	f.Keys = nil // trust only what the org certified
	ts, err := secchange.NewTrustSet(f)
	if err != nil || ts.Len() != 1 || len(ts.Issues) != 0 {
		t.Fatalf("exported certificate does not verify: %v %v", err, ts.Issues)
	}

	// A certificate for another machine is refused and nothing is kept.
	if _, err := provenanceVerifyCert(orgclient.ChangeKeyCertificate{Certificate: []byte(`{}`)}, k.KeyID, "org-1", "m"); err == nil {
		t.Fatal("an empty certificate verified")
	}

	// A server without org.security.ci: nothing kept, not asked again soon.
	m := newProvenanceNode(t)
	m.svc.keyDir = t.TempDir()
	m.svc.enrolment = n.svc.enrolment
	asked := 0
	m.svc.enrol = func(context.Context, ed25519.PrivateKey, string, time.Time) (orgclient.ChangeKeyCertificate, error) {
		asked++
		return orgclient.ChangeKeyCertificate{}, orgclient.ErrChangeKeyNotSupported
	}
	if err := m.svc.enrolKey(ctx); err != nil {
		t.Fatal(err)
	}
	_ = m.svc.enrolKey(ctx)
	if asked != 1 {
		t.Fatalf("asked %d times", asked)
	}
	if k, _, _ := m.st.ActiveChangeKey(ctx); k.Attestation != secchange.AttestationSelf {
		t.Fatalf("attestation %s", k.Attestation)
	}
}
