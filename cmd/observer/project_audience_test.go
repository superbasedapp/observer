package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// writeProjectAudienceFixture caches a v3 composed bundle and its mapping (one
// project, X, listing the remote of the returned directory's repository) the
// way the org client does, and returns the bundle path and that directory.
func writeProjectAudienceFixture(t *testing.T) (bundlePath, dir string) {
	t.Helper()
	base := t.TempDir()
	dir = filepath.Join(base, "widget")
	remote := "https://github.com/acme/widget.git"
	if _, err := exec.LookPath("git"); err == nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", remote}} {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: 2, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash(git.NormalizeRemote(remote))}}}},
	})
	b := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "# floor\n", PublicKey: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 2, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	bundlePath = filepath.Join(base, "home", "org-policy-bundle.json")
	write := func(path string, v any) {
		raw, _ := json.Marshal(v)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(bundlePath, b)
	write(projectmatch.LayoutFor(bundlePath).MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: time.Now()})
	return bundlePath, dir
}

// TestProjectMatcherRecordsAndFeedsThePosture is milestone 4b: the matcher
// writes the identity root's match record (a clone of a known repository
// matches before any session), rewrites it only when the match changes, and
// the posture writer's reader returns it while it belongs to the delivery in
// force.
func TestProjectMatcherRecordsAndFeedsThePosture(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	bundle, dir := writeProjectAudienceFixture(t)
	m := projectMatcher{bundlePath: bundle, now: time.Now}
	rec, ok, err := m.matchAndRecord(context.Background(), dir)
	if err != nil || !ok || !reflect.DeepEqual(rec.OrgProjectIDs, []string{"X"}) || rec.Epoch != 2 {
		t.Fatalf("match = %+v ok=%v err=%v", rec, ok, err)
	}
	ids, epoch := projectMatchForPosture(bundle)(rec.ProjectRootHash)
	if !reflect.DeepEqual(ids, []string{"X"}) || epoch != 2 {
		t.Fatalf("posture reader = %v %d", ids, epoch)
	}
	path := projectmatch.LayoutFor(bundle).MatchPath(rec.ProjectRootHash)
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if _, _, err := m.matchAndRecord(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an unchanged match rewrote its record")
	}
	// A node with no v3 delivery records nothing and the posture reads empty.
	if err := os.WriteFile(bundle, []byte(`{"version":1,"bundle_toml":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.matchAndRecord(context.Background(), dir); ok {
		t.Fatal("a v2 bundle produced a match")
	}
	if ids, _ := projectMatchForPosture(bundle)(rec.ProjectRootHash); ids != nil {
		t.Fatalf("a stale record fed the posture: %v", ids)
	}
}

// writeAboveCapFixture caches a v3 delivery whose mapping is truncated (the
// member is above the 200-project cap) and does not list the widget
// repository, which the org placed in project Z. It returns the bundle path,
// the widget directory and the org key, so a test can sign resolve answers.
func writeAboveCapFixture(t *testing.T, truncated bool) (bundlePath, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	bundlePath, dir = writeProjectAudienceFixture(t)
	_, priv, _ = ed25519.GenerateKey(rand.Reader)
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: 2, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge, Truncated: truncated,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "A", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash("github.com/acme/elsewhere")}}}},
	})
	b := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "# floor\n", PublicKey: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 2, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	for path, v := range map[string]any{
		bundlePath: b,
		projectmatch.LayoutFor(bundlePath).MappingPath(): projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: time.Now()},
	} {
		raw, _ := json.Marshal(v)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bundlePath, dir, priv
}

// fakeResolve answers like the org server: project Z for the widget remote,
// signed by priv, counting its calls; fail makes it fail instead.
type fakeResolve struct {
	priv  ed25519.PrivateKey
	calls int
	fail  error
}

func (f *fakeResolve) call(_ context.Context, req orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error) {
	f.calls++
	if f.fail != nil {
		return orgcontract.ProjectResolveAnswer{}, f.fail
	}
	var ids []string
	for _, h := range req.RemoteHashes {
		if h == projectmatch.Hash(git.NormalizeRemote("https://github.com/acme/widget.git")) {
			ids = []string{"Z"}
		}
	}
	env := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n",
		PublicKey:      base64.RawURLEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey)),
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", OrgProjectID: "Z", Epoch: 2},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(f.priv, env)
	now := time.Now()
	ans := orgcontract.ProjectResolveAnswer{
		OrgID: "org", Subject: "u", Epoch: 2, BundleVersion: 9, RequestDigest: orgcontract.ProjectResolveRequestDigest(req),
		Nonce: req.Nonce, OrgProjectIDs: ids, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	if len(ids) > 0 {
		ans.Envelopes = []orgcontract.PolicyBundle{env}
	}
	return orgcontract.SignProjectResolveAnswer(f.priv, ans), nil
}

// TestProjectMatcherResolvesAboveTheCap is milestone 1 on the node: a root the
// truncated mapping does not match is resolved (once: the answer stands until
// it expires), the record says so, and the answer's envelope is written where
// the guard reads it; a failed resolve above the cap records the project
// layer unknown, and below the cap leaves the mapping's "unmatched".
func TestProjectMatcherResolvesAboveTheCap(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	bundle, dir, priv := writeAboveCapFixture(t, true)
	f := &fakeResolve{priv: priv}
	m := projectMatcher{bundlePath: bundle, now: time.Now, resolve: f.call}
	rec, ok, err := m.matchAndRecord(ctx, dir)
	if err != nil || !ok || rec.Source != projectmatch.SourceResolve || !reflect.DeepEqual(rec.OrgProjectIDs, []string{"Z"}) || rec.BundleVersion != 9 {
		t.Fatalf("resolve record = %+v ok=%v err=%v", rec, ok, err)
	}
	if _, err := os.Stat(projectmatch.LayoutFor(bundle).ResolvedEnvelopePath("Z")); err != nil {
		t.Fatalf("the resolved envelope was not written: %v", err)
	}
	if _, _, err := m.matchAndRecord(ctx, dir); err != nil || f.calls != 1 {
		t.Fatalf("a current answer was asked again: %d calls (%v)", f.calls, err)
	}
	if ids, _ := projectMatchForPosture(bundle)(rec.ProjectRootHash); !reflect.DeepEqual(ids, []string{"Z"}) {
		t.Fatalf("posture reader = %v", ids)
	}

	// A failed resolve above the cap: the project layer is unknown.
	bundle2, dir2, priv2 := writeAboveCapFixture(t, true)
	m2 := projectMatcher{bundlePath: bundle2, now: time.Now, resolve: (&fakeResolve{priv: priv2, fail: errors.New("offline")}).call}
	rec2, _, err := m2.matchAndRecord(ctx, dir2)
	if err != nil || !rec2.Unknown || rec2.Reason != projectmatch.ReasonResolveFailed || len(rec2.OrgProjectIDs) != 0 {
		t.Fatalf("failed resolve above the cap = %+v (%v)", rec2, err)
	}
	if !rec2.ValidUntil.Before(time.Now().Add(projectResolveUnknownRetry + time.Minute)) {
		t.Fatalf("an unknown record must be retried soon: valid until %s", rec2.ValidUntil)
	}
	// Below the cap a failed resolve leaves the mapping's answer (unmatched),
	// remembered with a backoff (lane sec-p2a audit finding 4).
	bundle3, dir3, priv3 := writeAboveCapFixture(t, false)
	m3 := projectMatcher{bundlePath: bundle3, now: time.Now, resolve: (&fakeResolve{priv: priv3, fail: errors.New("offline")}).call}
	rec3, _, err := m3.matchAndRecord(ctx, dir3)
	if err != nil || rec3.Unknown || len(rec3.OrgProjectIDs) != 0 || rec3.Reason != projectResolveFailedBelowCap {
		t.Fatalf("failed resolve below the cap = %+v (%v)", rec3, err)
	}
	// An answer signed by another key is refused (the record is unknown).
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bundle4, dir4, _ := writeAboveCapFixture(t, true)
	m4 := projectMatcher{bundlePath: bundle4, now: time.Now, resolve: (&fakeResolve{priv: other}).call}
	if rec4, _, _ := m4.matchAndRecord(ctx, dir4); !rec4.Unknown || len(rec4.OrgProjectIDs) != 0 {
		t.Fatalf("a foreign-key answer was accepted: %+v", rec4)
	}
}

// writeV3Bundle caches a v3 composed bundle and its mapping of entries under
// base, the way the org client does, and returns the bundle path.
func writeV3Bundle(t *testing.T, base string, entries []orgcontract.ProjectMappingEntry) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := orgcontract.SignProjectMapping(priv, orgcontract.ProjectMapping{
		OrgID: "org", Subject: "u", Epoch: 2, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge, Projects: entries,
	})
	b := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: "# floor\n", PublicKey: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 2, MappingDigest: orgcontract.ProjectMappingDigest(m)},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	bundlePath := filepath.Join(base, "home", "org-policy-bundle.json")
	for path, v := range map[string]any{
		bundlePath: b,
		projectmatch.LayoutFor(bundlePath).MappingPath(): projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: time.Now()},
	} {
		raw, _ := json.Marshal(v)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bundlePath
}

// TestProjectMatcherRootCommitAtLaunch is the fork, mirror and remote-removed
// copy hard case: a repository only the root commit can match is matched at
// launch by running git.DefaultRootCommit once, before any resolve call; the
// root commit is cached in the store, so the next launch and the daemon loop
// (which never runs git) match from the cache; a repository with a failed
// exec is not re-run inside the store's 7-day fence.
func TestProjectMatcherRootCommitAtLaunch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	base := t.TempDir()
	dir := filepath.Join(base, "copy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return string(out)
	}
	gitIn("init", "-q")
	gitIn("commit", "-q", "--allow-empty", "-m", "root")
	root, err := git.DefaultRootCommit(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeV3Bundle(t, base, []orgcontract.ProjectMappingEntry{
		{OrgProjectID: "W", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash("github.com/acme/widget"), RootCommitHash: projectmatch.Hash(root)}}},
	})
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(base, "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	execs, resolves := 0, 0
	rootCommit := func(ctx context.Context, r string) (string, error) { execs++; return git.DefaultRootCommit(ctx, r) }
	resolve := func(context.Context, orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error) {
		resolves++
		return orgcontract.ProjectResolveAnswer{}, errors.New("not reached")
	}
	launch := projectMatcher{bundlePath: bundle, st: st, now: time.Now, rootCommit: rootCommit, resolve: resolve}
	rec, _, err := launch.matchAndRecord(ctx, dir)
	if err != nil || !reflect.DeepEqual(rec.OrgProjectIDs, []string{"W"}) || rec.Source != projectmatch.SourceMapping {
		t.Fatalf("launch match = %+v (%v)", rec, err)
	}
	if execs != 1 || resolves != 0 {
		t.Fatalf("execs %d resolves %d, want the root commit once and no resolve call", execs, resolves)
	}
	id, _ := git.ResolveIdentity(dir, git.IdentityOptions{SkipContentFingerprint: true})
	if sha, _ := st.CachedRootCommit(ctx, id.Root); sha != root {
		t.Fatalf("root commit not cached in the store: %q", sha)
	}
	// The daemon loop has no exec and matches from the cache.
	loop := projectMatcher{bundlePath: bundle, st: st, now: time.Now, resolve: resolve}
	if rec, _, _ := loop.match(ctx, dir, nil); !reflect.DeepEqual(rec.OrgProjectIDs, []string{"W"}) {
		t.Fatalf("loop match from the cache = %+v", rec)
	}
	if _, _, _ = launch.matchAndRecord(ctx, dir); execs != 1 {
		t.Fatalf("a cached root commit ran git again: %d", execs)
	}

	// A repository whose exec fails is fenced: tried once, not on the next
	// launch.
	other := filepath.Join(base, "empty")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	dir = other
	gitIn("init", "-q")
	failing := 0
	launch.rootCommit = func(context.Context, string) (string, error) { failing++; return "", errors.New("timeout") }
	launch.resolve = nil
	for i := 0; i < 2; i++ {
		_, _, _ = launch.matchAndRecord(ctx, other)
	}
	if failing != 1 {
		t.Fatalf("a failed root commit ran %d times inside the fence, want 1", failing)
	}
}
