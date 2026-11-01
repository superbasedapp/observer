//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// provenanceTrailerRepo is a provenance node with the trailer consented and
// the working directory in the repository, and a step that runs the
// prepare-commit-msg step on a fresh message.
func provenanceTrailerRepo(t *testing.T) (*provenanceNode, string, func(msg string, at time.Time) (string, string)) {
	t.Helper()
	n := newProvenanceNode(t)
	ctx := context.Background()
	layout := t.TempDir()
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, false, true, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(n.root)
	provenanceCandidate.Store(nil)
	t.Cleanup(func() { provenanceCandidate.Store(nil) })
	msgFile := filepath.Join(t.TempDir(), "COMMIT_EDITMSG")
	step := func(msg string, at time.Time) (string, string) {
		t.Helper()
		if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil {
			t.Fatal(err)
		}
		reason, err := provenanceTrailerStep(ctx, n.st, layout, gitview.RunReadOnlyTimeout, true, msgFile, "", at)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := os.ReadFile(msgFile)
		return reason, string(out)
	}
	return n, layout, step
}

// TestProvenanceTrailerOnlyAfterAllow is audit finding F3: the marker is
// written only once guard and the commit gate allowed the agent's commit,
// bound to HEAD and the index of that moment, for at most 30 seconds. A
// denied agent commit followed by a person's commit gets no trailer, and so
// does a person's commit from another index or on another HEAD.
func TestProvenanceTrailerOnlyAfterAllow(t *testing.T) {
	n, layout, step := provenanceTrailerRepo(t)
	marker := provenancePendingPath(layout, secposture.ProjectRootHash(n.root))
	const msg = "feat: c\n"

	// A denied agent commit: the enrich step held the candidate, the gate
	// denied, the hook process ended. Then the person commits.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the enrich step wrote a marker before guard decided")
	}
	provenanceCandidate.Store(nil)
	if reason, out := step(msg, time.Now()); reason != "not_an_agent_commit" || strings.Contains(out, "Assisted-by") {
		t.Fatalf("person's commit after a denied agent commit: %s %q", reason, out)
	}

	// Allowed, then a person stages another file and commits that index.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the allowed agent commit left no marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(n.root, "person.txt"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, n.root, "add", "person.txt")
	if reason, out := step(msg, time.Now()); reason != "marker_other_tree" || strings.Contains(out, "Assisted-by") {
		t.Fatalf("person's commit from another index: %s %q", reason, out)
	}

	// Allowed, then HEAD moves before the next commit.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	gitRun(t, n.root, "commit", "-q", "-m", "chore: person")
	if reason, _ := step(msg, time.Now()); reason != "marker_other_head" {
		t.Fatalf("person's commit on another HEAD: %s", reason)
	}

	// Allowed, but the commit comes 31 seconds later.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if reason, _ := step(msg, time.Now().Add(31*time.Second)); reason != "marker_stale" {
		t.Fatalf("a commit 31 s later: %s", reason)
	}

	// Allowed, and the agent's commit follows on the same HEAD and index.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if reason, out := step(msg, time.Now()); reason != "agent_commit" || !strings.Contains(out, "Assisted-by: claude-code") {
		t.Fatalf("the agent's own commit: %s %q", reason, out)
	}
}

// TestProvenanceTrailerCommentCharAndScissors is audit finding F8 through
// the real step: core.commentChar is honoured and the trailer lands above
// the scissors line of `git commit -v`.
func TestProvenanceTrailerCommentCharAndScissors(t *testing.T) {
	n, layout, step := provenanceTrailerRepo(t)
	gitRun(t, n.root, "config", "core.commentChar", ";")
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	in := "feat: c\n\n#12 the issue\n\n; Please enter the commit message\n; ------------------------ >8 ------------------------\n+line\n"
	want := "feat: c\n\n#12 the issue\n\nAssisted-by: claude-code\n\n; Please enter the commit message\n; ------------------------ >8 ------------------------\n+line\n"
	if reason, out := step(in, time.Now()); reason != "agent_commit" || out != want {
		t.Fatalf("%s\n got %q\nwant %q", reason, out, want)
	}
}

// TestProvenanceConsentRootMatchesTheHook is audit finding F4: consent
// given from a subdirectory or a linked worktree keys on the same root the
// hook and the records use (git.FindRoot, P-041), so the trailer flag the
// consent wrote is the one the hook finds.
func TestProvenanceConsentRootMatchesTheHook(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	sub := filepath.Join(n.root, "pkg", "inner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, n.root, "worktree", "add", "-q", "-b", "wt-branch", wt)
	wtSub := filepath.Join(wt, "pkg")
	if err := os.MkdirAll(wtSub, 0o755); err != nil {
		t.Fatal(err)
	}
	want := hookRootOf(n.root)
	for _, dir := range []string{n.root, sub, wt, wtSub} {
		got, err := provenanceResolveRoot(ctx, gitview.RunReadOnlyTimeout, dir)
		if err != nil || got != want || got != hookRootOf(dir) {
			t.Fatalf("%s: consent root %q (%v), hook root %q, want %q", dir, got, err, hookRootOf(dir), want)
		}
	}
	layout := t.TempDir()
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, wtSub, false, true, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	provenanceCandidate.Store(nil)
	defer provenanceCandidate.Store(nil)
	provenanceNoteAgentCommit(layout, hookRootOf(wtSub), provenanceCommitEvent(wtSub, "git commit -m c"), "claude-code", true, nil)
	if provenanceCandidate.Load() == nil {
		t.Fatal("the hook did not find the consent given from the linked worktree")
	}
	if _, err := provenanceResolveRoot(ctx, gitview.RunReadOnlyTimeout, t.TempDir()); err == nil {
		t.Fatal("a directory outside any repository resolved")
	}
}

// provenanceSignWith signs a minimal record for sha with priv at recorded.
func provenanceSignWith(t *testing.T, priv ed25519.PrivateKey, sha, tree string, recorded time.Time) secchange.Envelope {
	t.Helper()
	pub, _ := priv.Public().(ed25519.PublicKey)
	r := secchange.Record{
		Binding:     secchange.Binding{CommitSHA: sha, TreeSHA: tree},
		Key:         secchange.KeyRef{ID: secchange.KeyID(pub), Attestation: secchange.AttestationSelf, Storage: secchange.StorageFileKey},
		CommittedAt: secchange.FormatTime(recorded.Add(-time.Minute)), RecordedAt: secchange.FormatTime(recorded),
	}
	env, err := secchange.Sign(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (n *provenanceNode) seed(t *testing.T, id string) ed25519.PrivateKey {
	t.Helper()
	s, err := n.keys.Get(provenanceKeyName(id))
	if err != nil {
		t.Fatalf("seed of %s: %v", id, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(s)
	return ed25519.NewKeyFromSeed(raw)
}

func (n *provenanceNode) exportedTrust(t *testing.T) secchange.TrustSet {
	t.Helper()
	f, err := provenanceKeysFile(context.Background(), n.st)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := secchange.NewTrustSet(f)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// TestProvenanceRetiredKeyIsRefused is audit finding F1: a retired key's
// seed is deleted, the keys file bounds it with not_after = retired_at (a
// record it signs after retirement fails), a key rotated by hand is revoked
// (every record it signed fails), and a record signed inside the window
// still verifies. The node's own record view shows a failure as failed.
func TestProvenanceRetiredKeyIsRefused(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	_, k1, err := n.svc.signingKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err != nil || out != provRecorded {
		t.Fatalf("record: %s %v", out, err)
	}
	seed1 := n.seed(t, k1.KeyID)
	later := time.Now().Add(91 * 24 * time.Hour)
	n.svc.now = func() time.Time { return later }
	_, k2, err := n.svc.signingKey(ctx)
	if err != nil || k2.KeyID == k1.KeyID {
		t.Fatalf("rotation: %+v %v", k2, err)
	}
	if _, err := n.keys.Get(provenanceKeyName(k1.KeyID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("the retired key's seed is still stored: %v", err)
	}
	trust := n.exportedTrust(t)
	// The record k1 signed before it retired still verifies.
	recs, err := n.st.ListChangeRecords(ctx, "", 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records: %v %v", recs, err)
	}
	views, err := provenanceRecordViews(ctx, n.st, recs)
	if err != nil || views[0].Verification != string(secchange.ProvenanceVerified) {
		t.Fatalf("an in-window record: %+v %v", views, err)
	}
	// A record the old seed signs after retirement fails: not_after.
	if _, err := secchange.Verify(provenanceSignWith(t, seed1, n.commit.SHA, recs[0].TreeSHA, later.Add(time.Hour)), trust); !errors.Is(err, secchange.ErrKeyExpired) {
		t.Fatalf("a record signed after retirement: %v", err)
	}
	// Rotated by hand: revoked, every record it signed fails.
	seed2 := n.seed(t, k2.KeyID)
	early := provenanceSignWith(t, seed2, n.commit.SHA, recs[0].TreeSHA, later)
	if _, err := n.svc.rotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := n.keys.Get(provenanceKeyName(k2.KeyID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("a hand-rotated key's seed is still stored: %v", err)
	}
	if _, err := secchange.Verify(early, n.exportedTrust(t)); !errors.Is(err, secchange.ErrRevoked) {
		t.Fatalf("a record of a hand-rotated key: %v", err)
	}
	f, _ := provenanceKeysFile(ctx, n.st)
	if len(f.Revoked) != 1 || f.Revoked[0].KeyID != k2.KeyID {
		t.Fatalf("revocations: %+v", f.Revoked)
	}
	// A stored record whose payload does not match its commit row shows as
	// failed with its code, never as unknown.
	bad := recs[0]
	bad.TreeSHA = strings.Repeat("6", 40)
	if st, code := provenanceVerifyStored(trust, bad); st != string(secchange.ProvenanceFailed) || code != "payload_does_not_match_commit" {
		t.Fatalf("a mismatched stored record: %s %s", st, code)
	}
	if st, code := provenanceVerifyStored(trust, store.ChangeRecordRow{Envelope: []byte("{")}); st != string(secchange.ProvenanceFailed) || code != "malformed_envelope" {
		t.Fatalf("a malformed stored record: %s %s", st, code)
	}
}

// TestProvenanceEnrolmentReadErrorKeepsTheKey is audit finding F5: an
// enrolment read that fails returns an error and never rotates the key as
// a re-enrolment.
func TestProvenanceEnrolmentReadErrorKeepsTheKey(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	_, k1, err := n.svc.signingKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n.svc.enrolment = func(context.Context) (*store.Enrolment, error) {
		return nil, errors.New("database is locked (SQLITE_BUSY)")
	}
	if _, _, err := n.svc.signingKey(ctx); err == nil || !strings.Contains(err.Error(), "enrolment") {
		t.Fatalf("a failed enrolment read: %v", err)
	}
	if _, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err == nil {
		t.Fatal("a record was made over a failed enrolment read")
	}
	n.svc.enrolment = nil
	if _, k, err := n.svc.signingKey(ctx); err != nil || k.KeyID != k1.KeyID {
		t.Fatalf("after the busy read: %+v %v", k, err)
	}
	if keys, _ := n.st.ChangeKeys(ctx); len(keys) != 1 {
		t.Fatalf("keys = %d, want 1 (no rotation)", len(keys))
	}
}

// fakeKeychain is a keychain-class store whose reads can fail the way a
// locked macOS keychain does.
type fakeKeychain struct {
	keystore.MemStore
	getErr error
}

func (f *fakeKeychain) Backend() string { return "keychain" }

func (f *fakeKeychain) Get(name string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.MemStore.Get(name)
}

// macOSLockedKeychainErrors are the error values of the macOS live run's
// check 6: /usr/bin/security exits 36, "User interaction is not allowed.".
func macOSLockedKeychainErrors(t *testing.T) []error {
	t.Helper()
	out := []error{errors.New("SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.")}
	if runtime.GOOS != "windows" {
		if err := exec.Command("sh", "-c", "exit 36").Run(); err != nil {
			out = append(out, err)
		}
	}
	return out
}

// TestProvenanceLockedKeychain is the macOS live run's check 6: over a
// non-interactive session the locked keychain routes the key to the 0600
// file fallback with the named reason (shown in status and doctor's
// words), a later process with a working keychain reads the same key from
// the file (never a new key per call), and a key that IS in the keychain
// while it is locked is kept with a named error, never regenerated.
func TestProvenanceLockedKeychain(t *testing.T) {
	for _, locked := range macOSLockedKeychainErrors(t) {
		n := newProvenanceNode(t)
		ctx := context.Background()
		keyDir := t.TempDir()
		file := &keystore.MemStore{}
		kc := &fakeKeychain{}
		storeFor := func(storage string) keystore.Store {
			if storage == secchange.StorageKeychain {
				return kc
			}
			return file
		}
		n.svc.openKeys = func() (keystore.Store, string) { return file, keystore.FallbackReason(locked) }
		n.svc.storeFor, n.svc.keyDir = storeFor, keyDir
		_, k1, err := n.svc.signingKey(ctx)
		if err != nil || k1.Storage != secchange.StorageFileKey {
			t.Fatalf("%v: %+v %v", locked, k1, err)
		}
		s, err := readProvenanceStatus(ctx, n.st, keyDir, true, time.Now())
		if err != nil || s.Key == nil || s.Key.StorageReason != keystore.ReasonInteractionNotAllowed {
			t.Fatalf("%v: status %+v %v", locked, s.Key, err)
		}
		var buf bytes.Buffer
		writeProvenanceStatus(&buf, s)
		if !strings.Contains(buf.String(), "locked") || !strings.Contains(buf.String(), keystore.ReasonInteractionNotAllowed) {
			t.Fatalf("status text does not name the reason:\n%s", buf.String())
		}
		// A later process whose keychain works reads the same key.
		later := &provenanceSvc{
			st: n.st, openKeys: func() (keystore.Store, string) { return kc, "" }, storeFor: storeFor,
			git: gitview.RunReadOnlyTimeout, now: time.Now, logger: discardLogger(),
		}
		for i := 0; i < 3; i++ {
			if _, k, err := later.signingKey(ctx); err != nil || k.KeyID != k1.KeyID {
				t.Fatalf("%v: call %d: %+v %v", locked, i, k, err)
			}
		}
		// A key stored in the keychain, read while it is locked.
		if _, err := later.rotateKey(ctx); err != nil {
			t.Fatal(err)
		}
		_, k2, err := later.signingKey(ctx)
		if err != nil || k2.Storage != secchange.StorageKeychain {
			t.Fatalf("keychain key: %+v %v", k2, err)
		}
		kc.getErr = locked
		for i := 0; i < 3; i++ {
			_, _, err := later.signingKey(ctx)
			if err == nil || !strings.Contains(err.Error(), "kept") {
				t.Fatalf("%v: a locked keychain read: %v", locked, err)
			}
		}
		if k, ok, _ := n.st.ActiveChangeKey(ctx); !ok || k.KeyID != k2.KeyID {
			t.Fatalf("the locked keychain key was replaced: %+v", k)
		}
		if keys, _ := n.st.ChangeKeys(ctx); len(keys) != 2 {
			t.Fatalf("keys = %d, want 2 (no key per call)", len(keys))
		}
	}
}

// TestProvenanceTrailerPreview is audit finding F7: the preview names the
// exact block and the hook file before the write, and reports it
// installed after the consent.
func TestProvenanceTrailerPreview(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	pv, err := provenanceTrailerPreview(ctx, gitview.RunReadOnlyTimeout, n.root, "/x/observer")
	if err != nil || pv.Installed || pv.Block != secchange.TrailerBlock("/x/observer") || filepath.Base(pv.HookPath) != "prepare-commit-msg" || len(pv.Digest) != 64 {
		t.Fatalf("before: %+v %v", pv, err)
	}
	if _, err := provenanceSetConsent(ctx, n.st, t.TempDir(), gitview.RunReadOnlyTimeout, n.root, false, true, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	if after, _ := provenanceTrailerPreview(ctx, gitview.RunReadOnlyTimeout, n.root, "/x/observer"); !after.Installed || after.Digest != pv.Digest {
		t.Fatalf("after: %+v", after)
	}
}
