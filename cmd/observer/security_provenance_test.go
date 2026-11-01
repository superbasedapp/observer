//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// provenanceNode is a throwaway repository with an AI session whose edit
// reached one real commit, and the provenance service over it.
type provenanceNode struct {
	root    string
	st      *store.Store
	svc     *provenanceSvc
	keys    *keystore.MemStore
	commit  commitlog.Commit
	project int64
}

func newProvenanceNode(t *testing.T) *provenanceNode {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	n := &provenanceNode{root: t.TempDir(), keys: &keystore.MemStore{}}
	n.st, _ = openTestStore(t)
	gitInitMain(t, n.root)
	edited := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	path := filepath.Join(n.root, "a.go")
	events := []models.ToolEvent{
		{
			SessionID: "sess-a", ProjectRoot: n.root, Target: "add a", ActionType: models.ActionUserPrompt, RawToolInput: "add a",
			RawToolName: "user_message", Tool: models.ToolClaudeCode, SourceFile: "/tmp/s.jsonl", SourceEventID: "p1", Timestamp: edited, Success: true,
		},
		{
			SessionID: "sess-a", ProjectRoot: n.root, Target: path, ActionType: models.ActionEditFile,
			RawToolInput: `{"file_path":"` + path + `","old_string":"x := 0","new_string":"a := 1\nb := 2\nc := 3"}`,
			RawToolName:  "Edit", Tool: models.ToolClaudeCode, SourceFile: "/tmp/s.jsonl", SourceEventID: "e1", Timestamp: edited.Add(time.Minute), Success: true,
		},
	}
	if _, err := n.st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var err error
	if n.project, err = n.st.ProjectIDForRoot(ctx, n.root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package a\n\na := 1\nb := 2\nc := 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, n.root, "add", "a.go")
	gitRun(t, n.root, "commit", "-q", "-m", "feat: a")
	sha := gitRun(t, n.root, "rev-parse", "HEAD")
	n.commit = commitlog.Commit{
		SHA: sha, AuthorHash: "au", AuthoredAt: time.Now().UTC(), CommittedAt: time.Now().UTC().Truncate(time.Second), Subject: "feat: a",
		Files: []commitlog.CommitFile{{RelPath: "a.go", PathHash: loc.PathHash(n.root, path), Added: 5}},
	}
	if _, err := n.st.UpsertCommits(ctx, n.project, []commitlog.Commit{n.commit}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	n.svc = &provenanceSvc{
		st: n.st, openKeys: func() (keystore.Store, string) { return n.keys, "" }, git: gitview.RunReadOnlyTimeout,
		now: time.Now, logger: nil, linkWindow: 14 * 24 * time.Hour,
	}
	n.svc.logger = discardLogger()
	return n
}

func (n *provenanceNode) trust(t *testing.T) secchange.TrustSet {
	t.Helper()
	keys, err := n.st.ChangeKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f := secchange.TrustFile{Version: secchange.TrustVersion}
	for _, k := range keys {
		f.Keys = append(f.Keys, secchange.TrustKey{KeyID: k.KeyID, PublicKey: k.PublicKey})
	}
	ts, err := secchange.NewTrustSet(f)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// TestProvenanceRecordsAnAgentCommit drives the whole node path on a real
// repository: the key lands in the keystore (public half in the table),
// the agent's commit gets one signed record whose binding is the commit's
// own tree and patch, a second offer is idempotent, and nothing a person
// could read as prompt text is in the payload.
func TestProvenanceRecordsAnAgentCommit(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	root := commitscan.Root{ProjectID: n.project, RootPath: n.root}

	// Before the loop made a key: no record (provenance never signs what it
	// did not see from the start).
	if out, err := n.svc.recordCommit(ctx, root, n.commit); err != nil || out != provBeforeKey {
		t.Fatalf("before the key: %s %v", out, err)
	}
	if _, k, err := n.svc.signingKey(ctx); err != nil || k.Storage != secchange.StorageFileKey {
		t.Fatalf("signingKey: %+v %v", k, err)
	}
	if len(n.keys.Names()) != 1 || !strings.HasPrefix(n.keys.Names()[0], "change-key-") {
		t.Fatalf("keystore holds %v", n.keys.Names())
	}
	out, err := n.svc.recordCommit(ctx, root, n.commit)
	if err != nil || out != provRecorded {
		t.Fatalf("record: %s %v", out, err)
	}
	if out, _ := n.svc.recordCommit(ctx, root, n.commit); out != provExists {
		t.Fatalf("second offer = %s", out)
	}
	recs, err := n.st.ListChangeRecords(ctx, secposture.ProjectRootHash(n.root), 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records: %v %v", recs, err)
	}
	env, err := secchange.ParseEnvelope(recs[0].Envelope)
	if err != nil {
		t.Fatal(err)
	}
	v, err := secchange.Verify(env, n.trust(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	tree := gitRun(t, n.root, "rev-parse", n.commit.SHA+"^{tree}")
	if m, row := secchange.CheckBinding(v.Record.Binding, secchange.CommitFacts{SHA: n.commit.SHA, Tree: tree}); m != secchange.MatchExact {
		t.Fatalf("binding %s (%s)", m, row)
	}
	if v.Record.Binding.PatchFPState != "ok" || v.Record.Lines.AI == 0 || strings.Join(v.Record.Sessions, ",") != "sess-a" {
		t.Fatalf("record = %+v", v.Record)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	for _, leak := range []string{"add a", "a.go", n.root} {
		if strings.Contains(string(payload), leak) {
			t.Errorf("payload carries %q", leak)
		}
	}
	if recs[0].Paths[0] != "a.go" || recs[0].RecordDigest != v.Digest {
		t.Errorf("row = %+v", recs[0])
	}
}

// TestProvenanceKeyRotation pins the schedule over the real keystore seam:
// 90 days retire the key and make a new one, the old public half stays.
func TestProvenanceKeyRotation(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	_, k1, err := n.svc.signingKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, again, _ := n.svc.signingKey(ctx); again.KeyID != k1.KeyID {
		t.Fatal("a fresh key rotated")
	}
	n.svc.now = func() time.Time { return time.Now().Add(91 * 24 * time.Hour) }
	_, k2, err := n.svc.signingKey(ctx)
	if err != nil || k2.KeyID == k1.KeyID {
		t.Fatalf("rotation: %+v %v", k2, err)
	}
	keys, _ := n.st.ChangeKeys(ctx)
	if len(keys) != 2 {
		t.Fatalf("keys = %d", len(keys))
	}
	for _, k := range keys {
		if k.KeyID == k1.KeyID && k.RetireReason != string(secchange.RotationAge) {
			t.Errorf("old key retire reason %q", k.RetireReason)
		}
	}
	// A key whose secret vanished from the keychain is replaced.
	_ = n.keys.Delete(provenanceKeyName(k2.KeyID))
	if _, k3, err := n.svc.signingKey(ctx); err != nil || k3.KeyID == k2.KeyID {
		t.Fatalf("missing secret: %+v %v", k3, err)
	}
	// By hand.
	if id, err := n.svc.rotateKey(ctx); err != nil || id == "" {
		t.Fatalf("rotateKey: %q %v", id, err)
	}
	if _, ok, _ := n.st.ActiveChangeKey(ctx); ok {
		t.Fatal("rotate-key left an active key")
	}
}

// TestProvenanceProducerInertWhenOff: with the loop not running the org
// wire provider reads nothing and the commit seam does nothing.
func TestProvenanceProducerInertWhenOff(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	if _, _, err := n.svc.signingKey(ctx); err != nil {
		t.Fatal(err)
	}
	provenanceRT.Store(nil)
	newProvenanceOnCommit(discardLogger())(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit)
	if recs, _ := n.st.ListChangeRecords(ctx, "", 10); len(recs) != 0 {
		t.Fatal("the commit seam recorded while provenance was off")
	}
	if _, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err != nil {
		t.Fatal(err)
	}
	rows, err := provenanceChangeRecords(n.st)(ctx, 10, store.SecurityScope{})
	if err != nil || rows != nil {
		t.Fatalf("producer with the loop off: %v %v", rows, err)
	}
	provenanceRT.Store(n.svc)
	defer provenanceRT.Store(nil)
	if rows, _ := provenanceChangeRecords(n.st)(ctx, 10, store.SecurityScope{}); len(rows) != 1 {
		t.Fatalf("producer with the loop on: %d rows", len(rows))
	}
}

// TestProvenanceNotesUnderConsent: no note without consent; with a
// person's consent the record is appended under refs/notes/observer once,
// and the branch's history is untouched (no rewrite).
func TestProvenanceNotesUnderConsent(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	layout := t.TempDir()
	if _, _, err := n.svc.signingKey(ctx); err != nil {
		t.Fatal(err)
	}
	if out, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err != nil || out != provRecorded {
		t.Fatalf("record: %s %v", out, err)
	}
	head := gitRun(t, n.root, "rev-parse", "HEAD")
	if w, err := n.svc.writeNotes(ctx, provenanceGitWrite); err != nil || w != 0 {
		t.Fatalf("without consent: %d %v", w, err)
	}
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, true, false, "cli", false, "/x/observer"); !errors.Is(err, errProvenanceOff) {
		t.Fatalf("consent while off: %v", err)
	}
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, true, false, "cli", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	if w, err := n.svc.writeNotes(ctx, provenanceGitWrite); err != nil || w != 1 {
		t.Fatalf("with consent: %d %v", w, err)
	}
	if w, _ := n.svc.writeNotes(ctx, provenanceGitWrite); w != 0 {
		t.Fatalf("second pass wrote %d", w)
	}
	note := gitRun(t, n.root, "notes", "--ref=refs/notes/observer", "show", n.commit.SHA)
	env, err := secchange.ParseEnvelope([]byte(note))
	if err != nil {
		t.Fatalf("note: %v\n%s", err, note)
	}
	if _, err := secchange.Verify(env, n.trust(t)); err != nil {
		t.Fatalf("the note does not verify: %v", err)
	}
	if got := gitRun(t, n.root, "rev-parse", "HEAD"); got != head {
		t.Fatalf("HEAD moved: %s -> %s", head, got)
	}
	if hooks, _ := os.ReadDir(filepath.Join(n.root, ".git", "hooks")); len(hooks) > 0 {
		for _, h := range hooks {
			if h.Name() == "prepare-commit-msg" {
				t.Fatal("notes consent installed the trailer hook")
			}
		}
	}
}

// TestProvenanceTrailerUnderConsent: consent installs the marked block
// (withdrawal removes it byte-exactly); the trailer is added only to the
// agent's own commit (the hook's marker, consumed once), never to a
// person's commit, and never without consent.
func TestProvenanceTrailerUnderConsent(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	layout := t.TempDir()
	hook := filepath.Join(n.root, ".git", "hooks", "prepare-commit-msg")
	mine := "#!/bin/sh\necho mine\n"
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte(mine), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, false, true, "dashboard", true, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hook)
	if !secchange.HasTrailerBlock(string(b)) || !strings.HasSuffix(string(b), "echo mine\n") {
		t.Fatalf("hook = %q", b)
	}
	t.Chdir(n.root)
	msgFile := filepath.Join(t.TempDir(), "COMMIT_EDITMSG")
	step := func(source string) (string, string) {
		t.Helper()
		if err := os.WriteFile(msgFile, []byte("feat: b\n\n# comment\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		reason, err := provenanceTrailerStep(ctx, n.st, layout, gitview.RunReadOnlyTimeout, true, msgFile, source, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		out, _ := os.ReadFile(msgFile)
		return reason, string(out)
	}
	// A person's commit: no marker, no trailer.
	if reason, msg := step(""); reason != "not_an_agent_commit" || strings.Contains(msg, "Assisted-by") {
		t.Fatalf("person's commit: %s %q", reason, msg)
	}
	// The agent's commit: the hook leaves the marker, the step adds the
	// trailer and consumes it.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	reason, msg := step("")
	if reason != "agent_commit" || !strings.Contains(msg, "\n\nAssisted-by: claude-code\n\n# comment") {
		t.Fatalf("agent's commit: %s %q", reason, msg)
	}
	if reason, _ := step(""); reason != "not_an_agent_commit" {
		t.Fatalf("the marker was not consumed: %s", reason)
	}
	// A merge never gets it.
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if reason, _ := step("merge"); reason != "merge_or_squash" {
		t.Fatalf("merge: %s", reason)
	}
	// Withdrawal: the block is removed byte-exactly, the flag is gone, and
	// the hook leaves no marker any more.
	if _, err := provenanceSetConsent(ctx, n.st, layout, gitview.RunReadOnlyTimeout, n.root, false, false, "cli", false, "/x/observer"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(hook); string(b) != mine {
		t.Fatalf("withdrawal left %q", b)
	}
	provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
	provenanceAgentCommitAllowed()
	if _, err := os.Stat(provenancePendingPath(layout, secposture.ProjectRootHash(n.root))); err == nil {
		// The merge case above left one marker; a fresh one must not be
		// written without the flag.
		_ = os.Remove(provenancePendingPath(layout, secposture.ProjectRootHash(n.root)))
		provenanceNoteAgentCommit(layout, n.root, provenanceCommitEvent(n.root, "git commit -m c"), "claude-code", true, nil)
		provenanceAgentCommitAllowed()
		if _, err := os.Stat(provenancePendingPath(layout, secposture.ProjectRootHash(n.root))); err == nil {
			t.Fatal("a marker was written without consent")
		}
	}
	if reason, _ := step(""); reason != "no_consent" {
		t.Fatalf("after withdrawal: %s", reason)
	}
}

// TestProvenanceStatusAndDoctor: with no [components] block the component
// reads off (doctor says so, no warning); the status read names the key,
// the records and the consented repositories, and the keys file export
// carries every key ever used.
func TestProvenanceStatusAndDoctor(t *testing.T) {
	n := newProvenanceNode(t)
	ctx := context.Background()
	if line, warn := provenanceDoctorDetail(ctx, filepath.Join(t.TempDir(), "none.toml"), n.st); warn || !strings.Contains(line, "off") {
		t.Fatalf("doctor with no block: %q %v", line, warn)
	}
	if _, _, err := n.svc.signingKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := n.svc.recordCommit(ctx, commitscan.Root{ProjectID: n.project, RootPath: n.root}, n.commit); err != nil {
		t.Fatal(err)
	}
	s, err := readProvenanceStatus(ctx, n.st, "", true, time.Now())
	if err != nil || s.Key == nil || s.Key.Rotation != "keep" || s.Records.Records != 1 || len(s.Consents) != 0 {
		t.Fatalf("status: %+v %v", s, err)
	}
	var buf bytes.Buffer
	writeProvenanceStatus(&buf, s)
	if !strings.Contains(buf.String(), "node-reported attribution") || !strings.Contains(buf.String(), "no repository has your consent") {
		t.Fatalf("status text: %s", buf.String())
	}
	if _, err := n.svc.rotateKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.svc.signingKey(ctx); err != nil {
		t.Fatal(err)
	}
	f, err := provenanceKeysFile(ctx, n.st)
	if err != nil || len(f.Keys) != 2 {
		t.Fatalf("keys file: %+v %v", f, err)
	}
	if _, err := secchange.NewTrustSet(f); err != nil {
		t.Fatalf("the export is not a keys file: %v", err)
	}
}
