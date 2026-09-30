package invariant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCommitOwnershipWireCarriesNoAuthorOrPath is the end-to-end seeded-value
// pin for the ONE org projection of the node-local commit ledger (lane
// F-PROJ, docs/security.md COMMIT-3). An AI-owned commit is seeded with
// sentinels in its author hash, its per-file rel_path and its subject, and the
// marshaled push payload is checked under all three share postures:
//
//   - the commit sha HASH does ship (positive canary: the wire is live, so
//     the absence checks below are not vacuous);
//   - the RAW commit sha ships ONLY under the raw-content posture (review
//     2026-09-29 finding 3: a raw sha is a lookup key into any readable
//     repository);
//   - the author hash NEVER ships (COMMIT-2: an unsalted hash of the author
//     name is not adequate pseudonymisation for an org projection);
//   - no per-file path, rel_path or path hash ever ships;
//   - the subject ships ONLY under the raw-content posture.
func TestCommitOwnershipWireCarriesNoAuthorOrPath(t *testing.T) {
	const (
		authorSentinel  = "SBCOAUTHORINV"
		relPathSentinel = "SBCORELPATHINV"
		subjectSentinel = "SBCOSUBJECTINV"
		sha             = "c0ffee0000000000000000000000000000c0ffee"
	)
	shaHashGot := sha256HexInv(sha)
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	root := "/inv/commit-owner"
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	events := []models.ToolEvent{
		{
			SessionID: "inv-co-sess", ProjectRoot: root, Target: "ship the parser",
			ActionType: models.ActionUserPrompt, RawToolInput: "ship the parser", RawToolName: "user_message",
			Tool: models.ToolClaudeCode, SourceFile: "/tmp/inv.jsonl", SourceEventID: "inv-co-p1",
			Timestamp: base, Success: true,
		},
		{
			SessionID: "inv-co-sess", ProjectRoot: root, Target: root + "/a.go",
			ActionType:   models.ActionEditFile,
			RawToolInput: `{"file_path":"` + root + `/a.go","old_string":"a := 1","new_string":"a := 2"}`,
			RawToolName:  "Edit", Tool: models.ToolClaudeCode, SourceFile: "/tmp/inv.jsonl", SourceEventID: "inv-co-e1",
			Timestamp: base.Add(time.Minute), Success: true,
		},
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := st.ProjectIDForRoot(ctx, root)
	if err != nil {
		t.Fatalf("ProjectIDForRoot: %v", err)
	}
	pathHash := loc.PathHash(root, root+"/a.go")
	if _, err := st.UpsertCommits(ctx, projectID, []commitlog.Commit{{
		SHA: sha, AuthorHash: authorSentinel, AuthoredAt: base.Add(5 * time.Minute), CommittedAt: base.Add(5 * time.Minute),
		Subject: subjectSentinel,
		Files:   []commitlog.CommitFile{{RelPath: relPathSentinel + "/a.go", PathHash: pathHash, Added: 1}},
	}}, base.Add(10*time.Minute)); err != nil {
		t.Fatalf("UpsertCommits: %v", err)
	}

	for _, p := range []struct {
		name        string
		share       store.ShareOptions
		wantSubject bool
	}{
		{"metadata_only", store.ShareOptions{}, false},
		{"full_content", store.ShareOptions{FullContent: true}, true},
		{"admin_managed", store.ShareOptions{AdminManaged: true}, true},
	} {
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<22, "org-1", "dev@x", p.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%s): %v", p.name, err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal(%s): %v", p.name, err)
		}
		if len(batch.CommitOwnership) != 1 || !bytes.Contains(raw, []byte(shaHashGot)) {
			t.Fatalf("%s: positive canary missing - the commit ownership wire did not carry the owned commit (%d rows)",
				p.name, len(batch.CommitOwnership))
		}
		if got := bytes.Contains(raw, []byte(sha)); got != p.wantSubject {
			t.Errorf("%s: raw commit sha shipped=%v, want %v (the raw sha rides shipsRawContent() only)", p.name, got, p.wantSubject)
		}
		for _, bad := range []string{authorSentinel, relPathSentinel, pathHash} {
			if bytes.Contains(raw, []byte(bad)) {
				t.Errorf("%s: %q reached the push payload - no author identity and no path may ever ship (COMMIT-2/COMMIT-3)", p.name, bad)
			}
		}
		if got := bytes.Contains(raw, []byte(subjectSentinel)); got != p.wantSubject {
			t.Errorf("%s: subject shipped=%v, want %v (the subject rides shipsRawContent() only)", p.name, got, p.wantSubject)
		}
	}
}

// sha256HexInv is sha256 hex, the wire's commit_sha_hash rule.
func sha256HexInv(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
