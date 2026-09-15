package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// projectRow snapshots the migration-102 columns for assertions below.
type projectRow struct {
	upstreamRemote     sql.NullString
	upstreamRemoteHash sql.NullString
	remoteOwnerHash    sql.NullString
	upstreamOwnerHash  sql.NullString
	rootCommitSHA      sql.NullString
	rootCommitHash     sql.NullString
	rootCommitChecked  sql.NullString
	fingerprint        sql.NullString
	fingerprintHash    sql.NullString
}

func readProjectRow(t *testing.T, db *sql.DB, projectID int64) projectRow {
	t.Helper()
	var r projectRow
	err := db.QueryRow(
		`SELECT git_upstream_remote, git_upstream_remote_hash, git_remote_owner_hash,
		        git_upstream_owner_hash, root_commit_sha, root_commit_hash,
		        root_commit_checked_at, content_fingerprint, content_fingerprint_hash
		 FROM projects WHERE id = ?`, projectID,
	).Scan(&r.upstreamRemote, &r.upstreamRemoteHash, &r.remoteOwnerHash,
		&r.upstreamOwnerHash, &r.rootCommitSHA, &r.rootCommitHash,
		&r.rootCommitChecked, &r.fingerprint, &r.fingerprintHash)
	if err != nil {
		t.Fatalf("readProjectRow: %v", err)
	}
	return r
}

func TestUpsertProjectWithIdentity_BackfillOnTouch(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi1", "git@github.com:acme/repo.git", ProjectIdentity{
		UpstreamRemote:     "github.com/acme/repo",
		RemoteOwner:        "github.com/acme",
		UpstreamOwner:      "github.com/acme",
		RootCommitSHA:      "aaa111",
		ContentFingerprint: "fp1",
	})
	if err != nil {
		t.Fatalf("UpsertProjectWithIdentity: %v", err)
	}

	row := readProjectRow(t, db, pid)
	if row.upstreamRemote.String != "github.com/acme/repo" {
		t.Errorf("upstreamRemote = %q, want github.com/acme/repo", row.upstreamRemote.String)
	}
	if row.upstreamRemoteHash.String != sha256Hex("github.com/acme/repo") {
		t.Errorf("upstreamRemoteHash mismatch: %q", row.upstreamRemoteHash.String)
	}
	if row.remoteOwnerHash.String != sha256Hex("github.com/acme") {
		t.Errorf("remoteOwnerHash mismatch: %q", row.remoteOwnerHash.String)
	}
	if row.rootCommitSHA.String != "aaa111" {
		t.Errorf("rootCommitSHA = %q, want aaa111", row.rootCommitSHA.String)
	}
	if row.rootCommitHash.String != sha256Hex("aaa111") {
		t.Errorf("rootCommitHash mismatch: %q", row.rootCommitHash.String)
	}
	if row.fingerprint.String != "fp1" {
		t.Errorf("fingerprint = %q, want fp1", row.fingerprint.String)
	}

	// An empty-identity write (e.g. a later event from an adapter with no
	// git info) must never clobber what's already stored.
	pid2, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi1", "", ProjectIdentity{})
	if err != nil {
		t.Fatalf("UpsertProjectWithIdentity (empty): %v", err)
	}
	if pid2 != pid {
		t.Fatalf("project id changed: %d -> %d", pid, pid2)
	}
	row2 := readProjectRow(t, db, pid)
	if row2.upstreamRemote.String != "github.com/acme/repo" {
		t.Errorf("empty write clobbered upstreamRemote: %q", row2.upstreamRemote.String)
	}
	if row2.rootCommitSHA.String != "aaa111" {
		t.Errorf("empty write clobbered rootCommitSHA: %q", row2.rootCommitSHA.String)
	}
	if row2.fingerprint.String != "fp1" {
		t.Errorf("empty write clobbered fingerprint: %q", row2.fingerprint.String)
	}

	// A genuinely new non-empty value must still win (a fork's upstream
	// changed, or a re-parse found a better signal).
	pid3, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi1", "", ProjectIdentity{
		UpstreamRemote: "github.com/acme/repo-renamed",
	})
	if err != nil {
		t.Fatalf("UpsertProjectWithIdentity (update): %v", err)
	}
	if pid3 != pid {
		t.Fatalf("project id changed on update: %d -> %d", pid, pid3)
	}
	row3 := readProjectRow(t, db, pid)
	if row3.upstreamRemote.String != "github.com/acme/repo-renamed" {
		t.Errorf("non-empty update did not win: %q", row3.upstreamRemote.String)
	}
	// rootCommitSHA untouched by this call (ProjectIdentity{} zero for it).
	if row3.rootCommitSHA.String != "aaa111" {
		t.Errorf("unrelated field clobbered by partial update: %q", row3.rootCommitSHA.String)
	}
}

func TestUpsertProjectWithIdentity_EmptyInputEmptyHash(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi2", "", ProjectIdentity{})
	if err != nil {
		t.Fatalf("UpsertProjectWithIdentity: %v", err)
	}
	row := readProjectRow(t, db, pid)
	for name, v := range map[string]sql.NullString{
		"upstreamRemote":     row.upstreamRemote,
		"upstreamRemoteHash": row.upstreamRemoteHash,
		"remoteOwnerHash":    row.remoteOwnerHash,
		"upstreamOwnerHash":  row.upstreamOwnerHash,
		"rootCommitSHA":      row.rootCommitSHA,
		"rootCommitHash":     row.rootCommitHash,
		"fingerprint":        row.fingerprint,
		"fingerprintHash":    row.fingerprintHash,
	} {
		if v.Valid && v.String != "" {
			t.Errorf("%s = %q, want empty (never sha256(\"\"))", name, v.String)
		}
	}
}

func TestUpsertProjectWithIdentity_Idempotent(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	id := ProjectIdentity{
		UpstreamRemote:     "github.com/acme/repo",
		RemoteOwner:        "github.com/acme",
		RootCommitSHA:      "sha1",
		ContentFingerprint: "fp",
	}
	pid, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi3", "", id)
	if err != nil {
		t.Fatal(err)
	}
	row1 := readProjectRow(t, db, pid)

	if _, err := s.UpsertProjectWithIdentity(ctx, "/tmp/pi3", "", id); err != nil {
		t.Fatal(err)
	}
	row2 := readProjectRow(t, db, pid)

	if row1 != row2 {
		t.Errorf("re-running the identical identity changed the row: %+v -> %+v", row1, row2)
	}
}

func TestRootCommitNeedsCheck(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	t.Run("no_project_row_is_false", func(t *testing.T) {
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/never-seen")
		if err != nil {
			t.Fatal(err)
		}
		if needs {
			t.Error("a root path with no projects row should not need a check")
		}
	})

	pid, err := s.UpsertProject(ctx, "/tmp/rc1", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("never_checked_is_true", func(t *testing.T) {
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rc1")
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("a project never checked should need a check")
		}
	})

	t.Run("has_sha_is_false_regardless_of_checked_at", func(t *testing.T) {
		if _, err := db.ExecContext(ctx,
			`UPDATE projects SET root_commit_sha = 'x', root_commit_checked_at = NULL WHERE id = ?`, pid); err != nil {
			t.Fatal(err)
		}
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rc1")
		if err != nil {
			t.Fatal(err)
		}
		if needs {
			t.Error("a project with a known sha should never need a re-check")
		}
		// Reset for the following subtests.
		if _, err := db.ExecContext(ctx, `UPDATE projects SET root_commit_sha = '' WHERE id = ?`, pid); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("recently_checked_is_false", func(t *testing.T) {
		recent := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339Nano)
		if _, err := db.ExecContext(ctx,
			`UPDATE projects SET root_commit_sha = '', root_commit_checked_at = ? WHERE id = ?`, recent, pid); err != nil {
			t.Fatal(err)
		}
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rc1")
		if err != nil {
			t.Fatal(err)
		}
		if needs {
			t.Error("a project checked 1h ago should not need a re-check")
		}
	})

	t.Run("stale_checked_is_true", func(t *testing.T) {
		stale := time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)
		if _, err := db.ExecContext(ctx,
			`UPDATE projects SET root_commit_sha = '', root_commit_checked_at = ? WHERE id = ?`, stale, pid); err != nil {
			t.Fatal(err)
		}
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rc1")
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("a project checked 8 days ago should need a re-check (RootCommitRecheckInterval = 7d)")
		}
	})

	t.Run("unparsable_checked_at_fails_open_to_true", func(t *testing.T) {
		if _, err := db.ExecContext(ctx,
			`UPDATE projects SET root_commit_sha = '', root_commit_checked_at = 'garbage' WHERE id = ?`, pid); err != nil {
			t.Fatal(err)
		}
		needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rc1")
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("an unparsable checked_at should fail open toward rechecking")
		}
	})
}

func TestRecordRootCommitCheck(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/tmp/rcc1", "")
	if err != nil {
		t.Fatal(err)
	}

	// A failed exec (empty sha) must still stamp checked_at — that is the
	// entire point of the retry fence.
	if err := s.RecordRootCommitCheck(ctx, "/tmp/rcc1", ""); err != nil {
		t.Fatal(err)
	}
	row := readProjectRow(t, db, pid)
	if row.rootCommitSHA.Valid && row.rootCommitSHA.String != "" {
		t.Errorf("empty sha should not populate root_commit_sha, got %q", row.rootCommitSHA.String)
	}
	if !row.rootCommitChecked.Valid || row.rootCommitChecked.String == "" {
		t.Fatal("root_commit_checked_at must be stamped even on a failed check")
	}
	needs, err := s.RootCommitNeedsCheck(ctx, "/tmp/rcc1")
	if err != nil {
		t.Fatal(err)
	}
	if needs {
		t.Error("immediately after a check, needs-check should be false (within the 7-day fence)")
	}

	// A later success populates the sha and hash without disturbing
	// anything else.
	if err := s.RecordRootCommitCheck(ctx, "/tmp/rcc1", "cafef00d"); err != nil {
		t.Fatal(err)
	}
	row2 := readProjectRow(t, db, pid)
	if row2.rootCommitSHA.String != "cafef00d" {
		t.Errorf("rootCommitSHA = %q, want cafef00d", row2.rootCommitSHA.String)
	}
	if row2.rootCommitHash.String != sha256Hex("cafef00d") {
		t.Errorf("rootCommitHash mismatch: %q", row2.rootCommitHash.String)
	}
}

// TestIngest_LazyRootCommitResolver proves the Ingest-level wiring: a
// resolver set via SetRootCommitResolver runs exactly once per project
// per batch (gated by RootCommitNeedsCheck), its result is persisted, and
// a subsequent Ingest for the same project does not call it again.
func TestIngest_LazyRootCommitResolver(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	calls := 0
	s.SetRootCommitResolver(func(ctx context.Context, repoRoot string) (string, error) {
		calls++
		return "resolved-sha", nil
	})

	events := []models.ToolEvent{{
		SourceFile:    "f1",
		SourceEventID: "e1",
		SessionID:     "s1",
		ProjectRoot:   "/tmp/lazyrc1",
		Timestamp:     time.Now(),
		ActionType:    models.ActionUserPrompt,
		Tool:          "claude-code",
	}}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if calls != 1 {
		t.Fatalf("resolver called %d times on first ingest, want 1", calls)
	}

	var pid int64
	if err := db.QueryRow(`SELECT id FROM projects WHERE root_path = ?`, "/tmp/lazyrc1").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	row := readProjectRow(t, db, pid)
	if row.rootCommitSHA.String != "resolved-sha" {
		t.Errorf("rootCommitSHA = %q, want resolved-sha", row.rootCommitSHA.String)
	}

	// A second batch touching the same project must not re-invoke the
	// resolver: RootCommitNeedsCheck now sees a non-empty sha.
	events2 := []models.ToolEvent{{
		SourceFile:    "f1",
		SourceEventID: "e2",
		SessionID:     "s1",
		ProjectRoot:   "/tmp/lazyrc1",
		Timestamp:     time.Now(),
		ActionType:    models.ActionUserPrompt,
		Tool:          "claude-code",
	}}
	if _, err := s.Ingest(ctx, events2, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest (second batch): %v", err)
	}
	if calls != 1 {
		t.Errorf("resolver called %d times after second ingest, want still 1", calls)
	}
}

// TestIngest_NilRootCommitResolverNeverExecs proves the New() default
// (no resolver wired) never attempts the exec, so internal/store's test
// suite never depends on a git binary.
func TestIngest_NilRootCommitResolverNeverExecs(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{{
		SourceFile:    "f1",
		SourceEventID: "e1",
		SessionID:     "s1",
		ProjectRoot:   "/tmp/norc1",
		Timestamp:     time.Now(),
		ActionType:    models.ActionUserPrompt,
		Tool:          "claude-code",
	}}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var pid int64
	if err := db.QueryRow(`SELECT id FROM projects WHERE root_path = ?`, "/tmp/norc1").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	row := readProjectRow(t, db, pid)
	if row.rootCommitSHA.Valid && row.rootCommitSHA.String != "" {
		t.Errorf("expected no root commit without a wired resolver, got %q", row.rootCommitSHA.String)
	}
}

// TestUpsertSession_WorkspaceRoundTrip proves the session-level half of
// the identity bundle: workspace/workspace_hash/is_worktree persist, and
// a later write with empty/false values never clobbers them (the same
// backfill-on-touch idiom git_branch already uses).
func TestUpsertSession_WorkspaceRoundTrip(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/tmp/wsround", "")
	if err != nil {
		t.Fatal(err)
	}

	sess := models.Session{
		ID:         "sess-ws-1",
		ProjectID:  pid,
		Tool:       "claude-code",
		StartedAt:  time.Now(),
		Workspace:  "platform/services/payments",
		IsWorktree: true,
	}
	if err := s.UpsertSession(ctx, sess); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}

	var workspace, workspaceHash sql.NullString
	var isWorktree int
	readSession := func() {
		t.Helper()
		if err := db.QueryRow(
			`SELECT workspace, workspace_hash, is_worktree FROM sessions WHERE id = ?`, sess.ID,
		).Scan(&workspace, &workspaceHash, &isWorktree); err != nil {
			t.Fatalf("read session: %v", err)
		}
	}

	readSession()
	if workspace.String != "platform/services/payments" {
		t.Errorf("workspace = %q, want platform/services/payments", workspace.String)
	}
	if workspaceHash.String != sha256Hex("platform/services/payments") {
		t.Errorf("workspace_hash mismatch: %q", workspaceHash.String)
	}
	if isWorktree != 1 {
		t.Errorf("is_worktree = %d, want 1", isWorktree)
	}

	// A later write with an empty workspace and IsWorktree=false (e.g. a
	// token-event upsert that didn't carry the signal) must not clobber
	// either.
	if err := s.UpsertSession(ctx, models.Session{
		ID:        sess.ID,
		ProjectID: pid,
		Tool:      "claude-code",
		StartedAt: sess.StartedAt,
	}); err != nil {
		t.Fatalf("UpsertSession (empty follow-up): %v", err)
	}
	readSession()
	if workspace.String != "platform/services/payments" {
		t.Errorf("empty follow-up clobbered workspace: %q", workspace.String)
	}
	if isWorktree != 1 {
		t.Errorf("empty follow-up (IsWorktree=false) clobbered is_worktree: %d", isWorktree)
	}
}

// TestUpsertSession_WorkspaceEmptyNeverHashesToNonEmpty pins that a
// session at the repo root (Workspace == "") stores an equally empty hash
// — sha256Hex("") never silently becomes sha256("").
func TestUpsertSession_WorkspaceEmptyNeverHashesToNonEmpty(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/tmp/wsempty", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID:        "sess-ws-empty",
		ProjectID: pid,
		Tool:      "claude-code",
		StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	var workspaceHash sql.NullString
	if err := db.QueryRow(`SELECT workspace_hash FROM sessions WHERE id = ?`, "sess-ws-empty").Scan(&workspaceHash); err != nil {
		t.Fatal(err)
	}
	if workspaceHash.Valid && workspaceHash.String != "" {
		t.Errorf("workspace_hash = %q, want empty", workspaceHash.String)
	}
}

// errStore surfaces a canned error from RootCommitNeedsCheck's query path
// to prove maybeRunLazyRootCommit fails open rather than propagating it.
// It's exercised indirectly by closing the underlying *sql.DB before the
// call, which is the simplest way to force a query error without a mock.
func TestMaybeRunLazyRootCommit_FailsOpenOnStoreError(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	s.SetRootCommitResolver(func(ctx context.Context, repoRoot string) (string, error) {
		return "should-not-be-recorded", nil
	})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// Must not panic and must not return an error the caller has to
	// handle — Ingest's callers don't check maybeRunLazyRootCommit at all.
	s.maybeRunLazyRootCommit(ctx, "/tmp/closed-db")
}
