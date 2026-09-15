package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestSelectUnpushedSince_IdentityV2HashesShipByDefault pins the Project
// Identity Resolver v2 wire posture (docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
// §3.2): in the DEFAULT metadata-only ShareOptions, the six new hash columns
// (four on projects, one on sessions, plus the worktree bool) ship, while
// the two raw counterparts (git_upstream_remote, workspace) stay empty.
func TestSelectUnpushedSince_IdentityV2HashesShipByDefault(t *testing.T) {
	s, db := newTestStore(t)
	pid := seedPushData(t, s, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		`UPDATE projects SET
		    git_upstream_remote = 'git@example.com:acme/upstream.git',
		    git_upstream_remote_hash = 'sha256:upstream-remote-hash',
		    git_remote_owner_hash = 'sha256:remote-owner-hash',
		    git_upstream_owner_hash = 'sha256:upstream-owner-hash',
		    root_commit_hash = 'sha256:root-commit-hash',
		    content_fingerprint_hash = 'sha256:content-fingerprint-hash'
		 WHERE id = ?`, pid); err != nil {
		t.Fatalf("stuff project identity v2 columns: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE sessions SET workspace = 'services/payments', workspace_hash = 'sha256:workspace-hash', is_worktree = 1
		 WHERE id = 's1'`); err != nil {
		t.Fatalf("stuff session identity v2 columns: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.Sessions) != 1 {
		t.Fatalf("expected 1 session row, got %d", len(batch.Sessions))
	}
	r := batch.Sessions[0]

	// (a) hashes ship in the default metadata-only mode.
	if r.GitUpstreamRemoteHash != "sha256:upstream-remote-hash" {
		t.Errorf("GitUpstreamRemoteHash = %q, want the hash", r.GitUpstreamRemoteHash)
	}
	if r.GitRemoteOwnerHash != "sha256:remote-owner-hash" {
		t.Errorf("GitRemoteOwnerHash = %q, want the hash", r.GitRemoteOwnerHash)
	}
	if r.GitUpstreamOwnerHash != "sha256:upstream-owner-hash" {
		t.Errorf("GitUpstreamOwnerHash = %q, want the hash", r.GitUpstreamOwnerHash)
	}
	if r.RootCommitHash != "sha256:root-commit-hash" {
		t.Errorf("RootCommitHash = %q, want the hash", r.RootCommitHash)
	}
	if r.ContentFingerprintHash != "sha256:content-fingerprint-hash" {
		t.Errorf("ContentFingerprintHash = %q, want the hash", r.ContentFingerprintHash)
	}
	if r.WorkspaceHash != "sha256:workspace-hash" {
		t.Errorf("WorkspaceHash = %q, want the hash", r.WorkspaceHash)
	}
	if !r.IsWorktree {
		t.Errorf("IsWorktree = false, want true")
	}

	// (b) the two raws are empty in the default mode.
	if r.GitUpstreamRemote != "" {
		t.Errorf("GitUpstreamRemote = %q, want empty in metadata-only mode", r.GitUpstreamRemote)
	}
	if r.Workspace != "" {
		t.Errorf("Workspace = %q, want empty in metadata-only mode", r.Workspace)
	}
}

// TestSelectUnpushedSince_IdentityV2RawsShipUnderFullContent pins (c): the
// two raw resolver-v2 fields ship only under ShareOptions.FullContent.
func TestSelectUnpushedSince_IdentityV2RawsShipUnderFullContent(t *testing.T) {
	s, db := newTestStore(t)
	pid := seedPushData(t, s, db)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx,
		`UPDATE projects SET git_upstream_remote = 'git@example.com:acme/upstream.git' WHERE id = ?`, pid); err != nil {
		t.Fatalf("stuff project git_upstream_remote: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE sessions SET workspace = 'services/payments' WHERE id = 's1'`); err != nil {
		t.Fatalf("stuff session workspace: %v", err)
	}

	batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.Sessions) != 1 {
		t.Fatalf("expected 1 session row, got %d", len(batch.Sessions))
	}
	r := batch.Sessions[0]
	if r.GitUpstreamRemote != "git@example.com:acme/upstream.git" {
		t.Errorf("GitUpstreamRemote = %q, want raw value under FullContent", r.GitUpstreamRemote)
	}
	if r.Workspace != "services/payments" {
		t.Errorf("Workspace = %q, want raw value under FullContent", r.Workspace)
	}
}

// TestSelectUnpushedSince_IdentityV2PreImagesNeverShip pins (d): the raw
// pre-image columns root_commit_sha and content_fingerprint never appear in
// the marshalled batch bytes, in EITHER share mode — only their hashes leave
// the node, per migration 102's privacy header.
func TestSelectUnpushedSince_IdentityV2PreImagesNeverShip(t *testing.T) {
	s, db := newTestStore(t)
	pid := seedPushData(t, s, db)
	ctx := context.Background()

	const rootSHA = "deadbeefcafef00ddeadbeefcafef00ddeadbeef"
	const fingerprint = "SECRET_CONTENT_FINGERPRINT_PREIMAGE"
	if _, err := db.ExecContext(ctx,
		`UPDATE projects SET root_commit_sha = ?, content_fingerprint = ? WHERE id = ?`,
		rootSHA, fingerprint, pid); err != nil {
		t.Fatalf("stuff project pre-image columns: %v", err)
	}

	for _, share := range []ShareOptions{{}, {FullContent: true}} {
		batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince(%+v): %v", share, err)
		}
		b, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("marshal batch: %v", err)
		}
		raw := string(b)
		if strings.Contains(raw, rootSHA) {
			t.Errorf("[%+v] root_commit_sha pre-image leaked into the push payload", share)
		}
		if strings.Contains(raw, fingerprint) {
			t.Errorf("[%+v] content_fingerprint pre-image leaked into the push payload", share)
		}
	}
}
