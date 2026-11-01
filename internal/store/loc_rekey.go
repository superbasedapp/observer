package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codexpatch"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// loc_rekey.go keys file_changes by the CHECKOUT-relative path (SHR-8, lane
// SHR-FOLLOWUPS): an edit inside a linked worktree hashes like the same
// file in the main checkout, so it joins the commit that carried it on the
// Projects page (commits hash repository-relative paths,
// internal/commitlog). internal/loc stays pure: the checkout-relative step
// reads the filesystem, so it runs here, at the store boundary, through the
// one seam git.CheckoutRelativePath, and only then hashes with
// loc.PathHash. An edit outside every linked worktree hashes exactly as
// before (a golden pins it).

// locPathHashes returns the file_path_hash of path in projectRoot and, when
// an earlier build stored it under a different key, that key (else "").
// Only a path in a project that has linked worktrees can differ, and only
// when it lies inside one of them; everything else takes the old
// loc.PathHash with no filesystem read beyond one stat.
//
// A relative path (a codex patch header, written relative to the session's
// working directory) is anchored on the project root, the main checkout,
// the way the raw header was read before (lane LEFT-SHARED, the SHR-8
// patch-header residual): when the anchored path lies inside a linked
// worktree (an in-tree `.worktrees/x/...` header, or `../wt/...` for an
// out-of-tree one) it hashes checkout-relative like the commit that carries
// it; a header that already names the checkout-relative path (a session
// whose working directory is the worktree's top level) hashes as before.
func locPathHashes(projectRoot, path string) (hash, legacy string) {
	// The root reaching here is canonicalProjectRoot's host spelling (the
	// 2026-10-21 wave translates a foreign `C:\Repo` root at ingest), while
	// the edit's own path may still be the foreign spelling the tool wrote.
	// Translate both the same way (pathnorm.NormalizeForeign leaves a
	// native path byte-for-byte unchanged), so a foreign edit inside its
	// project keeps the project-relative hash it had before (the plain-repo
	// golden's "windows case").
	projectRoot, path = pathnorm.NormalizeForeign(projectRoot), pathnorm.NormalizeForeign(path)
	old := loc.PathHash(projectRoot, path)
	p := strings.TrimSpace(path)
	if old == "" || projectRoot == "" || !git.HasLinkedWorktrees(projectRoot) {
		return old, ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(projectRoot, filepath.FromSlash(p))
	}
	rel := git.CheckoutRelativePath(projectRoot, p)
	if rel == "" || rel == git.RelativePath(projectRoot, p) || strings.HasPrefix(rel, "[external]/") {
		return old, ""
	}
	h := loc.PathHash("", rel)
	if h == "" || h == old {
		return old, ""
	}
	return h, old
}

// locHeaderBase is the directory an action's relative patch headers are
// relative to (lane LEFT2-SEC item R-024): a Codex patch header is written
// relative to the session's working directory, and the adapter stores the
// first header resolved there as the action's target, so the target's
// leading part beyond the header names that directory for every other
// relative header of the same envelope. "" (headers anchored on the
// project root, as before) when no relative path is the target's tail: an
// older row whose target is the raw header, a session at the root, or a
// shape with no headers.
func locHeaderBase(target string, stats []loc.FileStats) string {
	for _, fs := range stats {
		if base, ok := codexpatch.HeaderBase(target, fs.Path); ok {
			return base
		}
	}
	return ""
}

// rekeyFileChangeSQL moves one action row from its legacy key to its
// checkout-relative key, unless a row already holds the new key (then both
// stay: nothing is ever deleted).
const rekeyFileChangeSQL = `UPDATE file_changes SET file_path_hash = ?
	WHERE action_id = ? AND source = ? AND file_path_hash = ?
	AND NOT EXISTS (SELECT 1 FROM file_changes x WHERE x.action_id = ? AND x.source = ? AND x.file_path_hash = ?)`

// rekeyFileChangeTx applies rekeyFileChangeSQL in tx and reports whether a
// row moved.
func rekeyFileChangeTx(ctx context.Context, tx *sql.Tx, actionID int64, source, from, to string) (bool, error) {
	res, err := tx.ExecContext(ctx, rekeyFileChangeSQL, to, actionID, source, from, actionID, source, to)
	if err != nil {
		return false, fmt.Errorf("rekey file_changes row: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RekeyLOCOptions configures RekeyWorktreeFileChanges.
type RekeyLOCOptions struct {
	// Since restricts the pass to actions at or after this time.
	Since time.Time
	// Apply writes; false (the default) counts what would change.
	Apply bool
}

// RekeyLOCResult is what a re-key pass found, per table. Only file_changes
// holds an edit's path hash keyed by the project root (commit rows are
// already repository-relative), so it is the one table.
type RekeyLOCResult struct {
	ActionsScanned int `json:"actions_scanned"`
	// Sessions is how many sessions name a path inside a linked worktree.
	Sessions int `json:"sessions"`
	// Tables holds the per-table counts.
	Tables map[string]RekeyLOCTable `json:"tables"`
}

// RekeyLOCTable is one table's counts.
type RekeyLOCTable struct {
	// Rekeyed rows moved to the checkout-relative key (or, in a dry run,
	// that would move).
	Rekeyed int `json:"rekeyed"`
	// AlreadyKeyed rows already hold the new key (a second run, or a
	// re-ingest after the upgrade).
	AlreadyKeyed int `json:"already_keyed"`
	// Clashes are edits held under BOTH keys; both rows stay, nothing is
	// deleted.
	Clashes int `json:"clashes"`
	// NotCounted edits have no row under either key yet; `observer
	// backfill --loc` counts them under the new key.
	NotCounted int `json:"not_counted"`
}

// RekeyWorktreeFileChanges re-keys the file_changes rows of edits made
// inside a linked worktree to the checkout-relative path hash. It reads
// the actions through the rescan path's page loader (keyset on actions.id,
// short read transactions), re-derives each action's files with loc.Extract
// and the new key with locPathHashes, and moves each row in its own
// transaction. Dry run unless opts.Apply. Idempotent: a second run moves
// nothing. No loc.Version bump: rows outside a linked worktree are never
// read twice or touched.
func (s *Store) RekeyWorktreeFileChanges(ctx context.Context, opts RekeyLOCOptions) (RekeyLOCResult, error) {
	res := RekeyLOCResult{Tables: map[string]RekeyLOCTable{}}
	var t RekeyLOCTable
	sessions := map[string]bool{}
	hasWT := map[string]bool{}
	var cursor int64
	for {
		batch, err := s.loadLOCBackfillPage(ctx, cursor, locBackfillPage, BackfillLOCOptions{Since: opts.Since, Rescan: true})
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			break
		}
		cursor = batch[len(batch)-1].ID
		res.ActionsScanned += len(batch)
		for _, a := range batch {
			wt, seen := hasWT[a.ProjectRoot]
			if !seen {
				wt = git.HasLinkedWorktrees(a.ProjectRoot)
				hasWT[a.ProjectRoot] = wt
			}
			if !wt {
				continue
			}
			stats := loc.Extract(loc.Input{RawToolInput: a.RawToolInput, ActionType: a.ActionType, Target: a.Target, BeforeLines: -1})
			source := locSourceFor(a, stats)
			base := locHeaderBase(a.Target, stats)
			for _, fs := range stats {
				to, from := locPathHashes(a.ProjectRoot, codexpatch.AnchorHeader(base, fs.Path))
				if from == "" {
					continue
				}
				sessions[a.SessionID] = true
				if err := s.rekeyOne(ctx, a.ID, source, from, to, opts.Apply, &t); err != nil {
					return res, err
				}
			}
		}
	}
	res.Sessions = len(sessions)
	res.Tables["file_changes"] = t
	return res, nil
}

// rekeyOne classifies one edit's rows and, when applying, moves it in its
// own transaction.
func (s *Store) rekeyOne(ctx context.Context, actionID int64, source, from, to string, apply bool, t *RekeyLOCTable) error {
	has := func(hash string) (bool, error) {
		var n int
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM file_changes WHERE action_id = ? AND source = ? AND file_path_hash = ?`,
			actionID, source, hash).Scan(&n)
		return n > 0, err
	}
	old, err := has(from)
	if err != nil {
		return fmt.Errorf("store.RekeyWorktreeFileChanges: %w", err)
	}
	cur, err := has(to)
	if err != nil {
		return fmt.Errorf("store.RekeyWorktreeFileChanges: %w", err)
	}
	switch {
	case old && cur:
		t.Clashes++
		return nil
	case cur:
		t.AlreadyKeyed++
		return nil
	case !old:
		t.NotCounted++
		return nil
	}
	if !apply {
		t.Rekeyed++
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.RekeyWorktreeFileChanges: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	moved, err := rekeyFileChangeTx(ctx, tx, actionID, source, from, to)
	if err != nil {
		return fmt.Errorf("store.RekeyWorktreeFileChanges: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.RekeyWorktreeFileChanges: commit: %w", err)
	}
	if moved {
		t.Rekeyed++
	}
	return nil
}
