package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// PostWrite is one file write the store ingested, reported to the security
// post-write seam (security plan section 5.3, "The post-write seam"). It
// carries the session, the action id, the project root and the normalized
// project-relative path the adapter reported, nothing else: file_changes
// deliberately holds no readable path or content, and this seam does not
// change that. The consumer re-opens the file itself.
type PostWrite struct {
	SessionID   string
	ActionID    int64
	ProjectRoot string
	// Path is project-relative, slash-separated, never escaping the root.
	// For a write in an out-of-tree linked worktree it is the checkout's
	// sighting key (WorktreeSightingPath): the file lives under Checkout.
	Path string
	// Checkout is the top level of the out-of-tree linked worktree the
	// write landed in, and CheckoutPath the file's path there
	// (slash-separated); both "" for a write under ProjectRoot (lane
	// LEFT-SEC, SECP-25 residual f).
	Checkout     string
	CheckoutPath string
}

// worktreeSightingPrefix opens an out-of-tree linked worktree's sighting
// key. The brackets can never begin a real project-relative path the
// adapters store (a bracket path is the old "[external]/..." form, which
// is never reported), so a key never names a file in the main checkout.
const worktreeSightingPrefix = "[worktree:"

// WorktreeSightingKey is the per-checkout key of an out-of-tree linked
// worktree: "[worktree:<16 hex of sha256(the cleaned checkout path)>]".
func WorktreeSightingKey(checkout string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(checkout)))
	return worktreeSightingPrefix + hex.EncodeToString(sum[:8]) + "]"
}

// WorktreeSightingPath is the sighting path of rel (slash-separated) in the
// out-of-tree checkout: its key, a slash, rel.
func WorktreeSightingPath(checkout, rel string) string {
	return WorktreeSightingKey(checkout) + "/" + rel
}

// SplitWorktreeSighting splits a sighting path into its checkout key and
// the path in that checkout; ok is false for any other path.
func SplitWorktreeSighting(p string) (key, rel string, ok bool) {
	if !strings.HasPrefix(p, worktreeSightingPrefix) {
		return "", "", false
	}
	key, rel, ok = strings.Cut(p, "/")
	if !ok || !strings.HasSuffix(key, "]") || len(key) != len(worktreeSightingPrefix)+17 || rel == "" {
		return "", "", false
	}
	return key, rel, true
}

// WorktreeCheckoutFor finds the linked worktree of the repository at root
// whose sighting key is key (the minute rescan reopens the file there); ok
// is false when no listed worktree has it (removed, or never one of root's).
func WorktreeCheckoutFor(root, key string) (string, bool) {
	if root == "" || key == "" {
		return "", false
	}
	for _, dir := range worktreeLayouts.get(root).checkouts {
		if WorktreeSightingKey(dir) == key {
			return dir, true
		}
	}
	return "", false
}

// WorktreeSightingGone reports whether the out-of-tree worktree a sighting
// key names is provably gone from the repository at root, so a sighting
// at it may close as deleted (lane LEFT-SEC audit F1): root's linked
// worktree admin entries were read whole, fresh from disk (no unreadable
// gitdir, no checkout off disk, nothing left past the 200-checkout cap;
// git.ListLinkedWorktrees Complete) and no entry points to a checkout with
// that key. Any partial read answers false: the sighting stays open.
func WorktreeSightingGone(root, key string) bool {
	return worktreeSightingGone(root, key, maxLayoutCheckouts)
}

func worktreeSightingGone(root, key string, max int) bool {
	if root == "" || key == "" {
		return false
	}
	l := git.ListLinkedWorktrees(root, max)
	if !l.Complete {
		return false
	}
	for _, dir := range l.Pointed {
		if WorktreeSightingKey(dir) == key {
			return false
		}
	}
	return true
}

// outOfTreeCheckout returns the linked worktree checkout of root that holds
// the absolute path p when that checkout is outside root, with p's path in
// it.
func outOfTreeCheckout(root, p string) (checkout, rel string, ok bool) {
	if root == "" || p == "" {
		return "", "", false
	}
	for _, dir := range worktreeLayouts.get(root).checkouts {
		if _, in := underDir(filepath.Clean(root), filepath.Clean(dir)); in {
			continue // an in-tree worktree is reported under root
		}
		if r, in := underDir(dir, filepath.Clean(p)); in && r != "." {
			return dir, r, true
		}
	}
	return "", "", false
}

// PostWriteSink receives post-writes. It must not block: the consumer
// queues (internal/secpostwrite is bounded and deduplicating).
type PostWriteSink func(PostWrite)

// SetPostWriteSink wires the post-write seam (set from the cmd layer, like
// SetCacheEngine). nil disables it.
func (s *Store) SetPostWriteSink(fn PostWriteSink) { s.postWriteSink = fn }

// postWriteActions are the action types that write a file.
var postWriteActions = map[string]bool{
	models.ActionWriteFile: true,
	models.ActionEditFile:  true,
}

// notifyPostWrites reports the batch's inserted, successful writes.
func (s *Store) notifyPostWrites(actions []models.Action, projectIDs map[string]int64) {
	if s.postWriteSink == nil || len(actions) == 0 {
		return
	}
	roots := make(map[int64]string, len(projectIDs))
	for root, id := range projectIDs {
		roots[id] = root
	}
	for i := range actions {
		a := &actions[i]
		if a.ID == 0 || !a.Success || !postWriteActions[a.ActionType] {
			continue
		}
		root := roots[a.ProjectID]
		w, ok := PostWriteFor(root, a.Target, a.RawToolInput)
		if !ok {
			continue
		}
		w.SessionID, w.ActionID = a.SessionID, a.ID
		s.postWriteSink(w)
	}
}

// PostWriteFor is the reported write for a stored target whose stored form
// may be checkout-independent (PT-39): a write into a linked worktree is
// reported at its real place under root (an in-tree worktree's
// `.worktrees/x/pkg/a.go`, as before the checkout path seam), so the
// scanner never reads the main checkout's copy for it; a write in an
// out-of-tree linked worktree of root (which used to be skipped; lane
// LEFT-SEC, SECP-25 residual f) is reported under that checkout with its
// per-checkout sighting key as Path. The post-write scan reads the file in
// that checkout, and the minute rescan of that checkout
// (WorktreeCheckoutFor) is what closes the sighting.
func PostWriteFor(root, target, rawInput string) (PostWrite, bool) {
	if p, ok := checkoutDiskPath(root, target, rawInput); ok {
		if rel, ok := projectRelative(root, p); ok {
			return PostWrite{ProjectRoot: root, Path: rel}, true
		}
		if dir, rel, ok := outOfTreeCheckout(root, p); ok {
			return PostWrite{ProjectRoot: root, Path: WorktreeSightingPath(dir, rel), Checkout: dir, CheckoutPath: rel}, true
		}
		return PostWrite{}, false
	}
	rel, ok := projectRelative(root, target)
	if !ok {
		return PostWrite{}, false
	}
	return PostWrite{ProjectRoot: root, Path: rel}, true
}

// projectRelative normalizes target to a slash-separated path under root;
// ok is false for an empty target, a missing root, or a path outside root.
func projectRelative(root, target string) (string, bool) {
	if root == "" || strings.TrimSpace(target) == "" {
		return "", false
	}
	p := target
	if !filepath.IsAbs(p) && !rootedPath(p) {
		p = filepath.Join(root, p)
	}
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// rootedPath reports whether p begins with a path separator. On Linux and
// macOS that is exactly filepath.IsAbs. On Windows a rooted path without a
// drive ("\etc\passwd", "/tmp/x") is not IsAbs, but it names a place from the
// root of the current drive, never one under the project, so it must not be
// joined onto root: that turned "/etc/passwd" into the in-project
// "etc/passwd". filepath.Rel then places it under root or refuses it.
func rootedPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, string(filepath.Separator))
}

// MaxActionID returns the highest action id stored (0 for none): the
// post-write feed's starting watermark, so a daemon start never re-scans
// the whole history.
func (s *Store) MaxActionID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM actions`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store.MaxActionID: %w", err)
	}
	return id.Int64, nil
}

// PostWritesAfter returns the successful file writes stored with an id
// above afterID, oldest first, at most limit, and the highest id read
// (afterID when none). It reads the actions table, so a write ingested by
// any writer is seen once: the daemon's watcher, the API proxy, and the
// hook process, whose rows the daemon's watcher later skips as
// duplicates (security plan section 5.3, "The post-write seam"; lane
// SEC-C2). The path is normalized like notifyPostWrites does; a write
// outside its project root is skipped.
func (s *Store) PostWritesAfter(ctx context.Context, afterID int64, limit int) ([]PostWrite, int64, error) {
	if limit <= 0 {
		limit = 256
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.session_id, COALESCE(p.root_path, ''), COALESCE(a.target, '')
		FROM actions a JOIN projects p ON p.id = a.project_id
		WHERE a.id > ? AND a.success = 1 AND a.action_type IN (?, ?)
		ORDER BY a.id LIMIT ?`, afterID, models.ActionWriteFile, models.ActionEditFile, limit)
	if err != nil {
		return nil, afterID, fmt.Errorf("store.PostWritesAfter: %w", err)
	}
	defer rows.Close()
	type row struct {
		id                    int64
		session, root, target string
	}
	var got []row
	last := afterID
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.session, &r.root, &r.target); err != nil {
			return nil, afterID, fmt.Errorf("store.PostWritesAfter: scan: %w", err)
		}
		last = r.id
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		return nil, afterID, fmt.Errorf("store.PostWritesAfter: %w", err)
	}
	// Close before the per-row reads below (one connection may serve both).
	rows.Close()
	var out []PostWrite
	for _, r := range got {
		raw := ""
		if git.HasLinkedWorktrees(r.root) && r.target != "" && !filepath.IsAbs(r.target) {
			// The raw input is read only where the stored target can name
			// more than one checkout (a write's input may hold the file).
			if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(raw_tool_input, '') FROM actions WHERE id = ?`, r.id).Scan(&raw); err != nil {
				return nil, afterID, fmt.Errorf("store.PostWritesAfter: raw input: %w", err)
			}
		}
		w, ok := PostWriteFor(r.root, r.target, raw)
		if !ok {
			continue
		}
		w.SessionID, w.ActionID = r.session, r.id
		out = append(out, w)
	}
	return out, last, nil
}
