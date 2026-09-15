// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update.go is the ONE writer of the node's update tables (agent migration
// 105): `update_state`, the single-row current posture, and `update_events`,
// the local audit ledger `observer update history` reads.
//
// Both table names are in tests/invariant/privacy_test.go's forbidden-name
// set and must never appear inside internal/store/orgpush.go. What reaches an
// org server is the enum-only orgcontract.UpdatePostureRow, composed in the
// SIBLING file internal/store/updateposture.go and reached from the push seam
// by a FUNCTION CALL — the routing_summaries / file_changes arrangement. That
// is not decoration: `update_state` stores local paths (a rollback binary, a
// DB snapshot) and `update_events.detail` is free text, and those are exactly
// the two value classes ruling R10 keeps off the wire.
//
// The apply path (cmd/observer/update_apply.go) is a state machine whose only
// durable memory is the row below, because the process that started an apply
// may not be the process that finishes it. Everything a rollback needs — the
// previous binary, the pre-apply schema version, the snapshot path — is
// written HERE before the swap, while the old daemon is still alive to write
// it (§3.7 step 5).

// UpdateStateRow is the node's durable update state: update.NodeState (the
// shape W1 already defined and the JSON file already carried) plus the
// accepted manifest's canonical bytes.
//
// Keeping NodeState embedded rather than re-declaring twelve fields means the
// pure package stays the single owner of the vocabulary, and a new field
// lands in one place.
type UpdateStateRow struct {
	update.NodeState
	// ManifestJSON is the canonical bytes of the last ACCEPTED manifest, so
	// a restarted daemon can resume without a fetch. It is the org's own
	// signed document coming back, never node data going out.
	ManifestJSON string
}

// UpdateEventRow is one line of the node-local audit ledger.
type UpdateEventRow struct {
	ID              int64
	At              time.Time
	FromVersion     string
	ToVersion       string
	ManifestVersion int64
	State           update.State
	ErrorClass      update.ErrorClass
	// Detail is the human-readable reason and MAY contain a local path. It
	// is what makes the history usable and it is why this table never
	// leaves the node.
	Detail     string
	DurationMS int64
}

// LoadUpdateState reads the singleton row.
//
// Migration 105 inserts the row, so a missing row means a database from
// before 105 or a hand-edited one; the DEFAULT is returned rather than an
// error, because notify is fail-open (§2.4) and a node that has never seen a
// manifest is idle, not broken.
func (s *Store) LoadUpdateState(ctx context.Context) (UpdateStateRow, error) {
	const q = `
SELECT channel, last_manifest_version, last_manifest_json, last_manifest_seen_at,
       target_version, state, reason, error_class,
       previous_binary_path, previous_version, previous_schema_version,
       previous_db_backup_path, applying_started_at, applied_at, updated_at
  FROM update_state WHERE id = 1`
	var (
		row UpdateStateRow
		ch  string
		st  string
		rsn string
		ec  string
	)
	err := s.db.QueryRowContext(ctx, q).Scan(
		&ch, &row.LastManifestVersion, &row.ManifestJSON, &row.LastManifestSeenAt,
		&row.TargetVersion, &st, &rsn, &ec,
		&row.PreviousBinaryPath, &row.PreviousVersion, &row.PreviousSchemaVersion,
		&row.PreviousDBBackupPath, &row.ApplyingStartedAt, &row.AppliedAt, &row.UpdatedAt,
	)
	if err != nil {
		return UpdateStateRow{NodeState: update.DefaultNodeState()}, nil //nolint:nilerr // fail-open by design: see the doc comment.
	}
	row.Channel = update.Channel(ch)
	row.State = update.State(st)
	row.Reason = update.Reason(rsn)
	row.ErrorClass = update.ErrorClass(ec)
	if strings.TrimSpace(string(row.State)) == "" || !update.KnownState(row.State) {
		row.State = update.StateIdle
	}
	return row, nil
}

// SaveUpdateState writes the singleton row.
//
// It refuses an unknown state rather than storing one: the state column feeds
// the org board through the posture composer, and a value outside the closed
// vocabulary would arrive there as an enum nobody can render. A caller moves
// between states with update.Transition, which validates the EDGE; this
// validates the destination, so an illegal write fails at the seam either way.
func (s *Store) SaveUpdateState(ctx context.Context, row UpdateStateRow) error {
	if !update.KnownState(row.State) {
		return fmt.Errorf("store.SaveUpdateState: unknown state %q", row.State)
	}
	const q = `
UPDATE update_state SET
  channel = ?, last_manifest_version = ?, last_manifest_json = ?,
  last_manifest_seen_at = ?, target_version = ?, state = ?, reason = ?,
  error_class = ?, previous_binary_path = ?, previous_version = ?,
  previous_schema_version = ?, previous_db_backup_path = ?,
  applying_started_at = ?, applied_at = ?, updated_at = ?
WHERE id = 1`
	res, err := s.db.ExecContext(ctx, q,
		string(row.Channel), row.LastManifestVersion, row.ManifestJSON,
		row.LastManifestSeenAt, row.TargetVersion, string(row.State), string(row.Reason),
		string(row.ErrorClass), row.PreviousBinaryPath, row.PreviousVersion,
		row.PreviousSchemaVersion, row.PreviousDBBackupPath,
		row.ApplyingStartedAt, row.AppliedAt, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store.SaveUpdateState: %w", err)
	}
	// A database migrated to 105 always has the row. If it does not (a
	// hand-edited file), create it rather than silently discarding the write.
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO update_state (id) VALUES (1)`); err != nil {
			return fmt.Errorf("store.SaveUpdateState: restore singleton: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, q,
			string(row.Channel), row.LastManifestVersion, row.ManifestJSON,
			row.LastManifestSeenAt, row.TargetVersion, string(row.State), string(row.Reason),
			string(row.ErrorClass), row.PreviousBinaryPath, row.PreviousVersion,
			row.PreviousSchemaVersion, row.PreviousDBBackupPath,
			row.ApplyingStartedAt, row.AppliedAt, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			return fmt.Errorf("store.SaveUpdateState: %w", err)
		}
	}
	return nil
}

// TransitionUpdateState moves the node from its current state to next,
// validating the edge against update.CanTransition, and appends an event.
//
// This is the seam every apply step uses instead of assigning a state field:
// an impossible sequence then fails where it happens rather than surfacing
// as a nonsensical row on the org board two push cycles later.
func (s *Store) TransitionUpdateState(ctx context.Context, next update.State, mutate func(*UpdateStateRow), ev UpdateEventRow) error {
	cur, err := s.LoadUpdateState(ctx)
	if err != nil {
		return err
	}
	moved, err := update.Transition(cur.State, next)
	if err != nil {
		return fmt.Errorf("store.TransitionUpdateState: %w", err)
	}
	cur.State = moved
	if mutate != nil {
		mutate(&cur)
	}
	if err := s.SaveUpdateState(ctx, cur); err != nil {
		return err
	}
	if ev.State == "" {
		ev.State = moved
	}
	if ev.FromVersion == "" {
		ev.FromVersion = cur.PreviousVersion
	}
	if ev.ToVersion == "" {
		ev.ToVersion = cur.TargetVersion
	}
	if ev.ManifestVersion == 0 {
		ev.ManifestVersion = cur.LastManifestVersion
	}
	return s.AppendUpdateEvent(ctx, ev)
}

// AppendUpdateEvent adds one line to the node-local ledger.
func (s *Store) AppendUpdateEvent(ctx context.Context, ev UpdateEventRow) error {
	_, err := s.AppendUpdateEventID(ctx, ev)
	return err
}

// AppendUpdateEventID appends one ledger line and returns its row id.
//
// The id is what a detached apply hands back to its caller: the dashboard
// answers 202 with it, and `observer update history` is where the operator
// follows the same row to its terminal state. AppendUpdateEvent is the same
// write for the callers that have no use for the id.
func (s *Store) AppendUpdateEventID(ctx context.Context, ev UpdateEventRow) (int64, error) {
	at := ev.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	const q = `
INSERT INTO update_events (at, from_version, to_version, manifest_version, state, error_class, detail, duration_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := s.db.ExecContext(ctx, q,
		at.UTC().Format(time.RFC3339Nano), ev.FromVersion, ev.ToVersion, ev.ManifestVersion,
		string(ev.State), string(ev.ErrorClass), ev.Detail, ev.DurationMS,
	)
	if err != nil {
		return 0, fmt.Errorf("store.AppendUpdateEvent: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		// The row IS written; only its id is unknown. Reporting an error here
		// would make a caller treat a recorded event as a lost one.
		return 0, nil //nolint:nilerr // see the comment: the write succeeded.
	}
	return id, nil
}

// SaveVerifiedManifest is the ONE writer of the node's memory of a manifest
// the update rail has VERIFIED (§3.4's last_manifest_json /
// last_manifest_seen_at, agent migration 105).
//
// It exists because W3 shipped the columns and nothing ever wrote them: the
// org client cached the verify outcome in memory only, so a notify-only node
// (the BYO default, auto_apply off) showed `idle` with no target on its own
// Health card, on the banner, on the org board and in `observer update
// status`, and `observer update apply` with the daemon stopped refused with
// "this node holds no accepted manifest" — permanently, not just until the
// next fetch. A restart also reset rule 6's replay memory, which migration
// 105's comment had promised to make durable.
//
// It writes through TransitionUpdateState when the state actually moves, so
// the transition table still validates the edge, and falls back to a direct
// save when the destination equals the current state (re-verifying the same
// manifest must not be an illegal available -> available move).
//
// manifestJSON is the org's own CANONICAL SIGNED BYTES coming back — never
// node data going out.
func (s *Store) SaveVerifiedManifest(ctx context.Context, in VerifiedManifest) error {
	if !update.KnownState(in.State) {
		return fmt.Errorf("store.SaveVerifiedManifest: unknown state %q", in.State)
	}
	seenAt := in.SeenAt
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	mutate := func(row *UpdateStateRow) {
		if in.Channel != "" {
			row.Channel = in.Channel
		}
		if in.ManifestVersion > 0 {
			row.LastManifestVersion = in.ManifestVersion
		}
		if strings.TrimSpace(in.ManifestJSON) != "" {
			row.ManifestJSON = in.ManifestJSON
		}
		row.LastManifestSeenAt = seenAt.UTC().Format(time.RFC3339)
		row.TargetVersion = in.TargetVersion
		row.Reason = in.Reason
		row.ErrorClass = ""
	}
	cur, err := s.LoadUpdateState(ctx)
	if err != nil {
		return err
	}
	// An apply in flight owns the row. A manifest fetch that landed
	// mid-handshake must not rewrite target_version underneath it — that is
	// the value the rollback decision and the child's self-check both read.
	if cur.State == update.StateApplying || cur.State == update.StateDownloading ||
		cur.State == update.StateVerified {
		return nil
	}
	if cur.State == in.State {
		row := cur
		mutate(&row)
		return s.SaveUpdateState(ctx, row)
	}
	ev := UpdateEventRow{
		State: in.State, ToVersion: in.TargetVersion, ManifestVersion: in.ManifestVersion,
		Detail: in.Detail,
	}
	err = s.TransitionUpdateState(ctx, in.State, mutate, ev)
	if err == nil || in.State == update.StateAvailable {
		return err
	}
	// Re-arm through `available` when the direct edge is not legal — the same
	// two-step moveUpdateState uses, for the same reason. Every terminal state
	// can reach `available` precisely so a LATER manifest re-arms a node that
	// already finished (or failed) an apply, and `applied -> blocked` is
	// exactly that case: the node applied, then the org published something
	// this platform has no artifact for.
	if rearm := s.TransitionUpdateState(ctx, update.StateAvailable, nil, UpdateEventRow{
		State: update.StateAvailable, Detail: "re-armed: a newer manifest was verified",
	}); rearm != nil {
		return err
	}
	return s.TransitionUpdateState(ctx, in.State, mutate, ev)
}

// VerifiedManifest is one verification outcome, durably recorded.
type VerifiedManifest struct {
	// Channel / ManifestVersion / TargetVersion identify the document.
	Channel         update.Channel
	ManifestVersion int64
	TargetVersion   string
	// ManifestJSON is the canonical signed bytes, so a restarted daemon can
	// apply without a fetch. Empty on a rule 6-9 outcome that produced a
	// posture but no usable document.
	ManifestJSON string
	// State / Reason are what the node now reports.
	State  update.State
	Reason update.Reason
	// SeenAt is when the fetch verified; Detail is the ledger line.
	SeenAt time.Time
	Detail string
}

// LoadUpdateEvents returns the ledger newest-first. A non-positive limit
// returns the default page.
func (s *Store) LoadUpdateEvents(ctx context.Context, limit int) ([]UpdateEventRow, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
SELECT id, at, from_version, to_version, manifest_version, state, error_class, detail, duration_ms
  FROM update_events ORDER BY at DESC, id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("store.LoadUpdateEvents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []UpdateEventRow
	for rows.Next() {
		var (
			r  UpdateEventRow
			at string
			st string
			ec string
		)
		if err := rows.Scan(&r.ID, &at, &r.FromVersion, &r.ToVersion, &r.ManifestVersion, &st, &ec, &r.Detail, &r.DurationMS); err != nil {
			return nil, fmt.Errorf("store.LoadUpdateEvents: scan: %w", err)
		}
		r.At = parseUpdateTime(at)
		r.State = update.State(st)
		r.ErrorClass = update.ErrorClass(ec)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadUpdateEvents: %w", err)
	}
	return out, nil
}

// parseUpdateTime tolerates both precisions the ledger has ever written.
func parseUpdateTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// CloseDatabase closes the handle this Store holds.
//
// It lives HERE, in the update file, because the update path is the only
// caller and the reason is specific to it: restoring a pre-apply snapshot
// renames the live database aside, and a process that keeps its handle open
// goes on writing to an orphaned inode while every hook process (which opens
// by path) writes to the restored file. Closing first is what bounds the
// discarded window to the drain-plus-handshake ruling R15 promises.
//
// Every other component's handle on the same *sql.DB is closed by this too,
// which is exactly why the only caller is a rollback that ends with the
// process exiting.
func (s *Store) CloseDatabase() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// SchemaVersion reports the agent DB's migration high-water mark.
//
// It exists because migrations run automatically INSIDE db.Open
// (internal/db/db.go), so this number is UNRECOVERABLE once a new binary has
// booted. The old daemon records it into update_state.previous_schema_version
// before the swap; without it, a rollback across a migration cannot tell
// whether restoring an older binary is safe.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	v, err := db.Version(ctx, s.db)
	if err != nil {
		return 0, fmt.Errorf("store.SchemaVersion: %w", err)
	}
	return v, nil
}

// SnapshotDatabase writes a consistent pre-apply snapshot to dest.
//
// It delegates to db.BackupInto (VACUUM INTO), the SAME primitive
// `observer db backup` and the org-server preflight use — one owner for
// "make a consistent copy of a live SQLite database", so a fix to WAL
// handling or headroom is a fix everywhere. It is taken while the node is
// quiesced and immediately before the swap, so the window a failed rollback
// discards is a drain plus a handshake, not a session (ruling R15).
func (s *Store) SnapshotDatabase(ctx context.Context, dest string) error {
	if strings.TrimSpace(dest) == "" {
		return fmt.Errorf("store.SnapshotDatabase: destination path required")
	}
	// A snapshot from a previous, abandoned apply must not silently satisfy
	// this one: BackupInto refuses an existing destination, so remove ours
	// deliberately rather than inheriting stale bytes as a rollback target.
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store.SnapshotDatabase: clearing %s: %w", dest, err)
	}
	if err := db.BackupInto(ctx, s.db, dest); err != nil {
		return fmt.Errorf("store.SnapshotDatabase: %w", err)
	}
	return nil
}

// PruneUpdateArtifacts deletes rollback binaries, staged downloads and DB
// snapshots older than keepDays under stateDir, EXCEPT the paths the current
// state row still names as its rollback target.
//
// The exception is the whole point. `keep_previous_days` is a retention
// policy, not a garbage collector, and deleting the binary or the snapshot a
// live update_state row points at would turn a recoverable rollback into the
// brick this feature exists to prevent. A non-positive keepDays disables
// pruning entirely.
func (s *Store) PruneUpdateArtifacts(ctx context.Context, stateDir string, keepDays int) (int, error) {
	if keepDays <= 0 || strings.TrimSpace(stateDir) == "" {
		return 0, nil
	}
	cur, err := s.LoadUpdateState(ctx)
	if err != nil {
		return 0, err
	}
	keep := map[string]bool{}
	for _, p := range []string{cur.PreviousBinaryPath, cur.PreviousDBBackupPath} {
		if strings.TrimSpace(p) != "" {
			keep[filepath.Clean(p)] = true
		}
	}
	cutoff := time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour)
	removed := 0
	// Only the two directories this feature writes into are swept, and only
	// their direct entries. A recursive walk over an operator-chosen
	// state_dir is a delete loop pointed at a path we do not own.
	for _, dir := range []string{stateDir, filepath.Join(stateDir, "rollback")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := filepath.Clean(filepath.Join(dir, e.Name()))
			if keep[path] {
				continue
			}
			if !isPrunableUpdateArtifact(e.Name(), dir == stateDir) {
				continue
			}
			info, err := e.Info()
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			var rmErr error
			if e.IsDir() {
				rmErr = os.RemoveAll(path)
			} else {
				rmErr = os.Remove(path)
			}
			if rmErr == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// isPrunableUpdateArtifact is the name allow-list the sweep walks. Naming
// what MAY be deleted, rather than what may not, is what keeps an operator's
// own file in state_dir safe from a retention pass.
func isPrunableUpdateArtifact(name string, topLevel bool) bool {
	if !topLevel {
		// Inside state_dir/rollback everything is ours: preserved binaries.
		return true
	}
	switch {
	case strings.HasPrefix(name, "preupgrade-") && strings.HasSuffix(name, ".db"):
		return true
	case looksLikeVersionDirName(name):
		// A per-version staging directory (state_dir/<version>/...).
		return true
	default:
		return false
	}
}

// looksLikeVersionDirName reports whether name is one of OUR per-version
// staging directories ("v1.33.0", "v1.33.0-rc.1").
//
// A one-letter "starts with v" prefix was too broad for a delete loop pointed
// at an operator-chosen state_dir: `vault/`, `venv/` and `vendor/` all match
// it. The shape is what identifies the directory, so the shape is what the
// allow-list tests.
func looksLikeVersionDirName(name string) bool {
	rest := strings.TrimPrefix(name, "v")
	if len(rest) < 3 || rest[0] < '0' || rest[0] > '9' {
		return false
	}
	return strings.Contains(rest, ".")
}
