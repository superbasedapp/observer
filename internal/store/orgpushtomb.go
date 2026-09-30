package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Org push DELETE propagation (agent migration 141, lane R2-TOMB).
//
// Migration 141's delete triggers record, for every CORRECTION delete of an
// already-eligible cursor-wire row, the row's wire identity in
// org_push_deletions with its own change sequence; node-local ageing
// (internal/retention, under db.WithRetentionDeletes) records nothing. The
// push ships queued tombstones as orgcontract.PushDeletion (NodeRev = the
// sequence at the delete) and the org deletes its copy only when the copy is
// older. `observer org resync --deletions` additionally queues per-session
// MANIFESTS (org_push_manifests) that heal rows deleted before 141.
//
// This file owns both node-local tables; orgpush.go names neither (the
// privacy sentinel forbids it there) and reaches them only through the
// functions below.

// pushDeletionRowCap bounds the tombstones one push ships.
const pushDeletionRowCap = 2000

// pushDeletionScanCap bounds one settle pass over the tombstone queue.
const pushDeletionScanCap = 2000

// pushManifestCap bounds the session manifests one push ships.
const pushManifestCap = 50

// deletionRow is one queued tombstone.
type deletionRow struct {
	seq, rowID int64
	projectID  sql.NullInt64
	tbl        string
	k1, k2, k3 sql.NullString
}

// wire converts a queued tombstone to its wire shape. The source-file key is
// always the HASH (the raw path never crosses in a tombstone, whatever the
// share posture): the node's stored hash, or the hash of the stored path for
// a row written before the hash column existed.
func (d deletionRow) wire() orgcontract.PushDeletion {
	out := orgcontract.PushDeletion{Table: d.tbl, NodeRev: d.seq}
	switch d.tbl {
	case orgcontract.DeletionSessions:
		out.SessionID = d.k1.String
	case orgcontract.DeletionActions, orgcontract.DeletionTokenUsage:
		out.SourceEventID = d.k2.String
		out.SourceFileHash = d.k3.String
		if out.SourceFileHash == "" {
			out.SourceFileHash = sha256Hex(d.k1.String)
		}
	case orgcontract.DeletionAPITurns:
		out.SessionID = d.k1.String
		out.RequestID = d.k2.String
		out.Timestamp = d.k3.String
	}
	return out
}

// deletionTwins returns the ids of live rows that carry a queued tombstone's
// wire identity - a row re-inserted under the same key (a squatter evicted
// then rewritten), or a duplicate deleted beside a surviving twin that shares
// the key the org dedups by.
func (s *Store) deletionTwins(ctx context.Context, d deletionRow) ([]int64, error) {
	var (
		q    string
		args []any
	)
	switch d.tbl {
	case orgcontract.DeletionSessions:
		q, args = `SELECT rowid FROM sessions WHERE id = ?`, []any{d.k1}
	case orgcontract.DeletionActions:
		q, args = `SELECT id FROM actions WHERE source_file IS ? AND source_event_id IS ?`, []any{d.k1, d.k2}
	case orgcontract.DeletionTokenUsage:
		q, args = `SELECT id FROM token_usage WHERE source_file IS ? AND source_event_id IS ?`, []any{d.k1, d.k2}
	case orgcontract.DeletionAPITurns:
		if d.k2.String != "" {
			q, args = `SELECT id FROM api_turns WHERE request_id = ? AND timestamp = ?`, []any{d.k2.String, d.k3.String}
		} else {
			q, args = `SELECT id FROM api_turns WHERE session_id IS ? AND COALESCE(request_id, '') = '' AND timestamp = ?`, []any{d.k1, d.k3.String}
		}
	default:
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, closeRows(rows)
}

// settlePushDeletions runs before a push reads its change-sequence snapshot.
// A tombstone whose identity is live again on the node (the row was
// re-inserted under the same key, or a duplicate was deleted beside a twin
// that carries the same key) must NOT ship - it would delete the org's copy
// of a row the node still counts. Such a tombstone is dropped and the live
// row(s) are queued for a RE-SEND at a fresh sequence, so the org converges on
// the live version through the ordinary newer-wins path. A stale retention
// marker (committed by a crashed or buggy retention writer, which would
// silently suppress every correction) is cleared here too. No write happens
// when there is nothing to settle.
func (s *Store) settlePushDeletions(ctx context.Context, tr pushTracking) error {
	marker, err := s.readMeta(ctx, db.RetentionDeleteMarkerKey)
	if err != nil {
		return fmt.Errorf("settle deletions: marker: %w", err)
	}
	queued, err := s.loadDeletionRows(ctx, `ORDER BY seq LIMIT ?`, pushDeletionScanCap)
	if err != nil {
		return fmt.Errorf("settle deletions: %w", err)
	}
	type superseded struct {
		d     deletionRow
		twins []int64
	}
	var hits []superseded
	for _, d := range queued {
		twins, err := s.deletionTwins(ctx, d)
		if err != nil {
			return fmt.Errorf("settle deletions: twins %s: %w", d.tbl, err)
		}
		if len(twins) > 0 {
			hits = append(hits, superseded{d, twins})
		}
	}
	if marker == "" && len(hits) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("settle deletions: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The marker is only ever legitimately present INSIDE a retention write
	// transaction, which this transaction cannot observe (one writer at a
	// time); a committed one is a leak.
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, db.RetentionDeleteMarkerKey); err != nil {
		return fmt.Errorf("settle deletions: clear marker: %w", err)
	}
	if len(hits) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1`); err != nil {
			return fmt.Errorf("settle deletions: bump: %w", err)
		}
		for _, h := range hits {
			if _, err := tx.ExecContext(ctx, `DELETE FROM org_push_deletions WHERE seq = ?`, h.d.seq); err != nil {
				return fmt.Errorf("settle deletions: drop: %w", err)
			}
			floor, tracked := tr.floor[h.d.tbl]
			if !tracked {
				continue
			}
			for _, id := range h.twins {
				if id <= floor {
					continue
				}
				if _, err := tx.ExecContext(ctx,
					`INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
					 VALUES (?, ?, (SELECT rev FROM org_push_rev WHERE k = 1))`, h.d.tbl, id); err != nil {
					return fmt.Errorf("settle deletions: requeue: %w", err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("settle deletions: commit: %w", err)
	}
	return nil
}

// settleOrgPushDeletions is SelectUnpushedSince's entry into the settle pass:
// a no-op on a node that is not enrolled (no floors, no triggers armed).
func (s *Store) settleOrgPushDeletions(ctx context.Context) error {
	_, tr, err := s.loadPushTracking(ctx)
	if err != nil || tr == nil {
		return err
	}
	return s.settlePushDeletions(ctx, *tr)
}

// loadDeletionRows reads queued tombstones; tail is the ORDER/LIMIT clause
// (and any leading WHERE) with its bound args.
func (s *Store) loadDeletionRows(ctx context.Context, tail string, args ...any) ([]deletionRow, error) {
	//nolint:gosec // G202: tail is an in-package literal clause; values bind via args.
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, row_id, project_id, tbl, k1, k2, k3 FROM org_push_deletions `+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("load deletions: %w", err)
	}
	var out []deletionRow
	for rows.Next() {
		var d deletionRow
		if err := rows.Scan(&d.seq, &d.rowID, &d.projectID, &d.tbl, &d.k1, &d.k2, &d.k3); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("load deletions: scan: %w", err)
		}
		out = append(out, d)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("load deletions: %w", err)
	}
	return out, nil
}

// scopeSet parses SelectUnpushedSince's resolved project-id IN-list. nil
// means no scope (every project ships).
func scopeSet(scopeFilter string) map[int64]bool {
	if scopeFilter == "" {
		return nil
	}
	set := map[int64]bool{}
	for _, p := range strings.Split(scopeFilter, ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64); err == nil {
			set[id] = true
		}
	}
	return set
}

// inScope reports whether a row of projectID may ship under scope. A row
// whose project is unknown ships only when no scope is set, like the cursor
// lanes' `project_id IN (...)` filter (which a NULL never satisfies).
func inScope(scope map[int64]bool, projectID sql.NullInt64) bool {
	if scope == nil {
		return true
	}
	return projectID.Valid && scope[projectID.Int64]
}

// controlFits is the budget guard shared by the tombstone and manifest lanes:
// together with the re-send lane they take at most half the envelope, and the
// very first item of an otherwise empty batch always fits (forward progress).
func controlFits(batch *PushBatch, budget *envelopeBudget, sz int64) bool {
	if batch.RowCount() == 0 && len(batch.Deletions) == 0 && len(batch.SessionManifests) == 0 {
		return true
	}
	return budget.est+sz <= (budget.max-pushEnvelopeCursorSlack)/2
}

// composeDeletions is the TOMBSTONE lane of SelectUnpushedSince: the oldest
// queued deletions with seq <= rev (the batch's snapshot), each shipped with
// its own seq as NodeRev. A tombstone whose deleted row belonged to a project
// outside the push scope is acknowledged without shipping (the org never got
// that row, and its identity must not cross either).
func (s *Store) composeDeletions(ctx context.Context, batch *PushBatch, budget *envelopeBudget, rev int64, scopeFilter string) error {
	queued, err := s.loadDeletionRows(ctx, `WHERE seq <= ? ORDER BY seq LIMIT ?`, rev, pushDeletionRowCap)
	if err != nil {
		return fmt.Errorf("store.SelectUnpushedSince: %w", err)
	}
	scope := scopeSet(scopeFilter)
	for _, d := range queued {
		if !inScope(scope, d.projectID) {
			batch.Acks.deletions = append(batch.Acks.deletions, d.seq)
			continue
		}
		w := d.wire()
		sz := jsonSize(w)
		if !controlFits(batch, budget, sz) {
			break
		}
		batch.Deletions = append(batch.Deletions, w)
		batch.Acks.deletions = append(batch.Acks.deletions, d.seq)
		budget.est += sz
	}
	return nil
}

// manifestQueued is one queued session manifest.
type manifestQueued struct {
	sessionID string
	seq       int64
	notBefore string
	projectID sql.NullInt64
	exists    bool
}

// composeManifests is the HEAL lane of SelectUnpushedSince: for each queued
// session (oldest first, seq <= rev), the digest of every row identity the
// node holds in that session, per family, stamped with the batch's snapshot as
// NodeRev. A manifest ships whole or not at all (a partial list would delete
// rows the node still has); one that can never fit, or whose session is gone
// or outside the push scope, is acknowledged without shipping.
func (s *Store) composeManifests(ctx context.Context, batch *PushBatch, budget *envelopeBudget, rev int64, scopeFilter string) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.session_id, m.seq, COALESCE(m.not_before, ''), s.project_id, s.id IS NOT NULL
		   FROM org_push_manifests m LEFT JOIN sessions s ON s.id = m.session_id
		  WHERE m.seq <= ? ORDER BY m.seq LIMIT ?`, rev, pushManifestCap)
	if err != nil {
		return fmt.Errorf("store.SelectUnpushedSince: manifests: %w", err)
	}
	var queued []manifestQueued
	for rows.Next() {
		var m manifestQueued
		if err := rows.Scan(&m.sessionID, &m.seq, &m.notBefore, &m.projectID, &m.exists); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store.SelectUnpushedSince: manifests scan: %w", err)
		}
		queued = append(queued, m)
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store.SelectUnpushedSince: manifests: %w", err)
	}
	scope := scopeSet(scopeFilter)
	for _, m := range queued {
		ack := manifestAck{sessionID: m.sessionID, seq: m.seq}
		if !m.exists || !inScope(scope, m.projectID) || m.notBefore == "" {
			batch.Acks.manifests = append(batch.Acks.manifests, ack)
			continue
		}
		man, ok, err := s.buildSessionManifest(ctx, m.sessionID, rev)
		if err != nil {
			return fmt.Errorf("store.SelectUnpushedSince: manifest %s: %w", m.sessionID, err)
		}
		if !ok {
			batch.Acks.manifests = append(batch.Acks.manifests, ack)
			continue
		}
		man.NotBefore = m.notBefore
		sz := jsonSize(man)
		if !controlFits(batch, budget, sz) {
			if batch.RowCount() == 0 && len(batch.Deletions) == 0 && len(batch.SessionManifests) == 0 {
				// Cannot fit even alone: drop it rather than wedge the lane.
				batch.Acks.manifests = append(batch.Acks.manifests, ack)
				continue
			}
			break
		}
		batch.SessionManifests = append(batch.SessionManifests, man)
		batch.Acks.manifests = append(batch.Acks.manifests, ack)
		budget.est += sz
	}
	return nil
}

// manifestFamilies is the per-family identity read for a session manifest:
// the family name and the SELECT producing each row's two key parts (the
// manifest key is keyOf(a, b)). Rows without a source event id are never
// listed, and the org never deletes a row without one through a manifest.
var manifestFamilies = []struct {
	family, q string
	keyOf     func(a, b string) string
}{
	{
		orgcontract.DeletionActions,
		`SELECT source_event_id, '' FROM actions WHERE session_id = ? AND COALESCE(source_event_id, '') <> ''`,
		func(a, _ string) string { return a },
	},
	{
		orgcontract.DeletionTokenUsage,
		`SELECT source_event_id, '' FROM token_usage WHERE session_id = ? AND COALESCE(source_event_id, '') <> ''`,
		func(a, _ string) string { return a },
	},
	{
		orgcontract.DeletionAPITurns,
		`SELECT COALESCE(request_id, ''), COALESCE(timestamp, '') FROM api_turns WHERE session_id = ?`,
		orgcontract.ManifestAPITurnKey,
	},
}

// buildSessionManifest reads every row identity the node holds in sessionID.
// ok is false when the session holds more identities than one manifest may
// carry.
func (s *Store) buildSessionManifest(ctx context.Context, sessionID string, rev int64) (orgcontract.SessionManifest, bool, error) {
	man := orgcontract.SessionManifest{SessionID: sessionID, NodeRev: rev}
	total := 0
	for _, f := range manifestFamilies {
		rows, err := s.db.QueryContext(ctx, f.q, sessionID)
		if err != nil {
			return man, false, err
		}
		set := map[string]struct{}{}
		for rows.Next() {
			var a, b string
			if err := rows.Scan(&a, &b); err != nil {
				_ = rows.Close()
				return man, false, err
			}
			set[orgcontract.ManifestDigest(f.family, f.keyOf(a, b))] = struct{}{}
		}
		if err := closeRows(rows); err != nil {
			return man, false, err
		}
		list := make([]string, 0, len(set))
		for k := range set {
			list = append(list, k)
		}
		sort.Strings(list)
		total += len(list)
		if len(list) > orgcontract.ManifestMaxRowsPerFamily {
			return man, false, nil
		}
		switch f.family {
		case orgcontract.DeletionActions:
			man.Actions = list
		case orgcontract.DeletionTokenUsage:
			man.TokenUsage = list
		case orgcontract.DeletionAPITurns:
			man.APITurns = list
		}
	}
	if total > orgcontract.ManifestMaxRows {
		return man, false, nil
	}
	return man, true, nil
}

// manifestAck is one manifest a push delivered (or dropped): it is removed
// only while its seq is unchanged, so a re-queue during the flight survives.
type manifestAck struct {
	sessionID string
	seq       int64
}

// ackPushDeletionsTx removes the tombstones and manifests an ACCEPTED push
// delivered (or deliberately dropped).
func ackPushDeletionsTx(ctx context.Context, tx *sql.Tx, a PushAcks) error {
	if err := deleteBySeq(ctx, tx, a.deletions); err != nil {
		return fmt.Errorf("deletions: %w", err)
	}
	for _, m := range a.manifests {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM org_push_manifests WHERE session_id = ? AND seq = ?`, m.sessionID, m.seq); err != nil {
			return fmt.Errorf("manifests: %w", err)
		}
	}
	return nil
}

// deleteBySeq removes tombstones by seq in bounded IN-list chunks.
func deleteBySeq(ctx context.Context, tx *sql.Tx, seqs []int64) error {
	const chunk = 500
	for len(seqs) > 0 {
		n := len(seqs)
		if n > chunk {
			n = chunk
		}
		args := make([]any, 0, n)
		for _, v := range seqs[:n] {
			args = append(args, v)
		}
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
		q := `DELETE FROM org_push_deletions WHERE seq IN (` + strings.TrimSuffix(strings.Repeat("?,", n), ",") + `)`
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return err
		}
		seqs = seqs[n:]
	}
	return nil
}

// clearPushDeletionsTx empties both queues (unenrol, cursor re-baseline).
func clearPushDeletionsTx(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_push_deletions`); err != nil {
		return fmt.Errorf("clear push deletions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_push_manifests`); err != nil {
		return fmt.Errorf("clear push manifests: %w", err)
	}
	return nil
}

// PushDeletionsPending reports the queued tombstones and session manifests.
func (s *Store) PushDeletionsPending(ctx context.Context) (tombstones, manifests int64, err error) {
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_push_deletions`).Scan(&tombstones); err != nil {
		return 0, 0, fmt.Errorf("store.PushDeletionsPending: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_push_manifests`).Scan(&manifests); err != nil {
		return 0, 0, fmt.Errorf("store.PushDeletionsPending: %w", err)
	}
	return tombstones, manifests, nil
}

// PushManifestOptions bounds `observer org resync --deletions`.
type PushManifestOptions struct {
	// Since limits the heal to sessions started at or after it.
	Since time.Time
	// NotBefore is the caller's lower bound on the row times the org may
	// delete through these manifests: the node's CONFIGURED ageing horizon
	// (retention.AgeingHorizon), so a row the node aged out can never look
	// deleted. The store raises it further (manifestHorizon); zero leaves
	// the window start and the store's own bounds.
	NotBefore time.Time
	// Limit caps the sessions queued (most recent first).
	Limit int
	// DryRun reports without writing.
	DryRun bool
}

// PushManifestReport is what EnqueuePushManifests did (or would do).
type PushManifestReport struct {
	Queued  int
	TooBig  int
	Checked int
	// NotBefore is the effective horizon the queued manifests carry: the
	// latest of the caller's bound, the recorded retention cutoff and (one
	// day after) the oldest action this node still holds.
	NotBefore time.Time
}

// manifestHorizon is the retention-safe NotBefore for resync manifests: the
// LATEST of the caller's bound (its window start and configured ageing
// horizon), the latest cutoff any retention pass recorded
// (db.AgeingCutoffKey), and one day after the oldest action still on the
// node - which also covers passes that ran before the cutoff was recorded,
// because an age pass leaves nothing older than its cutoff behind.
func (s *Store) manifestHorizon(ctx context.Context, floor time.Time) (time.Time, error) {
	out := floor.UTC()
	raise := func(v string, margin time.Duration) {
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v)); err == nil {
			if t = t.UTC().Add(margin); t.After(out) {
				out = t
			}
		}
	}
	cut, err := s.readMeta(ctx, db.AgeingCutoffKey)
	if err != nil {
		return out, fmt.Errorf("manifest horizon: cutoff: %w", err)
	}
	raise(cut, 24*time.Hour)
	var oldest sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(timestamp) FROM actions`).Scan(&oldest); err != nil {
		return out, fmt.Errorf("manifest horizon: oldest action: %w", err)
	}
	if oldest.Valid {
		raise(oldest.String, 24*time.Hour)
	}
	return out, nil
}

// EnqueuePushManifests queues a session manifest for each session started in
// the window (most recent first, capped), so the push loop ships the node's
// complete per-session row identities and the org drops the rows it holds for
// those sessions that the node no longer has (rows deleted before migration
// 141). A session holding more identities than one manifest may carry is
// reported, not queued. Refused on a node that is not enrolled.
func (s *Store) EnqueuePushManifests(ctx context.Context, opt PushManifestOptions) (PushManifestReport, error) {
	var rep PushManifestReport
	if opt.Limit <= 0 {
		return rep, errors.New("store.EnqueuePushManifests: Limit must be positive")
	}
	_, tr, err := s.loadPushTracking(ctx)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: %w", err)
	}
	if tr == nil {
		return rep, ErrPushNotTracked
	}
	floor := opt.NotBefore
	if opt.Since.After(floor) {
		floor = opt.Since
	}
	if rep.NotBefore, err = s.manifestHorizon(ctx, floor); err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: %w", err)
	}
	ids, err := s.resyncSessionIDs(ctx, opt.Since.UTC().Format(time.RFC3339Nano), opt.Limit)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: %w", err)
	}
	var keep []string
	for _, id := range ids {
		rep.Checked++
		var n int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT (SELECT COUNT(*) FROM actions WHERE session_id = ?)
			      + (SELECT COUNT(*) FROM token_usage WHERE session_id = ?)
			      + (SELECT COUNT(*) FROM api_turns WHERE session_id = ?)`, id, id, id).Scan(&n); err != nil {
			return rep, fmt.Errorf("store.EnqueuePushManifests: count: %w", err)
		}
		if n > orgcontract.ManifestMaxRows {
			rep.TooBig++
			continue
		}
		keep = append(keep, id)
	}
	rep.Queued = len(keep)
	if opt.DryRun || len(keep) == 0 {
		return rep, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1`); err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: bump: %w", err)
	}
	nb := rep.NotBefore.UTC().Format(time.RFC3339Nano)
	for _, id := range keep {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO org_push_manifests (session_id, seq, not_before)
			 VALUES (?, (SELECT rev FROM org_push_rev WHERE k = 1), ?)`, id, nb); err != nil {
			return rep, fmt.Errorf("store.EnqueuePushManifests: queue: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return rep, fmt.Errorf("store.EnqueuePushManifests: commit: %w", err)
	}
	return rep, nil
}
