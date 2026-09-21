package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// Guard-layer persistence helpers per docs/plans/
// guard-layer-implementation-spec-2026-06-10.md §10 (migration 040).
//
// Four tables back the guard subsystem:
//
//   guard_events       — hash-chained audit rows, one per verdict worth
//                        recording (§10.4 tamper-evident chain).
//   guard_pins         — MCP-server / hook-config / native-dialect pin
//                        records (§9.2, §13.2).
//   guard_policy_state — append-only version log of policy source loads
//                        (§14.4 policy-change log).
//   guard_approvals    — operator-granted scoped exceptions (§6.3): the
//                        reviewable exception register.
//
// OWNERSHIP INVARIANT (spec §17.4) — this file is the ONE owner of all
// four tables. No other code may INSERT/UPDATE/DELETE them. Each helper
// owns its own transaction and is failure-isolated by contract: callers
// on hot paths (hook reply, ingest) treat a returned error as
// log-and-continue, never as a reason to fail the ingest or delay the
// hook reply. The helpers therefore never panic and never leave a
// half-applied batch (single tx per call).
//
// PRIVACY INVARIANT (spec §10.2) — guard_events rows DO enter the org
// push wire (unlike the fully node-local cache_* tables), with the
// content-bearing columns (reason, target_excerpt, taint_origin)
// stripped in Go at orgpush.go::SelectUnpushedSince unless
// [org_client.share].full_content is set; target_hash always ships.
// guard_pins / guard_policy_state / guard_approvals are NODE-LOCAL
// until the G13/G14 teams arc deliberately adds their wire surfaces.
// Both postures are pinned by tests/invariant/privacy_test.go.
//
// MODULE-BOUNDARY NOTE — the row types here are the store's own
// SQL-shaped types, NOT policy/guard domain types (the cachetrack
// precedent: domain types do not leak past the evaluation seam). The
// guard composition layer (G3) translates policy.Verdict + policy.Event
// into GuardEventRow values at the boundary before calling these
// helpers.

// guardChainCheckpointKey is the schema_meta key holding the chain_hash
// of the last PRUNED guard_events row (§10.3): after retention removes
// a chain prefix, verification re-anchors on this value instead of the
// empty-string genesis anchor. Absent until the first prune.
const guardChainCheckpointKey = "guard_chain_checkpoint"

// Bounded-content limits enforced at this seam (CLAUDE.md "no file
// contents in the DB" Don't — excerpts only, bounded). Enforced HERE,
// at the one owner, so no caller can accidentally persist unbounded
// content. Truncation happens BEFORE the chain hash is computed, so
// the canonical bytes always describe exactly what the row stores.
const (
	guardMaxExcerptRunes = 256
	guardMaxReasonRunes  = 1024
)

// GuardEventRow is one row of guard_events. ChainPrev/ChainHash are
// OUTPUT fields — InsertGuardEvents computes and stamps them; any
// caller-supplied values are ignored. ID is set on rows returned by
// the Load* helpers and ignored on insert.
//
// ActionID / APITurnID anchor the event to the originating surface
// (watcher action row, proxy turn). Both nil on the hook path — hook
// verdicts precede the action row's existence.
type GuardEventRow struct {
	ID            int64
	TS            time.Time
	SessionID     string
	ActionID      *int64
	APITurnID     *int64
	Tool          string
	EventKind     string
	RuleID        string
	Category      string
	Severity      string
	Decision      string
	DegradedFrom  string
	Enforced      bool
	Source        string
	Reason        string
	TargetHash    string
	TargetExcerpt string
	TaintOrigin   string
	ChainPrev     string
	ChainHash     string

	// tsStored is the exact string persisted in the ts column — the
	// canonical-bytes computation and the verify walk must agree on
	// the byte-level timestamp form, so it is captured once at insert
	// time and round-tripped verbatim on load.
	tsStored string
}

// canonicalBytes returns the audit-canonical serialization of the row:
// the chain-hash preimage's row half (§10.4). Fields are joined with
// the ASCII unit separator (0x1f) in a FIXED, documented order; the
// id, chain_prev and chain_hash columns are excluded (id is assigned
// by SQLite and not part of row identity; chain_prev is the OTHER half
// of the preimage; chain_hash is the output). Nullable int anchors
// serialize as their decimal form or "" when NULL. The ts field is the
// stored column string, not a re-formatted time.Time, so verification
// recomputes byte-identical input from a SELECT.
//
// Field order (stable, append-only — changing it breaks every existing
// chain): ts, session_id, action_id, api_turn_id, tool, event_kind,
// rule_id, category, severity, decision, degraded_from, enforced,
// source, reason, target_hash, target_excerpt, taint_origin.
func (r *GuardEventRow) canonicalBytes() []byte {
	fields := []string{
		r.tsStored,
		r.SessionID,
		formatNullableID(r.ActionID),
		formatNullableID(r.APITurnID),
		r.Tool,
		r.EventKind,
		r.RuleID,
		r.Category,
		r.Severity,
		r.Decision,
		r.DegradedFrom,
		strconv.Itoa(boolToInt(r.Enforced)),
		r.Source,
		r.Reason,
		r.TargetHash,
		r.TargetExcerpt,
		r.TaintOrigin,
	}
	return []byte(strings.Join(fields, "\x1f"))
}

// guardChainHash computes SHA-256(prev || 0x1e || canonical row bytes)
// as lowercase hex — the §10.4 chain link. The ASCII record separator
// between the two halves removes prefix ambiguity (prev is itself hex
// of fixed length, but the separator makes the framing explicit and
// future-proof against anchor-format changes).
func guardChainHash(prev string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0x1e})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// formatNullableID renders a nullable row-id anchor for the canonical
// byte form: decimal when set, empty string when NULL.
func formatNullableID(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

// truncateRunes returns s cut to at most max runes (rune-safe — never
// splits a UTF-8 sequence), appending "…" when truncation occurred so
// a bounded excerpt is visibly bounded.
func truncateRunes(s string, max int) string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max]) + "…"
}

const insertGuardEventSQL = `
INSERT INTO guard_events (
    ts, session_id, action_id, api_turn_id, tool, event_kind,
    rule_id, category, severity, decision, degraded_from, enforced,
    source, reason, target_hash, target_excerpt, taint_origin,
    chain_prev, chain_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// InsertGuardEvents appends a batch of guard_events rows inside a
// single transaction, computing the §10.4 hash chain link for each:
//
//	chain_prev = chain_hash of the previous row (table tail), or the
//	             prune checkpoint when the table is empty post-prune,
//	             or "" on a virgin table (genesis);
//	chain_hash = SHA-256(chain_prev || 0x1e || canonical row bytes).
//
// The previous-tail read and the inserts share one transaction; db.Open
// opens every transaction BEGIN IMMEDIATE (_txlock=immediate), so two
// writer processes (daemon + hook subprocess) serialize on the SQLite
// write lock and the chain can never fork.
//
// Content bounds are enforced here (the one-owner seam): Reason is
// truncated to 1024 runes and TargetExcerpt to 256 runes BEFORE the
// chain hash is computed, so the stored bytes and the chain preimage
// always agree.
//
// On success the computed ChainPrev/ChainHash (and the bounded
// Reason/TargetExcerpt) are stamped back into the caller's slice — the
// hook path appends them to its forensics JSONL. Returns the count
// written; a mid-batch failure rolls the whole batch back.
//
// Failure isolation contract: callers on hot paths log the error and
// continue — a guard-write failure never fails an ingest or delays a
// hook reply (spec §17.4).
func (s *Store) InsertGuardEvents(ctx context.Context, events []GuardEventRow) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertGuardEvents: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prev, err := guardChainTailTx(ctx, tx)
	if err != nil {
		return 0, fmt.Errorf("store.InsertGuardEvents: read chain tail: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, insertGuardEventSQL)
	if err != nil {
		return 0, fmt.Errorf("store.InsertGuardEvents: prepare: %w", err)
	}
	defer stmt.Close()

	for i := range events {
		ev := &events[i]
		ev.Reason = truncateRunes(ev.Reason, guardMaxReasonRunes)
		ev.TargetExcerpt = truncateRunes(ev.TargetExcerpt, guardMaxExcerptRunes)
		ev.tsStored = timestamp(ev.TS)
		ev.ChainPrev = prev
		ev.ChainHash = guardChainHash(prev, ev.canonicalBytes())
		if _, err := stmt.ExecContext(
			ctx,
			ev.tsStored,
			nullableString(ev.SessionID),
			nullableInt64Ptr(ev.ActionID),
			nullableInt64Ptr(ev.APITurnID),
			nullableString(ev.Tool),
			nullableString(ev.EventKind),
			ev.RuleID,
			nullableString(ev.Category),
			nullableString(ev.Severity),
			nullableString(ev.Decision),
			nullableString(ev.DegradedFrom),
			boolToInt(ev.Enforced),
			nullableString(ev.Source),
			nullableString(ev.Reason),
			nullableString(ev.TargetHash),
			nullableString(ev.TargetExcerpt),
			nullableString(ev.TaintOrigin),
			ev.ChainPrev,
			ev.ChainHash,
		); err != nil {
			return 0, fmt.Errorf("store.InsertGuardEvents: exec[%d]: %w", i, err)
		}
		prev = ev.ChainHash
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.InsertGuardEvents: commit: %w", err)
	}
	return len(events), nil
}

// guardChainTailTx returns the chain anchor for the next guard_events
// insert, read INSIDE the caller's transaction: the newest row's
// chain_hash; else (empty table) the prune checkpoint; else "" —
// the genesis anchor.
func guardChainTailTx(ctx context.Context, tx *sql.Tx) (string, error) {
	var tail string
	err := tx.QueryRowContext(ctx,
		`SELECT chain_hash FROM guard_events ORDER BY id DESC LIMIT 1`).Scan(&tail)
	switch {
	case err == nil:
		return tail, nil
	case errors.Is(err, sql.ErrNoRows):
		// fall through to the checkpoint
	default:
		return "", err
	}
	var checkpoint string
	err = tx.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = ?`, guardChainCheckpointKey).Scan(&checkpoint)
	switch {
	case err == nil:
		return checkpoint, nil
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	default:
		return "", err
	}
}

// GuardChainReport is the result of a VerifyGuardChain walk.
type GuardChainReport struct {
	// Checked is the number of rows walked.
	Checked int
	// OK is true when every link verified.
	OK bool
	// FirstDivergenceID is the id of the first row whose link failed
	// (0 when OK).
	FirstDivergenceID int64
	// Detail is a one-line human-readable description of the first
	// divergence ("" when OK). It names the failure class —
	// broken-link (chain_prev doesn't match the prior row) or
	// rewritten-row (recomputed hash doesn't match chain_hash) — so
	// `observer guard verify-audit` (G5) can report without
	// re-deriving.
	Detail string
}

// VerifyGuardChain walks the full guard_events chain in id order and
// verifies every link (§10.4): each row's chain_prev must equal the
// prior row's chain_hash (the first row anchors on the prune
// checkpoint, or "" genesis), and each row's chain_hash must equal
// the recomputed SHA-256 over its stored column values. Returns the
// first divergence, or OK.
//
// Honest framing (spec F4): this proves tamper-EVIDENCE, not
// tamper-proofness — an attacker with DB write access could recompute
// the whole chain. What it catches is silent row edits and mid-chain
// deletions by anything that doesn't deliberately re-chain.
func (s *Store) VerifyGuardChain(ctx context.Context) (GuardChainReport, error) {
	expectedPrev := ""
	var checkpoint string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM schema_meta WHERE key = ?`, guardChainCheckpointKey).Scan(&checkpoint)
	switch {
	case err == nil:
		expectedPrev = checkpoint
	case errors.Is(err, sql.ErrNoRows):
		// genesis anchor
	default:
		return GuardChainReport{}, fmt.Errorf("store.VerifyGuardChain: read checkpoint: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, COALESCE(session_id,''), action_id, api_turn_id,
		       COALESCE(tool,''), COALESCE(event_kind,''), rule_id,
		       COALESCE(category,''), COALESCE(severity,''), COALESCE(decision,''),
		       COALESCE(degraded_from,''), enforced, COALESCE(source,''),
		       COALESCE(reason,''), COALESCE(target_hash,''),
		       COALESCE(target_excerpt,''), COALESCE(taint_origin,''),
		       chain_prev, chain_hash
		FROM guard_events ORDER BY id ASC`)
	if err != nil {
		return GuardChainReport{}, fmt.Errorf("store.VerifyGuardChain: query: %w", err)
	}
	defer rows.Close()

	report := GuardChainReport{OK: true}
	for rows.Next() {
		var r GuardEventRow
		var enforced int
		var actionID, apiTurnID sql.NullInt64
		if err := rows.Scan(
			&r.ID, &r.tsStored, &r.SessionID, &actionID, &apiTurnID,
			&r.Tool, &r.EventKind, &r.RuleID,
			&r.Category, &r.Severity, &r.Decision,
			&r.DegradedFrom, &enforced, &r.Source,
			&r.Reason, &r.TargetHash,
			&r.TargetExcerpt, &r.TaintOrigin,
			&r.ChainPrev, &r.ChainHash,
		); err != nil {
			return GuardChainReport{}, fmt.Errorf("store.VerifyGuardChain: scan: %w", err)
		}
		r.Enforced = enforced != 0
		if actionID.Valid {
			v := actionID.Int64
			r.ActionID = &v
		}
		if apiTurnID.Valid {
			v := apiTurnID.Int64
			r.APITurnID = &v
		}
		report.Checked++
		if !report.OK {
			continue // keep counting rows, first divergence already recorded
		}
		if r.ChainPrev != expectedPrev {
			report.OK = false
			report.FirstDivergenceID = r.ID
			report.Detail = fmt.Sprintf(
				"broken link at id %d: chain_prev does not match the prior row's chain_hash (possible mid-chain deletion or reorder)", r.ID,
			)
		} else if recomputed := guardChainHash(r.ChainPrev, r.canonicalBytes()); recomputed != r.ChainHash {
			report.OK = false
			report.FirstDivergenceID = r.ID
			report.Detail = fmt.Sprintf(
				"rewritten row at id %d: recomputed hash does not match chain_hash (row contents changed after insert)", r.ID,
			)
		}
		expectedPrev = r.ChainHash
	}
	if err := rows.Err(); err != nil {
		return GuardChainReport{}, fmt.Errorf("store.VerifyGuardChain: rows: %w", err)
	}
	return report, nil
}

// guardEventSelectColumns is the shared column list for the Load*
// helpers — kept in one place so the scan in loadGuardEventRows can't
// drift from the SELECT.
const guardEventSelectColumns = `
	SELECT id, ts, COALESCE(session_id,''), action_id, api_turn_id,
	       COALESCE(tool,''), COALESCE(event_kind,''), rule_id,
	       COALESCE(category,''), COALESCE(severity,''), COALESCE(decision,''),
	       COALESCE(degraded_from,''), enforced, COALESCE(source,''),
	       COALESCE(reason,''), COALESCE(target_hash,''),
	       COALESCE(target_excerpt,''), COALESCE(taint_origin,''),
	       chain_prev, chain_hash
	FROM guard_events`

// LoadGuardEventsForSession returns all guard events for a session,
// ordered by id ascending (insert order == chain order). Used by the
// dashboard session panel (G7) and `observer guard status` (G5).
func (s *Store) LoadGuardEventsForSession(ctx context.Context, sessionID string) ([]GuardEventRow, error) {
	rows, err := s.db.QueryContext(ctx,
		guardEventSelectColumns+` WHERE session_id = ? ORDER BY id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadGuardEventsForSession: query: %w", err)
	}
	return loadGuardEventRows(rows, "store.LoadGuardEventsForSession")
}

// GuardEventAnchoredRow extends GuardEventRow with the upstream
// actions.message_id / actions.turn_index resolved from the event's
// action_id anchor. Session-scoped only — feeds the Messages tab's
// exact-placement guard interleave (LOC/guardmsg/APM followups plan, Item
// 2). Live-grounded 2026-09-21: 34,165 of 34,610 guard_events rows carry a
// resolvable action_id (~99%); MessageID is empty for the small remainder
// (the hook path's pre-execution case, which precedes the action row's
// existence) and for an action_id that no longer resolves (a pruned row).
type GuardEventAnchoredRow struct {
	GuardEventRow
	MessageID string
	TurnIndex *int64
}

// LoadGuardEventsForSessionWithMessageAnchor is LoadGuardEventsForSession's
// sibling for the Messages-tab interleave: the same session-scoped,
// unbounded, insert-order read, plus a LEFT JOIN onto actions resolving
// each action-anchored event's message_id/turn_index. A caller that needs
// to place a verdict on the EXACT message row it judged (rather than
// guessing from timestamps) uses this; every other caller (the Security
// page's global timeline, `observer guard status`) keeps using
// LoadGuardEventsForSession, which doesn't pay the join.
func (s *Store) LoadGuardEventsForSessionWithMessageAnchor(ctx context.Context, sessionID string) ([]GuardEventAnchoredRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ge.id, ge.ts, COALESCE(ge.session_id,''), ge.action_id, ge.api_turn_id,
		       COALESCE(ge.tool,''), COALESCE(ge.event_kind,''), ge.rule_id,
		       COALESCE(ge.category,''), COALESCE(ge.severity,''), COALESCE(ge.decision,''),
		       COALESCE(ge.degraded_from,''), ge.enforced, COALESCE(ge.source,''),
		       COALESCE(ge.reason,''), COALESCE(ge.target_hash,''),
		       COALESCE(ge.target_excerpt,''), COALESCE(ge.taint_origin,''),
		       ge.chain_prev, ge.chain_hash,
		       COALESCE(a.message_id, ''), a.turn_index
		FROM guard_events ge
		LEFT JOIN actions a ON a.id = ge.action_id
		WHERE ge.session_id = ?
		ORDER BY ge.id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadGuardEventsForSessionWithMessageAnchor: query: %w", err)
	}
	defer rows.Close()
	var out []GuardEventAnchoredRow
	for rows.Next() {
		var r GuardEventAnchoredRow
		var enforced int
		var actionID, apiTurnID, turnIndex sql.NullInt64
		if err := rows.Scan(
			&r.ID, &r.tsStored, &r.SessionID, &actionID, &apiTurnID,
			&r.Tool, &r.EventKind, &r.RuleID,
			&r.Category, &r.Severity, &r.Decision,
			&r.DegradedFrom, &enforced, &r.Source,
			&r.Reason, &r.TargetHash,
			&r.TargetExcerpt, &r.TaintOrigin,
			&r.ChainPrev, &r.ChainHash,
			&r.MessageID, &turnIndex,
		); err != nil {
			return nil, fmt.Errorf("store.LoadGuardEventsForSessionWithMessageAnchor: scan: %w", err)
		}
		r.Enforced = enforced != 0
		if actionID.Valid {
			v := actionID.Int64
			r.ActionID = &v
		}
		if apiTurnID.Valid {
			v := apiTurnID.Int64
			r.APITurnID = &v
		}
		if turnIndex.Valid {
			v := turnIndex.Int64
			r.TurnIndex = &v
		}
		r.TS = parseStamp(r.tsStored)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadGuardEventsForSessionWithMessageAnchor: rows: %w", err)
	}
	return out, nil
}

// LoadRecentGuardEvents returns up to limit guard events with ts >=
// since, newest first. A zero since means no lower bound (the
// timestamp() helper maps zero times to NOW, which would exclude
// everything — callers wanting "last N regardless of window" pass the
// zero time). limit <= 0 defaults to 200. Powers the verdict timeline
// (G5 CLI, G7 dashboard).
func (s *Store) LoadRecentGuardEvents(ctx context.Context, since time.Time, limit int) ([]GuardEventRow, error) {
	if limit <= 0 {
		limit = 200
	}
	q := guardEventSelectColumns
	args := []any{}
	if !since.IsZero() {
		q += ` WHERE ts >= ?`
		args = append(args, timestamp(since))
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadRecentGuardEvents: query: %w", err)
	}
	return loadGuardEventRows(rows, "store.LoadRecentGuardEvents")
}

// loadGuardEventRows scans guardEventSelectColumns result rows into
// GuardEventRow values, closing rows on all paths.
func loadGuardEventRows(rows *sql.Rows, caller string) ([]GuardEventRow, error) {
	defer rows.Close()
	var out []GuardEventRow
	for rows.Next() {
		var r GuardEventRow
		var enforced int
		var actionID, apiTurnID sql.NullInt64
		if err := rows.Scan(
			&r.ID, &r.tsStored, &r.SessionID, &actionID, &apiTurnID,
			&r.Tool, &r.EventKind, &r.RuleID,
			&r.Category, &r.Severity, &r.Decision,
			&r.DegradedFrom, &enforced, &r.Source,
			&r.Reason, &r.TargetHash,
			&r.TargetExcerpt, &r.TaintOrigin,
			&r.ChainPrev, &r.ChainHash,
		); err != nil {
			return nil, fmt.Errorf("%s: scan: %w", caller, err)
		}
		r.Enforced = enforced != 0
		if actionID.Valid {
			v := actionID.Int64
			r.ActionID = &v
		}
		if apiTurnID.Valid {
			v := apiTurnID.Int64
			r.APITurnID = &v
		}
		r.TS = parseStamp(r.tsStored)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", caller, err)
	}
	return out, nil
}

// GuardPinRow is one row of guard_pins (§9.2 pin records). The
// (Kind, Name, Client) triple is the natural identity (UNIQUE in the
// schema); UpsertGuardPin updates pin_hash / last_verified / status on
// conflict.
type GuardPinRow struct {
	ID           int64
	Kind         string // 'mcp_server' | 'hook_config' | 'native_dialect'
	Name         string
	Client       string
	PinHash      string
	FirstSeen    time.Time
	LastVerified time.Time
	Status       string // 'pinned' | 'drifted' | 'approved'
}

// UpsertGuardPin inserts a pin record or, when (kind, name, client)
// already exists, updates the observed fields (pin_hash, last_verified,
// status). first_seen is preserved on conflict — it records the FIRST
// sighting (§9.2: first sight of a server ⇒ pin record).
func (s *Store) UpsertGuardPin(ctx context.Context, pin GuardPinRow) error {
	if pin.Kind == "" || pin.Name == "" {
		return errors.New("store.UpsertGuardPin: kind and name required")
	}
	if pin.Status == "" {
		pin.Status = "pinned"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO guard_pins (kind, name, client, pin_hash, first_seen, last_verified, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(kind, name, client) DO UPDATE SET
		    pin_hash      = excluded.pin_hash,
		    last_verified = excluded.last_verified,
		    status        = excluded.status`,
		pin.Kind, pin.Name, pin.Client, pin.PinHash,
		timestamp(pin.FirstSeen), timestamp(pin.LastVerified), pin.Status)
	if err != nil {
		return fmt.Errorf("store.UpsertGuardPin: %w", err)
	}
	return nil
}

// LoadGuardPins returns pin records, optionally filtered by kind
// (empty kind = all), ordered by kind, name, client.
func (s *Store) LoadGuardPins(ctx context.Context, kind string) ([]GuardPinRow, error) {
	q := `SELECT id, kind, name, client, pin_hash, first_seen, last_verified, status
	        FROM guard_pins`
	args := []any{}
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY kind, name, client`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadGuardPins: query: %w", err)
	}
	defer rows.Close()
	var out []GuardPinRow
	for rows.Next() {
		var r GuardPinRow
		var firstSeen, lastVerified string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Name, &r.Client, &r.PinHash,
			&firstSeen, &lastVerified, &r.Status); err != nil {
			return nil, fmt.Errorf("store.LoadGuardPins: scan: %w", err)
		}
		r.FirstSeen = parseStamp(firstSeen)
		r.LastVerified = parseStamp(lastVerified)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadGuardPins: rows: %w", err)
	}
	return out, nil
}

// UpdateGuardPinStatus sets the status of pin rows matching (kind,
// name) — and client, when non-empty — stamping last_verified. It
// returns the number of rows updated (0 = no such pin). Backs
// `observer guard mcp approve`: approval is a status flip on the
// CURRENT pin, never a hash rewrite (the scan owns hashes).
func (s *Store) UpdateGuardPinStatus(ctx context.Context, kind, name, client, status string, now time.Time) (int, error) {
	if kind == "" || name == "" || status == "" {
		return 0, errors.New("store.UpdateGuardPinStatus: kind, name and status required")
	}
	q := `UPDATE guard_pins SET status = ?, last_verified = ? WHERE kind = ? AND name = ?`
	args := []any{status, timestamp(now), kind, name}
	if client != "" {
		q += ` AND client = ?`
		args = append(args, client)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, fmt.Errorf("store.UpdateGuardPinStatus: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.UpdateGuardPinStatus: rows affected: %w", err)
	}
	return int(n), nil
}

// GuardMCPServerApproved reports whether an MCP server name is
// pinned-and-approved for taint purposes (guard spec §9.2): at least
// one mcp_server pin row with status 'approved' and NO row drifted —
// a drifted pin means the server changed since the operator's grant,
// so trust is suspended until re-approval. One indexed read; backs
// the injected guard.MCPPinLookup.
func (s *Store) GuardMCPServerApproved(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	var approved, drifted int
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN status = 'drifted' THEN 1 ELSE 0 END), 0)
		FROM guard_pins WHERE kind = 'mcp_server' AND name = ?`, name).
		Scan(&approved, &drifted)
	if err != nil {
		return false, fmt.Errorf("store.GuardMCPServerApproved: %w", err)
	}
	return approved > 0 && drifted == 0, nil
}

// GuardPolicyStateRow is one row of guard_policy_state — one loaded
// policy-source version (§14.4 policy-change log). Signature is empty
// for local (user/project) layers.
type GuardPolicyStateRow struct {
	ID          int64
	Layer       string // 'org' | 'user' | 'project'
	Path        string
	Version     string
	ContentHash string
	Signature   string
	LoadedAt    time.Time
}

// RecordGuardPolicyState appends a policy-state row IF the content hash
// differs from the most recent row for the same (layer, path) — the
// log records version CHANGES, and daemon restarts that reload an
// unchanged file stay silent (idempotent). Returns whether a row was
// appended.
func (s *Store) RecordGuardPolicyState(ctx context.Context, row GuardPolicyStateRow) (bool, error) {
	if row.Layer == "" || row.Path == "" {
		return false, errors.New("store.RecordGuardPolicyState: layer and path required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store.RecordGuardPolicyState: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var lastHash string
	err = tx.QueryRowContext(ctx, `
		SELECT content_hash FROM guard_policy_state
		WHERE layer = ? AND path = ? ORDER BY id DESC LIMIT 1`,
		row.Layer, row.Path).Scan(&lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("store.RecordGuardPolicyState: read latest: %w", err)
	}
	if err == nil && lastHash == row.ContentHash {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO guard_policy_state (layer, path, version, content_hash, signature, loaded_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		row.Layer, row.Path, row.Version, row.ContentHash,
		nullableString(row.Signature), timestamp(row.LoadedAt)); err != nil {
		return false, fmt.Errorf("store.RecordGuardPolicyState: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store.RecordGuardPolicyState: commit: %w", err)
	}
	return true, nil
}

// LatestGuardPolicyStates returns the most recent row per (layer, path)
// — the currently-effective policy sources, for `observer guard status`
// and the §14.4 evidence pack.
func (s *Store) LatestGuardPolicyStates(ctx context.Context) ([]GuardPolicyStateRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.id, g.layer, g.path, g.version, g.content_hash,
		       COALESCE(g.signature,''), g.loaded_at
		FROM guard_policy_state g
		JOIN (SELECT layer, path, MAX(id) AS max_id
		        FROM guard_policy_state GROUP BY layer, path) latest
		  ON g.id = latest.max_id
		ORDER BY g.layer, g.path`)
	if err != nil {
		return nil, fmt.Errorf("store.LatestGuardPolicyStates: query: %w", err)
	}
	defer rows.Close()
	var out []GuardPolicyStateRow
	for rows.Next() {
		var r GuardPolicyStateRow
		var loadedAt string
		if err := rows.Scan(&r.ID, &r.Layer, &r.Path, &r.Version,
			&r.ContentHash, &r.Signature, &loadedAt); err != nil {
			return nil, fmt.Errorf("store.LatestGuardPolicyStates: scan: %w", err)
		}
		r.LoadedAt = parseStamp(loadedAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LatestGuardPolicyStates: rows: %w", err)
	}
	return out, nil
}

// GuardBudgetSpend returns the spend-so-far pair the §12.1 budget
// rules compare against: the session's total and the calendar-day
// total since dayStart (caller-supplied so the day boundary policy —
// UTC midnight — lives at the composition site). Read-only over
// api_turns (proxy ground truth, cost_usd) and token_usage (watcher
// tiers, estimated_cost_usd); a session observed by BOTH sources
// counts ONCE at the larger of its two sums — summing both would
// double-count the same turns, taking a global max would drop
// disjoint sessions (documented approximation; backs the injected
// guard.BudgetLookup).
func (s *Store) GuardBudgetSpend(ctx context.Context, sessionID string, dayStart, weekStart, monthStart time.Time) (spend GuardBudgetWindows, err error) {
	if sessionID != "" {
		err = s.db.QueryRowContext(ctx, `
			SELECT MAX(
			    (SELECT COALESCE(SUM(COALESCE(cost_usd,0)),0) FROM api_turns WHERE session_id = ?),
			    (SELECT COALESCE(SUM(COALESCE(estimated_cost_usd,0)),0) FROM token_usage WHERE session_id = ?))`,
			sessionID, sessionID).Scan(&spend.SessionUSD)
		if err != nil {
			return spend, fmt.Errorf("store.GuardBudgetSpend: session: %w", err)
		}
	}
	if spend.DailyUSD, err = s.windowSpendSince(ctx, dayStart); err != nil {
		return spend, fmt.Errorf("store.GuardBudgetSpend: daily: %w", err)
	}
	if spend.WeeklyUSD, err = s.windowSpendSince(ctx, weekStart); err != nil {
		return spend, fmt.Errorf("store.GuardBudgetSpend: weekly: %w", err)
	}
	if spend.MonthlyUSD, err = s.windowSpendSince(ctx, monthStart); err != nil {
		return spend, fmt.Errorf("store.GuardBudgetSpend: monthly: %w", err)
	}
	return spend, nil
}

// GuardBudgetWindows is the spend-so-far bundle the §12.1 budget rows
// compare against: the current session's total plus the node-wide
// totals in the day / rolling-7-day / calendar-month windows. The
// window totals share GuardBudgetSpend's per-session MAX(api_turns,
// token_usage) de-dup (a session seen by both sources counts once at
// the larger sum).
type GuardBudgetWindows struct {
	SessionUSD float64
	DailyUSD   float64
	WeeklyUSD  float64
	MonthlyUSD float64
}

// windowSpendSince returns the node-wide spend since `since`, de-duped
// per session at the larger of the proxy (api_turns.cost_usd) and
// watcher (token_usage.estimated_cost_usd) sums. A zero `since`
// (window disabled) still runs — the caller gates on the configured
// threshold, and the query is bounded by the 30s guard cache.
// api_turns.session_id is nullable (unattributed proxy turns) —
// COALESCE to ” so those rows still group, join and count.
func (s *Store) windowSpendSince(ctx context.Context, since time.Time) (float64, error) {
	ts := timestamp(since)
	var total float64
	err := s.db.QueryRowContext(ctx, `
		WITH p AS (SELECT COALESCE(session_id,'') sid, SUM(COALESCE(cost_usd,0)) c
		             FROM api_turns WHERE timestamp >= ? GROUP BY COALESCE(session_id,'')),
		     u AS (SELECT session_id sid, SUM(COALESCE(estimated_cost_usd,0)) c
		             FROM token_usage WHERE timestamp >= ? GROUP BY session_id)
		SELECT COALESCE(SUM(MAX(COALESCE(p.c,0), COALESCE(u.c,0))),0)
		FROM (SELECT sid FROM p UNION SELECT sid FROM u) s
		LEFT JOIN p ON p.sid = s.sid
		LEFT JOIN u ON u.sid = s.sid`,
		ts, ts).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

// LatestLimitWindows returns the most-recent provider usage-window
// utilization (0..1) observed across ALL scopes/providers — the 5h and
// weekly fractions the §12.1 B-610..B-613 limit rules gate on. It
// selects the newest limit_snapshots row that actually carries a
// window (window_5h_util OR window_7d_util NOT NULL); ok=false when no
// window has ever been observed. Provider-agnostic by design: only the
// provider's unified usage headers populate these columns (Anthropic
// today), so this resolves to whichever credential is subject to them
// without branching on provider identity. Read-only, node-local.
func (s *Store) LatestLimitWindows(ctx context.Context) (util5h, util7d float64, ok bool, err error) {
	var w5, w7 sql.NullFloat64
	qerr := s.db.QueryRowContext(ctx, `
		SELECT window_5h_util, window_7d_util
		  FROM limit_snapshots
		 WHERE window_5h_util IS NOT NULL OR window_7d_util IS NOT NULL
		 ORDER BY observed_at DESC, id DESC LIMIT 1`).Scan(&w5, &w7)
	if qerr != nil {
		if errors.Is(qerr, sql.ErrNoRows) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("store.LatestLimitWindows: %w", qerr)
	}
	return w5.Float64, w7.Float64, true, nil
}

// GuardBudgetObserved is the observed-spend basis for the G2.4 budget
// suggestions: distributions over per-session totals and per-calendar-
// day totals in a trailing window, on the SAME substrate and dedup
// discipline as GuardBudgetSpend — per-session cost takes the larger
// of the proxy and watcher sums (the B-601 comparison shape); daily
// totals sum per-(day, session) maxima (the B-602 shape). Zero-cost
// sessions/days are excluded: they're observationally vacant for
// sizing a budget threshold.
type GuardBudgetObserved struct {
	Sessions      int
	SessionP95USD float64
	SessionMaxUSD float64
	Days          int
	DailyP95USD   float64
	DailyMaxUSD   float64
}

// GuardBudgetObservedStats computes GuardBudgetObserved since the
// given time (the dashboard passes now-30d). Percentiles run in Go
// over the loaded value lists — bounded by distinct sessions/days in
// the window, hundreds not millions.
func (s *Store) GuardBudgetObservedStats(ctx context.Context, since time.Time) (GuardBudgetObserved, error) {
	var out GuardBudgetObserved
	ts := timestamp(since)

	sessVals, err := s.queryFloats(ctx, `
		WITH p AS (SELECT COALESCE(session_id,'') sid, SUM(COALESCE(cost_usd,0)) c
		             FROM api_turns WHERE timestamp >= ? GROUP BY COALESCE(session_id,'')),
		     u AS (SELECT session_id sid, SUM(COALESCE(estimated_cost_usd,0)) c
		             FROM token_usage WHERE timestamp >= ? GROUP BY session_id)
		SELECT MAX(COALESCE(p.c,0), COALESCE(u.c,0)) c
		FROM (SELECT sid FROM p UNION SELECT sid FROM u) k
		LEFT JOIN p ON p.sid = k.sid
		LEFT JOIN u ON u.sid = k.sid
		WHERE MAX(COALESCE(p.c,0), COALESCE(u.c,0)) > 0`, ts, ts)
	if err != nil {
		return out, fmt.Errorf("store.GuardBudgetObservedStats: sessions: %w", err)
	}
	out.Sessions = len(sessVals)
	out.SessionP95USD, out.SessionMaxUSD = p95AndMax(sessVals)

	dayVals, err := s.queryFloats(ctx, `
		WITH p AS (SELECT COALESCE(session_id,'') sid, DATE(timestamp) d, SUM(COALESCE(cost_usd,0)) c
		             FROM api_turns WHERE timestamp >= ? GROUP BY COALESCE(session_id,''), DATE(timestamp)),
		     u AS (SELECT session_id sid, DATE(timestamp) d, SUM(COALESCE(estimated_cost_usd,0)) c
		             FROM token_usage WHERE timestamp >= ? GROUP BY session_id, DATE(timestamp)),
		     m AS (SELECT k.sid, k.d, MAX(COALESCE(p.c,0), COALESCE(u.c,0)) c
		             FROM (SELECT sid, d FROM p UNION SELECT sid, d FROM u) k
		             LEFT JOIN p ON p.sid = k.sid AND p.d = k.d
		             LEFT JOIN u ON u.sid = k.sid AND u.d = k.d)
		SELECT SUM(c) FROM m GROUP BY d HAVING SUM(c) > 0`, ts, ts)
	if err != nil {
		return out, fmt.Errorf("store.GuardBudgetObservedStats: days: %w", err)
	}
	out.Days = len(dayVals)
	out.DailyP95USD, out.DailyMaxUSD = p95AndMax(dayVals)
	return out, nil
}

// queryFloats runs a query whose result is one float64 column.
func (s *Store) queryFloats(ctx context.Context, q string, args ...any) ([]float64, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// p95AndMax returns the 95th-percentile (nearest-rank) and maximum of
// vals; zeros on an empty slice.
func p95AndMax(vals []float64) (p95, maxV float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sort.Float64s(vals)
	idx := int(math.Ceil(0.95*float64(len(vals)))) - 1
	if idx < 0 {
		idx = 0
	}
	return vals[idx], vals[len(vals)-1]
}

// GuardApprovalRow is one row of guard_approvals — an operator-granted
// scoped exception (§6.3). SessionID anchors 'once'/'session' scopes;
// ProjectRootHash (sha256 hex, never the raw path) anchors 'project'.
// ExpiresAt zero means the grant does not expire.
//
// SessionID is an in-implementation addition over the spec §10.1 column
// list: the scope vocabulary includes 'once' and 'session', which are
// unenforceable without a session anchor.
type GuardApprovalRow struct {
	ID              int64
	TS              time.Time
	RuleID          string
	Scope           string // 'once' | 'session' | 'project' | 'global'
	SessionID       string
	ProjectRootHash string
	GrantedBy       string
	ExpiresAt       time.Time
}

// InsertGuardApproval appends an approval grant and returns its id.
func (s *Store) InsertGuardApproval(ctx context.Context, a GuardApprovalRow) (int64, error) {
	if a.RuleID == "" || a.Scope == "" {
		return 0, errors.New("store.InsertGuardApproval: rule_id and scope required")
	}
	expires := ""
	if !a.ExpiresAt.IsZero() {
		expires = timestamp(a.ExpiresAt)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO guard_approvals (ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		timestamp(a.TS), a.RuleID, a.Scope, a.SessionID, a.ProjectRootHash, a.GrantedBy, expires)
	if err != nil {
		return 0, fmt.Errorf("store.InsertGuardApproval: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.InsertGuardApproval: last id: %w", err)
	}
	return id, nil
}

// ActiveGuardApprovals returns the non-expired approvals for a rule
// (empty ruleID = all rules), evaluated against now. Scope semantics
// (matching a grant to a session/project) live at the guard layer; this
// helper only filters expiry — the store stays SQL-shaped.
func (s *Store) ActiveGuardApprovals(ctx context.Context, ruleID string, now time.Time) ([]GuardApprovalRow, error) {
	q := `SELECT id, ts, rule_id, scope, session_id, project_root_hash, granted_by, expires_at
	        FROM guard_approvals
	       WHERE (expires_at = '' OR expires_at > ?)`
	args := []any{timestamp(now)}
	if ruleID != "" {
		q += ` AND rule_id = ?`
		args = append(args, ruleID)
	}
	q += ` ORDER BY id ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ActiveGuardApprovals: query: %w", err)
	}
	defer rows.Close()
	var out []GuardApprovalRow
	for rows.Next() {
		var r GuardApprovalRow
		var ts, expires string
		if err := rows.Scan(&r.ID, &ts, &r.RuleID, &r.Scope, &r.SessionID,
			&r.ProjectRootHash, &r.GrantedBy, &expires); err != nil {
			return nil, fmt.Errorf("store.ActiveGuardApprovals: scan: %w", err)
		}
		r.TS = parseStamp(ts)
		if expires != "" {
			r.ExpiresAt = parseStamp(expires)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ActiveGuardApprovals: rows: %w", err)
	}
	return out, nil
}

// PersistGuardVerdicts translates the guard layer's post-hoc batch
// results into guard_events rows and appends them through
// InsertGuardEvents (the chain owner). The translation lives HERE at
// the store seam — guard domain types never spread past this call
// (the cachetrack PersistCacheObservation precedent), and guard never
// imports store.
//
// Row mapping notes:
//   - ts is the ACTION's timestamp (event time, not write time) so
//     the audit timeline aligns with the action timeline. The chain
//     orders by insert (id), not ts — post-hoc batches may interleave
//     timestamps and that's fine (the prune prefix logic tolerates
//     skew by design).
//   - reason carries Verdict.Reason with Verdict.Advice appended —
//     the row has one text column for both (the §6 hook surfaces keep
//     them separate; the audit row doesn't need to).
//   - enforced / degraded_from come from the verdict record: the
//     watcher path always leaves them zero (post-hoc channels cannot
//     block), the hook path sets them from the resolved Emission
//     (guard spec §6.2).
//   - target_excerpt is the action target — InsertGuardEvents bounds
//     it at the seam; target_hash uses the store's canonical
//     sha256Hex of the FULL target (matching actions.target_hash for
//     cross-table joins).
//
// Returns the count written. Failure isolation is the caller's
// contract: Ingest logs and continues.
func (s *Store) PersistGuardVerdicts(ctx context.Context, verdicts []guard.ActionVerdict) (int, error) {
	if len(verdicts) == 0 {
		return 0, nil
	}
	rows := make([]GuardEventRow, 0, len(verdicts))
	for i := range verdicts {
		v := &verdicts[i]
		reason := v.Verdict.Reason
		if v.Verdict.Advice != "" {
			reason += " Advice: " + v.Verdict.Advice
		}
		decision := v.Verdict.Decision.String()
		if v.ProxyAction != "" {
			// The §8.2 proxy-only decision ("mask") persists in place
			// of the policy decision string — the one place outside
			// internal/policy that knows the extra vocabulary.
			decision = v.ProxyAction
		}
		row := GuardEventRow{
			TS:            v.Input.Timestamp,
			SessionID:     v.Input.SessionID,
			Tool:          v.Input.Tool,
			EventKind:     string(v.Kind),
			RuleID:        v.Verdict.RuleID,
			Category:      v.Category,
			Severity:      v.Verdict.Severity.String(),
			Decision:      decision,
			DegradedFrom:  v.DegradedFrom,
			Enforced:      v.Enforced,
			Source:        v.Verdict.Source,
			Reason:        reason,
			TargetHash:    sha256Hex(v.Input.Target),
			TargetExcerpt: v.Input.Target,
			TaintOrigin:   v.TaintOrigin,
		}
		if v.Input.ActionID != 0 {
			id := v.Input.ActionID
			row.ActionID = &id
		}
		if v.Input.APITurnID != 0 {
			// Proxy response-inspection anchor (NULL elsewhere) — lets
			// the obs trajectory enrichment join the verdict by api_turn id.
			id := v.Input.APITurnID
			row.APITurnID = &id
		}
		rows = append(rows, row)
	}
	return s.InsertGuardEvents(ctx, rows)
}

// GuardEventSummary aggregates guard_events for the status surfaces
// (`observer guard status`, the G7 dashboard panel).
type GuardEventSummary struct {
	// Total is the row count in the window.
	Total int
	// ByDecision / BySeverity / ByCategory count rows per enum value.
	ByDecision map[string]int
	BySeverity map[string]int
	ByCategory map[string]int
	// Enforced counts rows whose decision actually blocked/asked.
	Enforced int
}

// SummarizeGuardEvents aggregates guard_events with ts >= since
// (zero since = all rows). One pass, grouped in SQL.
func (s *Store) SummarizeGuardEvents(ctx context.Context, since time.Time) (GuardEventSummary, error) {
	return s.SummarizeGuardEventsBetween(ctx, since, time.Time{})
}

// SummarizeGuardEventsBetween aggregates guard_events over the
// half-open window [since, until) — the §14.4 evidence pack's
// verdict-statistics read (`observer guard report --period` reports
// on PAST windows, which the since-only form cannot bound). Zero
// times mean unbounded on that side. Lexicographic ts comparison is
// valid because timestamp() emits fixed-form UTC RFC3339Nano (the
// PruneGuardRows precedent).
func (s *Store) SummarizeGuardEventsBetween(ctx context.Context, since, until time.Time) (GuardEventSummary, error) {
	sum := GuardEventSummary{
		ByDecision: map[string]int{},
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
	}
	q := `SELECT COALESCE(decision,''), COALESCE(severity,''), COALESCE(category,''),
	             COALESCE(enforced,0), COUNT(*)
	        FROM guard_events`
	var conds []string
	args := []any{}
	if !since.IsZero() {
		conds = append(conds, `ts >= ?`)
		args = append(args, timestamp(since))
	}
	if !until.IsZero() {
		conds = append(conds, `ts < ?`)
		args = append(args, timestamp(until))
	}
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, ` AND `)
	}
	q += ` GROUP BY decision, severity, category, enforced`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return sum, fmt.Errorf("store.SummarizeGuardEventsBetween: query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var decision, severity, category string
		var enforced, n int
		if err := rows.Scan(&decision, &severity, &category, &enforced, &n); err != nil {
			return sum, fmt.Errorf("store.SummarizeGuardEventsBetween: scan: %w", err)
		}
		sum.Total += n
		if decision != "" {
			sum.ByDecision[decision] += n
		}
		if severity != "" {
			sum.BySeverity[severity] += n
		}
		if category != "" {
			sum.ByCategory[category] += n
		}
		if enforced != 0 {
			sum.Enforced += n
		}
	}
	if err := rows.Err(); err != nil {
		return sum, fmt.Errorf("store.SummarizeGuardEventsBetween: rows: %w", err)
	}
	return sum, nil
}

// DeleteGuardApproval removes one approval grant by id (the
// `observer guard revoke` surface). Returns whether a row existed.
func (s *Store) DeleteGuardApproval(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM guard_approvals WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store.DeleteGuardApproval: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ApprovalActiveFor reports whether an active (non-expired) approval
// grant covers ruleID for this session/project — the §6.3 lookup the
// guard's ApprovalLookup wires to. Scope semantics:
//
//   - scope='global'  matches unconditionally;
//   - scope='session' matches when the grant's session_id equals the
//     event's (and the event has one);
//   - scope='project' matches when the grant's project_root_hash
//     equals the event's (sha256 hex; ” never matches);
//   - scope='once' is deferred: a one-shot grant needs a consumed
//     flag to be one-shot, and the consumption write would race the
//     hook's read-only fast path. Recorded as a G8 deferral — 'once'
//     rows are ignored here until the consumption design lands.
//
// Errors report false: fail-safe toward enforcement, never toward a
// silent grant.
func (s *Store) ApprovalActiveFor(ctx context.Context, ruleID, sessionID, projectRootHash string, now time.Time) bool {
	const q = `
		SELECT 1 FROM guard_approvals
		WHERE rule_id = ?
		  AND (expires_at = '' OR expires_at > ?)
		  AND (
		        scope = 'global'
		     OR (scope = 'session' AND session_id != '' AND session_id = ?)
		     OR (scope = 'project' AND project_root_hash != '' AND project_root_hash = ?)
		  )
		LIMIT 1`
	var one int
	err := s.db.QueryRowContext(ctx, q, ruleID, timestamp(now), sessionID, projectRootHash).Scan(&one)
	return err == nil
}

// ProjectRootForSession resolves a session's project root path (empty
// when the session is unknown or carries no project). The dashboard's
// approval-grant endpoint uses it to anchor a project-scoped grant
// from a verdict row's session id — the hash itself is computed at the
// guard layer (guard.HashProjectRoot), keeping one hash owner.
func (s *Store) ProjectRootForSession(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", nil
	}
	var root sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT p.root_path FROM sessions s
		JOIN projects p ON p.id = s.project_id
		WHERE s.id = ?`, sessionID).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store.ProjectRootForSession: %w", err)
	}
	return root.String, nil
}

// GuardEventExistsForAction reports whether a guard event already
// anchors to (actionID, ruleID) — the `observer guard rescan`
// idempotency gate: re-running a rescan over the same window must not
// duplicate verdict rows for actions already judged (by the live
// ingest seam or a prior rescan).
func (s *Store) GuardEventExistsForAction(ctx context.Context, actionID int64, ruleID string) (bool, error) {
	if actionID == 0 {
		return false, nil
	}
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM guard_events WHERE action_id = ? AND rule_id = ? LIMIT 1`,
		actionID, ruleID).Scan(&one)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("store.GuardEventExistsForAction: %w", err)
	}
}

// LoadGuardReplayInputs loads historical actions as guard evaluation
// inputs for `observer guard simulate` / `observer guard rescan`
// (§11.1: replay history against CURRENT policy — possible only
// because the history exists). Joins projects for the root the
// boundary rules need; rows order by timestamp so taint sequencing
// replays faithfully. limit <= 0 defaults to 50k (a generous sweep
// bound; the CLI reports when it was hit so a silent cap never reads
// as full coverage).
func (s *Store) LoadGuardReplayInputs(ctx context.Context, since time.Time, limit int) ([]guard.ActionInput, error) {
	if limit <= 0 {
		limit = 50000
	}
	const q = `
		SELECT a.id, a.session_id, COALESCE(p.root_path, ''), a.tool,
		       a.action_type, COALESCE(a.target, ''), a.timestamp,
		       COALESCE(a.turn_index, 0), COALESCE(a.success, 1)
		FROM actions a
		LEFT JOIN projects p ON a.project_id = p.id
		WHERE a.timestamp >= ?
		ORDER BY a.timestamp ASC, a.id ASC
		LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, timestamp(since), limit)
	if err != nil {
		return nil, fmt.Errorf("store.LoadGuardReplayInputs: query: %w", err)
	}
	defer rows.Close()
	var out []guard.ActionInput
	for rows.Next() {
		var in guard.ActionInput
		var ts string
		var success int
		if err := rows.Scan(&in.ActionID, &in.SessionID, &in.ProjectRoot, &in.Tool,
			&in.ActionType, &in.Target, &ts, &in.TurnIndex, &success); err != nil {
			return nil, fmt.Errorf("store.LoadGuardReplayInputs: scan: %w", err)
		}
		in.Timestamp = parseStamp(ts)
		in.Success = success != 0
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadGuardReplayInputs: rows: %w", err)
	}
	return out, nil
}

// PruneGuardRows applies §10.3 retention:
//
//   - guard_events: removes the maximal chain PREFIX (by id) whose
//     rows are all older than retentionDays, then records the last
//     pruned row's chain_hash as the schema_meta checkpoint so chain
//     verification re-anchors (§10.3 "prune writes a checkpoint").
//     Pruning by prefix — not by raw ts — means an old-stamped row
//     that landed AFTER a newer row (clock skew) is retained rather
//     than punching a hole in the chain; it ages out on a later pass.
//   - guard_approvals: removes approvals that are BOTH expired and
//     older than retentionDays. Non-expiring grants (expires_at = ”)
//     persist — they are live configuration, and the §14.4 exception
//     register wants expired-but-recent rows kept for review.
//   - guard_pins / guard_policy_state: never pruned here. Pins are
//     live config state, not time-series; the policy-state version
//     log is compliance data with negligible volume (a row per policy
//     change). Recorded as a deliberate decision per the cachetrack
//     §9 lesson.
//
// retentionDays <= 0 is "no prune" (returns 0) so callers can pass
// config straight through. Returns total rows removed.
func (s *Store) PruneGuardRows(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := timestamp(time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour))

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.PruneGuardRows: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var removed int

	// Prefix boundary: the smallest id that must be KEPT. Rows with
	// ts >= cutoff are kept; everything below the first kept id goes.
	// COALESCE to MAX(id)+1 when every row is older than the cutoff
	// (prune-all). Lexicographic ts comparison is valid because
	// timestamp() emits fixed-form UTC RFC3339Nano.
	var firstKeep int64
	err = tx.QueryRowContext(ctx, `
		SELECT COALESCE(
		    (SELECT MIN(id) FROM guard_events WHERE ts >= ?),
		    (SELECT COALESCE(MAX(id), 0) + 1 FROM guard_events))`,
		cutoff).Scan(&firstKeep)
	if err != nil {
		return 0, fmt.Errorf("store.PruneGuardRows: boundary: %w", err)
	}

	// Checkpoint BEFORE deleting: the chain_hash of the newest row
	// being pruned anchors the surviving suffix.
	var checkpoint string
	err = tx.QueryRowContext(ctx, `
		SELECT chain_hash FROM guard_events WHERE id < ? ORDER BY id DESC LIMIT 1`,
		firstKeep).Scan(&checkpoint)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// nothing to prune; skip both the checkpoint write and the delete
	case err != nil:
		return 0, fmt.Errorf("store.PruneGuardRows: checkpoint read: %w", err)
	default:
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO schema_meta(key, value) VALUES(?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			guardChainCheckpointKey, checkpoint); err != nil {
			return 0, fmt.Errorf("store.PruneGuardRows: checkpoint write: %w", err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM guard_events WHERE id < ?`, firstKeep)
		if err != nil {
			return 0, fmt.Errorf("store.PruneGuardRows: events: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += int(n)
	}

	res, err := tx.ExecContext(ctx, `
		DELETE FROM guard_approvals
		WHERE ts < ? AND expires_at != '' AND expires_at < ?`,
		cutoff, timestamp(time.Now().UTC()))
	if err != nil {
		return 0, fmt.Errorf("store.PruneGuardRows: approvals: %w", err)
	}
	n, _ := res.RowsAffected()
	removed += int(n)

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.PruneGuardRows: commit: %w", err)
	}
	return removed, nil
}

// --- §15 cloud-dispatcher helpers (G15) --------------------------------------

// guardCloudCursorKey is the schema_meta key holding the cloud
// dispatcher's high-water guard_events id.
const guardCloudCursorKey = "guard_cloud_cursor"

// GuardEventsAfter returns guard_events rows with id strictly greater
// than afterID, ascending, bounded by limit (<=0 = 200). This is the
// §15 cloud dispatcher's read: an id-ordered tail that covers every
// recording process (hook, watcher, proxy) uniformly, so cloud
// alerting needs zero hot-path coupling.
func (s *Store) GuardEventsAfter(ctx context.Context, afterID int64, limit int) ([]GuardEventRow, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		guardEventSelectColumns+` WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.GuardEventsAfter: query: %w", err)
	}
	return loadGuardEventRows(rows, "store.GuardEventsAfter")
}

// SaveGuardCloudCursor persists the cloud dispatcher's high-water
// guard_events id in schema_meta (the Save/LoadOrgPolicyETag pattern —
// zero migrations).
func (s *Store) SaveGuardCloudCursor(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		guardCloudCursorKey, strconv.FormatInt(id, 10)); err != nil {
		return fmt.Errorf("store.SaveGuardCloudCursor: %w", err)
	}
	return nil
}

// LoadGuardCloudCursor reads the cursor; 0 when never saved (the
// dispatcher then anchors at the current tail so pre-existing history
// never alert-storms on first enable).
func (s *Store) LoadGuardCloudCursor(ctx context.Context) (int64, error) {
	v, err := s.readMeta(ctx, guardCloudCursorKey)
	if err != nil {
		return 0, fmt.Errorf("store.LoadGuardCloudCursor: %w", err)
	}
	if v == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store.LoadGuardCloudCursor: parse %q: %w", v, err)
	}
	return id, nil
}

// --- §11.4 / §14.4 export + evidence-pack helpers (G16) ----------------------

// guardOTelCursorKey is the schema_meta key holding the [guard.export]
// otel feed's high-water guard_events id. Deliberately SEPARATE from
// guardCloudCursorKey — the cloud dispatcher and the OTel tail are
// independent consumers of the same id-ordered tail, each resuming
// from its own position.
const guardOTelCursorKey = "guard_otel_cursor"

// SaveGuardOTelCursor persists the OTel guard-event tail's high-water
// guard_events id (the SaveGuardCloudCursor pattern — schema_meta,
// zero migrations).
func (s *Store) SaveGuardOTelCursor(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		guardOTelCursorKey, strconv.FormatInt(id, 10)); err != nil {
		return fmt.Errorf("store.SaveGuardOTelCursor: %w", err)
	}
	return nil
}

// LoadGuardOTelCursor reads the OTel cursor; 0 when never saved (the
// tail then anchors at the current tip so pre-existing history never
// floods the collector on first enable — the cloud-dispatcher
// posture).
func (s *Store) LoadGuardOTelCursor(ctx context.Context) (int64, error) {
	v, err := s.readMeta(ctx, guardOTelCursorKey)
	if err != nil {
		return 0, fmt.Errorf("store.LoadGuardOTelCursor: %w", err)
	}
	if v == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store.LoadGuardOTelCursor: parse %q: %w", v, err)
	}
	return id, nil
}

// LoadGuardPolicyStates returns the FULL guard_policy_state load log
// in id (load) order — the §14.4 policy-change log. Reading the whole
// table is deliberate: volume is negligible by design (one row per
// policy CHANGE — RecordGuardPolicyState skips unchanged reloads, and
// PruneGuardRows never touches this table), and the evidence pack
// needs effective-at views for arbitrary past instants, which a
// latest-only read cannot answer.
func (s *Store) LoadGuardPolicyStates(ctx context.Context) ([]GuardPolicyStateRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, layer, path, version, content_hash,
		       COALESCE(signature,''), loaded_at
		FROM guard_policy_state ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store.LoadGuardPolicyStates: query: %w", err)
	}
	defer rows.Close()
	var out []GuardPolicyStateRow
	for rows.Next() {
		var r GuardPolicyStateRow
		var loadedAt string
		if err := rows.Scan(&r.ID, &r.Layer, &r.Path, &r.Version,
			&r.ContentHash, &r.Signature, &loadedAt); err != nil {
			return nil, fmt.Errorf("store.LoadGuardPolicyStates: scan: %w", err)
		}
		r.LoadedAt = parseStamp(loadedAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadGuardPolicyStates: rows: %w", err)
	}
	return out, nil
}
