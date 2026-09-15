package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// terminaldevorgrows.go is the W2.6 org-wire seam for the per-developer
// terminal-run / terminal-command / remote-access visibility wire (org-parity
// plan §4 "W2.6", docs/plans/org-parity-full-depth-plan-2026-08-24.md). This
// file — NOT orgpush.go — owns the terminal_run / terminal_run_session /
// terminal_commands / remote_audit reads for the org-push path (module-
// boundary discipline: one owner per table/read seam; the push path composes
// these rows via a function call, exactly like SelectSessionProcessRows in
// processorgrows.go).
//
// *** LOAD-BEARING CROSS-FILE NOTE (read before wiring these into orgpush.go) ***
// tests/invariant/privacy_test.go currently pins ALL FOUR of these table names
// (remote_audit, terminal_run, terminal_run_session, terminal_commands) in
// forbiddenCacheTables, and carries two dedicated, whole-batch,
// field-agnostic tests — TestRemoteAuditTablePinnedOutOfPush and
// TestTerminalRunTablesPinnedOutOfPush — that seed a sentinel value into
// each table, call SelectUnpushedSince with maximum disclosure
// (ShareOptions{FullContent: true}), and assert the sentinel string never
// appears anywhere in the marshalled batch. Those tests were written under
// the PRE-org-parity ("never ships, not even under full_content") posture,
// and the node-side migration header comments for remote_audit (063) and
// terminal_run/terminal_commands (064/065) say the same thing.
//
// W2.6's own spec text (§4) explicitly and deliberately instructs shipping
// this exact data raw under admin_managed, per §0's "enterprise-first —
// SUPERSEDES any teams-privacy framing below" governing rule. That is a
// sanctioned reversal, not a bug — but it means TestRemoteAuditTablePinnedOutOfPush
// and TestTerminalRunTablesPinnedOutOfPush WILL start failing (by design: the
// sentinel is supposed to fire loudly on an unreviewed leak) the moment
// SelectTerminalRunRows / SelectTerminalCommandRows / SelectRemoteAuditRows
// below are actually composed into orgpush.go's SelectUnpushedSince. Whoever
// does that wiring must, in the SAME change, update forbiddenCacheTables and
// rewrite (or narrow) those two tests to reflect the new admin_managed-gated
// posture — this file intentionally does NOT touch tests/invariant/privacy_test.go
// (out of this task's scope; a shared file other agents also touch).

// terminalDevWindowDays bounds the recompute to runs/events active in the
// recent window; the server upserts by natural key, so re-pushing a window is
// idempotent — same model as sessionProcessWindowDays / verbositySummaryWindowDays.
const terminalDevWindowDays = 7

// terminalCommandsPerRunCap bounds how many terminal_commands rows a single
// run contributes per push. A run is an interactive terminal session and can
// in principle accumulate many boundaries; 100 comfortably covers a normal
// working session's command count while bounding a pathological
// rapid-command-loop run from dominating the payload. Kept the most RECENT
// boundaries (by turn_seq, which is monotonic within a run) per run, applied
// in Go after an ORDER BY run_id, turn_seq DESC — this codebase does not use
// SQL window functions (no ROW_NUMBER() OVER usage exists elsewhere in
// internal/store; see sessionProcessRunCap's identical rationale).
const terminalCommandsPerRunCap = 100

// remoteAuditEventCap bounds the total remote_audit rows a single push sends.
// Unlike terminal_commands (bounded per-run), remote-access events are not
// naturally scoped to a single parent row, so this is a flat cap on the
// windowed set, keeping the MOST RECENT events (by id, remote_audit's own
// insertion order) — 500 comfortably covers a developer's connect/pair/revoke
// activity over the trailing window while bounding worst case (mirrors the
// guard package's guardSessionEventCap-style flat caps).
const remoteAuditEventCap = 500

// SelectTerminalRunRows reads terminal_run (+ its best correlated session via
// terminal_run_session, + a terminal_commands COUNT per run) for every run
// launched within the trailing window. It reuses the exact correlated-subquery
// idiom internal/store/termrun.go::ListTerminalRuns already uses for the
// node's own terminal-history view, so the org panel's "attached session"
// picks the SAME best match. OrgID/UserEmail are left zero here — the
// orgclient push loop stamps them (forcePusherOrgID / forcePusherEmail),
// exactly like SelectSessionProcessRows and SelectSessionVerbositySummaries.
func (s *Store) SelectTerminalRunRows(ctx context.Context) ([]orgcontract.TerminalRunRow, error) {
	since := isoSinceDays(terminalDevWindowDays)
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.run_id, r.tool, r.kind, r.source_session_id,
		        (SELECT trs.session_id FROM terminal_run_session trs
		           WHERE trs.run_id = r.run_id
		           ORDER BY trs.confidence DESC, trs.id ASC LIMIT 1),
		        (SELECT trs.confidence FROM terminal_run_session trs
		           WHERE trs.run_id = r.run_id
		           ORDER BY trs.confidence DESC, trs.id ASC LIMIT 1),
		        r.launched_at, r.ended_at, r.exit_code, r.end_reason,
		        (SELECT COUNT(*) FROM terminal_commands tc WHERE tc.run_id = r.run_id)
		   FROM terminal_run r
		  WHERE r.launched_at >= ?
		  ORDER BY r.launched_at DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectTerminalRunRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.TerminalRunRow{}
	for rows.Next() {
		var (
			r        orgcontract.TerminalRunRow
			bestSess sql.NullString
			bestConf sql.NullFloat64
			ended    sql.NullString
			exit     sql.NullInt64
		)
		if err := rows.Scan(
			&r.RunID, &r.Tool, &r.Kind, &r.SourceSessionID,
			&bestSess, &bestConf,
			&r.LaunchedAt, &ended, &exit, &r.EndReason,
			&r.CommandCount,
		); err != nil {
			return nil, fmt.Errorf("store.SelectTerminalRunRows: scan: %w", err)
		}
		if bestSess.Valid {
			r.CorrelatedSessionID = bestSess.String
		}
		if bestConf.Valid {
			r.CorrelatedConfidence = bestConf.Float64
		}
		if ended.Valid {
			r.EndedAt = ended.String
			r.Exited = true
		}
		if exit.Valid {
			r.ExitCode = exit.Int64
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectTerminalRunRows: %w", err)
	}
	return out, nil
}

// SelectTerminalCommandRows reads terminal_commands for every run launched
// within the trailing window, capped at terminalCommandsPerRunCap most-recent
// boundaries per run. Never reads command text or output — the node itself
// never stores it (see the TerminalCommandRow ground-truth doc comment in
// internal/orgcontract/terminaldev.go).
func (s *Store) SelectTerminalCommandRows(ctx context.Context) ([]orgcontract.TerminalCommandRow, error) {
	since := isoSinceDays(terminalDevWindowDays)
	rows, err := s.db.QueryContext(ctx,
		`SELECT tc.run_id, tc.turn_seq, tc.started_at, tc.ended_at, tc.exit_code, tc.trust, tc.cmd_hash
		   FROM terminal_commands tc
		   JOIN terminal_run r ON r.run_id = tc.run_id
		  WHERE r.launched_at >= ?
		  ORDER BY tc.run_id, tc.turn_seq DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectTerminalCommandRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	perRun := map[string]int{}
	out := []orgcontract.TerminalCommandRow{}
	for rows.Next() {
		var (
			c       orgcontract.TerminalCommandRow
			started sql.NullString
			ended   sql.NullString
			exit    sql.NullInt64
			trust   sql.NullString
			cmdHash sql.NullString
		)
		if err := rows.Scan(&c.RunID, &c.TurnSeq, &started, &ended, &exit, &trust, &cmdHash); err != nil {
			return nil, fmt.Errorf("store.SelectTerminalCommandRows: scan: %w", err)
		}

		if perRun[c.RunID] >= terminalCommandsPerRunCap {
			continue
		}
		perRun[c.RunID]++

		if started.Valid {
			c.StartedAt = started.String
		}
		if ended.Valid {
			c.EndedAt = ended.String
			c.Exited = true
		}
		if exit.Valid {
			c.ExitCode = exit.Int64
		}
		c.Trust = trust.String
		c.CmdHash = cmdHash.String

		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectTerminalCommandRows: %w", err)
	}
	return out, nil
}

// SelectRemoteAuditRows reads remote_audit for events within the trailing
// window, newest first, flat-capped at remoteAuditEventCap. EventKey is the
// stringified local remote_audit.id (unique per node, not globally — the
// server's natural key is (org_id, user_email, event_key)).
func (s *Store) SelectRemoteAuditRows(ctx context.Context) ([]orgcontract.RemoteAuditRow, error) {
	since := isoSinceDays(terminalDevWindowDays)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, kind, session_id, principal, remote_addr, route, decision, detail
		   FROM remote_audit
		  WHERE ts >= ?
		  ORDER BY id DESC
		  LIMIT ?`, since, remoteAuditEventCap)
	if err != nil {
		return nil, fmt.Errorf("store.SelectRemoteAuditRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.RemoteAuditRow{}
	for rows.Next() {
		var (
			r  orgcontract.RemoteAuditRow
			id int64
		)
		if err := rows.Scan(
			&id, &r.Timestamp, &r.Kind, &r.SessionID, &r.Principal,
			&r.RemoteAddr, &r.Route, &r.Decision, &r.Detail,
		); err != nil {
			return nil, fmt.Errorf("store.SelectRemoteAuditRows: scan: %w", err)
		}
		r.EventKey = fmt.Sprintf("%d", id)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectRemoteAuditRows: %w", err)
	}
	return out, nil
}

// probeTerminalActivity is the Track R2 change-detection probe SHARED by every
// wire fed from the terminal tables: terminal_runs and terminal_commands (this
// file) and terminal_summary (terminalsummary.go). It lives here — with the
// other terminal_* SQL — so orgsnapgate.go and orgpush.go stay free of the
// table names the privacy sentinel forbids there.
//
// PROBE: (MAX(rowid), COUNT(*), COUNT(ended_at), MAX(ended_at)) over
// terminal_run, plus MAX(id) on terminal_commands and terminal_run_session.
//
// WHY ended_at IS IN THE PROBE: terminal_run is the most visibly MUTABLE
// substrate in the snapshot family — a run is INSERTed at launch and later
// UPDATEd with ended_at / exit_code / end_reason. An id-only probe would leave
// every finished run rendered as still-running on the org dashboard until the
// next launch. Counting and maximising ended_at catches the transition that
// matters, and terminal_run is small (one row per terminal launch), so the
// scan is trivial. terminal_commands supplies the per-run command count the
// wires ship, and terminal_run_session the session correlation.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: the shutdown stampers set
// end_reason WITHOUT setting ended_at on attach runs, and the resume path
// rewrites end_reason alone; neither moves the probe. snapGate's maxSkipAge
// recomputes within the hour.
func (s *Store) probeTerminalActivity(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'tr' || (SELECT COALESCE(MAX(rowid), 0) || '/' || COUNT(*) || '/' || COUNT(ended_at) ||
		                       '/' || COALESCE(MAX(ended_at), '')
		                  FROM terminal_run) ||
		       ':tc' || (SELECT COALESCE(MAX(id), 0) FROM terminal_commands) ||
		       ':ts' || (SELECT COALESCE(MAX(id), 0) FROM terminal_run_session)`)
}

// probeRemoteAudit is the Track R2 change-detection probe SHARED by both wires
// fed from the remote-audit log: remote_audit_rows (this file) and
// remote_audit_summary (terminalsummary.go). It lives here — with the other
// remote_audit SQL — so orgsnapgate.go and orgpush.go stay free of the table
// name the privacy sentinel forbids there.
//
// PROBE: COALESCE(MAX(id),0) — one index-endpoint seek, O(1).
//
// WHY THAT REFLECTS MUTATION: remote_audit is a strictly append-only audit log;
// InsertRemoteAudit is its only writer and an audit row is never revised.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: retention DELETEs inside the 7-day
// window are invisible to MAX(id); snapGate's maxSkipAge recomputes within the
// hour.
func (s *Store) probeRemoteAudit(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'ra' || COALESCE(MAX(id), 0) FROM remote_audit`)
}
