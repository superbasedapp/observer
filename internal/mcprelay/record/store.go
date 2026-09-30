// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// SQLStore is the production Store over the node's migrated *sql.DB (agent
// migration 131). It is the ONE owner of the three mcp_relay_* tables.
type SQLStore struct {
	db      *sql.DB
	nodeKey string
}

var _ Store = (*SQLStore)(nil)

// NewSQLStore opens the store over db. nodeKey is the node's stable identity
// the chain genesis is derived from (Genesis); a store opened with an empty
// nodeKey is READ-ONLY for the chain (Append and Verify return ErrNoNodeKey),
// which is how the push composer reads records without owning the genesis.
func NewSQLStore(db *sql.DB, nodeKey string) *SQLStore {
	return &SQLStore{db: db, nodeKey: nodeKey}
}

// recordColumns is every mcp_relay_record column in DDL order; scanRecord
// and insertChainedTx depend on this exact order.
const recordColumns = `seq, record_kind, ts, family, decision_seq,
	vserver, server_ref_hmac, tool_ref_hmac, server, tool,
	call_id, trace_id, coding_session_id, turn_ref, action_ref, corr_confidence,
	method, event_kind, decision, reason_code, client_attestation, credential_assurance, capture_level,
	args_excerpt, args_full, args_scrub_status, result_full, result_scrub_status,
	error_full, error_scrub_status, elicitation_full, elicitation_scrub_status,
	result_size_bytes, latency_ms, result_status,
	gap_from, gap_to, lost_count, gap_reason,
	resolves_seq, resolved_range_start, resolved_range_end, resolution,
	chain_prev, chain_hash`

// Append implements Store.
func (s *SQLStore) Append(ctx context.Context, rec Record) (AppendResult, error) {
	if s.nodeKey == "" {
		return AppendResult{}, ErrNoNodeKey
	}
	if rec.Family == "" {
		rec.Family = DefaultFamily
	}
	if err := rec.Validate(); err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.checkParentTx(ctx, tx, rec); err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: %w", err)
	}
	head, err := s.headTx(ctx, tx)
	if err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: %w", err)
	}
	var res AppendResult
	// R13.5 step 3: outstanding pending loss becomes a gap record FIRST, in
	// this same transaction, and the accounting is zeroed with it.
	pl, err := pendingLossTx(ctx, tx, rec.Family)
	if err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: %w", err)
	}
	if pl.Count > 0 {
		gap := gapFromPendingLoss(pl, rec.TS, rec.Family)
		gap, err = insertChainedTx(ctx, tx, gap, &head)
		if err != nil {
			return AppendResult{}, fmt.Errorf("record.Append: gap: %w", err)
		}
		if err := setPendingLossTx(ctx, tx, rec.Family, PendingLoss{}); err != nil {
			return AppendResult{}, fmt.Errorf("record.Append: zero pending loss: %w", err)
		}
		res.Gap = &gap
	}
	rec, err = insertChainedTx(ctx, tx, rec, &head)
	if err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AppendResult{}, fmt.Errorf("record.Append: commit: %w", err)
	}
	res.Record = rec
	return res, nil
}

// gapFromPendingLoss builds the gap record that accounts for p.
func gapFromPendingLoss(p PendingLoss, ts int64, family string) Record {
	from, to := p.FirstAt, p.LastAt
	if from <= 0 {
		from = ts
	}
	if to < from {
		to = from
	}
	reason := p.Reason
	if reason == "" {
		reason = "local_append_failed"
	}
	return Record{
		Kind: KindGap, TS: ts, Family: family,
		GapFrom: Int(from), GapTo: Int(to), LostCount: Int(p.Count), GapReason: reason,
	}
}

// checkParentTx enforces the cross-row rules the DDL cannot express
// (R14.3): a completion points at a decision row; a gap_resolution points at
// a gap row and lies within its range.
func (s *SQLStore) checkParentTx(ctx context.Context, tx *sql.Tx, rec Record) error {
	switch rec.Kind {
	case KindCompletion:
		parent, err := getTx(ctx, tx, *rec.DecisionSeq)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: decision_seq %d does not exist", ErrInvalid, *rec.DecisionSeq)
		}
		if err != nil {
			return err
		}
		if parent.Kind != KindDecision {
			return fmt.Errorf("%w: decision_seq %d is a %s row, not a decision", ErrInvalid, *rec.DecisionSeq, parent.Kind)
		}
	case KindGapResolution:
		parent, err := getTx(ctx, tx, *rec.ResolvesSeq)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: resolves_seq %d does not exist", ErrInvalid, *rec.ResolvesSeq)
		}
		if err != nil {
			return err
		}
		if parent.Kind != KindGap {
			return fmt.Errorf("%w: resolves_seq %d is a %s row, not a gap", ErrInvalid, *rec.ResolvesSeq, parent.Kind)
		}
		if *rec.ResolvedRangeStart < *parent.GapFrom || *rec.ResolvedRangeEnd > *parent.GapTo {
			return fmt.Errorf("%w: resolved range [%d,%d] is not contained in gap %d's range [%d,%d]",
				ErrInvalid, *rec.ResolvedRangeStart, *rec.ResolvedRangeEnd, parent.Seq, *parent.GapFrom, *parent.GapTo)
		}
	}
	return nil
}

// insertChainedTx links rec at head+1 and inserts it, advancing head.
func insertChainedTx(ctx context.Context, tx *sql.Tx, rec Record, head *Head) (Record, error) {
	rec.Seq = head.Seq + 1
	rec.ChainPrev = head.Hash
	rec.ChainHash = HashRecord(Canonical(rec), rec.ChainPrev)
	_, err := tx.ExecContext(ctx, `INSERT INTO mcp_relay_record (`+recordColumns+`) VALUES (
		?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,?,?,
		?,?,?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,
		?,?,?,
		?,?,?,?,
		?,?,?,?,
		?,?)`,
		rec.Seq, string(rec.Kind), rec.TS, rec.Family, nullInt(rec.DecisionSeq),
		nullStr(rec.VServer), nullStr(rec.ServerRefHMAC), nullStr(rec.ToolRefHMAC), nullStr(rec.Server), nullStr(rec.Tool),
		nullStr(rec.CallID), nullStr(rec.TraceID), nullStr(rec.CodingSessionID), nullStr(rec.TurnRef), nullStr(rec.ActionRef), nullStr(string(rec.CorrConfidence)),
		nullStr(rec.Method), nullStr(string(rec.EventKind)), nullStr(string(rec.Decision)), nullStr(rec.ReasonCode), nullStr(string(rec.ClientAttestation)), nullStr(rec.CredentialAssurance), nullStr(string(rec.CaptureLevel)),
		nullStr(rec.ArgsExcerpt), nullStr(rec.ArgsFull), nullStr(string(rec.ArgsScrubStatus)), nullStr(rec.ResultFull), nullStr(string(rec.ResultScrubStatus)),
		nullStr(rec.ErrorFull), nullStr(string(rec.ErrorScrubStatus)), nullStr(rec.ElicitationFull), nullStr(string(rec.ElicitationScrubStatus)),
		nullInt(rec.ResultSizeBytes), nullInt(rec.LatencyMS), nullStr(rec.ResultStatus),
		nullInt(rec.GapFrom), nullInt(rec.GapTo), nullInt(rec.LostCount), nullStr(rec.GapReason),
		nullInt(rec.ResolvesSeq), nullInt(rec.ResolvedRangeStart), nullInt(rec.ResolvedRangeEnd), nullStr(string(rec.Resolution)),
		rec.ChainPrev, rec.ChainHash)
	if err != nil {
		return Record{}, fmt.Errorf("insert seq %d: %w", rec.Seq, err)
	}
	head.Seq, head.Hash = rec.Seq, rec.ChainHash
	return rec, nil
}

// Head implements Store.
func (s *SQLStore) Head(ctx context.Context) (Head, error) {
	return s.headTx(ctx, s.db)
}

func (s *SQLStore) headTx(ctx context.Context, q querier) (Head, error) {
	var h Head
	err := q.QueryRowContext(ctx, `SELECT seq, chain_hash FROM mcp_relay_record ORDER BY seq DESC LIMIT 1`).Scan(&h.Seq, &h.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return Head{Seq: 0, Hash: Genesis(s.nodeKey)}, nil
	}
	if err != nil {
		return Head{}, fmt.Errorf("record.Head: %w", err)
	}
	return h, nil
}

// querier is the subset of *sql.DB / *sql.Tx the reads use.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Get implements Store.
func (s *SQLStore) Get(ctx context.Context, seq int64) (Record, error) {
	return getTx(ctx, s.db, seq)
}

func getTx(ctx context.Context, q querier, seq int64) (Record, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+recordColumns+` FROM mcp_relay_record WHERE seq = ?`, seq)
	if err != nil {
		return Record{}, fmt.Errorf("record.Get: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Record{}, fmt.Errorf("record.Get: %w", err)
		}
		return Record{}, ErrNotFound
	}
	r, err := scanRecord(rows)
	if err != nil {
		return Record{}, fmt.Errorf("record.Get: %w", err)
	}
	return r, nil
}

// ReadAfter implements Store.
func (s *SQLStore) ReadAfter(ctx context.Context, after int64, limit int) ([]Record, error) {
	q := `SELECT ` + recordColumns + ` FROM mcp_relay_record WHERE seq > ? ORDER BY seq ASC`
	args := []any{after}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("record.ReadAfter: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("record.ReadAfter: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("record.ReadAfter: %w", err)
	}
	return out, nil
}

// Verify implements Store.
func (s *SQLStore) Verify(ctx context.Context) (VerifyResult, error) {
	if s.nodeKey == "" {
		return VerifyResult{}, ErrNoNodeKey
	}
	all, err := s.ReadAfter(ctx, 0, 0)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("record.Verify: %w", err)
	}
	return VerifyRecords(Genesis(s.nodeKey), all), nil
}

// DailyActivity is one bucket of the HMAC-only daily aggregate the org wire
// carries (orgcontract.MCPRelayActivityRow): decision rows grouped by UTC
// day x virtual server x tool_ref_hmac x decision x client_attestation.
type DailyActivity struct {
	Day               string
	VServer           string
	ToolRefHMAC       string
	Decision          Decision
	ClientAttestation ClientAttestation
	N                 int64
}

// DailyActivity aggregates the decision rows with ts >= sinceTS (unix
// seconds). Only decision rows count: completions, gaps and resolutions are
// not calls. NULL dimensions read as "".
func (s *SQLStore) DailyActivity(ctx context.Context, sinceTS int64) ([]DailyActivity, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%d', ts, 'unixepoch'), COALESCE(vserver, ''), COALESCE(tool_ref_hmac, ''),
		       decision, COALESCE(client_attestation, ''), COUNT(*)
		FROM mcp_relay_record
		WHERE record_kind = 'decision' AND ts >= ?
		GROUP BY 1, 2, 3, 4, 5
		ORDER BY 1, 2, 3, 4, 5`, sinceTS)
	if err != nil {
		return nil, fmt.Errorf("record.DailyActivity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DailyActivity
	for rows.Next() {
		var d DailyActivity
		var decision, att string
		if err := rows.Scan(&d.Day, &d.VServer, &d.ToolRefHMAC, &decision, &att, &d.N); err != nil {
			return nil, fmt.Errorf("record.DailyActivity: scan: %w", err)
		}
		d.Decision, d.ClientAttestation = Decision(decision), ClientAttestation(att)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("record.DailyActivity: %w", err)
	}
	return out, nil
}

// scanRecord reads one recordColumns row.
func scanRecord(rows *sql.Rows) (Record, error) {
	var (
		r                                                                                      Record
		kind                                                                                   string
		decisionSeq, resultSize, latency, gapFrom, gapTo, lost, resolves, rangeStart, rangeEnd sql.NullInt64
		vserver, serverHMAC, toolHMAC, server, tool                                            sql.NullString
		callID, traceID, session, turn, action, corr                                           sql.NullString
		method, event, decision, reason, att, cred, capture                                    sql.NullString
		argsEx, argsFull, argsSt, resFull, resSt, errFull, errSt, eliFull, eliSt               sql.NullString
		resultStatus, gapReason, resolution                                                    sql.NullString
	)
	if err := rows.Scan(&r.Seq, &kind, &r.TS, &r.Family, &decisionSeq,
		&vserver, &serverHMAC, &toolHMAC, &server, &tool,
		&callID, &traceID, &session, &turn, &action, &corr,
		&method, &event, &decision, &reason, &att, &cred, &capture,
		&argsEx, &argsFull, &argsSt, &resFull, &resSt,
		&errFull, &errSt, &eliFull, &eliSt,
		&resultSize, &latency, &resultStatus,
		&gapFrom, &gapTo, &lost, &gapReason,
		&resolves, &rangeStart, &rangeEnd, &resolution,
		&r.ChainPrev, &r.ChainHash); err != nil {
		return Record{}, err
	}
	r.Kind = Kind(kind)
	r.DecisionSeq = optInt(decisionSeq)
	r.VServer, r.ServerRefHMAC, r.ToolRefHMAC, r.Server, r.Tool = vserver.String, serverHMAC.String, toolHMAC.String, server.String, tool.String
	r.CallID, r.TraceID, r.CodingSessionID, r.TurnRef, r.ActionRef = callID.String, traceID.String, session.String, turn.String, action.String
	r.CorrConfidence = CorrConfidence(corr.String)
	r.Method, r.EventKind, r.Decision, r.ReasonCode = method.String, EventKind(event.String), Decision(decision.String), reason.String
	r.ClientAttestation, r.CredentialAssurance, r.CaptureLevel = ClientAttestation(att.String), cred.String, CaptureLevel(capture.String)
	r.ArgsExcerpt, r.ArgsFull, r.ArgsScrubStatus = argsEx.String, argsFull.String, ScrubStatus(argsSt.String)
	r.ResultFull, r.ResultScrubStatus = resFull.String, ScrubStatus(resSt.String)
	r.ErrorFull, r.ErrorScrubStatus = errFull.String, ScrubStatus(errSt.String)
	r.ElicitationFull, r.ElicitationScrubStatus = eliFull.String, ScrubStatus(eliSt.String)
	r.ResultSizeBytes, r.LatencyMS, r.ResultStatus = optInt(resultSize), optInt(latency), resultStatus.String
	r.GapFrom, r.GapTo, r.LostCount, r.GapReason = optInt(gapFrom), optInt(gapTo), optInt(lost), gapReason.String
	r.ResolvesSeq, r.ResolvedRangeStart, r.ResolvedRangeEnd = optInt(resolves), optInt(rangeStart), optInt(rangeEnd)
	r.Resolution = Resolution(resolution.String)
	return r, nil
}

func optInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// --- mcp_relay_state -------------------------------------------------------

// PendingLoss implements Store.
func (s *SQLStore) PendingLoss(ctx context.Context, family string) (PendingLoss, error) {
	return pendingLossTx(ctx, s.db, family)
}

func pendingLossTx(ctx context.Context, q querier, family string) (PendingLoss, error) {
	var (
		p                PendingLoss
		first, last      sql.NullInt64
		reason, callJSON sql.NullString
	)
	err := q.QueryRowContext(ctx, `SELECT pending_loss_count, pending_loss_first_at, pending_loss_last_at,
		pending_loss_reason, pending_loss_call_ids FROM mcp_relay_state WHERE family = ?`, family).
		Scan(&p.Count, &first, &last, &reason, &callJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return PendingLoss{}, nil
	}
	if err != nil {
		return PendingLoss{}, fmt.Errorf("record.PendingLoss: %w", err)
	}
	p.FirstAt, p.LastAt, p.Reason = first.Int64, last.Int64, reason.String
	if callJSON.Valid && callJSON.String != "" {
		if err := json.Unmarshal([]byte(callJSON.String), &p.CallIDs); err != nil {
			return PendingLoss{}, fmt.Errorf("record.PendingLoss: call ids: %w", err)
		}
	}
	return p, nil
}

// SetPendingLoss implements Store.
func (s *SQLStore) SetPendingLoss(ctx context.Context, family string, p PendingLoss) error {
	return setPendingLossTx(ctx, s.db, family, p)
}

func setPendingLossTx(ctx context.Context, q querier, family string, p PendingLoss) error {
	if family == "" {
		family = DefaultFamily
	}
	if len(p.CallIDs) > MaxPendingLossCallIDs {
		p.CallIDs = p.CallIDs[:MaxPendingLossCallIDs]
	}
	var callJSON any
	if len(p.CallIDs) > 0 {
		b, err := json.Marshal(p.CallIDs)
		if err != nil {
			return fmt.Errorf("record.SetPendingLoss: call ids: %w", err)
		}
		callJSON = string(b)
	}
	var first, last any
	if p.FirstAt > 0 {
		first = p.FirstAt
	}
	if p.LastAt > 0 {
		last = p.LastAt
	}
	_, err := q.ExecContext(ctx, `INSERT INTO mcp_relay_state
		(family, pending_loss_count, pending_loss_first_at, pending_loss_last_at, pending_loss_reason, pending_loss_call_ids)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(family) DO UPDATE SET
		  pending_loss_count = excluded.pending_loss_count,
		  pending_loss_first_at = excluded.pending_loss_first_at,
		  pending_loss_last_at = excluded.pending_loss_last_at,
		  pending_loss_reason = excluded.pending_loss_reason,
		  pending_loss_call_ids = excluded.pending_loss_call_ids`,
		family, p.Count, first, last, nullStr(p.Reason), callJSON)
	if err != nil {
		return fmt.Errorf("record.SetPendingLoss: %w", err)
	}
	return nil
}

// State implements Store.
func (s *SQLStore) State(ctx context.Context, family string) (State, error) {
	var (
		st                 State
		version, applied   sql.NullInt64
		hash, status, mode sql.NullString
		first, last        sql.NullInt64
		reason, callJSON   sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `SELECT family, running_version, effective_hash, status, mode, last_applied,
		pending_loss_count, pending_loss_first_at, pending_loss_last_at, pending_loss_reason, pending_loss_call_ids
		FROM mcp_relay_state WHERE family = ?`, family).
		Scan(&st.Family, &version, &hash, &status, &mode, &applied,
			&st.PendingLoss.Count, &first, &last, &reason, &callJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return State{}, ErrNotFound
	}
	if err != nil {
		return State{}, fmt.Errorf("record.State: %w", err)
	}
	st.RunningVersion, st.EffectiveHash, st.Status, st.Mode, st.LastApplied = version.Int64, hash.String, status.String, mode.String, applied.Int64
	st.PendingLoss.FirstAt, st.PendingLoss.LastAt, st.PendingLoss.Reason = first.Int64, last.Int64, reason.String
	if callJSON.Valid && callJSON.String != "" {
		if err := json.Unmarshal([]byte(callJSON.String), &st.PendingLoss.CallIDs); err != nil {
			return State{}, fmt.Errorf("record.State: call ids: %w", err)
		}
	}
	return st, nil
}

// PutState implements Store.
func (s *SQLStore) PutState(ctx context.Context, st State) error {
	if st.Family == "" {
		st.Family = DefaultFamily
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO mcp_relay_state
		(family, running_version, effective_hash, status, mode, last_applied)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(family) DO UPDATE SET
		  running_version = excluded.running_version,
		  effective_hash = excluded.effective_hash,
		  status = excluded.status,
		  mode = excluded.mode,
		  last_applied = excluded.last_applied`,
		st.Family, st.RunningVersion, nullStr(st.EffectiveHash), nullStr(st.Status), nullStr(st.Mode), st.LastApplied)
	if err != nil {
		return fmt.Errorf("record.PutState: %w", err)
	}
	return nil
}

// --- mcp_relay_launch_spec -------------------------------------------------

// PutLaunchSpec implements Store.
func (s *SQLStore) PutLaunchSpec(ctx context.Context, spec LaunchSpec, expectedGeneration int64) error {
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("record.PutLaunchSpec: %w", err)
	}
	args, err := jsonOrNil(spec.OrigArgs)
	if err != nil {
		return fmt.Errorf("record.PutLaunchSpec: orig_args: %w", err)
	}
	envRefs, err := jsonOrNil(spec.OrigEnvRefs)
	if err != nil {
		return fmt.Errorf("record.PutLaunchSpec: orig_env_refs: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("record.PutLaunchSpec: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var stored int64
	err = tx.QueryRowContext(ctx, `SELECT config_generation FROM mcp_relay_launch_spec
		WHERE client = ? AND config_path = ? AND entry_key = ?`, spec.Client, spec.ConfigPath, spec.EntryKey).Scan(&stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedGeneration != 0 {
			return fmt.Errorf("%w: launch spec does not exist (expected generation %d)", ErrConflict, expectedGeneration)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO mcp_relay_launch_spec
			(client, config_path, entry_key, orig_command, orig_args, orig_cwd, orig_env_refs,
			 config_generation, backup_path, backup_sha256, applied_at, applied_sha256,
			 vserver_id, registry_server_id)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			spec.Client, spec.ConfigPath, spec.EntryKey, spec.OrigCommand, args, nullStr(spec.OrigCwd), envRefs,
			spec.ConfigGeneration, spec.BackupPath, spec.BackupSHA256, spec.AppliedAt, nullStr(spec.AppliedSHA256),
			nullStr(spec.VServer), nullStr(spec.RegistryServerID))
	case err != nil:
		return fmt.Errorf("record.PutLaunchSpec: %w", err)
	default:
		if stored != expectedGeneration {
			return fmt.Errorf("%w: launch spec generation is %d, expected %d", ErrConflict, stored, expectedGeneration)
		}
		_, err = tx.ExecContext(ctx, `UPDATE mcp_relay_launch_spec SET
			orig_command = ?, orig_args = ?, orig_cwd = ?, orig_env_refs = ?,
			config_generation = ?, backup_path = ?, backup_sha256 = ?, applied_at = ?, applied_sha256 = ?,
			vserver_id = ?, registry_server_id = ?
			WHERE client = ? AND config_path = ? AND entry_key = ?`,
			spec.OrigCommand, args, nullStr(spec.OrigCwd), envRefs,
			spec.ConfigGeneration, spec.BackupPath, spec.BackupSHA256, spec.AppliedAt, nullStr(spec.AppliedSHA256),
			nullStr(spec.VServer), nullStr(spec.RegistryServerID),
			spec.Client, spec.ConfigPath, spec.EntryKey)
	}
	if err != nil {
		return fmt.Errorf("record.PutLaunchSpec: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("record.PutLaunchSpec: commit: %w", err)
	}
	return nil
}

func jsonOrNil(v []string) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

const launchSpecColumns = `client, config_path, entry_key, orig_command, orig_args, orig_cwd, orig_env_refs,
	config_generation, backup_path, backup_sha256, applied_at, applied_sha256,
	vserver_id, registry_server_id`

// GetLaunchSpec implements Store.
func (s *SQLStore) GetLaunchSpec(ctx context.Context, client, configPath, entryKey string) (LaunchSpec, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+launchSpecColumns+` FROM mcp_relay_launch_spec
		WHERE client = ? AND config_path = ? AND entry_key = ?`, client, configPath, entryKey)
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("record.GetLaunchSpec: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return LaunchSpec{}, fmt.Errorf("record.GetLaunchSpec: %w", err)
		}
		return LaunchSpec{}, ErrNotFound
	}
	l, err := scanLaunchSpec(rows)
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("record.GetLaunchSpec: %w", err)
	}
	return l, nil
}

// ListLaunchSpecs implements Store.
func (s *SQLStore) ListLaunchSpecs(ctx context.Context) ([]LaunchSpec, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+launchSpecColumns+` FROM mcp_relay_launch_spec
		ORDER BY client, config_path, entry_key`)
	if err != nil {
		return nil, fmt.Errorf("record.ListLaunchSpecs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LaunchSpec
	for rows.Next() {
		l, err := scanLaunchSpec(rows)
		if err != nil {
			return nil, fmt.Errorf("record.ListLaunchSpecs: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("record.ListLaunchSpecs: %w", err)
	}
	return out, nil
}

func scanLaunchSpec(rows *sql.Rows) (LaunchSpec, error) {
	var (
		l                           LaunchSpec
		args, cwd, envRefs, applied sql.NullString
		vserver, regServer          sql.NullString
	)
	if err := rows.Scan(&l.Client, &l.ConfigPath, &l.EntryKey, &l.OrigCommand, &args, &cwd, &envRefs,
		&l.ConfigGeneration, &l.BackupPath, &l.BackupSHA256, &l.AppliedAt, &applied,
		&vserver, &regServer); err != nil {
		return LaunchSpec{}, err
	}
	l.OrigCwd = cwd.String
	l.AppliedSHA256 = applied.String
	l.VServer, l.RegistryServerID = vserver.String, regServer.String
	if args.Valid {
		if err := json.Unmarshal([]byte(args.String), &l.OrigArgs); err != nil {
			return LaunchSpec{}, fmt.Errorf("orig_args: %w", err)
		}
	}
	if envRefs.Valid {
		if err := json.Unmarshal([]byte(envRefs.String), &l.OrigEnvRefs); err != nil {
			return LaunchSpec{}, fmt.Errorf("orig_env_refs: %w", err)
		}
	}
	return l, nil
}

// DeleteLaunchSpec implements Store.
func (s *SQLStore) DeleteLaunchSpec(ctx context.Context, client, configPath, entryKey string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM mcp_relay_launch_spec
		WHERE client = ? AND config_path = ? AND entry_key = ?`, client, configPath, entryKey); err != nil {
		return fmt.Errorf("record.DeleteLaunchSpec: %w", err)
	}
	return nil
}
