// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/mcpintel/correlate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// mcpcorrelate.go is the NODE store seam of Agent Access P11(a) (doc3
// §11.12b (a), R10.7 / R11.8): it loads one session's MCP-call + user-prompt
// actions (this package owns actions) and the relay records anchored to that
// session (through internal/mcprelay/record, the one owner of
// mcp_relay_record - this file never names that table), maps both onto the
// pure internal/mcpintel/correlate inputs, and returns the derivation. The
// org drawer runs the SAME derivation over the org copies
// (internal/orgserver/rollup/sessionmcp.go), so the two surfaces agree.
//
// Every node relay record is relay-originated by construction (the node's
// own relay wrote it), so each is a trusted carrier; the link confidence is
// still earned per call by the rules table, never assumed.

// mcpCorrelateCallCap bounds the calls one session panel returns (the latest
// decisions win the record read; the derivation lists them oldest first).
const mcpCorrelateCallCap = 500

// mcpCorrelateActionCap bounds the MCP / prompt actions read for one session.
const mcpCorrelateActionCap = 20000

// LoadSessionMCPCalls returns the MCP calls correlated to the session, each
// with its derived link (exact | inferred) and the de-duplicated call data;
// a session with no relay records returns an empty, non-nil call list.
func (s *Store) LoadSessionMCPCalls(ctx context.Context, sessionID string) (correlate.Result, error) {
	acts, err := s.loadCorrelationActions(ctx, sessionID)
	if err != nil {
		return correlate.Result{}, fmt.Errorf("store.LoadSessionMCPCalls: %w", err)
	}
	refs := make([]string, 0, len(acts))
	for _, a := range acts {
		if a.ActionType == correlateActionMCPCall || a.RawToolName != "" {
			refs = append(refs, a.Key, a.MessageID)
		}
	}
	recs, err := record.NewSQLStore(s.db, "").ForCorrelation(ctx, sessionID, refs, mcpCorrelateCallCap)
	if err != nil {
		return correlate.Result{}, fmt.Errorf("store.LoadSessionMCPCalls: %w", err)
	}
	in := correlate.DeriveInput{SessionID: sessionID, Actions: acts, Records: make([]correlate.Record, 0, len(recs)), Limit: mcpCorrelateCallCap}
	for _, r := range recs {
		if cr, ok := nodeCorrelateRecord(r); ok {
			in.Records = append(in.Records, cr)
		}
	}
	if err := s.loadUnanchoredCorrelation(ctx, sessionID, &in); err != nil {
		return correlate.Result{}, fmt.Errorf("store.LoadSessionMCPCalls: %w", err)
	}
	return correlate.Derive(in), nil
}

// loadUnanchoredCorrelation adds the unanchored tier's inputs (backlog item
// 10): the relay decisions that carried NO anchor inside the windows the
// session's own candidate actions define, the candidate pool of EVERY
// session on this node inside those decisions' windows, and the pool keys
// some relay record names exactly. The pure derivation then decides which
// session (if any) owns each call - the same rows the org drawer reads, so
// both surfaces agree.
func (s *Store) loadUnanchoredCorrelation(ctx context.Context, sessionID string, in *correlate.DeriveInput) error {
	own, err := s.loadCorrelationPool(ctx, sessionID, nil)
	if err != nil {
		return fmt.Errorf("session candidates: %w", err)
	}
	ownActs := make([]correlate.Action, len(own))
	for i := range own {
		ownActs[i] = own[i].Action
	}
	wins := correlate.RecordWindows(ownActs)
	if len(wins) == 0 {
		return nil
	}
	ranges := make([]record.TimeRange, len(wins))
	for i, w := range wins {
		ranges[i] = record.TimeRange{From: w.From.Unix(), To: w.To.Unix()}
	}
	store := record.NewSQLStore(s.db, "")
	recs, err := store.UnanchoredForCorrelation(ctx, ranges, mcpCorrelateCallCap)
	if err != nil {
		return err
	}
	var un []correlate.Record
	for _, r := range recs {
		if cr, ok := nodeCorrelateRecord(r); ok {
			un = append(un, cr)
		}
	}
	if len(un) == 0 {
		return nil
	}
	pool, err := s.loadCorrelationPool(ctx, "", correlate.PoolWindows(un))
	if err != nil {
		return fmt.Errorf("pool: %w", err)
	}
	keys := make([]string, 0, len(pool))
	for _, p := range pool {
		keys = append(keys, p.Key)
	}
	named, err := store.NamedActionRefs(ctx, keys)
	if err != nil {
		return err
	}
	in.Records = append(in.Records, un...)
	in.Pool, in.AnchoredKeys = pool, named
	return nil
}

// loadCorrelationPool reads unanchored-tier candidate actions
// (correlate.CandidateActionTypes with a target): one session's (sessionID
// set, wins ignored) or every session's inside wins (sessionID ""). The
// match reads the TARGET only - the name column the org copy also carries.
func (s *Store) loadCorrelationPool(ctx context.Context, sessionID string, wins []correlate.Window) ([]correlate.PoolAction, error) {
	types := correlate.CandidateActionTypes
	args := make([]any, 0, len(types)+2*len(wins)+2)
	for _, t := range types {
		args = append(args, t)
	}
	where := `action_type IN (` + placeholders(len(types)) + `) AND COALESCE(target, '') <> ''`
	if sessionID != "" {
		where += ` AND session_id = ?`
		args = append(args, sessionID)
	} else {
		if len(wins) == 0 {
			return nil, nil
		}
		conds := make([]string, 0, len(wins))
		for _, w := range wins {
			from, to := correlate.TextRange(w)
			conds = append(conds, `(timestamp >= ? AND timestamp < ?)`)
			args = append(args, from, to)
		}
		where += ` AND (` + strings.Join(conds, ` OR `) + `)`
	}
	args = append(args, mcpCorrelateActionCap)
	//nolint:gosec // G202: only fixed terms and "?" placeholders are concatenated; every value binds.
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(session_id, ''), COALESCE(source_event_id, ''), COALESCE(message_id, ''), turn_index, COALESCE(timestamp, ''),
       COALESCE(action_type, ''), COALESCE(target, '')
  FROM actions
 WHERE `+where+`
 ORDER BY id
 LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []correlate.PoolAction
	for rows.Next() {
		var p correlate.PoolAction
		var turn sql.NullInt64
		var ts string
		if err := rows.Scan(&p.SessionID, &p.Key, &p.MessageID, &turn, &ts, &p.ActionType, &p.Target); err != nil {
			return nil, fmt.Errorf("actions: scan: %w", err)
		}
		if turn.Valid {
			v := turn.Int64
			p.TurnIndex = &v
		}
		p.TS, _ = correlate.ParseTimestamp(ts)
		out = append(out, p)
	}
	return out, rows.Err()
}

// correlateActionMCPCall mirrors models.ActionMCPCall.
const correlateActionMCPCall = "mcp_call"

// loadCorrelationActions reads the session's MCP-call and user-prompt
// actions - the only rows correlation reads.
func (s *Store) loadCorrelationActions(ctx context.Context, sessionID string) ([]correlate.Action, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT COALESCE(source_event_id, ''), COALESCE(message_id, ''), turn_index, COALESCE(timestamp, ''),
       COALESCE(action_type, ''), COALESCE(raw_tool_name, ''), COALESCE(target, '')
  FROM actions
 WHERE session_id = ?
   AND (action_type IN ('mcp_call', 'user_prompt') OR raw_tool_name LIKE 'mcp\_\_%' ESCAPE '\')
 ORDER BY id
 LIMIT ?`, sessionID, mcpCorrelateActionCap)
	if err != nil {
		return nil, fmt.Errorf("actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []correlate.Action
	for rows.Next() {
		var a correlate.Action
		var turn sql.NullInt64
		var ts, raw string
		if err := rows.Scan(&a.Key, &a.MessageID, &turn, &ts, &a.ActionType, &raw, &a.Target); err != nil {
			return nil, fmt.Errorf("actions: scan: %w", err)
		}
		if turn.Valid {
			v := turn.Int64
			a.TurnIndex = &v
		}
		a.TS, _ = correlate.ParseTimestamp(ts)
		if len(raw) > 5 && raw[:5] == "mcp__" {
			a.RawToolName = raw
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("actions: %w", err)
	}
	return out, nil
}

// nodeCorrelateRecord maps one relay record onto the correlate input
// (decision and completion kinds only).
func nodeCorrelateRecord(r record.Record) (correlate.Record, bool) {
	var kind correlate.Kind
	switch r.Kind {
	case record.KindDecision:
		kind = correlate.KindDecision
	case record.KindCompletion:
		kind = correlate.KindCompletion
	default:
		return correlate.Record{}, false
	}
	return correlate.Record{
		Source: correlate.SourceNode, Kind: kind, CallID: r.CallID, TS: r.TS, Trusted: true,
		VirtualServer: r.VServer, Server: r.Server, Tool: r.Tool, Method: r.Method,
		Decision: string(r.Decision), Reason: r.ReasonCode,
		CodingSessionID: r.CodingSessionID, TurnRef: r.TurnRef, ActionRef: r.ActionRef, StoredConfidence: string(r.CorrConfidence),
		CaptureLevel: string(r.CaptureLevel), ArgsExcerpt: r.ArgsExcerpt, ArgsFull: r.ArgsFull, ArgsScrubStatus: string(r.ArgsScrubStatus),
		ResultStatus: r.ResultStatus, LatencyMS: r.LatencyMS, ResultSizeBytes: r.ResultSizeBytes,
		ResultFull: r.ResultFull, ResultScrubStatus: string(r.ResultScrubStatus),
		ErrorFull: r.ErrorFull, ErrorScrubStatus: string(r.ErrorScrubStatus),
	}, true
}
