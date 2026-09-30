// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// correlate.go is the READ half of Agent Access P11(a) on the node (doc3
// §11.12b (a), R10.7 / R11.8 / R12.7): the decision + completion records a
// coding session's MCP panel correlates. internal/store/mcpcorrelate.go
// composes it with the session's actions and the pure
// internal/mcpintel/correlate derivation; this package stays the one owner
// of the mcp_relay_record SQL.

// correlateChunk bounds one action_ref IN (...) list (well under SQLite's
// bound-parameter limit).
const correlateChunk = 500

// ForCorrelation returns the decision records anchored to a coding session -
// coding_session_id = sessionID, OR an action_ref naming one of actionRefs
// (the session's own tool-use ids: a loopback / IPC stream may carry the
// per-call action anchor without the session one) - capped at the latest
// limit decisions (limit <= 0: 500), plus the completion records of those
// decisions, all seq ascending. Gap rows never appear (they carry no
// anchors). It is read-only and needs no node key.
func (s *SQLStore) ForCorrelation(ctx context.Context, sessionID string, actionRefs []string, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 500
	}
	bySeq := map[int64]Record{}
	collect := func(q string, args ...any) error { return s.collectInto(ctx, bySeq, q, args...) }
	if sessionID != "" {
		if err := collect(`SELECT `+recordColumns+` FROM mcp_relay_record
			WHERE record_kind = 'decision' AND coding_session_id = ? ORDER BY seq DESC LIMIT ?`, sessionID, limit); err != nil {
			return nil, fmt.Errorf("record.ForCorrelation: by session: %w", err)
		}
	}
	refs := dedupeNonEmpty(actionRefs)
	for i := 0; i < len(refs); i += correlateChunk {
		chunk := refs[i:min(i+correlateChunk, len(refs))]
		args := make([]any, 0, len(chunk)+1)
		for _, r := range chunk {
			args = append(args, r)
		}
		args = append(args, limit)
		//nolint:gosec // G202: only "?" placeholders are concatenated; every value binds.
		q := `SELECT ` + recordColumns + ` FROM mcp_relay_record
			WHERE record_kind = 'decision' AND action_ref IN (` + placeholders(len(chunk)) + `) ORDER BY seq DESC LIMIT ?`
		if err := collect(q, args...); err != nil {
			return nil, fmt.Errorf("record.ForCorrelation: by action_ref: %w", err)
		}
	}
	out, err := s.withCompletions(ctx, bySeq, limit)
	if err != nil {
		return nil, fmt.Errorf("record.ForCorrelation: %w", err)
	}
	return out, nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func dedupeNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// TimeRange is one closed [From, To] range of record ts (unix seconds).
type TimeRange struct {
	From, To int64
}

// correlateRangeChunk bounds the ts ranges OR-ed into one query.
const correlateRangeChunk = 50

// UnanchoredForCorrelation returns the decision records that carry NO
// correlation anchor (no coding_session_id, action_ref or turn_ref - a
// client that sent no tool-use id over a transport with no session env)
// whose ts falls in one of ranges, capped at the latest limit decisions
// (limit <= 0: 500), plus their completion records, seq ascending. The
// unanchored tier of internal/mcpintel/correlate decides which session, if
// any, owns each. Read-only.
func (s *SQLStore) UnanchoredForCorrelation(ctx context.Context, ranges []TimeRange, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 500
	}
	bySeq := map[int64]Record{}
	for i := 0; i < len(ranges); i += correlateRangeChunk {
		chunk := ranges[i:min(i+correlateRangeChunk, len(ranges))]
		conds := make([]string, 0, len(chunk))
		args := make([]any, 0, 2*len(chunk)+1)
		for _, r := range chunk {
			conds = append(conds, "(ts BETWEEN ? AND ?)")
			args = append(args, r.From, r.To)
		}
		args = append(args, limit)
		//nolint:gosec // G202: only fixed "(ts BETWEEN ? AND ?)" terms are concatenated; every value binds.
		q := `SELECT ` + recordColumns + ` FROM mcp_relay_record
			WHERE record_kind = 'decision'
			  AND COALESCE(coding_session_id, '') = '' AND COALESCE(action_ref, '') = '' AND COALESCE(turn_ref, '') = ''
			  AND (` + strings.Join(conds, " OR ") + `) ORDER BY seq DESC LIMIT ?`
		if err := s.collectInto(ctx, bySeq, q, args...); err != nil {
			return nil, fmt.Errorf("record.UnanchoredForCorrelation: %w", err)
		}
	}
	out, err := s.withCompletions(ctx, bySeq, limit)
	if err != nil {
		return nil, fmt.Errorf("record.UnanchoredForCorrelation: %w", err)
	}
	return out, nil
}

// NamedActionRefs returns the subset of refs some decision record names by
// action_ref (the call exactly anchored to that action): such an action is
// never a candidate for an unanchored call.
func (s *SQLStore) NamedActionRefs(ctx context.Context, refs []string) ([]string, error) {
	refs = dedupeNonEmpty(refs)
	var out []string
	for i := 0; i < len(refs); i += correlateChunk {
		chunk := refs[i:min(i+correlateChunk, len(refs))]
		args := make([]any, 0, len(chunk))
		for _, r := range chunk {
			args = append(args, r)
		}
		//nolint:gosec // G202: only "?" placeholders are concatenated; every value binds.
		q := `SELECT DISTINCT action_ref FROM mcp_relay_record
			WHERE record_kind = 'decision' AND action_ref IN (` + placeholders(len(chunk)) + `)`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("record.NamedActionRefs: %w", err)
		}
		for rows.Next() {
			var ref string
			if err := rows.Scan(&ref); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("record.NamedActionRefs: scan: %w", err)
			}
			out = append(out, ref)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("record.NamedActionRefs: %w", err)
		}
	}
	sort.Strings(out)
	return out, nil
}

// collectInto runs one record query and keys its rows by seq into bySeq.
func (s *SQLStore) collectInto(ctx context.Context, bySeq map[int64]Record, q string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return err
		}
		bySeq[r.Seq] = r
	}
	return rows.Err()
}

// withCompletions caps the collected decisions at the latest limit, adds
// their completion records, and returns everything seq ascending.
func (s *SQLStore) withCompletions(ctx context.Context, bySeq map[int64]Record, limit int) ([]Record, error) {
	decisions := make([]int64, 0, len(bySeq))
	for seq := range bySeq {
		decisions = append(decisions, seq)
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i] > decisions[j] })
	if len(decisions) > limit {
		for _, seq := range decisions[limit:] {
			delete(bySeq, seq)
		}
		decisions = decisions[:limit]
	}
	for i := 0; i < len(decisions); i += correlateChunk {
		chunk := decisions[i:min(i+correlateChunk, len(decisions))]
		args := make([]any, 0, len(chunk))
		for _, s := range chunk {
			args = append(args, s)
		}
		//nolint:gosec // G202: only "?" placeholders are concatenated; every value binds.
		q := `SELECT ` + recordColumns + ` FROM mcp_relay_record
			WHERE record_kind = 'completion' AND decision_seq IN (` + placeholders(len(chunk)) + `)`
		if err := s.collectInto(ctx, bySeq, q, args...); err != nil {
			return nil, fmt.Errorf("completions: %w", err)
		}
	}
	out := make([]Record, 0, len(bySeq))
	for _, r := range bySeq {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}
