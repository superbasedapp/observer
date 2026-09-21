package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SessionLineageChild is a compact descriptor of a session spawned from
// (forked or subagent-of) a parent session — surfaced in the parent's
// session-detail "spawned sessions" list. Since the 2026-08-21 operator
// ruling that per-sub-agent usage must be visible on the parent's detail
// view (opencode sub-agents are separate sessions, unlike claude-code's
// same-session sidechains), each child carries lightweight rollups:
// token sums over its non-sidechain token_usage rows, their recorded
// estimated cost, and its action count. These are plain indexed GROUP BY
// aggregates — deliberately NOT the heavy per-turn cost-engine CTE, which
// stays single-owned by handleSessionDetail.
type SessionLineageChild struct {
	ID           string
	ThreadSource string
	StartedAt    string
	// InputTokens / OutputTokens sum the child's non-sidechain token_usage
	// rows; CostUSD sums their recorded estimated_cost_usd (zero when the
	// adapter doesn't record cost). ActionCount is the child's actions row
	// count (zero when pruned or not yet ingested).
	InputTokens  int64
	OutputTokens int64
	CostUSD      float64
	ActionCount  int64
}

// SessionLineageView is the codex fork/subagent lineage for one session
// (migration 069): its own markers, whether the fork parent is present in
// this database, and the children forked/spawned from it. All fields carry
// zero values for a non-codex or non-lineage session.
type SessionLineageView struct {
	// ForkedFromID / ParentThreadID / ThreadSource mirror the sessions
	// columns of the same name (empty when unset).
	ForkedFromID   string
	ParentThreadID string
	ThreadSource   string
	// ParentInDB reports whether a session row exists for ForkedFromID.
	// Only queried when ForkedFromID is non-empty; false otherwise.
	ParentInDB bool
	// Children are the sessions whose forked_from_id OR parent_thread_id
	// equals this session id (codex user-forks stamp forked_from_id;
	// codex + opencode sub-agent spawns stamp parent_thread_id), ordered
	// by start time. Nil when there are none.
	Children []SessionLineageChild
}

// SubagentChildIDs returns the session ids of sub-agents spawned from
// parentID, for folding a sub-agent's own lines-of-code back under the
// parent's session card (see internal/store/locread.go::LoadSessionLOC).
//
// The link is the lineage the adapters already record: a session whose
// parent_thread_id is parentID and whose thread_source is 'subagent'
// (claude-code dedicated-file children, opencode, openclaw, codex, devin).
// It deliberately does NOT encode the claude-code `<parent>:agent:<id>` id
// convention — LoadSessionLOC adds an id-prefix LIKE for the orphan case
// (a child whose session row was never materialized) on top of this — so
// this helper stays a plain, capability-based lineage read with no
// tool-name or id-string knowledge. A separate-session sub-agent that
// records no lineage row (the clinecli model) is NOT folded; it stays a
// first-class session shown apart, its own card honest about its lines.
//
// An empty slice (never an error) is returned for a session with no
// sub-agent children, so callers can union unconditionally.
func (s *Store) SubagentChildIDs(ctx context.Context, parentID string) ([]string, error) {
	if parentID == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM sessions
		 WHERE parent_thread_id = ? AND thread_source = 'subagent'`, parentID)
	if err != nil {
		return nil, fmt.Errorf("store.SubagentChildIDs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store.SubagentChildIDs: scan: %w", err)
		}
		if id != "" && id != parentID {
			out = append(out, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SubagentChildIDs: rows: %w", err)
	}
	return out, nil
}

// LoadSessionLineage resolves the codex fork/subagent lineage for a single
// session (migration 069). It returns sql.ErrNoRows when the session does
// not exist, mirroring LoadSessionShape. Since sessions.id for codex is the
// codex thread uuid, the parent is the row WHERE id = forked_from_id and the
// children are the rows WHERE forked_from_id = sessionID.
func (s *Store) LoadSessionLineage(ctx context.Context, sessionID string) (SessionLineageView, error) {
	var v SessionLineageView
	if sessionID == "" {
		return v, errors.New("store.LoadSessionLineage: sessionID is required")
	}

	var forked, parentThread, source sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(forked_from_id, ''), COALESCE(parent_thread_id, ''),
		        COALESCE(thread_source, '')
		 FROM sessions WHERE id = ?`, sessionID,
	).Scan(&forked, &parentThread, &source); err != nil {
		return v, err // sql.ErrNoRows propagates to the caller unwrapped.
	}
	v.ForkedFromID = forked.String
	v.ParentThreadID = parentThread.String
	v.ThreadSource = source.String

	// Parent presence is only meaningful when this session was forked or
	// spawned from another thread; skip the lookup otherwise.
	if v.ForkedFromID != "" {
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT EXISTS(SELECT 1 FROM sessions WHERE id = ?)`, v.ForkedFromID,
		).Scan(&v.ParentInDB); err != nil {
			return v, fmt.Errorf("store.LoadSessionLineage: parent presence: %w", err)
		}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, COALESCE(s.thread_source, ''), s.started_at,
		        COALESCE(tu.input_tokens, 0), COALESCE(tu.output_tokens, 0),
		        COALESCE(tu.cost_usd, 0), COALESCE(ac.action_count, 0)
		 FROM sessions s
		 LEFT JOIN (
		       SELECT session_id,
		              SUM(input_tokens) AS input_tokens,
		              SUM(output_tokens) AS output_tokens,
		              SUM(estimated_cost_usd) AS cost_usd
		         FROM token_usage
		        WHERE COALESCE(is_sidechain, 0) = 0
		        GROUP BY session_id
		 ) tu ON tu.session_id = s.id
		 LEFT JOIN (
		       SELECT session_id, COUNT(*) AS action_count
		         FROM actions GROUP BY session_id
		 ) ac ON ac.session_id = s.id
		 WHERE s.forked_from_id = ? OR s.parent_thread_id = ?
		 ORDER BY s.started_at`, sessionID, sessionID)
	if err != nil {
		return v, fmt.Errorf("store.LoadSessionLineage: children: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c SessionLineageChild
		if err := rows.Scan(&c.ID, &c.ThreadSource, &c.StartedAt,
			&c.InputTokens, &c.OutputTokens, &c.CostUSD, &c.ActionCount); err != nil {
			return v, fmt.Errorf("store.LoadSessionLineage: scan child: %w", err)
		}
		v.Children = append(v.Children, c)
	}
	if err := rows.Err(); err != nil {
		return v, fmt.Errorf("store.LoadSessionLineage: children rows: %w", err)
	}
	return v, nil
}
