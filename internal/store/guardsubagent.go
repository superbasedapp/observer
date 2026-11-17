package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Sub-agent attribution of hook-path guard verdicts.
//
// A Claude Code sub-agent's PreToolUse payload carries the ROOT session id
// (session_id) plus an agent_id, while the transcript adapter files the
// sub-agent's actions under the sidechain session `<root>:agent:<agent>`.
// The hook path records its verdict under the payload's session id and
// with no action anchor (the action row does not exist yet), so every ask
// or deny the gate raised on a sub-agent's call landed on the ROOT session
// only, and the sub-agent's own session detail showed nothing
// (2026-11-10 live grounding: 19 of 19 S-793 asks of a desktop session
// were sub-agent commits, all filed under the root). The evaluation keys
// on the root on purpose (a session-scoped approval of the root covers its
// sub-agents), so the stored row keeps the root id; the read below
// attributes each unanchored root row to the sub-agent action it judged.
//
// THE MATCH (attributeSubagentRow, one rule, one test row each): the
// action is in a `<root>:agent:%` session, carries the verdict's
// target_hash, and its timestamp lies within [verdict - lookBack,
// verdict + lookAhead] (the transcript stamps the tool_use a moment before
// the hook runs: about 250 ms on the grounding host). The nearest action
// wins; a tie goes to the lower action id. A verdict no sub-agent action
// matches stays the root's alone.

// subagentAttributionLookBack / LookAhead bound the match window.
const (
	subagentAttributionLookBack  = 60 * time.Second
	subagentAttributionLookAhead = 10 * time.Second
)

// subagentSessionMarker is the claude-code sidechain id infix (the
// convention internal/adapter/claudecode/subagent.go writes and
// locread.go's fold already reads).
const subagentSessionMarker = ":agent:"

// subagentRoot returns the root session id of a `<root>:agent:<agent>` id.
func subagentRoot(sessionID string) (string, bool) {
	root, agent, ok := strings.Cut(sessionID, subagentSessionMarker)
	if !ok || root == "" || agent == "" {
		return "", false
	}
	return root, true
}

// subagentActionCandidate is one sub-agent action a root verdict may have
// judged.
type subagentActionCandidate struct {
	ActionID   int64
	SessionID  string
	MessageID  string
	TargetHash string
	At         time.Time
}

// attributeSubagentRow picks the candidate the verdict at `at` on
// targetHash judged (see THE MATCH). ok=false when none qualifies.
func attributeSubagentRow(targetHash string, at time.Time, cands []subagentActionCandidate) (subagentActionCandidate, bool) {
	if targetHash == "" || at.IsZero() {
		return subagentActionCandidate{}, false
	}
	var best subagentActionCandidate
	var bestDist time.Duration
	found := false
	for _, c := range cands {
		if c.TargetHash != targetHash || c.At.IsZero() {
			continue
		}
		if c.At.Before(at.Add(-subagentAttributionLookBack)) || c.At.After(at.Add(subagentAttributionLookAhead)) {
			continue
		}
		d := c.At.Sub(at)
		if d < 0 {
			d = -d
		}
		if !found || d < bestDist || (d == bestDist && c.ActionID < best.ActionID) {
			best, bestDist, found = c, d, true
		}
	}
	return best, found
}

// unattributedHookRow reports a row the hook path wrote: no action and no
// api turn anchor. Only those can belong to a sub-agent's call while
// carrying the root id (the watcher and proxy rows carry their own anchor).
func unattributedHookRow(r *GuardEventAnchoredRow) bool {
	return r.ActionID == nil && r.APITurnID == nil && r.TargetHash != ""
}

// loadSubagentCandidates loads the actions of every `<root>:agent:%`
// session that carry one of hashes.
func (s *Store) loadSubagentCandidates(ctx context.Context, root string, hashes []string) ([]subagentActionCandidate, error) {
	var out []subagentActionCandidate
	const batch = 200
	for start := 0; start < len(hashes); start += batch {
		end := min(start+batch, len(hashes))
		part := hashes[start:end]
		args := make([]any, 0, len(part)+1)
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value binds via args.
		q := `SELECT id, session_id, COALESCE(message_id, ''), target_hash, timestamp
		        FROM actions WHERE target_hash IN (` + placeholders(len(part)) + `) AND session_id LIKE ? ESCAPE '\'`
		for _, h := range part {
			args = append(args, h)
		}
		args = append(args, escapeLikePrefix(root)+subagentSessionMarker+"%")
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("store.loadSubagentCandidates: query: %w", err)
		}
		for rows.Next() {
			var c subagentActionCandidate
			var ts string
			if err := rows.Scan(&c.ActionID, &c.SessionID, &c.MessageID, &c.TargetHash, &ts); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.loadSubagentCandidates: scan: %w", err)
			}
			c.At = parseStamp(ts)
			out = append(out, c)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("store.loadSubagentCandidates: rows: %w", err)
		}
	}
	return out, nil
}

// distinctTargetHashes collects the target hashes of the rows unattributed
// hook rows carry, deduplicated and sorted (a stable query).
func distinctTargetHashes(rows []GuardEventAnchoredRow) []string {
	set := map[string]bool{}
	for i := range rows {
		if unattributedHookRow(&rows[i]) {
			set[rows[i].TargetHash] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// attributeRootRows stamps SubagentSessionID on each of the root's own
// unattributed hook rows a sub-agent action matches.
func (s *Store) attributeRootRows(ctx context.Context, root string, rows []GuardEventAnchoredRow) error {
	hashes := distinctTargetHashes(rows)
	if len(hashes) == 0 {
		return nil
	}
	cands, err := s.loadSubagentCandidates(ctx, root, hashes)
	if err != nil || len(cands) == 0 {
		return err
	}
	for i := range rows {
		if !unattributedHookRow(&rows[i]) {
			continue
		}
		if c, ok := attributeSubagentRow(rows[i].TargetHash, rows[i].TS, cands); ok {
			rows[i].SubagentSessionID = c.SessionID
		}
	}
	return nil
}

// loadRootRowsForSubagent returns the root's unattributed hook rows that
// judged one of sub-agent session sub's actions, attributed to it and
// anchored on that action's message.
func (s *Store) loadRootRowsForSubagent(ctx context.Context, root, sub string) ([]GuardEventAnchoredRow, error) {
	rootRows, err := s.loadGuardEventsAnchored(ctx, root)
	if err != nil {
		return nil, err
	}
	hashes := distinctTargetHashes(rootRows)
	if len(hashes) == 0 {
		return nil, nil
	}
	cands, err := s.loadSubagentCandidates(ctx, root, hashes)
	if err != nil || len(cands) == 0 {
		return nil, err
	}
	var out []GuardEventAnchoredRow
	for i := range rootRows {
		r := rootRows[i]
		if !unattributedHookRow(&r) {
			continue
		}
		// Every sub-agent of the root competes, so a verdict nearer a
		// sibling sub-agent's identical command is not claimed here.
		c, ok := attributeSubagentRow(r.TargetHash, r.TS, cands)
		if !ok || c.SessionID != sub {
			continue
		}
		r.SubagentSessionID = sub
		r.MessageID = c.MessageID
		out = append(out, r)
	}
	return out, nil
}
