package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// secfixobs.go holds the READ-ONLY session facts the security code
// inferences and fix observations decide from (security pillar plan
// sections 5.7 and 5.11 (a), lane sec-g5): an agent's edit payloads, the
// session's prompt before an edit, and, for a file, the session that last
// edited it with its later commands and its edited files. It writes
// nothing and names no sec_* table (secfindings.go owns those; the one
// write, the fixed_verified move, is MarkSecFindingFixedVerified there).

// AgentEdit is one successful agent write or edit, with its stored
// (scrubbed) tool input.
type AgentEdit struct {
	ID          int64
	SessionID   string
	ProjectRoot string
	Target      string
	// RawInput is actions.raw_tool_input, at most maxAgentEditInput bytes
	// (the rest is cut, so a payload that long parses as incomplete).
	RawInput string
	At       time.Time
}

// maxAgentEditInput caps the tool input read per edit.
const maxAgentEditInput = 256 << 10

// AgentEditsAfter returns the successful file writes and edits stored with
// an id above afterID, oldest first, at most limit, and the highest id
// read (afterID when none).
func (s *Store) AgentEditsAfter(ctx context.Context, afterID int64, limit int) ([]AgentEdit, int64, error) {
	if limit <= 0 {
		limit = 256
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.session_id, COALESCE(p.root_path, ''), COALESCE(a.target, ''),
		       COALESCE(substr(a.raw_tool_input, 1, ?), ''), a.timestamp
		FROM actions a JOIN projects p ON p.id = a.project_id
		WHERE a.id > ? AND a.success = 1 AND a.action_type IN (?, ?)
		ORDER BY a.id LIMIT ?`, maxAgentEditInput, afterID, models.ActionWriteFile, models.ActionEditFile, limit)
	if err != nil {
		return nil, afterID, fmt.Errorf("store.AgentEditsAfter: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AgentEdit
	last := afterID
	for rows.Next() {
		var e AgentEdit
		var ts string
		if err := rows.Scan(&e.ID, &e.SessionID, &e.ProjectRoot, &e.Target, &e.RawInput, &ts); err != nil {
			return nil, afterID, fmt.Errorf("store.AgentEditsAfter: scan: %w", err)
		}
		e.At = parseLOCTime(ts)
		last = e.ID
		out = append(out, e)
	}
	return out, last, rows.Err()
}

// SessionPromptBefore returns the text of the session's latest user prompt
// at or before at (actions.target of its user_prompt action), and whether
// there is one. A host that records no prompt has none.
func (s *Store) SessionPromptBefore(ctx context.Context, sessionID string, at time.Time) (string, bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(target, ''), timestamp FROM actions
		WHERE session_id = ? AND action_type = ?
		ORDER BY id DESC LIMIT 200`, sessionID, models.ActionUserPrompt)
	if err != nil {
		return "", false, fmt.Errorf("store.SessionPromptBefore: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var text, ts string
		if err := rows.Scan(&text, &ts); err != nil {
			return "", false, fmt.Errorf("store.SessionPromptBefore: scan: %w", err)
		}
		if t := parseLOCTime(ts); !t.IsZero() && !t.After(at) && text != "" {
			return text, true, nil
		}
	}
	return "", false, rows.Err()
}

// FixCommand is one command a session ran.
type FixCommand struct {
	At      time.Time
	Command string
	// ExitKnown: a failure row carried an exit code (ExitCode), or the
	// action was recorded as a success, which is only the host's success
	// flag (HostReportedSuccess, ExitCode 0), never an observed exit code.
	ExitKnown           bool
	ExitCode            int
	HostReportedSuccess bool
}

// FixEvidenceRows are the facts about the session that last edited a file.
type FixEvidenceRows struct {
	SessionID string
	// LastEditAt is that session's last AI edit of the file (zero: none).
	LastEditAt time.Time
	// Commands are the session's commands after LastEditAt, oldest first
	// (at most 500).
	Commands []FixCommand
	// EditedTargets are the session's edited files as stored (at most 2000).
	EditedTargets []string
}

// LoadFixEvidence returns the facts about the session whose AI edit of rel
// (project-relative, matched by internal/loc.PathHash) was the latest at
// or before before. No such edit: the zero value.
func (s *Store) LoadFixEvidence(ctx context.Context, root, rel string, before time.Time) (FixEvidenceRows, error) {
	var out FixEvidenceRows
	pid, err := s.ProjectIDForRoot(ctx, root)
	if err != nil || pid == 0 {
		return out, err
	}
	hash := loc.PathHash(root, rel)
	if hash == "" {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(fc.session_id, a.session_id), fc.saved_at FROM file_changes fc
		JOIN actions a ON a.id = fc.action_id
		WHERE fc.project_id = ? AND fc.file_path_hash = ? AND fc.actor = ? AND fc.action_id IS NOT NULL
		ORDER BY fc.saved_at DESC LIMIT 200`, pid, hash, LOCActorAI)
	if err != nil {
		return out, fmt.Errorf("store.LoadFixEvidence: edits: %w", err)
	}
	for rows.Next() {
		var sid, ts string
		if err := rows.Scan(&sid, &ts); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store.LoadFixEvidence: scan: %w", err)
		}
		at := parseLOCTime(ts)
		if at.IsZero() || at.After(before) {
			continue
		}
		if out.SessionID == "" {
			out.SessionID, out.LastEditAt = sid, at
		} else if sid == out.SessionID && at.After(out.LastEditAt) {
			out.LastEditAt = at
		}
	}
	_ = rows.Close()
	if out.SessionID == "" {
		return out, nil
	}
	if out.Commands, err = s.fixCommandsAfter(ctx, out.SessionID, out.LastEditAt); err != nil {
		return out, err
	}
	out.EditedTargets, err = s.fixEditedTargets(ctx, out.SessionID)
	return out, err
}

func (s *Store) fixCommandsAfter(ctx context.Context, sessionID string, after time.Time) ([]FixCommand, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.timestamp, COALESCE(a.target, ''), COALESCE(a.success, 0), f.exit_code
		FROM actions a LEFT JOIN failure_context f ON f.action_id = a.id
		WHERE a.session_id = ? AND a.action_type = ?
		ORDER BY a.id LIMIT 2000`, sessionID, models.ActionRunCommand)
	if err != nil {
		return nil, fmt.Errorf("store.LoadFixEvidence: commands: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []FixCommand
	for rows.Next() {
		var ts, cmd string
		var success int
		var exit sql.NullInt64
		if err := rows.Scan(&ts, &cmd, &success, &exit); err != nil {
			return nil, fmt.Errorf("store.LoadFixEvidence: scan: %w", err)
		}
		at := parseLOCTime(ts)
		if !at.After(after) || len(out) >= 500 {
			continue
		}
		c := FixCommand{At: at, Command: cmd}
		switch {
		case exit.Valid:
			c.ExitKnown, c.ExitCode = true, int(exit.Int64)
		case success == 1:
			c.ExitKnown, c.HostReportedSuccess = true, true
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) fixEditedTargets(ctx context.Context, sessionID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT COALESCE(target, '') FROM actions
		WHERE session_id = ? AND action_type IN (?, ?) LIMIT 2000`, sessionID, models.ActionWriteFile, models.ActionEditFile)
	if err != nil {
		return nil, fmt.Errorf("store.LoadFixEvidence: targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("store.LoadFixEvidence: scan: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// FixEditFacts are what file_changes proves about one file's edits in one
// session (security coverage gaps plan item 6): whether every write or edit
// action of the session on the file is covered by an AI row that only added
// lines, and whether any of them was a whole-file write.
type FixEditFacts struct {
	// Actions are the session's successful write and edit actions on the
	// file.
	Actions int
	// Additive are those actions with a file_changes row for this file
	// that is actor 'ai' at high confidence, with no unknown, deleted or
	// modified line, no overwrite and no deletion.
	Additive int
	// WholeWrite: at least one action was a whole-file write.
	WholeWrite bool
	// FirstEditAt is the session's first write or edit of the file.
	FirstEditAt time.Time
}

// AdditiveOnly reports whether every action is proven additive. Zero
// actions prove nothing (never vacuously true).
func (f FixEditFacts) AdditiveOnly() bool { return f.Actions > 0 && f.Additive == f.Actions }

// LoadFixEditFacts returns FixEditFacts for each project-relative path in
// rels, for one session. A path with no action is absent from the map.
func (s *Store) LoadFixEditFacts(ctx context.Context, root, sessionID string, rels []string) (map[string]FixEditFacts, error) {
	out := map[string]FixEditFacts{}
	if sessionID == "" || len(rels) == 0 {
		return out, nil
	}
	if len(rels) > 64 {
		rels = rels[:64]
	}
	byHash := make(map[string]string, len(rels))
	for _, r := range rels {
		if h := loc.PathHash(root, r); h != "" {
			byHash[h] = r
		}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, COALESCE(a.target, ''), a.action_type, a.timestamp
		FROM actions a
		WHERE a.session_id = ? AND a.success = 1 AND a.action_type IN (?, ?)
		ORDER BY a.id LIMIT 2000`, sessionID, models.ActionWriteFile, models.ActionEditFile)
	if err != nil {
		return nil, fmt.Errorf("store.LoadFixEditFacts: actions: %w", err)
	}
	type act struct {
		id   int64
		rel  string
		hash string
		kind string
		at   time.Time
	}
	var acts []act
	for rows.Next() {
		var a act
		var target, ts string
		if err := rows.Scan(&a.id, &target, &a.kind, &ts); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadFixEditFacts: scan: %w", err)
		}
		a.hash = loc.PathHash(root, target)
		rel, ok := byHash[a.hash]
		if !ok {
			continue
		}
		a.rel, a.at = rel, parseLOCTime(ts)
		acts = append(acts, a)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadFixEditFacts: %w", err)
	}
	for _, a := range acts {
		f := out[a.rel]
		f.Actions++
		if a.kind == models.ActionWriteFile {
			f.WholeWrite = true
		}
		if !a.at.IsZero() && (f.FirstEditAt.IsZero() || a.at.Before(f.FirstEditAt)) {
			f.FirstEditAt = a.at
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM file_changes
			WHERE action_id = ? AND file_path_hash = ? AND actor = ? AND actor_confidence = 'high'
			  AND unknown = 0 AND deleted_code = 0 AND modified_code = 0 AND deleted_comment = 0
			  AND overwrite = 0 AND deleted_file = 0`, a.id, a.hash, LOCActorAI).Scan(&n); err != nil {
			return nil, fmt.Errorf("store.LoadFixEditFacts: changes: %w", err)
		}
		var bad int
		if err := s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM file_changes
			WHERE action_id = ? AND file_path_hash = ? AND NOT (actor = ? AND actor_confidence = 'high'
			  AND unknown = 0 AND deleted_code = 0 AND modified_code = 0 AND deleted_comment = 0
			  AND overwrite = 0 AND deleted_file = 0)`, a.id, a.hash, LOCActorAI).Scan(&bad); err != nil {
			return nil, fmt.Errorf("store.LoadFixEditFacts: changes: %w", err)
		}
		if n > 0 && bad == 0 {
			f.Additive++
		}
		out[a.rel] = f
	}
	return out, nil
}

// SessionAgentEdits returns one session's successful file writes and edits
// with their stored (scrubbed) tool input, oldest first, at most limit
// (the item 6 tampering check reads the session's own test edits).
func (s *Store) SessionAgentEdits(ctx context.Context, sessionID string, limit int) ([]AgentEdit, error) {
	if sessionID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 512
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.session_id, COALESCE(a.target, ''), COALESCE(substr(a.raw_tool_input, 1, ?), ''), a.timestamp
		FROM actions a
		WHERE a.session_id = ? AND a.success = 1 AND a.action_type IN (?, ?)
		ORDER BY a.id LIMIT ?`, maxAgentEditInput, sessionID, models.ActionWriteFile, models.ActionEditFile, limit)
	if err != nil {
		return nil, fmt.Errorf("store.SessionAgentEdits: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AgentEdit
	for rows.Next() {
		var e AgentEdit
		var ts string
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Target, &e.RawInput, &ts); err != nil {
			return nil, fmt.Errorf("store.SessionAgentEdits: scan: %w", err)
		}
		e.At = parseLOCTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
