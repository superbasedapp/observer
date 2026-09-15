package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

// RecordToolAccounts retains conflicting observations and accepts evidence even
// before its action arrives. Replay never changes the first observation time.
func (s *Store) RecordToolAccounts(ctx context.Context, observations []models.ToolAccountObservation) error {
	for _, o := range observations {
		o, key, valid := toolaccount.Normalize(o)
		if !valid {
			continue
		}
		if o.ObservedAt.IsZero() {
			o.ObservedAt = time.Now().UTC()
		}
		_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO tool_account_observations
		(session_id,tool,binding_kind,binding_id,role,account_key,email,name,account_id,source,scope,stage,observed_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, o.SessionID, o.Tool, o.BindingKind, o.BindingID, o.Role, key, o.Email, o.Name, o.AccountID, o.Source, o.Scope, o.Stage, o.ObservedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return fmt.Errorf("store.RecordToolAccounts: %w", err)
		}
	}
	return nil
}

// LoadMessageAccounts resolves exact message/turn/tool-call keys. It never
// carries a login forward in time. Tool-call evidence can join a later transcript.
func (s *Store) LoadMessageAccounts(ctx context.Context, sessionID, tool string) (map[string]models.MessageAccount, error) {
	rows, err := s.db.QueryContext(ctx, `WITH bindings AS (
	 SELECT o.*, o.binding_id AS message_id FROM tool_account_observations o
	 WHERE o.session_id=? AND o.tool=? AND o.binding_kind IN ('message','turn')
	 UNION ALL
	 SELECT o.*, a.message_id FROM tool_account_observations o JOIN actions a
	 ON a.tool=o.tool AND a.source_event_id=o.binding_id
	 WHERE a.session_id=? AND o.tool=? AND o.binding_kind='tool_call' AND COALESCE(a.message_id,'')<>''
	 AND (o.session_id=a.session_id OR o.session_id=(SELECT parent_thread_id FROM sessions WHERE id=a.session_id))
	 UNION ALL
	 SELECT o.*, t.message_id FROM tool_account_observations o JOIN token_usage t
	 ON t.session_id=o.session_id AND t.tool=o.tool AND t.turn_id=o.binding_id
	 WHERE o.session_id=? AND o.tool=? AND o.binding_kind='turn' AND COALESCE(t.message_id,'')<>''
	) SELECT DISTINCT role,message_id,account_key,email,name,account_id,source,scope,stage,observed_at
	 FROM bindings WHERE stage<>'stop' ORDER BY observed_at,account_key,source,scope`, sessionID, tool, sessionID, tool, sessionID, tool)
	if err != nil {
		return nil, fmt.Errorf("store.LoadMessageAccounts: %w", err)
	}
	defer rows.Close()
	out := make(map[string]models.MessageAccount)
	for rows.Next() {
		var role, id string
		var e models.ToolAccountEvidence
		if err := rows.Scan(&role, &id, &e.Key, &e.Email, &e.Name, &e.AccountID, &e.Source, &e.Scope, &e.Stage, &e.ObservedAt); err != nil {
			return nil, fmt.Errorf("store.LoadMessageAccounts: scan: %w", err)
		}
		key := role + ":" + id
		out[key] = toolaccount.Merge(out[key], e)
	}
	return out, rows.Err()
}
