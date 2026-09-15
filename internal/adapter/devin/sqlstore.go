package devin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// errNoStore is returned when no sessions.db can be resolved from the
// transcript hints or watch roots.
var errNoStore = errors.New("devin: no sessions.db under any watch root")

// fileReadable reports whether path is an existing regular file.
func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// maxRowID returns the largest message_nodes.row_id in the store — the
// incremental watermark. A missing table (foreign/partial schema) yields 0.
func maxRowID(ctx context.Context, db *sql.DB) (int64, error) {
	if !tableExists(ctx, db, "message_nodes") {
		return 0, nil
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(row_id) FROM message_nodes`).Scan(&v); err != nil {
		return 0, err
	}
	return v.Int64, nil
}

// loadTouchedSessions returns the sessions that gained at least one
// message node with row_id > fromOffset, each with the metadata needed to
// walk its active chain.
func loadTouchedSessions(ctx context.Context, db *sql.DB, fromOffset int64) ([]sessionRow, error) {
	if !tableExists(ctx, db, "sessions") || !tableExists(ctx, db, "message_nodes") {
		return nil, nil
	}
	/* #nosec G202 -- hiddenExpr/metadataExpr return one of two compile-time
	   constants each (the column reference or a literal default); no input
	   reaches the SQL text, and fromOffset binds as a positional param. */
	rows, err := db.QueryContext(ctx, `
		SELECT s.id, COALESCE(s.working_directory, ''), COALESCE(s.model, ''), s.main_chain_id,
		       `+hiddenExpr(ctx, db)+`, `+metadataExpr(ctx, db)+`
		  FROM sessions s
		 WHERE EXISTS (
		       SELECT 1 FROM message_nodes m
		        WHERE m.session_id = s.id AND m.row_id > ?)
		 ORDER BY s.last_activity_at ASC, s.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []sessionRow
	for rows.Next() {
		var s sessionRow
		var hidden int64
		if err := rows.Scan(&s.ID, &s.WorkingDir, &s.Model, &s.MainChainID, &hidden, &s.Metadata); err != nil {
			return nil, err
		}
		s.Hidden = hidden != 0
		out = append(out, s)
	}
	return out, rows.Err()
}

// hiddenExpr / metadataExpr degrade the two lane-attribution columns to
// literals on stores predating the migrations that added them
// (`hidden` = the store's own migration 15, `metadata` = 16). A store
// written by an older Devin build must still parse — the surface /
// lineage stamps simply have nothing to resolve, which is the honest
// zero rather than a query error.
func hiddenExpr(ctx context.Context, db *sql.DB) string {
	if columnExists(ctx, db, "sessions", "hidden") {
		return "COALESCE(s.hidden, 0)"
	}
	return "0"
}

func metadataExpr(ctx context.Context, db *sql.DB) string {
	if columnExists(ctx, db, "sessions", "metadata") {
		return "COALESCE(s.metadata, '')"
	}
	return "''"
}

// loadSessionMeta loads one session's chain-walk metadata by id. A
// missing session yields a zero-value row (its empty node set makes
// loadActiveChain return nothing, which the transcript reader handles).
func loadSessionMeta(ctx context.Context, db *sql.DB, sessionID string) (sessionRow, error) {
	s := sessionRow{ID: sessionID}
	if !tableExists(ctx, db, "sessions") {
		return s, nil
	}
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(working_directory, ''), COALESCE(model, ''), main_chain_id
		  FROM sessions WHERE id = ?`, sessionID).Scan(&s.WorkingDir, &s.Model, &s.MainChainID)
	if err == sql.ErrNoRows {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, nil
}

// loadActiveChain walks the session's tree from the active leaf up to the
// root and returns the nodes in chronological (root-first) order. The
// active leaf is sessions.main_chain_id when it names a real node,
// otherwise the largest node_id (newest leaf) — this dedups regenerated
// (forked) turns down to the single live conversation. A cycle guard and
// an iteration cap keep a corrupt parent pointer from looping forever.
func loadActiveChain(ctx context.Context, db *sql.DB, s sessionRow) ([]node, []string) {
	rows, err := db.QueryContext(ctx, `
		SELECT node_id, parent_node_id, chat_message, created_at
		  FROM message_nodes
		 WHERE session_id = ?`, s.ID)
	if err != nil {
		return nil, []string{"devin: session " + s.ID + ": load nodes: " + err.Error()}
	}
	defer rows.Close()

	byID := map[int64]node{}
	var maxNode int64 = -1
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.NodeID, &n.ParentID, &n.RawMsg, &n.Created); err != nil {
			return nil, []string{"devin: session " + s.ID + ": scan node: " + err.Error()}
		}
		byID[n.NodeID] = n
		if n.NodeID > maxNode {
			maxNode = n.NodeID
		}
	}
	if err := rows.Err(); err != nil {
		return nil, []string{"devin: session " + s.ID + ": rows: " + err.Error()}
	}
	if len(byID) == 0 {
		return nil, nil
	}

	leaf := maxNode
	if s.MainChainID.Valid {
		if _, ok := byID[s.MainChainID.Int64]; ok {
			leaf = s.MainChainID.Int64
		}
	}

	var warns []string
	var reversed []node
	visited := map[int64]bool{}
	cur := leaf
	for i := 0; i < len(byID)+1; i++ {
		n, ok := byID[cur]
		if !ok || visited[cur] {
			break
		}
		visited[cur] = true
		reversed = append(reversed, n)
		if !n.ParentID.Valid {
			break
		}
		cur = n.ParentID.Int64
	}

	// Reverse to chronological (root-first) order.
	chain := make([]node, len(reversed))
	for i, n := range reversed {
		chain[len(reversed)-1-i] = n
	}
	return chain, warns
}

// columnExists reports whether a column is present on a table, so a
// store written by an older Devin build (one whose refinery migration
// history stops short of the column) degrades gracefully.
func columnExists(ctx context.Context, db *sql.DB, table, column string) bool {
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return err == nil && n > 0
}

// tableExists reports whether a table is present in the store, so a
// foreign or older schema degrades gracefully instead of erroring.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// contentString flattens a chat_message content field, which is a JSON
// string in every captured row. Non-string shapes (arrays/objects, should
// future Devin builds introduce them) fall back to the raw JSON text so
// nothing is silently dropped.
func contentString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// thinkingText extracts the assistant "thinking" narration, which is an
// object {"thinking": "..."} in the captured rows (tolerant of a bare
// string shape too).
func thinkingText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Thinking string `json:"thinking"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Thinking
	}
	return ""
}

// resultSuccess reads the tool-role result's success flag from
// metadata.extensions["chisel/tool_result_meta"].success. Absent metadata
// defaults to success (the result was recorded without a failure marker).
func resultSuccess(md *nodeMetadata) bool {
	if md == nil || len(md.Extensions) == 0 {
		return true
	}
	var ext struct {
		Meta struct {
			Success *bool `json:"success"`
		} `json:"chisel/tool_result_meta"`
	}
	if err := json.Unmarshal(md.Extensions, &ext); err != nil {
		return true
	}
	if ext.Meta.Success == nil {
		return true
	}
	return *ext.Meta.Success
}

func metaModel(md *nodeMetadata) string {
	if md == nil {
		return ""
	}
	return md.GenerationModel
}

func metaFinish(md *nodeMetadata) string {
	if md == nil {
		return ""
	}
	return md.FinishReason
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// eventKey prefers the node's native message_id UUID; it falls back to a
// session-stable node_id when a record carries no message_id, keeping
// SourceEventID deterministic across re-parses.
func eventKey(messageID string, nodeID int64) string {
	if messageID != "" {
		return messageID
	}
	return "n" + strconv.FormatInt(nodeID, 10)
}

// secondsToTime converts a Unix-seconds timestamp to UTC time; a
// non-positive value yields the zero time.
func secondsToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
