package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Transcript reading (session handoff, docs/session-handoff.md P2).
// OpenCode keeps the conversation in opencode.db's message + part tables:
// message.data is the role/model/time envelope (messageData), part.data
// the content (textPartData / toolPartData; reasoning parts are OpenCode's
// thinking — dropped, plan §8). Tool parts carry the call and its result
// in ONE row: state.status "completed"/"error" means settled. Times are
// unix millis. Foreign-mount stores go through the same stageMirror the
// ingestion path uses.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	path, err := a.stateDBPath(sourceHints)
	if err != nil {
		return nil, err
	}
	db, err := openReadOnlyDB(path)
	if err != nil {
		return nil, fmt.Errorf("opencode.ReadTranscript: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tables, err := listTables(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("opencode.ReadTranscript: tables: %w", err)
	}
	// A 1.x session (including one an OpenCode 2.x upgrade copied
	// forward) reads from the 1.x tables; a session that only exists in
	// the 2.x store reads from session_message.
	schema := detectSchema(tables)
	var msgs []models.TranscriptMessage
	if schema.v1 {
		if msgs, err = readSessionTranscript(ctx, db, sess.ID); err != nil {
			return nil, err
		}
	}
	if len(msgs) == 0 && schema.v2 {
		return readSessionTranscriptV2(ctx, db, sess.ID)
	}
	return msgs, nil
}

// stateDBPath resolves the session's OpenCode store: a usable hint first
// (the session's own source file, which names its channel's store),
// else the first watch root holding one, opencode.db before any
// opencode-<channel>.db (D-P0.1).
func (a *Adapter) stateDBPath(hints []string) (string, error) {
	for _, h := range hints {
		if isStoreDBName(filepath.Base(h)) && fileExists(h) {
			return h, nil
		}
	}
	for _, root := range a.roots {
		if stores := channelStoresIn(root); len(stores) > 0 {
			return stores[0], nil
		}
	}
	return "", fmt.Errorf("opencode.ReadTranscript: no OpenCode store under any watch root")
}

func readSessionTranscript(ctx context.Context, db *sql.DB, sessionID string) ([]models.TranscriptMessage, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.message_id, m.data, p.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		 WHERE p.session_id = ?
		 ORDER BY m.time_created, m.id, p.time_created, p.id`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("opencode.ReadTranscript: query: %w", err)
	}
	defer rows.Close()

	b := transcriptutil.New()
	lastUserMsg := "" // fold multi-part user messages into ONE user message
	for rows.Next() {
		var msgID, msgRaw, partRaw string
		if err := rows.Scan(&msgID, &msgRaw, &partRaw); err != nil {
			return nil, err
		}
		var msg messageData
		if err := json.Unmarshal([]byte(msgRaw), &msg); err != nil {
			continue
		}
		ts := opencodeMillis(msg.Time.Created)
		if msg.Role == "assistant" && opencodeMillis(msg.Time.Completed) != (time.Time{}) {
			ts = opencodeMillis(msg.Time.Completed)
		}

		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(partRaw), &head); err != nil {
			continue
		}
		switch {
		case msg.Role == "user" && head.Type == "text":
			var tp textPartData
			if json.Unmarshal([]byte(partRaw), &tp) != nil {
				continue
			}
			if msgID == lastUserMsg {
				// Additional text part of the same user message — append
				// as assistant-free continuation via a fresh User would
				// split the prompt; fold by re-issuing is wrong, so skip
				// duplicates conservatively (multi-text user messages are
				// file attachments; the first part is the typed prompt).
				continue
			}
			b.User(tp.Text, ts)
			lastUserMsg = msgID
		case msg.Role == "assistant" && head.Type == "text":
			var tp textPartData
			if json.Unmarshal([]byte(partRaw), &tp) != nil {
				continue
			}
			b.AssistantText(tp.Text, opencodeModel(msg), ts)
		case msg.Role == "assistant" && head.Type == "tool":
			var tp toolPartData
			if json.Unmarshal([]byte(partRaw), &tp) != nil {
				continue
			}
			b.AssistantCall(tp.CallID, tp.Tool, string(tp.State.Input), opencodeModel(msg), ts)
			if tp.State.Status == "completed" || tp.State.Status == "error" {
				out := tp.State.Output
				if out == "" {
					out = tp.State.Metadata.Output
				}
				b.Resolve(tp.CallID, out, time.Time{})
			}
			// reasoning / step-start / step-finish / subtask parts dropped:
			// reasoning is thinking; step markers are informational.
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b.Finish(), nil
}

func opencodeModel(m messageData) string {
	if m.Model.ModelID != "" {
		return m.Model.ModelID
	}
	return m.ModelID
}

func opencodeMillis(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
