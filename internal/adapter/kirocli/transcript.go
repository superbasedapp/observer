package kirocli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// ReadTranscript implements handoffsvc.TranscriptReader — the
// session-handoff transcript tier (docs/session-handoff.md). Kiro has
// no proxy tier, so the transcript is re-read from whichever store the
// session lives in: the flat-bundle `.jsonl` (interactive) or the
// SQLite conversations_v2 row (non-interactive). The session id
// resolves the flat bundle by filename; for the SQLite store it
// matches conversations_v2.conversation_id.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Prefer a flat bundle: a hint or a watch-root `<id>.jsonl`.
	if path, ok := a.flatJSONLPath(sess.ID, sourceHints); ok {
		return a.flatTranscript(path)
	}
	// Then a Kiro IDE session dir (`<bucket>/<id>/messages.jsonl`).
	if path, ok := a.ideMessagesPath(sess.ID, sourceHints); ok {
		return a.ideTranscript(path)
	}
	// Otherwise look for the conversation in a kiro-cli data.sqlite3.
	if path, ok := a.stateDBPath(sourceHints); ok {
		return a.sqliteTranscript(ctx, path, sess.ID)
	}
	return nil, fmt.Errorf("kirocli.ReadTranscript: no flat bundle, IDE session dir or data.sqlite3 for session %s", sess.ID)
}

func (a *Adapter) flatJSONLPath(sessionID string, hints []string) (string, bool) {
	name := sessionID + ".jsonl"
	for _, h := range hints {
		if filepath.Base(h) == name && fileReadable(h) {
			return h, true
		}
		// A `.json` hint resolves to its `.jsonl` sibling.
		if filepath.Base(h) == sessionID+".json" {
			jl := strings.TrimSuffix(h, ".json") + ".jsonl"
			if fileReadable(jl) {
				return jl, true
			}
		}
	}
	// The default watch root is the PARENT `<home>/.kiro/sessions` and
	// the flat bundles live in its `cli/` subdir; a root configured
	// directly at `.../sessions/cli` (an explicit NewWithOptions root)
	// is honoured too.
	for _, root := range a.roots {
		slashed := filepath.ToSlash(root)
		switch {
		case strings.HasSuffix(slashed, "/.kiro/sessions/cli"):
			if p := filepath.Join(root, name); fileReadable(p) {
				return p, true
			}
		case strings.HasSuffix(slashed, "/.kiro/sessions"):
			if p := filepath.Join(root, "cli", name); fileReadable(p) {
				return p, true
			}
		}
	}
	return "", false
}

// ideMessagesPath locates a Kiro IDE session's messages.jsonl: a
// `.../<sessionId>/messages.jsonl` hint, else a scan of the workspace
// buckets under every `<home>/.kiro/sessions` root. The `cli` bucket is
// skipped — it is the flat-bundle dir, not an IDE workspace.
func (a *Adapter) ideMessagesPath(sessionID string, hints []string) (string, bool) {
	for _, h := range hints {
		if filepath.Base(h) == "messages.jsonl" &&
			filepath.Base(filepath.Dir(h)) == sessionID &&
			fileReadable(h) {
			return h, true
		}
	}
	for _, root := range sessionRoots(a.roots) {
		buckets, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, b := range buckets {
			if !b.IsDir() || b.Name() == "cli" {
				continue
			}
			p := filepath.Join(root, b.Name(), sessionID, "messages.jsonl")
			if fileReadable(p) {
				return p, true
			}
		}
	}
	return "", false
}

// sessionRoots filters the adapter's watch roots down to the
// `<home>/.kiro/sessions` ones (excluding the kiro-cli SQLite dirs).
func sessionRoots(roots []string) []string {
	var out []string
	for _, root := range roots {
		if strings.HasSuffix(filepath.ToSlash(root), "/.kiro/sessions") {
			out = append(out, root)
		}
	}
	return out
}

// ideTranscript builds the normalized transcript from a Kiro IDE
// session's messages.jsonl. Reasoning operations and the non-message
// record types are skipped; tool calls fold into the owning assistant
// exchange the same way the SQLite path does.
func (a *Adapter) ideTranscript(messagesPath string) ([]models.TranscriptMessage, error) {
	body, err := os.ReadFile(messagesPath) //nolint:gosec // path derives from watch root / validated hint
	if err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: %w", err)
	}
	b := transcriptutil.New()
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec ideRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		appendIDETranscriptRecord(b, rec)
	}
	return b.Finish(), nil
}

// appendIDETranscriptRecord folds one IDE record into the transcript
// builder.
func appendIDETranscriptRecord(b *transcriptutil.Builder, rec ideRecord) {
	ts := parseRFC3339(rec.Timestamp)
	switch rec.Payload.Type {
	case "user":
		b.SetNextID(rec.ID)
		b.User(rec.Payload.Content.Text, ts)
	case "assistant":
		if rec.Payload.OperationType == "Reasoning" {
			return
		}
		b.SetNextID(rec.ID)
		b.AssistantText(rec.Payload.Content.Text, "", ts)
	case "tool_call":
		if rec.Payload.ToolCallID != "" {
			b.AssistantCall(rec.Payload.ToolCallID, rec.Payload.ToolName, string(rec.Payload.Args), "", ts)
		}
	case "tool_result":
		if rec.Payload.ToolCallID != "" {
			b.Resolve(rec.Payload.ToolCallID, rec.Payload.Content.Text, ts)
		}
	}
}

func (a *Adapter) stateDBPath(hints []string) (string, bool) {
	for _, h := range hints {
		if strings.EqualFold(filepath.Base(h), "data.sqlite3") && fileReadable(h) {
			return h, true
		}
	}
	for _, root := range a.roots {
		if strings.Contains(strings.ToLower(filepath.ToSlash(root)), "kiro-cli") {
			p := filepath.Join(root, "data.sqlite3")
			if fileReadable(p) {
				return p, true
			}
		}
	}
	return "", false
}

// flatTranscript builds the normalized transcript from a flat-bundle
// `.jsonl` stream, folding in only the Prompt / AssistantMessage TEXT.
//
// The older claim here — that interactive streams carry no tool uses —
// was measured on a text-only session and is wrong: a real interactive
// session carries `toolUse` blocks inside each AssistantMessage plus
// sibling `ToolResults` records (grounded 2026-09-03,
// testdata/kirocrew/kiro-cli/). parseFlatBundle emits those as action
// rows. They are deliberately NOT folded into the transcript here: the
// transcript is the handoff/injection surface, where the useful content
// is the conversational prose, and the SQLite path's own
// sqliteTranscript is the one that folds tool uses into their owning
// exchange.
func (a *Adapter) flatTranscript(jsonlPath string) ([]models.TranscriptMessage, error) {
	body, err := os.ReadFile(jsonlPath) //nolint:gosec // path derives from watch root / validated hint
	if err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: %w", err)
	}
	b := transcriptutil.New()
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var sl flatStreamLine
		if json.Unmarshal([]byte(line), &sl) != nil {
			continue
		}
		text := flatText(sl.Data.Content)
		switch sl.Kind {
		case "Prompt":
			b.SetNextID(sl.Data.MessageID)
			b.User(text, unixSeconds(sl.Data.Meta.Timestamp))
		case "AssistantMessage":
			b.SetNextID(sl.Data.MessageID)
			b.AssistantText(text, "", unixSeconds(sl.Data.Meta.Timestamp))
		}
	}
	return b.Finish(), nil
}

// sqliteTranscript builds the transcript from a conversations_v2 row
// matching conversation_id == sessionID. Tool uses + their results fold
// into the owning assistant exchange.
func (a *Adapter) sqliteTranscript(ctx context.Context, dbPath, sessionID string) ([]models.TranscriptMessage, error) {
	staged, err := stageMirrorIfForeign(canonicalDBPath(dbPath))
	if err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(staged))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	var value string
	err = db.QueryRowContext(ctx,
		"SELECT value FROM conversations_v2 WHERE conversation_id = ? ORDER BY updated_at DESC LIMIT 1",
		sessionID).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("kirocli.ReadTranscript: no conversations_v2 row for %s", sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: query: %w", err)
	}

	var conv sqliteConv
	if err := json.Unmarshal([]byte(value), &conv); err != nil {
		return nil, fmt.Errorf("kirocli.ReadTranscript: parse value: %w", err)
	}
	results := indexToolResults(conv)

	b := transcriptutil.New()
	for _, h := range conv.History {
		ts := entryTimestamp(h)
		if h.User.Content.Prompt != nil {
			b.User(h.User.Content.Prompt.Prompt, ts)
		}
		switch {
		case h.Assistant.ToolUse != nil:
			b.SetNextID(h.Assistant.ToolUse.MessageID)
			for _, tu := range h.Assistant.ToolUse.ToolUses {
				b.AssistantCall(tu.ID, tu.Name, string(tu.Args), h.Request.ModelID, ts)
				if rr, ok := results[tu.ID]; ok {
					b.Resolve(tu.ID, rr.output, ts)
				}
			}
		case h.Assistant.Response != nil:
			b.SetNextID(h.Assistant.Response.MessageID)
			b.AssistantText(h.Assistant.Response.Content, h.Request.ModelID, ts)
		}
	}
	return b.Finish(), nil
}

func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
