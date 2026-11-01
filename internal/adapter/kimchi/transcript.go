package kimchi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ReadTranscript implements handoffsvc.TranscriptReader, the
// session-handoff transcript tier (docs/session-handoff.md). Kimchi has no
// proxy tier, so the transcript is re-read from the session's own
// append-only pi-mono JSONL: user prompts, assistant text and tool calls,
// with each `toolResult` folded into the call it answers. Excerpt caps
// apply (the P1 default reader).
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// normalized stream with message text and tool-result bodies emitted whole
// (excerpt caps lifted) for the full_cache carry mode and the
// get_session_message MCP pull.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

// readTranscript resolves the session file and folds every entry into the
// supplied builder (which fixes the excerpt caps).
func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := a.sessionPath(sess.ID, sourceHints)
	if !ok {
		return nil, fmt.Errorf("kimchi.ReadTranscript: no transcript for session %s", sess.ID)
	}
	f, err := os.Open(path) //nolint:gosec // path is a watch-root/hint-derived session file
	if err != nil {
		return nil, fmt.Errorf("kimchi.ReadTranscript: open: %w", err)
	}
	defer f.Close()

	fold := &transcriptFold{b: b}
	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineStr, readErr := reader.ReadString('\n')
		if raw := strings.TrimRight(lineStr, "\r\n"); raw != "" {
			fold.line(raw)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("kimchi.ReadTranscript: read: %w", readErr)
		}
	}
	return b.Finish(), nil
}

// transcriptFold carries the selected-model state across entries.
type transcriptFold struct {
	b        *transcriptutil.Builder
	provider string
	model    string
}

// modelString mirrors parseState.modelString (`provider/model`).
func (t *transcriptFold) modelString() string {
	if t.provider != "" && t.model != "" {
		return t.provider + "/" + t.model
	}
	return t.model
}

// line folds one session entry. Entries the adapter does not consume (the
// harness's `custom` telemetry, `custom_message` reminders, session_info)
// are skipped, exactly as in ParseSessionFile.
func (t *transcriptFold) line(raw string) {
	var rec rawLine
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return
	}
	switch rec.Type {
	case typeModelChange:
		if rec.Provider != "" {
			t.provider = rec.Provider
		}
		if rec.ModelID != "" {
			t.model = rec.ModelID
		}
		return
	case typeMessage:
	default:
		return
	}
	msg := rec.Message
	if msg == nil {
		return
	}
	if msg.Provider != "" {
		t.provider = msg.Provider
	}
	if msg.Model != "" {
		t.model = msg.Model
	}
	ts := parseUnixMillis(msg.Timestamp)
	if ts.IsZero() {
		ts = parseTimestamp(rec.Timestamp)
	}
	t.b.SetNextID(rec.ID)
	switch msg.Role {
	case roleUser:
		t.b.User(msg.Content.text(), ts)
	case roleAssistant:
		model := t.modelString()
		t.b.AssistantText(msg.Content.text(), model, ts)
		for _, call := range msg.Content.toolCalls() {
			input, _ := json.Marshal(call.Arguments)
			t.b.AssistantCall(call.ID, call.Name, string(input), model, ts)
		}
	case roleToolResult:
		t.b.Resolve(msg.ToolCallID, msg.Content.text(), ts)
	case roleBashExecution:
		// The operator's `!`-prefixed shell command: a call and its result
		// in one entry, with no id of its own.
		id := "bashexec:" + rec.ID
		t.b.AssistantCall(id, "bash", msg.Command, t.modelString(), ts)
		t.b.Resolve(id, msg.Output, ts)
	}
}

// sessionPath resolves the session's JSONL: a usable hint first, else a
// walk of each watch root's `--<cwd-slug>--` dirs for `*_<sessionID>.jsonl`.
func (a *Adapter) sessionPath(sessionID string, hints []string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	for _, h := range hints {
		if strings.EqualFold(filepath.Ext(h), ".jsonl") && sessionIDFromPath(h) == sessionID && fileReadable(h) {
			return h, true
		}
	}
	for _, root := range a.roots {
		matches, err := filepath.Glob(filepath.Join(root, "*", "*_"+sessionID+".jsonl"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if fileReadable(m) {
				return m, true
			}
		}
	}
	return "", false
}

func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
