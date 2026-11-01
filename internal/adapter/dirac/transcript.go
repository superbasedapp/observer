package dirac

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Transcript reading (session handoff, docs/session-handoff.md P2).
// Dirac's conversation is the operation log of the task
// (`api_conversation_history.jsonl`, plus its rotated `.archive.<n>`
// siblings), so the reader REPLAYS the ops into the materialized history
// and folds it the way every other reader does: user prompts (only the
// genuine <task>/<feedback>/<answer>/... wrappers, never tool results or
// <environment_details>), assistant text, tool calls paired with their
// results (a tool_result rides in a user-role message and attaches to the
// owning exchange), and Dirac's own voice, the \`respond\` tool, rendered as
// assistant text. Thinking is dropped. SessionID == the task directory name.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	path, err := a.opsPath(sess.ID, sourceHints)
	if err != nil {
		return nil, err
	}
	hist, err := replayHistory(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("dirac.ReadTranscript: %w", err)
	}
	return a.foldTranscript(hist), nil
}

// opsPath locates the live op log of a session: a hint naming one wins,
// else `<root>/<sessionID>/api_conversation_history.jsonl` under a root.
func (a *Adapter) opsPath(sessionID string, hints []string) (string, error) {
	for _, h := range hints {
		if filepath.Base(h) == opsName && a.IsSessionFile(h) && fileExists(h) {
			return h, nil
		}
	}
	for _, root := range a.WatchPaths() {
		p := filepath.Join(root, sessionID, opsName)
		if fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("dirac.ReadTranscript: no task log on disk for session %s", sessionID)
}

func fileExists(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode().IsRegular()
}

// replayHistory applies every op of the task (archives ascending, then
// the live log) to an in-memory message list: append_message appends,
// append_user_content adds one block to the trailing user message, reset
// replaces the whole list.
func replayHistory(ctx context.Context, livePath string) ([]rawMessage, error) {
	var hist []rawMessage
	files := append(archivesOf(filepath.Dir(livePath)), livePath)
	for _, p := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := scanOps(p, -1, func(op *rawOp) {
			switch op.Type {
			case "append_message":
				if op.Message != nil {
					hist = append(hist, *op.Message)
				}
			case "reset":
				hist = append([]rawMessage(nil), op.Messages...)
			case "append_user_content":
				appendUserContent(hist, op.Content)
			}
		}); err != nil {
			if p == livePath {
				return nil, err
			}
			// A missing or unreadable archive degrades to a shorter history.
		}
	}
	return hist, nil
}

// appendUserContent adds one content block to the last user message
// (Dirac's append_user_content op).
func appendUserContent(hist []rawMessage, content json.RawMessage) {
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].Role != "user" {
			continue
		}
		blocks := decodeBlocks(hist[i].Content)
		blocks = append(blocks, decodeBlocks(content)...)
		if merged, err := json.Marshal(blocks); err == nil {
			hist[i].Content = merged
		}
		return
	}
}

// scanOps streams one op log, decoding every complete line. limit < 0
// reads the whole file; otherwise only the first limit bytes (the
// consumed prefix of a mid-file resume).
func scanOps(path string, limit int64, fn func(*rawOp)) error {
	f, err := os.Open(path) //nolint:gosec // watched task file or its rotated sibling
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader = f
	if limit >= 0 {
		src = io.LimitReader(f, limit)
	}
	r := bufio.NewReaderSize(src, 64*1024)
	for {
		line, readErr := r.ReadString('\n')
		if strings.HasSuffix(line, "\n") {
			if raw := strings.TrimRight(line, "\r\n"); raw != "" {
				var op rawOp
				if json.Unmarshal([]byte(raw), &op) == nil {
					fn(&op)
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

// countHistory is the message count of the task history after the ops
// already consumed by a mid-file resume: every rotated archive plus the
// live log up to `upto` bytes. ok is false when the live log cannot be
// read.
func countHistory(taskDir, livePath string, upto int64) (int, bool) {
	n := 0
	count := func(op *rawOp) {
		switch op.Type {
		case "append_message":
			if op.Message != nil {
				n++
			}
		case "reset":
			n = len(op.Messages)
		}
	}
	for _, arc := range archivesOf(taskDir) {
		_ = scanOps(arc, -1, count)
	}
	if err := scanOps(livePath, upto, count); err != nil {
		return 0, false
	}
	return n, true
}

// foldTranscript turns the replayed history into transcript messages.
func (a *Adapter) foldTranscript(hist []rawMessage) []models.TranscriptMessage {
	b := transcriptutil.New()
	for i := range hist {
		m := &hist[i]
		ts := msTime(m.Ts)
		model := ""
		if m.ModelInfo != nil {
			model = m.ModelInfo.ModelID
		}
		switch m.Role {
		case "assistant":
			for _, blk := range decodeBlocks(m.Content) {
				switch blk.Type {
				case "text":
					b.AssistantText(a.scrubber.String(blk.Text), model, ts)
				case "tool_use":
					a.foldToolUse(b, blk, model, ts)
				}
				// thinking / redacted_thinking dropped (plan section 8).
			}
		case "user":
			for _, blk := range decodeBlocks(m.Content) {
				switch blk.Type {
				case "text":
					if p := extractPrompt(blk.Text); p != "" {
						b.User(a.scrubber.String(p), ts)
					}
				case "tool_result":
					b.Resolve(blk.ToolUseID, a.scrubber.String(resultText(blk.Content)), msTime(0))
				}
			}
		}
	}
	return b.Finish()
}

// foldToolUse renders one tool_use: \`respond\` is Dirac's assistant voice
// (its text, whatever the operation), every other tool is a call.
func (a *Adapter) foldToolUse(b *transcriptutil.Builder, blk rawBlock, model string, ts time.Time) {
	if blk.Name == respondTool {
		if text := stringField(blk.Input, "text"); text != "" {
			b.AssistantText(a.scrubber.String(text), model, ts)
		}
		return
	}
	b.AssistantCall(blk.ID, blk.Name, a.scrubber.RawJSON(blk.Input), model, ts)
}
