package autohand

import (
	"bufio"
	"bytes"
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

// ReadTranscript implements handoffsvc.TranscriptReader — the session-handoff
// transcript tier. Autohand has no proxy tier, so the transcript is re-read
// from the session's own conversation.jsonl: user prompts, assistant text, and
// tool calls whose results (separate `tool` lines joined by tool_call_id) fold
// into the owning assistant exchange. Excerpt caps apply.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// stream with message text and tool-result bodies whole.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := a.conversationPath(sess.ID, sourceHints)
	if !ok {
		return nil, fmt.Errorf("autohand.ReadTranscript: no conversation.jsonl for session %s", sess.ID)
	}
	model := sess.Model
	if m, found, _ := readMetadata(filepath.Join(filepath.Dir(path), metadataName)); found && m.Model != "" {
		model = m.Model
	}
	f, err := os.Open(path) //nolint:gosec // watch-root/hint-derived session file
	if err != nil {
		return nil, fmt.Errorf("autohand.ReadTranscript: open: %w", err)
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, readErr := reader.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 && len(line) <= maxLineBytes {
			var msg message
			if json.Unmarshal(bytes.TrimSpace(line), &msg) == nil {
				foldMessage(b, msg, model)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("autohand.ReadTranscript: read: %w", readErr)
		}
	}
	return b.Finish(), nil
}

// foldMessage adds one transcript line to the builder.
func foldMessage(b *transcriptutil.Builder, msg message, model string) {
	ts := parseTime(msg.Timestamp)
	switch msg.Role {
	case "user":
		if msg.Meta.injected() {
			return // harness-injected peer context, not the operator's prompt
		}
		b.User(contentText(msg.Content), ts)
	case "assistant":
		b.AssistantText(contentText(msg.Content), model, ts)
		for _, tc := range msg.ToolCalls {
			if tc.Tool == "" {
				continue
			}
			b.AssistantCall(tc.ID, tc.Tool, string(tc.Args), model, ts)
		}
	case "tool":
		if msg.Meta.streamChunk() || msg.ToolCallID == "" {
			return
		}
		b.Resolve(msg.ToolCallID, stripANSI(contentText(msg.Content)), ts)
	}
}

// conversationPath resolves the session's conversation.jsonl: a usable hint
// first (the transcript or its sibling metadata.json), else the session
// directory under each watch root.
func (a *Adapter) conversationPath(sessionID string, hints []string) (string, bool) {
	if sessionID == "" || strings.ContainsAny(sessionID, "/\\") || sessionID == ".." {
		return "", false
	}
	for _, h := range hints {
		base := filepath.Base(h)
		if (base != conversationName && base != metadataName) || filepath.Base(filepath.Dir(h)) != sessionID {
			continue
		}
		if p := filepath.Join(filepath.Dir(h), conversationName); fileReadable(p) {
			return p, true
		}
	}
	for _, root := range a.roots {
		if p := filepath.Join(root, sessionID, conversationName); fileReadable(p) {
			return p, true
		}
	}
	return "", false
}

func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
