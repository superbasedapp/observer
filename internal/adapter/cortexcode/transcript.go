package cortexcode

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ReadTranscript implements handoffsvc.TranscriptReader: the session's
// normalized message stream re-read from its own
// conversations/<id>.history.jsonl, with the shared excerpt caps. Typed
// prompts become user messages; assistant text and tool calls fold into
// one exchange per user turn, and tool results (carried inside user-role
// records) resolve their calls. Harness-injected internalOnly blocks and
// thinking are dropped. Nothing is persisted.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// stream with message text, tool inputs and tool-result bodies whole.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

// readTranscript resolves the history log and folds it through b.
func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := a.historyPath(sess.ID, sourceHints)
	if !ok {
		return nil, fmt.Errorf("cortexcode.ReadTranscript: no history log for session %s", sess.ID)
	}
	f, err := os.Open(path) //nolint:gosec // watch-root or hint-derived session file
	if err != nil {
		return nil, fmt.Errorf("cortexcode.ReadTranscript: open: %w", err)
	}
	defer f.Close()

	fold := &transcriptFold{a: a, b: b, seen: map[string]bool{}}
	reader := bufio.NewReaderSize(f, 64*1024)
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return nil, fmt.Errorf("cortexcode.ReadTranscript: read: %w", readErr)
		}
		start := offset
		offset += int64(len(line))
		if raw := strings.TrimSpace(line); raw != "" {
			var rec histRecord
			if json.Unmarshal([]byte(raw), &rec) == nil {
				recKey := rec.ID
				if recKey == "" {
					recKey = "@" + strconv.FormatInt(start, 10)
				}
				fold.record(&rec, recKey)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	return b.Finish(), nil
}

// transcriptFold carries the per-read dedup state: user records are
// re-appended as growing snapshots, so identity is per BLOCK (prompt
// message_id, tool_result tool_use_id), exactly as the ingest parser keys
// it.
type transcriptFold struct {
	a    *Adapter
	b    *transcriptutil.Builder
	seen map[string]bool
}

func (t *transcriptFold) once(key string) bool {
	if t.seen[key] {
		return false
	}
	t.seen[key] = true
	return true
}

func (t *transcriptFold) record(rec *histRecord, recKey string) {
	switch rec.Role {
	case "user":
		ts := parseTime(rec.UserSentTime)
		for i, blk := range rec.Content {
			switch blk.Type {
			case "text":
				if !blk.IsUserPrompt || blk.InternalOnly {
					continue
				}
				key := firstNonEmpty(blk.MessageID, recKey+":"+strconv.Itoa(i))
				if !t.once("p:" + key) {
					continue
				}
				text := firstNonEmpty(strings.TrimSpace(blk.DisplayText), strings.TrimSpace(blk.Text))
				t.b.SetNextID(key)
				t.b.User(t.a.scrubber.String(text), ts)
			case "tool_result":
				tr := blk.ToolResult
				if tr == nil || tr.ToolUseID == "" || !t.once("r:"+tr.ToolUseID) {
					continue
				}
				t.b.Resolve(tr.ToolUseID, t.a.scrubber.String(resultText(tr.Content)), time.Time{})
			}
		}
	case "assistant":
		if !t.once("a:" + recKey) {
			return
		}
		ts := parseTime(rec.AssistantSentTime)
		if ts.IsZero() && rec.CreatedOn > 0 {
			ts = time.UnixMilli(rec.CreatedOn).UTC()
		}
		t.b.SetNextID(recKey)
		for _, blk := range rec.Content {
			switch blk.Type {
			case "text":
				if blk.InternalOnly {
					continue
				}
				t.b.AssistantText(t.a.scrubber.String(blk.Text), rec.Model, ts)
			case "tool_use":
				if blk.ToolUse == nil {
					continue
				}
				t.b.AssistantCall(blk.ToolUse.ToolUseID, blk.ToolUse.Name,
					t.a.scrubber.RawJSON(blk.ToolUse.Input), rec.Model, ts)
			}
		}
		t.b.SetNextID("")
	}
}

// historyPath resolves the session's history log: a usable hint first
// (a history log, or its metadata sibling, whose stem is the session id),
// else <root>/<id>.history.jsonl under each watch root.
func (a *Adapter) historyPath(sessionID string, hints []string) (string, bool) {
	if sessionID == "" || strings.ContainsAny(sessionID, `/\`) || !validStem(sessionID) {
		return "", false
	}
	for _, h := range hints {
		switch classifyLayout(h) {
		case layoutHistory:
			if sessionIDFromPath(h) == sessionID && fileReadable(h) {
				return h, true
			}
		case layoutMeta:
			if p := strings.TrimSuffix(h, metaSuffix) + historySuffix; sessionIDFromPath(h) == sessionID && fileReadable(p) {
				return p, true
			}
		}
	}
	for _, root := range a.roots {
		p := filepath.Join(root, sessionID+historySuffix)
		if fileReadable(p) {
			return p, true
		}
	}
	return "", false
}

// fileReadable reports whether p is an existing regular file.
func fileReadable(p string) bool {
	st, err := os.Stat(p) //nolint:gosec // G703: stat of a path under cortex's own data home, read only
	return err == nil && st.Mode().IsRegular()
}
