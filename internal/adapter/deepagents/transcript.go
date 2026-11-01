package deepagents

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ReadTranscript implements handoffsvc.TranscriptReader — the session-handoff
// transcript tier (docs/session-handoff.md). dcode has no proxy tier and no
// usable flat transcript (the `~/.deepagents/transcripts/*.jsonl` files are
// hook scratch that dcode rotates and that carry no tool calls), so the
// conversation is re-read from sessions.db by the same `messages` replay the
// ingest path uses: the thread's own namespace only (a sub-agent's run is
// its internal work; its answer reaches the transcript as the `task`
// result). Excerpt caps apply.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// stream with message text and tool-result bodies emitted whole (excerpt
// caps lifted) for the full_cache carry mode and the get_session_message
// MCP pull. Nothing is persisted.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, path := range a.transcriptCandidates(sourceHints) {
		msgs, found, err := readThreadMessages(ctx, path, sess.ID)
		if err != nil {
			return nil, fmt.Errorf("deepagents.ReadTranscript: %w", err)
		}
		if !found {
			continue
		}
		foldTranscript(b, msgs)
		return b.Finish(), nil
	}
	return nil, fmt.Errorf("deepagents.ReadTranscript: thread %s not found in any sessions.db", sess.ID)
}

// transcriptCandidates lists the stores to search: usable hints first (a
// -wal / -shm hint maps to its sessions.db), then every watch root's store
// (one per cross-mount home — a WSL and a Windows store can both exist).
func (a *Adapter) transcriptCandidates(hints []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		if st, err := os.Stat(p); err != nil || st.IsDir() || st.Size() == 0 {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, h := range hints {
		if a.IsSessionFile(h) || strings.EqualFold(filepath.Base(resolveDBPath(h)), "sessions.db") {
			add(resolveDBPath(h))
		}
	}
	for _, root := range a.roots {
		add(filepath.Join(root, "sessions.db"))
	}
	return out
}

// readThreadMessages replays a thread's own-namespace messages from one
// store. found is false when the store does not hold the thread.
func readThreadMessages(ctx context.Context, path, threadID string) ([]*rawMessage, bool, error) {
	db, err := openReadOnlyDB(path)
	if err != nil {
		return nil, false, fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	if !tableExists(ctx, db, "checkpoints") || !tableExists(ctx, db, "writes") {
		return nil, false, nil
	}
	var one int
	if err := db.QueryRowContext(ctx,
		`SELECT 1 FROM checkpoints WHERE thread_id = ? LIMIT 1`, threadID).Scan(&one); err != nil {
		return nil, false, nil //nolint:nilerr // absent thread: try the next store
	}
	writes, err := loadMessageWrites(ctx, db, threadID)
	if err != nil {
		return nil, false, fmt.Errorf("message writes: %w", err)
	}
	var own []messageWrite
	for _, w := range writes {
		if w.Namespace == "" {
			own = append(own, w)
		}
	}
	msgs, _, _ := replayMessages(own)
	return msgs, true, nil
}

// foldTranscript turns replayed messages into the normalized stream: typed
// prompts (the literal text when dcode recorded it; harness `[SYSTEM]`
// messages dropped), assistant text and tool calls per AI message, and tool
// results resolving their calls. Reasoning is not transcript content.
func foldTranscript(b *transcriptutil.Builder, msgs []*rawMessage) {
	model := ""
	for _, m := range msgs {
		ts := msgTime(m)
		switch m.Role {
		case "human":
			text := cleanPromptText(contentText(m.Content))
			if strings.HasPrefix(text, "[SYSTEM]") {
				continue
			}
			literal, _ := promptMeta(*m)
			if l := cleanPromptText(literal); l != "" {
				text = l
			}
			b.SetNextID(m.ID)
			b.User(text, ts)
		case "ai":
			if mm := firstString(m.ResponseMetadata, "model_name", "model"); mm != "" {
				model = mm
			}
			b.SetNextID(m.ID)
			if text := strings.TrimSpace(contentText(m.Content)); text != "" {
				b.AssistantText(text, model, ts)
			}
			for _, tc := range m.ToolCalls {
				b.AssistantCall(tc.ID, tc.Name, jsonArgs(tc.Args), model, ts)
			}
		case "tool":
			if m.ToolCallID != "" {
				b.Resolve(m.ToolCallID, contentText(m.Content), time.Time{})
			}
		}
	}
}
