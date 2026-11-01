package dimcode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Transcript reading (session handoff, docs/session-handoff.md). DimCode keeps
// the whole conversation in dimcode.sqlite's messages table, so the reader
// re-reads that one session from the same store the ingest path watches: user
// rows are the prompts (runtime-injected rows are skipped, exactly the
// harnessRules / userAuthored line the ingest path draws), assistant rows carry
// the narration (text parts) and the tool_use blocks, and role=tool_result rows
// resolve the call they answer by tool_use_id. Thinking parts are dropped
// (plan §8). Sub-agent sessions read the same way under their own id.
// Foreign-mount stores go through the same stageMirror the ingest path uses.

// ReadTranscript implements the handoffsvc TranscriptReader capability with
// the default excerpt caps.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements the handoffsvc FullTranscriptReader
// capability: the same normalization with UNCAPPED excerpts, for the
// full_cache carry and the get_session_message pull. Nothing is persisted;
// the bytes are re-read from DimCode's own store on demand.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := a.storePath(sourceHints)
	if err != nil {
		return nil, err
	}
	db, err := openReadOnlyDB(path)
	if err != nil {
		return nil, fmt.Errorf("dimcode.ReadTranscript: open: %w", err)
	}
	defer db.Close()

	msgs, err := loadMessages(ctx, db, sess.ID)
	if err != nil {
		return nil, fmt.Errorf("dimcode.ReadTranscript: messages: %w", err)
	}
	runs, err := loadRuns(ctx, db, sess.ID)
	if err != nil {
		return nil, fmt.Errorf("dimcode.ReadTranscript: runs: %w", err)
	}
	runModel := map[string]string{}
	for _, r := range runs {
		if r.Model != "" {
			runModel[r.RunID] = r.Model
		}
	}
	// The session's currently-selected model is the fallback for a row whose
	// run has no usage row (a run that failed before any model call).
	fallback := sess.Model

	for _, m := range msgs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var parts []part
		if strings.TrimSpace(m.Parts) != "" {
			if json.Unmarshal([]byte(m.Parts), &parts) != nil {
				continue // malformed parts: skip the row, keep the rest
			}
		}
		ts := parseTime(m.CreatedAt)
		model := firstNonEmpty(runModel[runIDOf(m)], fallback)
		switch m.Role {
		case "user":
			if !userAuthored(harnessMeta(m.Metadata)) {
				continue
			}
			var texts []string
			for _, p := range parts {
				if p.Type == "text" && strings.TrimSpace(p.Text) != "" {
					texts = append(texts, p.Text)
				}
			}
			b.SetNextID(m.ID)
			b.User(strings.Join(texts, "\n"), ts)
		case "assistant":
			b.SetNextID(m.ID)
			for _, p := range parts {
				switch p.Type {
				case "text":
					b.AssistantText(p.Text, model, firstTime(parseTime(p.StartTime), ts))
				case "tool_use":
					b.AssistantCall(p.ID, p.Name, string(p.Input), model, firstTime(parseTime(p.StartTime), ts))
				}
			}
		case "tool_result":
			for _, p := range parts {
				if p.Type == "tool_result" && p.ToolUseID != "" {
					b.Resolve(p.ToolUseID, flattenContent(p.Content), parseTime(m.UpdatedAt))
				}
			}
		}
	}
	return b.Finish(), nil
}

// storePath resolves dimcode.sqlite: a usable hint first (the ingest path's
// source_file is the store itself, or one of its -wal/-shm siblings), else the
// first watch root that holds one.
func (a *Adapter) storePath(hints []string) (string, error) {
	for _, h := range hints {
		p := resolveDBPath(h)
		if strings.EqualFold(filepath.Base(p), storeFile) && fileExists(p) {
			return p, nil
		}
	}
	for _, root := range a.roots {
		p := filepath.Join(root, storeFile)
		if fileExists(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("dimcode.ReadTranscript: no %s under any watch root", storeFile)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
