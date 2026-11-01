package codebuddy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// maxTranscriptLineBytes bounds one retained transcript line on re-read. A
// line past it (an inlined base64 image) is dropped whole: it decodes to
// invalid JSON when truncated, and no conversation text is lost with it.
const maxTranscriptLineBytes = 16 << 20

// ReadTranscript implements handoffsvc.TranscriptReader — the session-handoff
// transcript tier. CodeBuddy has no proxy tier, so the conversation is
// re-read from the session's own JSONL transcript: user prompts, assistant
// text and function_call / function_call_result pairs, folded into the
// normalized stream with the shared builder. Reasoning items, hook-blocked
// prompts, upstream errors, local slash-command bookkeeping and sub-agent
// forwarded items are not conversation and are dropped. Excerpt caps apply.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// normalized stream with message text and tool-result bodies emitted whole
// (excerpt caps lifted) for the full_cache carry mode and the
// get_session_message pull.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := a.transcriptPath(sess.ID, sourceHints)
	if !ok {
		return nil, fmt.Errorf("codebuddy.ReadTranscript: no transcript for session %s", sess.ID)
	}
	f, err := os.Open(path) //nolint:gosec // path is a watch-root/hint-derived session file
	if err != nil {
		return nil, fmt.Errorf("codebuddy.ReadTranscript: open: %w", err)
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, _, terminated, readErr := readBoundedLine(reader, maxTranscriptLineBytes)
		// An unterminated final line is a record still being written.
		if terminated && strings.TrimSpace(line) != "" {
			foldTranscriptLine(b, line)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("codebuddy.ReadTranscript: read: %w", readErr)
		}
	}
	return b.Finish(), nil
}

// foldTranscriptLine folds one transcript line into the builder.
func foldTranscriptLine(b *transcriptutil.Builder, raw string) {
	var rec rawLine
	if json.Unmarshal([]byte(raw), &rec) != nil || rec.FromSubAgent {
		return
	}
	switch rec.Type {
	case "message":
		text := partsText(parts(rec.Content))
		switch rec.Role {
		case "user":
			if rec.ProviderData != nil && rec.ProviderData.SkipRun {
				return
			}
			if isMetaUserText(text) {
				return
			}
			b.SetNextID(rec.ID)
			b.User(text, rec.Timestamp.t)
		case "assistant":
			if pd := rec.ProviderData; pd != nil {
				if errorMessage(pd.Error) != "" || pd.HookStatus == "blocked" {
					return
				}
			}
			b.SetNextID(rec.ID)
			b.AssistantText(text, modelOf(rec.ProviderData), rec.Timestamp.t)
		}
	case "function_call":
		input := ""
		if j := argumentsJSON(rec.Arguments); j != nil {
			input = string(j)
		} else if len(rec.Arguments) > 0 {
			input = string(rec.Arguments)
		}
		b.SetNextID(rec.ID)
		b.AssistantCall(rec.CallID, rec.Name, input, modelOf(rec.ProviderData), rec.Timestamp.t)
	case "function_call_result":
		if rec.CallID != "" {
			b.Resolve(rec.CallID, outputText(rec.Output), rec.Timestamp.t)
		}
	}
}

// transcriptPath resolves the session's main transcript: a usable hint
// first (a `projects/<slug>/<id>.jsonl` file whose stem is the session id),
// else a walk of `<root>/<slug>/<id>.jsonl` under each watch root.
func (a *Adapter) transcriptPath(sessionID string, hints []string) (string, bool) {
	if sessionID == "" || strings.ContainsAny(sessionID, `/\`) {
		return "", false
	}
	for _, h := range hints {
		if matchesShape(h) && sessionIDFromPath(h) == sessionID && fileReadable(h) {
			return h, true
		}
	}
	for _, root := range a.roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name(), sessionID+".jsonl")
			if fileReadable(p) {
				return p, true
			}
		}
	}
	return "", false
}

func fileReadable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
