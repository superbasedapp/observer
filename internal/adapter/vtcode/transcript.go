package vtcode

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

// ReadTranscript implements handoffsvc.TranscriptReader: the session's
// normalized message stream re-read from VT Code's own files. The source
// is the workspace events.jsonl (user goals from turn.started origin
// "user", agent_message text, tool invocations + outputs paired on
// tool_call_id); when that log is gone it falls back to the global
// archive's `messages`. Excerpt caps apply.
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// stream with message text and tool results emitted whole.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, hints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sess.ID == "" {
		return nil, fmt.Errorf("vtcode.ReadTranscript: empty session id")
	}
	doc, _ := a.archiveFor(sess.ID)
	if path, ok := a.eventsPathFor(sess.ID, hints, doc); ok {
		if err := a.foldEventsTranscript(ctx, path, b, doc); err != nil {
			return nil, err
		}
		return b.Finish(), nil
	}
	if doc == nil {
		for _, h := range hints {
			if isArchiveShape(h) && strings.TrimSuffix(filepath.Base(h), filepath.Ext(h)) == sess.ID {
				doc = a.arch.load(h)
				break
			}
		}
	}
	if doc == nil {
		return nil, fmt.Errorf("vtcode.ReadTranscript: no events.jsonl or archive for session %s", sess.ID)
	}
	foldArchiveTranscript(ctx, doc, b)
	return b.Finish(), nil
}

// eventsPathFor resolves a session's events.jsonl: a readable hint, a
// workspace watch root, else the workspace the archive names.
func (a *Adapter) eventsPathFor(sid string, hints []string, doc *archiveDoc) (string, bool) {
	for _, h := range hints {
		if isEventsShape(h) && sessionIDFromEventsPath(h) == sid && regularFile(h) {
			return h, true
		}
	}
	for _, r := range a.roots {
		if !isWorkspaceSessionsRoot(r) {
			continue
		}
		if p := filepath.Join(r, sid, eventsFileName); regularFile(p) {
			return p, true
		}
	}
	if doc != nil {
		for _, r := range a.roots {
			if isWorkspaceSessionsRoot(r) {
				continue
			}
			archive := filepath.Join(r, sid+".json")
			if !regularFile(archive) {
				continue
			}
			if ws := resolveWorkspacePath(archive, doc.file.Metadata.WorkspacePath); ws != "" {
				if p := filepath.Join(ws, workspaceDirName, sessionsDirName, sid, eventsFileName); regularFile(p) {
					return p, true
				}
			}
		}
	}
	return "", false
}

func regularFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// foldEventsTranscript streams events.jsonl into the builder.
func (a *Adapter) foldEventsTranscript(ctx context.Context, path string, b *transcriptutil.Builder, doc *archiveDoc) error {
	f, err := os.Open(path) //nolint:gosec // resolved session event log
	if err != nil {
		return fmt.Errorf("vtcode.ReadTranscript: open: %w", err)
	}
	defer f.Close()
	sessDir := filepath.Dir(path)
	turns := a.traj.turns(filepath.Join(filepath.Dir(filepath.Dir(sessDir)), logsDirName), sessionIDFromEventsPath(path))
	fallbackModel := ""
	if doc != nil {
		fallbackModel = strings.TrimSpace(doc.file.Metadata.Model)
	}
	model := func(turn string) string {
		if t := turns[turn]; t != nil && t.model != "" {
			return t.model
		}
		return fallbackModel
	}
	st := &transcriptState{called: map[string]bool{}, deferred: map[string]deferredCall{}}
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, readErr := r.ReadString('\n')
		if readErr == nil {
			var env envelope
			if json.Unmarshal([]byte(strings.TrimSpace(line)), &env) == nil {
				foldTranscriptEvent(b, &env.Event, model, st)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("vtcode.ReadTranscript: read: %w", readErr)
		}
	}
	return nil
}

// transcriptState tracks calls across events.
type transcriptState struct {
	called map[string]bool
	// deferred holds argument-less failed invocations: a phantom header
	// unless an output proves the call ran (see flushOrphanCalls).
	deferred map[string]deferredCall
}

type deferredCall struct {
	name, model string
	ts          time.Time
}

// foldTranscriptEvent adds one event to the builder. Only the primary
// conversation is folded; harness bookkeeping, permission and reasoning
// (harness diagnosis) items are not messages.
func foldTranscriptEvent(b *transcriptutil.Builder, ev *eventBody, model func(string) string, st *transcriptState) {
	switch ev.Type {
	case "turn.started":
		if c := ev.Context; c != nil && c.Origin == "user" {
			b.SetNextID(c.TurnID)
			b.User(c.Goal, parseTime(c.Timestamp))
		}
	case "item.completed":
		it := ev.Item
		if it == nil {
			return
		}
		ts := parseTime(it.Context.Timestamp)
		switch it.Type {
		case "agent_message":
			b.SetNextID(it.ID)
			b.AssistantText(it.Text, model(it.Context.TurnID), ts)
		case "tool_invocation":
			if it.ToolCallID == "" || st.called[it.ToolCallID] {
				return
			}
			m := argsMap(it.Arguments)
			switch {
			case m == nil && it.Outcome == "cancelled":
				return // phantom header: nothing ran
			case m == nil && it.Status == "failed":
				// Phantom unless an output proves the call ran.
				st.deferred[it.ToolCallID] = deferredCall{name: it.ToolName, model: model(it.Context.TurnID), ts: ts}
				return
			}
			st.called[it.ToolCallID] = true
			input := ""
			if m != nil {
				if input = patchText(it.Arguments, m); input == "" {
					input = string(it.Arguments)
				}
			}
			b.AssistantCall(it.ToolCallID, it.ToolName, input, model(it.Context.TurnID), ts)
		case "tool_output":
			if d, ok := st.deferred[it.ToolCallID]; ok && !st.called[it.ToolCallID] {
				delete(st.deferred, it.ToolCallID)
				st.called[it.ToolCallID] = true
				b.AssistantCall(it.ToolCallID, d.name, "", d.model, d.ts)
			}
			b.Resolve(it.ToolCallID, it.Output, ts)
		}
	}
}

// foldArchiveTranscript folds an archive's `messages` into the builder
// (the fallback when the event log is gone). Only TUI prompts carry a
// timestamp; System rows (harness notes) are not conversation.
func foldArchiveTranscript(ctx context.Context, doc *archiveDoc, b *transcriptutil.Builder) {
	msgs := doc.file.Messages
	anyMarked := hasUserInput(msgs)
	model := strings.TrimSpace(doc.file.Metadata.Model)
	firstUser := true
	for i := range msgs {
		if i%256 == 0 && ctx.Err() != nil {
			return
		}
		m := &msgs[i]
		switch m.role() {
		case roleUser:
			isFirst := firstUser
			firstUser = false
			if !m.isRealPrompt(anyMarked, isFirst) {
				continue
			}
			var ts time.Time
			if m.Metadata != nil && m.Metadata.Timestamp > 0 {
				ts = time.Unix(m.Metadata.Timestamp, 0).UTC()
			}
			b.User(m.text(), ts)
		case roleAssistant:
			b.AssistantText(m.text(), model, time.Time{})
			for _, c := range m.ToolCalls {
				b.AssistantCall(c.ID, c.Function.Name, c.Function.Arguments, model, time.Time{})
			}
		case roleTool:
			b.Resolve(m.ToolCallID, m.text(), time.Time{})
		}
	}
}
