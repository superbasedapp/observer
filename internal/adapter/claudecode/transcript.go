package claudecode

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Transcript reading (session handoff, plan §6 + Phase 0 findings):
// re-reads a session's message content from Claude Code's own
// ~/.claude/projects/<slug>/<session-id>.jsonl at handoff time. Nothing
// here is persisted — the normalized messages feed internal/handoff via
// the handoffsvc boundary.
//
// Normalization rules (D-P0.3): consecutive assistant-side records merge
// into ONE assistant exchange per user prompt; tool_result blocks — which
// arrive inside user-role carrier records — attach to the owning
// exchange's ToolCallRefs and never surface as user messages; thinking
// blocks are dropped; sidechain (sub-agent) records are skipped.

// ReadTranscript implements the handoffsvc TranscriptReader capability.
// sourceHints are real paths the store observed for the session; when none
// resolves, the path is DERIVED by globbing every watch root for
// <session-id>.jsonl (Phase 0 D-P0.1 — hook-fed sessions carry a sentinel
// instead of a path, so derivation is the primary lookup, not a fallback).
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements the handoffsvc FullTranscriptReader
// capability: the same normalization as ReadTranscript but with UNCAPPED
// excerpts (NewWithCaps(0,0,0)), so message text and tool_result bodies
// come through whole. It backs the `full_cache` carry (the actual read
// content inlined into the handover) and the get_session_message MCP pull.
// Nothing is persisted — the bytes are read from Claude Code's own files
// on demand (content-free-DB rule).
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, builder *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	path, err := a.transcriptPath(sess.ID, sourceHints)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("claudecode.ReadTranscript: %w", err)
	}
	defer f.Close()
	parent, agent := subagentFileIdentity(path)
	return parseTranscriptScoped(ctx, f, builder, parent != "" && sess.ID == subagentSessionID(parent, agent))
}

func (a *Adapter) transcriptPath(sessionID string, hints []string) (string, error) {
	for _, h := range hints {
		parent, agent := subagentFileIdentity(h)
		if strings.Contains(sessionID, ":agent:") && (parent == "" || sessionID != subagentSessionID(parent, agent)) {
			continue
		}
		if parent != "" && sessionID != subagentSessionID(parent, agent) {
			continue
		}
		if strings.HasSuffix(h, ".jsonl") && fileExists(h) {
			return h, nil
		}
	}
	var candidates []string
	for _, root := range a.WatchPaths() {
		pattern := filepath.Join(root, "*", sessionID+".jsonl")
		if parent, agent, ok := strings.Cut(sessionID, ":agent:"); ok && parent != "" && agent != "" && !strings.ContainsAny(parent+agent, `/\*?[]`) {
			pattern = filepath.Join(root, "*", parent, "subagents", "agent-"+agent+".jsonl")
		}
		m, _ := filepath.Glob(pattern)
		candidates = append(candidates, m...)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("claudecode.ReadTranscript: no transcript on disk for session %s", sessionID)
	}
	// Prefer the largest file — a resumed session can leave a stub next to
	// the real transcript.
	sort.Slice(candidates, func(i, j int) bool { return fileSize(candidates[i]) > fileSize(candidates[j]) })
	return candidates[0], nil
}

// transcriptRecord is the subset of a Claude Code JSONL line the reader
// needs.
type transcriptRecord struct {
	Type        string          `json:"type"`
	Timestamp   string          `json:"timestamp"`
	IsSidechain bool            `json:"isSidechain"`
	UUID        string          `json:"uuid"`
	Message     json.RawMessage `json:"message"`
}

type transcriptInnerMessage struct {
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
}

type transcriptBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
}

func parseTranscriptScoped(ctx context.Context, r io.Reader, builder *transcriptutil.Builder, includeSidechain bool) ([]models.TranscriptMessage, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	b := transcriptBuilder{b: builder, includeSidechain: includeSidechain}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := br.ReadString('\n')
		if line != "" {
			b.line(line)
		}
		if err != nil {
			break
		}
	}
	return b.finish(), nil
}

// transcriptBuilder wraps the shared exchange builder with claude-code's
// record dispatch (meta-prefix filtering, block walking).
type transcriptBuilder struct {
	b                *transcriptutil.Builder
	includeSidechain bool
}

func (b *transcriptBuilder) line(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	var rec transcriptRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return // malformed lines are skipped, not fatal
	}
	if (rec.IsSidechain && !b.includeSidechain) || (rec.Type != "user" && rec.Type != "assistant") || len(rec.Message) == 0 {
		return
	}
	var msg transcriptInnerMessage
	if err := json.Unmarshal(rec.Message, &msg); err != nil {
		return
	}
	ts := parseTranscriptTime(rec.Timestamp)
	// Stamp this record's uuid on whatever message the builder creates
	// next (this user message, or the opening record of an assistant
	// exchange — first-wins, so a merged multi-record exchange anchors on
	// its opener's uuid). Set per-record so a tool_result carrier or a
	// dropped meta-user record never leaks its uuid onto the next message.
	b.b.SetNextID(rec.UUID)

	// String content: a plain user prompt.
	var text string
	if err := json.Unmarshal(msg.Content, &text); err == nil {
		if rec.Type == "user" {
			b.userMessage(text, ts)
		} else {
			b.assistantText(text, msg.Model, ts)
		}
		return
	}

	var blocks []transcriptBlock
	if err := json.Unmarshal(msg.Content, &blocks); err != nil {
		return
	}
	if rec.Type == "assistant" {
		for _, blk := range blocks {
			switch blk.Type {
			case "text":
				b.assistantText(blk.Text, msg.Model, ts)
			case "tool_use":
				b.assistantCall(blk, msg.Model, ts)
			}
			// thinking / images dropped (plan §8).
		}
		return
	}
	// user record: real prompt text vs tool_result carrier (D-P0.3).
	for _, blk := range blocks {
		switch blk.Type {
		case "text":
			if strings.TrimSpace(blk.Text) != "" {
				b.userMessage(blk.Text, ts)
			}
		case "tool_result":
			b.resolve(blk)
		}
	}
}

// claudeMetaUserPrefixes mark harness-injected user records (local-command
// caveats, slash-command envelopes, command stdout) — the harness talking,
// not the operator. They never become user messages (live-found on the
// first real handoff: a caveat wrapper was quoted as the Mission).
var claudeMetaUserPrefixes = []string{
	"<local-command-caveat>",
	"<local-command-stdout>",
	"<command-name>",
	"<command-message>",
	"<bash-input>",
	"<bash-stdout>",
	"<bash-stderr>",
	"<system-reminder>",
	"<task-notification>",
	"Caveat: the messages below",
}

func isClaudeMetaUserText(s string) bool {
	s = strings.TrimSpace(s)
	for _, p := range claudeMetaUserPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (b *transcriptBuilder) userMessage(text string, ts time.Time) {
	if isClaudeMetaUserText(text) {
		return
	}
	b.b.User(text, ts)
}

func (b *transcriptBuilder) assistantText(text, model string, ts time.Time) {
	b.b.AssistantText(text, model, ts)
}

func (b *transcriptBuilder) assistantCall(blk transcriptBlock, model string, ts time.Time) {
	b.b.AssistantCall(blk.ID, blk.Name, compactJSON(blk.Input), model, ts)
}

func (b *transcriptBuilder) resolve(blk transcriptBlock) {
	// zero ts: results ride user-role carriers — the exchange keeps its
	// last assistant-record time.
	b.b.Resolve(blk.ToolUseID, flattenResult(blk.Content), time.Time{})
}

func (b *transcriptBuilder) finish() []models.TranscriptMessage {
	return b.b.Finish()
}

// flattenResult renders a tool_result content payload (string or block
// array) as plain text.
func flattenResult(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []transcriptBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, blk := range blocks {
		if blk.Type == "text" && strings.TrimSpace(blk.Text) != "" {
			parts = append(parts, strings.TrimSpace(blk.Text))
		}
	}
	return strings.Join(parts, " ")
}

func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw)
}

func parseTranscriptTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}
