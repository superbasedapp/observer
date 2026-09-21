package gemini

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// rawLegacy is the legacy single-object JSON shape gemini-cli writes today.
type rawLegacy struct {
	SessionID   string         `json:"sessionId"`
	ProjectHash string         `json:"projectHash"`
	StartTime   string         `json:"startTime"`
	Messages    []rawLegacyMsg `json:"messages"`
}

type rawLegacyMsg struct {
	ID        string         `json:"id"`
	Role      string         `json:"role"`
	Timestamp string         `json:"timestamp"`
	Cwd       string         `json:"cwd"`
	Model     string         `json:"model"`
	Content   contentParts   `json:"content"`
	Tokens    *legacyTokens  `json:"tokens,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`

	// ToolCalls / Thoughts are the LIVE shape (gemini-cli builds since at
	// least 2026-06): an assistant message writes `content: ""` and hangs
	// its tool calls and chain-of-thought off SIBLING TOP-LEVEL arrays
	// instead of putting `functionCall` / `thought` parts inside Content.
	// Both shapes are read (additive dispatch in emitMessage) — old
	// session files on disk still carry the content-part shape.
	ToolCalls []liveToolCall `json:"toolCalls,omitempty"`
	Thoughts  liveThoughts   `json:"thoughts,omitempty"`
}

// liveToolCall is one entry of a live assistant message's top-level
// `toolCalls` array. Unlike the legacy `functionCall` content part it
// EMBEDS its own result, so a tool row lands complete without waiting
// for the follow-up functionResponse message.
//
// Fields present on disk but deliberately not decoded: `resultDisplay`
// (polymorphic — a string for shell/topic calls, an object carrying
// `fileDiff`/`originalContent`/`newContent` for writes; decoding it
// would mean storing file contents, which the project forbids) and
// `renderOutputAsMarkdown` (a UI hint).
type liveToolCall struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Args        map[string]any   `json:"args"`
	Result      []liveToolResult `json:"result"`
	Status      string           `json:"status"`
	Timestamp   string           `json:"timestamp"`
	Description string           `json:"description"`
	DisplayName string           `json:"displayName"`
}

// liveToolResult wraps the functionResponse a live tool call carries in
// its `result` array. Same inner shape as the legacy content part, so
// the existing legacyFnResp type is reused.
type liveToolResult struct {
	FunctionResponse *legacyFnResp `json:"functionResponse"`
}

// liveThought is one entry of a live assistant message's top-level
// `thoughts` array: a short headline plus the model's reasoning body.
type liveThought struct {
	Subject     string `json:"subject"`
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// liveThoughts decodes the `thoughts` array defensively, for the same
// reason contentParts does: an unexpected shape here must not fail the
// WHOLE assistant line and drop the message (the 2026-06-27
// dropped-assistant-line bug). Accepts an array of objects (live), an
// array of strings, or a bare string.
type liveThoughts []liveThought

func (l *liveThoughts) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*l = nil
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			*l = nil
			return nil
		}
		*l = liveThoughts{{Description: s}}
		return nil
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		out := make(liveThoughts, 0, len(items))
		for _, item := range items {
			t := strings.TrimSpace(string(item))
			if t == "" || t == "null" {
				continue
			}
			if t[0] == '"' {
				var s string
				if err := json.Unmarshal(item, &s); err != nil {
					return err
				}
				out = append(out, liveThought{Description: s})
				continue
			}
			var th liveThought
			if err := json.Unmarshal(item, &th); err != nil {
				return err
			}
			out = append(out, th)
		}
		*l = out
		return nil
	default:
		var th liveThought
		if err := json.Unmarshal(b, &th); err != nil {
			return err
		}
		*l = liveThoughts{th}
		return nil
	}
}

// contentParts holds a Gemini message's content, which the live CLI writes
// in TWO shapes depending on role: user/tool messages carry an ARRAY of
// parts ([{"text":"…"}, {"functionCall":…}]), while a `gemini`
// (assistant) message carries a bare STRING ("hi there"). Without a custom
// unmarshaler the string shape fails to decode into []legacyPart and the
// WHOLE assistant line is dropped as malformed — so the dashboard shows only
// the user prompt (the live-capture bug, 2026-06-27). UnmarshalJSON
// normalizes both into a []legacyPart: a string becomes a single text part.
type contentParts []legacyPart

func (c *contentParts) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*c = nil
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = contentParts{{Type: "text", Text: s}}
		return nil
	case '[':
		var parts []legacyPart
		if err := json.Unmarshal(b, &parts); err != nil {
			return err
		}
		*c = contentParts(parts)
		return nil
	default:
		// A single object part (defensive — not observed live).
		var p legacyPart
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		*c = contentParts{p}
		return nil
	}
}

type legacyPart struct {
	Type             string         `json:"type"`
	Text             string         `json:"text"`
	Thought          string         `json:"thought"`
	FunctionCall     *legacyFnCall  `json:"functionCall"`
	FunctionResponse *legacyFnResp  `json:"functionResponse"`
	InlineData       map[string]any `json:"inlineData"`
}

type legacyFnCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type legacyFnResp struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type legacyTokens struct {
	Input     int64 `json:"input"`
	Output    int64 `json:"output"`
	CacheRead int64 `json:"cacheRead"`
	Cached    int64 `json:"cached"`
	// Reasoning ("thinking") tokens. The LIVE Gemini CLI emits "thoughts"
	// (verified 2026-06-26); the proposed event-record shape (issue #15292,
	// used by the testdata fixtures) emits "thoughtsTokenCount". Capture
	// both and take the max in tokenEventFor — with only the
	// thoughtsTokenCount tag, real reasoning tokens deserialized to 0 and
	// were silently dropped (under-billing, since reasoning bills at the
	// output rate; [[feedback_reasoning_tokens_billed]]).
	ThoughtsTokens int64 `json:"thoughtsTokenCount"`
	Thoughts       int64 `json:"thoughts"`
	Total          int64 `json:"total"`
}

// rawJSONL is the proposed event-record shape from issue #15292.
// Both `messages` rows from legacy and `event-record` lines from JSONL
// get normalized to this shape internally before emission.
type rawJSONL struct {
	Type        string         `json:"type"`
	SessionID   string         `json:"sessionId,omitempty"`
	ProjectHash string         `json:"projectHash,omitempty"`
	StartTime   string         `json:"startTime,omitempty"`
	ID          string         `json:"id,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
	Cwd         string         `json:"cwd,omitempty"`
	Model       string         `json:"model,omitempty"`
	Content     contentParts   `json:"content,omitempty"`
	Tokens      *legacyTokens  `json:"tokens,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	// Live shape — see rawLegacyMsg.ToolCalls / .Thoughts. The live CLI
	// writes these on its `type:"gemini"` lines; without them the JSONL
	// path saw only empty content and emitted no tool or reasoning rows
	// at all (WP-T6 finding G1).
	ToolCalls []liveToolCall `json:"toolCalls,omitempty"`
	Thoughts  liveThoughts   `json:"thoughts,omitempty"`
}

type sessionState struct {
	SessionID     string
	ProjectHash   string
	ProjectRoot   string
	ProjectRemote string
	// ProjectIdentity is the Project Identity Resolver v2 bundle
	// (2026-09-06, §3.1 / W1) resolved alongside ProjectRoot/ProjectRemote,
	// applied to every event in the ParseResult via
	// adapter.ApplyProjectIdentity before the top-level parse returns.
	ProjectIdentity git.Identity
	Model           string
	StartTime       time.Time
}

// parseLegacy handles a single-object JSON session file. Re-reads the
// file in full on every call (idempotent via dedup); returns the
// current file size as the cursor so the watcher's MAX-monotonic
// guard advances naturally on each turn append.
func (a *Adapter) parseLegacy(ctx context.Context, path string, fi os.FileInfo, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fi.Size() == 0 {
		return res, nil
	}
	if fi.Size() == fromOffset {
		// Watcher woke us with a non-content event (mtime touch, etc.).
		// File size unchanged → no work.
		return res, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("gemini.parseLegacy: read: %w", err)
	}
	var legacy rawLegacy
	if err := json.Unmarshal(body, &legacy); err != nil {
		// Truncated mid-write or genuinely malformed. Don't advance the
		// cursor in this case — the next call will retry once the file
		// is fully written.
		return adapter.ParseResult{
			NewOffset: fromOffset,
			Warnings:  []string{fmt.Sprintf("gemini: legacy JSON parse failed (likely mid-write); will retry: %v", err)},
		}, nil
	}

	state := sessionState{
		SessionID:   firstNonEmpty(legacy.SessionID, sessionIDFromPath(path)),
		ProjectHash: legacy.ProjectHash,
		StartTime:   parseTimestamp(legacy.StartTime),
	}
	// First pass: pick a cwd hint from any message that has one, so
	// downstream emission uses a stable project root.
	for _, m := range legacy.Messages {
		if strings.TrimSpace(m.Cwd) != "" {
			state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, m.Cwd)
			break
		}
	}
	if state.ProjectRoot == "" {
		state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, "")
	}

	for i, msg := range legacy.Messages {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		a.emitMessage(path, i, msg, &state, &res)
	}
	return res, nil
}

// maxRecordBytes bounds the memory a single gemini session record may
// consume while being read. It is a memory-safety bound, not a
// correctness limit: a record LARGER than it is SKIPPED (its bytes
// consumed and the cursor advanced past it) rather than aborting the
// whole file, which is what the previous bufio.Scanner token cap did
// ("bufio.Scanner: token too long" failed the file whole). Declared as
// a var so tests can lower it without allocating megabytes; treat it as
// an immutable constant everywhere else.
var maxRecordBytes int64 = 16 * 1024 * 1024

// readRecord reads one '\n'-terminated record from r under the maxBytes
// memory-safety bound. It returns the record bytes INCLUDING the
// terminating '\n' when one was present, the total bytes consumed from
// the stream (used to advance the byte cursor even when the record is
// skipped), whether the record exceeded maxBytes (data is nil and its
// bytes have been fully drained), and the terminating read error.
//
// The err return is the TERMINATOR SIGNAL callers rely on: bufio's
// ReadSlice reports a nil error the moment it locates '\n' and io.EOF
// only when the stream ends before one is found. So a record returned
// with consumed > 0 AND err == io.EOF is an UNTERMINATED trailing
// fragment — an append gemini-cli has not finished writing. A clean end
// of stream yields consumed == 0.
//
// This mirrors codex's reader (internal/adapter/codex/adapter.go
// readRecord) because the cursor invariant is the same one: only a
// terminated record may move the byte cursor.
func readRecord(r *bufio.Reader, maxBytes int64) (data []byte, consumed int64, oversized bool, err error) {
	var buf []byte
	for {
		frag, readErr := r.ReadSlice('\n')
		consumed += int64(len(frag))
		if !oversized {
			if int64(len(buf))+int64(len(frag)) > maxBytes {
				// The record crossed the bound: stop accumulating, drop
				// what we have, and keep draining to the terminator so the
				// cursor advances past the whole record.
				oversized = true
				buf = nil
			} else {
				// frag aliases r's internal buffer (valid only until the
				// next read); append copies it out immediately.
				buf = append(buf, frag...)
			}
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if oversized {
			return nil, consumed, true, readErr
		}
		return buf, consumed, false, readErr
	}
}

// parseJSONL handles the proposed event-record JSONL format. Streams
// from fromOffset, returns NewOffset = bytes consumed.
func (a *Adapter) parseJSONL(ctx context.Context, path string, fi os.FileInfo, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("gemini.parseJSONL: open: %w", err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("gemini.parseJSONL: seek: %w", err)
		}
	}

	state := sessionState{SessionID: sessionIDFromPath(path)}
	reader := bufio.NewReaderSize(f, 64*1024)

	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		record, consumed, oversized, readErr := readRecord(reader, maxRecordBytes)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return res, fmt.Errorf("gemini.parseJSONL: read: %w", readErr)
		}
		if consumed == 0 {
			break // clean end of stream
		}
		// UNTERMINATED TRAILING RECORD — DEFER IT WHOLE. The watcher
		// wakes on every append, so a parse routinely lands mid-write
		// with the last record only partly on disk. The discriminator is
		// the TERMINATOR, never JSON validity: gemini-cli writes one
		// '\n'-terminated JSON object per record (verified across the
		// whole live corpus — every session file's last byte is 0x0a),
		// so a record without '\n' is by construction incomplete.
		//
		// Committing the cursor past it strands the record forever: the
		// next pass resumes AFTER the fragment and the completed record
		// is never seen. That is one bug class with two faces, and both
		// are covered here — a partial record that happens to be
		// malformed JSON, and a partial record whose JSON prefix happens
		// to parse (the more dangerous one, since it emits truncated
		// events AND loses the rest). Do not parse it, do not count its
		// line (lineNum stays put so SourceEventID L-numbers remain
		// stable), do not advance the cursor past its start.
		if errors.Is(readErr, io.EOF) {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"gemini: deferred unterminated trailing record at offset %d (%d bytes) pending terminator", bytesRead, consumed,
			))
			break
		}
		nextOffset := bytesRead + consumed
		lineNum++
		if oversized {
			// Terminated but over the memory bound (the unterminated case
			// was deferred above). Skip the record and advance past it
			// rather than failing the whole file.
			bytesRead = nextOffset
			res.NewOffset = nextOffset
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"gemini: line %d skipped oversized record: %d bytes exceeds %d-byte per-record bound", lineNum, consumed, maxRecordBytes,
			))
			continue
		}
		// consumed is the exact terminator-inclusive byte length, so the
		// cursor is CRLF-correct — the previous len(line)+1 arithmetic
		// silently under-counted by one byte per line on a CRLF file and
		// over-counted by one at an unterminated EOF.
		raw := bytes.TrimRight(record, "\r\n")
		bytesRead = nextOffset
		if len(raw) == 0 {
			res.NewOffset = bytesRead
			continue
		}
		var line rawJSONL
		if err := json.Unmarshal(raw, &line); err != nil {
			// Terminated and genuinely corrupt: skip it with a warning and
			// advance, so one bad interior record can't wedge the file.
			res.Warnings = append(res.Warnings, fmt.Sprintf("gemini: line %d malformed: %v", lineNum, err))
			res.NewOffset = bytesRead
			continue
		}
		res.NewOffset = bytesRead

		switch line.Type {
		case "session_metadata":
			if line.SessionID != "" {
				state.SessionID = line.SessionID
			}
			if line.ProjectHash != "" {
				state.ProjectHash = line.ProjectHash
			}
			if line.StartTime != "" {
				state.StartTime = parseTimestamp(line.StartTime)
			}
			if state.ProjectRoot == "" {
				state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, line.Cwd)
			}
		case "user", "gemini", "model", "tool":
			// Convert event record → legacy-message shape and reuse emitMessage.
			msg := rawLegacyMsg{
				ID:        line.ID,
				Role:      line.Type,
				Timestamp: line.Timestamp,
				Cwd:       line.Cwd,
				Model:     line.Model,
				Content:   line.Content,
				Tokens:    line.Tokens,
				Metadata:  line.Metadata,
				ToolCalls: line.ToolCalls,
				Thoughts:  line.Thoughts,
			}
			if state.ProjectRoot == "" {
				state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, msg.Cwd)
			}
			a.emitMessage(path, lineNum, msg, &state, &res)
		case "message_update":
			// Token-row update for a previously emitted gemini message.
			// The store layer's ON CONFLICT DO UPDATE on token_usage will
			// pick up the new counts; we just emit a fresh TokenEvent
			// keyed by the same SourceEventID.
			if line.Tokens == nil || line.ID == "" {
				continue
			}
			ts := parseTimestamp(line.Timestamp)
			if ts.IsZero() {
				ts = state.StartTime
			}
			res.TokenEvents = append(res.TokenEvents, tokenEventFor(path, line.ID, ts, line.Model, &state, *line.Tokens))
		default:
			// The live CLI writes an untyped HEADER line
			// ({sessionId,projectHash,startTime,kind}) plus interleaved
			// {"$set":…} mutation lines. applyUntypedHeaderLine captures the
			// header as session metadata and skips every other untyped line
			// SILENTLY; a genuinely unknown TYPED event still logs a warning
			// here (forward-compat) since a warning per `$set` would flood
			// the watcher log on every session.
			if applyUntypedHeaderLine(path, line, &state) {
				continue
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("gemini: line %d unknown type %q", lineNum, line.Type))
		}
	}
	if state.ProjectRoot == "" {
		// Backfill: if no metadata line landed, give every event a root
		// derived from the path. emitMessage already handled per-line
		// resolution but a fully empty file would leave it blank.
		state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, "")
	}
	return res, nil
}

// applyUntypedHeaderLine handles a JSONL record whose `type` field is
// empty — parseJSONL's default-case sub-step for the live CLI's untyped
// lines. The live CLI writes an untyped HEADER line
// ({sessionId,projectHash,startTime,kind}) plus interleaved {"$set":…}
// mutation lines; this captures the header's metadata into state and
// silently no-ops on every other untyped line (a warning per `$set`
// would flood the watcher log on every session).
//
// The header carries metadata (projectHash/startTime/cwd) AND a UUID
// `sessionId`. Capture the metadata but do NOT override state.SessionID:
// gemini sessions are keyed by the path basename (sessionIDFromPath)
// everywhere else, and the live header's UUID differs from it —
// overriding here fragments the session into two rows (user prompt
// under the path id, the rest under the UUID). The proposed-format
// `session_metadata` case keeps its own SessionID handling for that
// (typed) shape.
//
// Returns handled=false when line.Type is non-empty, so the caller's
// switch default can fall through to its own unknown-typed-line warning.
func applyUntypedHeaderLine(path string, line rawJSONL, state *sessionState) (handled bool) {
	if line.Type != "" {
		return false
	}
	if line.SessionID != "" || line.ProjectHash != "" || line.StartTime != "" {
		if line.ProjectHash != "" {
			state.ProjectHash = line.ProjectHash
		}
		if line.StartTime != "" {
			state.StartTime = parseTimestamp(line.StartTime)
		}
		if state.ProjectRoot == "" {
			state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, line.Cwd)
		}
	}
	return true
}

// emitMessage walks one normalized message and appends ToolEvent /
// TokenEvent records to res. Shared between legacy + JSONL paths.
func (a *Adapter) emitMessage(path string, idx int, msg rawLegacyMsg, state *sessionState, res *adapter.ParseResult) {
	if msg.Cwd != "" && state.ProjectRoot == "" {
		state.ProjectRoot, state.ProjectRemote, state.ProjectIdentity = resolveProjectRoot(path, msg.Cwd)
	}
	if msg.Model != "" {
		state.Model = msg.Model
	}
	ts := parseTimestamp(msg.Timestamp)
	if ts.IsZero() {
		ts = state.StartTime
	}

	role := strings.ToLower(strings.TrimSpace(msg.Role))
	switch role {
	case "user":
		text := concatText(msg.Content)
		// The LIVE CLI delivers tool RESULTS as a user-role message whose
		// content is nothing but functionResponse parts. Those are not a
		// user prompt: join them onto the matching call rows and emit no
		// prompt row. (The legacy shape used role="tool" for this, handled
		// below; both feed the same joiner.)
		if strings.TrimSpace(text) == "" && joinResponses(res, path, msg.Content, a.scrubber) > 0 {
			return
		}
		// Image-only user turns (a pasted/attached image with no text)
		// would otherwise fall through silently — Gemini carries them as
		// `inlineData` content parts (mimeType + base64 data). Surface a
		// marker row (cowork-style) so the multimodal activity shows in
		// the timeline; the image's token cost lands on the next token
		// event's input bucket. Observability-only — no image bytes are
		// read or stored.
		// Structured user-attachment metadata (Issue 1): the images the
		// user attached to this turn (kind + optional media_type from
		// inlineData.mimeType), captured for both image-only turns and
		// turns that also carry text. Metadata only — no bytes, no name.
		atts := collectInlineImageAttachments(msg.Content)
		if strings.TrimSpace(text) == "" {
			if len(atts) > 0 {
				text = fmt.Sprintf("[user sent %d image attachment(s)]", len(atts))
			} else {
				return
			}
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         path,
			SourceEventID:      firstNonEmpty(msg.ID, fmt.Sprintf("user:%s:%d", state.SessionID, idx)),
			SessionID:          state.SessionID,
			ProjectRoot:        state.ProjectRoot,
			GitRemote:          state.ProjectRemote,
			GitUpstreamRemote:  state.ProjectIdentity.UpstreamRemote,
			GitRemoteOwner:     state.ProjectIdentity.RemoteOwner,
			GitUpstreamOwner:   state.ProjectIdentity.UpstreamOwner,
			RootCommitSHA:      state.ProjectIdentity.RootCommitSHA,
			ContentFingerprint: state.ProjectIdentity.ContentFingerprint,
			Workspace:          state.ProjectIdentity.Workspace,
			IsWorktree:         state.ProjectIdentity.IsWorktree,
			Timestamp:          ts,
			Model:              state.Model,
			Tool:               models.ToolGeminiCLI,
			ActionType:         models.ActionUserPrompt,
			Target:             truncate(text, 200),
			Success:            true,
			RawToolName:        "message.user",
			RawToolInput:       a.scrubber.String(text),
			MessageID:          "user:" + firstNonEmpty(msg.ID, fmt.Sprintf("L%d", idx)),
			UserAttachments:    atts,
		})
	case "gemini", "model", "assistant":
		// Reasoning arrives in one of two shapes: legacy `thought` content
		// parts, or the live top-level `thoughts` array. Prefer whichever
		// the file actually carries.
		reasoning := concatThought(msg.Content)
		if reasoning == "" {
			reasoning = concatLiveThoughts(msg.Thoughts)
		}
		assistantID := firstNonEmpty(msg.ID, fmt.Sprintf("assistant:%s:%d", state.SessionID, idx))
		// REASONING SEMANTICS (B3 convergence, 2026-07-31): the model's
		// "thought" reaches the timeline ONLY as PrecedingReasoning on the
		// tool calls below (FAN-OUT: a message's thought is threaded onto
		// every tool call of that message, legacy and live shape alike,
		// capped at the 200-char preview inside toolCallEvent). It is
		// deliberately NOT emitted as a standalone task_complete row of its
		// own: a reasoning block is not an action, and the phantom rows
		// polluted every action aggregate (see docs/plans/
		// b3-reasoning-convergence-plan-2026-07-31.md §1). The preview cap
		// stays exactly where it was — on the threading site.
		// Emit a standalone assistant-text row per non-empty text part on
		// this assistant message, mirroring the cross-adapter convention
		// (codex.assistant_text, cline.assistant_text, etc.). These rows
		// carry the body in ToolOutput but no token/cost fields — usage
		// flows through the dedicated TokenEvent emitter below.
		for partIdx, part := range msg.Content {
			if part.Type != "text" {
				continue
			}
			body := strings.TrimSpace(part.Text)
			if body == "" {
				continue
			}
			res.ToolEvents = append(res.ToolEvents, a.assistantTextEvent(path, msg, partIdx, idx, ts, state, body, assistantID))
		}
		// LEGACY shape: one ToolEvent per functionCall content part.
		// function responses on later parts/messages get joined onto the
		// call's ToolOutput via call ID.
		for partIdx, part := range msg.Content {
			if part.FunctionCall == nil {
				continue
			}
			call := normalizedCall{ID: part.FunctionCall.ID, Name: part.FunctionCall.Name, Args: part.FunctionCall.Args}
			res.ToolEvents = append(res.ToolEvents, a.toolCallEvent(path, msg, partIdx, ts, state, call, reasoning, assistantID))
		}
		// LIVE shape: one ToolEvent per top-level toolCalls[] entry, which
		// also carries its own result + status. A message never carries
		// both shapes (they are alternative encodings of the same thing),
		// so the two loops cannot double-count; if a future build emitted
		// both, the call ids would collide and the store would dedupe.
		for callIdx, tc := range msg.ToolCalls {
			res.ToolEvents = append(res.ToolEvents, a.toolCallEvent(path, msg, callIdx, ts, state, tc.normalize(), reasoning, assistantID))
		}
		// Capture token row whenever present.
		if msg.Tokens != nil && (msg.Tokens.Input > 0 || msg.Tokens.Output > 0 || msg.Tokens.CacheRead > 0 || msg.Tokens.Cached > 0 || msg.Tokens.ThoughtsTokens > 0) {
			res.TokenEvents = append(res.TokenEvents, tokenEventFor(path, assistantID, ts, state.Model, state, *msg.Tokens))
		}
	case "tool", "function", "function_response":
		// Tool/function response messages: join onto the matching tool
		// call by ID. The store layer doesn't update existing rows from
		// re-emit, so we attach output to events already in res via in-
		// memory lookup. Cross-message functionResponse parts (the
		// canonical legacy shape uses one tool message per response)
		// are handled here.
		joinResponses(res, path, msg.Content, a.scrubber)
	}
}

// messageKey is the per-message half of a SourceEventID. It uses the
// message's own id when present and falls back to the line/array
// position only when there is none.
//
// The position is deliberately NOT mixed in when an id exists: the live
// CLI appends the SAME assistant message TWICE (once when the text/
// thoughts land, again once its toolCalls resolve — verified on every
// multi-turn session in the live corpus, e.g. lines 5+7 and 10+12 of the
// WP-T6 probe). Keying on the line number made those two appends look
// like two different rows, which is why the all-time corpus carries more
// assistant_message rows than user prompts.
func messageKey(msg rawLegacyMsg, msgIdx int) string {
	return firstNonEmpty(msg.ID, fmt.Sprintf("L%d", msgIdx))
}

// assistantTextEvent shapes a text content part on an assistant-role
// message into a standalone observability row. SourceEventID embeds the
// session, message key, and part index for re-parse stability.
// MessageID echoes the assistant message id so this row joins to its
// sibling tool/token events. No token/cost fields.
func (a *Adapter) assistantTextEvent(path string, msg rawLegacyMsg, partIdx, msgIdx int, ts time.Time, state *sessionState, body, assistantID string) models.ToolEvent {
	preview := truncate(a.scrubber.String(body), 200)
	return models.ToolEvent{
		SourceFile:         path,
		SourceEventID:      fmt.Sprintf("asst:%s:%s:%d", state.SessionID, messageKey(msg, msgIdx), partIdx),
		SessionID:          state.SessionID,
		ProjectRoot:        state.ProjectRoot,
		GitRemote:          state.ProjectRemote,
		GitUpstreamRemote:  state.ProjectIdentity.UpstreamRemote,
		GitRemoteOwner:     state.ProjectIdentity.RemoteOwner,
		GitUpstreamOwner:   state.ProjectIdentity.UpstreamOwner,
		RootCommitSHA:      state.ProjectIdentity.RootCommitSHA,
		ContentFingerprint: state.ProjectIdentity.ContentFingerprint,
		Workspace:          state.ProjectIdentity.Workspace,
		IsWorktree:         state.ProjectIdentity.IsWorktree,
		Timestamp:          ts,
		Model:              state.Model,
		Tool:               models.ToolGeminiCLI,
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "gemini.assistant_text",
		ToolOutput:         a.scrubber.String(truncate(body, 4000)),
		MessageID:          assistantID,
	}
}

// normalizedCall is the shape-independent tool call that BOTH on-disk
// encodings resolve to at the parse boundary: the legacy `functionCall`
// content part and the live top-level `toolCalls[]` entry. Downstream
// emission is written against this, never against either raw shape
// (CLAUDE.md §3 — resolve source differences at the boundary).
//
// Output/Status/Error/TS are zero for the legacy shape, which carries
// none of them: the result arrives later as a functionResponse and is
// joined by joinResponse.
type normalizedCall struct {
	ID     string
	Name   string
	Args   map[string]any
	Output string
	Status string
	Error  string
	TS     time.Time
}

// normalize resolves a live toolCalls[] entry into the shape-independent
// form. The embedded result is unwrapped here so the row lands complete
// even when the follow-up functionResponse message is in a later parse
// batch (or never arrives, on an interrupted session).
func (tc liveToolCall) normalize() normalizedCall {
	return normalizedCall{
		ID:     tc.ID,
		Name:   tc.Name,
		Args:   tc.Args,
		Output: tc.outputText(),
		Status: tc.Status,
		Error:  tc.errorText(),
		TS:     parseTimestamp(tc.Timestamp),
	}
}

// outputText pulls the human-readable tool output out of a live call's
// embedded result. Gemini nests it at
// result[].functionResponse.response.output; anything else is carried as
// the marshalled response object rather than dropped.
func (tc liveToolCall) outputText() string {
	for _, r := range tc.Result {
		if r.FunctionResponse == nil || len(r.FunctionResponse.Response) == 0 {
			continue
		}
		if s, ok := r.FunctionResponse.Response["output"].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
		if body, err := json.Marshal(r.FunctionResponse.Response); err == nil {
			return string(body)
		}
	}
	return ""
}

// errorText pulls the failure reason out of a failed live call's
// embedded result. Gemini nests it at
// result[].functionResponse.response.error (observed live: a read_file
// call with status="error" whose response carries ONLY an `error` key
// and no `output`).
//
// This is load-bearing beyond display. The store's action upsert may
// flip an already-persisted success 1 → 0 ONLY when the re-emitted row
// carries a non-empty error_message (internal/store/store.go
// insertActionSQL — the flip is gated on EVIDENCE so a provisional
// re-emit can't downgrade a real success). The gemini adapter never set
// ErrorMessage, so that self-heal was structurally dead here: a call
// first persisted optimistically successful could never be corrected by
// the CLI's own re-append carrying status="error".
func (tc liveToolCall) errorText() string {
	for _, r := range tc.Result {
		if r.FunctionResponse == nil {
			continue
		}
		if text, meaningful := responseErrorText(r.FunctionResponse.Response); meaningful {
			return text
		}
	}
	return ""
}

// responseErrorText unwraps the `error` key of ONE functionResponse
// body. It is the single owner of "does this response report a failure,
// and what does it say" — shared by the live shape's
// [liveToolCall.errorText] and by [joinResponse], which applies the same
// verdict to the LEGACY shape (where the response arrives as its own
// record, not embedded on the call).
//
// The second return is deliberately a separate boolean rather than
// `text != ""`: it distinguishes "the body carries no error key" (the
// invention-refusal case — nothing may be claimed about the outcome)
// from "the body carries an error whose rendering happens to be empty"
// (an empty string, an explicit null). Both yield meaningful=false here,
// but the caller reads INTENT from the flag, not from the string, so a
// future non-empty-but-blank rendering can't silently flip a verdict.
//
// MEANINGFULNESS IS A TABLE, and a narrow one, because the flag ends up
// writing `success = 0` into a row that the store will then honour
// forever:
//
//   - non-empty string           → a failure report
//   - non-empty object / array   → a structured failure report (the real
//     legacy shape, e.g. {"error":{"code":403,…}})
//   - bool / number, ALONE       → NEVER meaningful. `{"error": false}`
//     and `{"error": 0}` are the idiomatic ways a payload says "no
//     error"; `{"error": true}` / `{"error": 1}` report no reason at
//     all, so filing them as a measured failure with the error text
//     "true" would be the same invention the SuccessKnown gate exists
//     to prevent. A build that starts reporting failures this way needs
//     a grounded row here, not a guess.
//   - empty string / empty object / empty array / null / absent → the
//     key is present but says nothing.
//   - any other concrete type (the decoder can't produce one from JSON)
//     → fail closed, not open.
func responseErrorText(resp map[string]any) (string, bool) {
	if len(resp) == 0 {
		return "", false
	}
	raw, ok := resp["error"]
	if !ok || raw == nil {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			return v, true
		}
		return "", false
	case map[string]any:
		if len(v) == 0 {
			return "", false
		}
		return marshalErrorValue(v)
	case []any:
		if len(v) == 0 {
			return "", false
		}
		return marshalErrorValue(v)
	default:
		return "", false
	}
}

// marshalErrorValue renders a structured error body. A marshal failure
// (an unmarshalable value can't come from the JSON decoder, but the type
// is `any`) degrades to "no meaningful error" rather than to a guess.
func marshalErrorValue(v any) (string, bool) {
	body, err := json.Marshal(v)
	if err != nil || string(body) == "null" {
		return "", false
	}
	return string(body), true
}

// failedCallStatuses lists the live `status` values that mean the call
// did not succeed. A table rather than an if/else ladder (CLAUDE.md §5);
// an unknown or absent status is treated as success, matching the
// legacy shape which carries no status at all.
//
// `error` and `cancelled` are gemini-cli's own terminal-failure states
// (CoreToolCallStatus, packages/core/src/scheduler/types.ts); the rest
// are defensive spellings, never observed on disk.
var failedCallStatuses = map[string]bool{
	"error":     true,
	"failed":    true,
	"failure":   true,
	"cancelled": true,
	"canceled":  true,
	"rejected":  true,
	"denied":    true,
	"timeout":   true,
}

// pendingCallStatuses lists the NON-TERMINAL states of gemini-cli's tool
// scheduler — CoreToolCallStatus minus its two terminal ends (`success`,
// `error`/`cancelled`). A call snapshotted in one of these has not
// finished: its Success=true is an optimistic placeholder, not a
// measured outcome, and the CLI re-appends the assistant message with
// the resolved status once it lands.
//
// Grounding note: the live corpus (8 sessions, 17 calls, 2026-06-26 →
// 2026-07-31) shows ONLY terminal statuses on disk — gemini-cli writes
// the `toolCalls` array once the calls resolve, and the earlier append
// of the same assistant message carries no `toolCalls` key at all. This
// table is therefore defensive: it exists so a non-terminal snapshot
// (interrupted session, future build that persists in-flight state) is
// recorded HONESTLY rather than filed as a measured success.
var pendingCallStatuses = map[string]bool{
	"validating":        true,
	"scheduled":         true,
	"executing":         true,
	"awaiting_approval": true,
}

func normalizeStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

// callSucceeded maps a live tool-call status onto ToolEvent.Success.
func callSucceeded(status string) bool {
	return !failedCallStatuses[normalizeStatus(status)]
}

// callPending reports whether a status is non-terminal, i.e. whether
// ToolEvent.Success is an optimistic placeholder that must not be filed
// as a measured outcome (models.ToolEvent.OutcomePending).
func callPending(status string) bool {
	return pendingCallStatuses[normalizeStatus(status)]
}

// toolCallEvent shapes one normalized tool call into a ToolEvent.
func (a *Adapter) toolCallEvent(path string, msg rawLegacyMsg, partIdx int, ts time.Time, state *sessionState, call normalizedCall, reasoning, assistantID string) models.ToolEvent {
	rawInput, _ := json.Marshal(call.Args)
	target := targetFromArgs(call.Args, call.Name)
	if !call.TS.IsZero() {
		ts = call.TS
	}
	ev := models.ToolEvent{
		SourceFile:         path,
		SourceEventID:      firstNonEmpty(call.ID, fmt.Sprintf("tool:%s:%s:%d:%d", state.SessionID, msg.ID, partIdx, len(rawInput))),
		SessionID:          state.SessionID,
		ProjectRoot:        state.ProjectRoot,
		GitRemote:          state.ProjectRemote,
		GitUpstreamRemote:  state.ProjectIdentity.UpstreamRemote,
		GitRemoteOwner:     state.ProjectIdentity.RemoteOwner,
		GitUpstreamOwner:   state.ProjectIdentity.UpstreamOwner,
		RootCommitSHA:      state.ProjectIdentity.RootCommitSHA,
		ContentFingerprint: state.ProjectIdentity.ContentFingerprint,
		Workspace:          state.ProjectIdentity.Workspace,
		IsWorktree:         state.ProjectIdentity.IsWorktree,
		Timestamp:          ts,
		Model:              state.Model,
		Tool:               models.ToolGeminiCLI,
		ActionType:         mapToolName(call.Name),
		Target:             truncate(target, 200),
		Success:            callSucceeded(call.Status),
		PrecedingReasoning: truncate(reasoning, 200),
		RawToolName:        call.Name,
		RawToolInput:       a.scrubber.RawJSON(rawInput),
		MessageID:          assistantID,
		// A non-terminal snapshot's Success=true is optimistic, not
		// measured — hold failure-context bookkeeping until the CLI
		// re-appends the message with the resolved status.
		OutcomePending: callPending(call.Status),
	}
	if call.Output != "" {
		ev.ToolOutput = truncate(a.scrubber.String(call.Output), 4096)
	}
	if !ev.Success {
		// Always non-empty on a failure: without it the store's
		// evidence-gated success 1 → 0 self-heal can never fire (see
		// liveToolCall.errorText). Falls back to naming the status when
		// the CLI reported no error body.
		reason := call.Error
		if strings.TrimSpace(reason) == "" {
			reason = "gemini: tool call reported status " + normalizeStatus(call.Status)
		}
		ev.ErrorMessage = truncate(a.scrubber.String(reason), 4096)
	}
	return ev
}

func tokenEventFor(path, msgID string, ts time.Time, modelHint string, state *sessionState, t legacyTokens) models.TokenEvent {
	// Gemini's `input` is the GROSS prompt count — promptTokenCount
	// INCLUDES the cached portion (cachedContentTokenCount ⊆ promptTokenCount).
	// The cost engine's TokenBundle.Input contract is NET non-cached (see
	// internal/intelligence/cost/engine.go): cached tokens bill at the
	// discounted cache-read rate via CacheReadTokens, NOT at the full input
	// rate too. Net at emit time — matching codex/cursor — or the cached
	// portion is double-billed (~3.4× over-billing on cached sessions; see
	// [[feedback_openai_input_is_gross]]).
	cacheRead := maxInt64(t.CacheRead, t.Cached)
	netInput := t.Input - cacheRead
	if netInput < 0 {
		netInput = 0
	}
	reasoning := maxInt64(t.ThoughtsTokens, t.Thoughts)
	return models.TokenEvent{
		SourceFile:         path,
		SourceEventID:      "usage:" + msgID,
		SessionID:          state.SessionID,
		ProjectRoot:        state.ProjectRoot,
		GitRemote:          state.ProjectRemote,
		GitUpstreamRemote:  state.ProjectIdentity.UpstreamRemote,
		GitRemoteOwner:     state.ProjectIdentity.RemoteOwner,
		GitUpstreamOwner:   state.ProjectIdentity.UpstreamOwner,
		RootCommitSHA:      state.ProjectIdentity.RootCommitSHA,
		ContentFingerprint: state.ProjectIdentity.ContentFingerprint,
		Workspace:          state.ProjectIdentity.Workspace,
		IsWorktree:         state.ProjectIdentity.IsWorktree,
		Timestamp:          ts,
		Tool:               models.ToolGeminiCLI,
		Model:              firstNonEmpty(modelHint, state.Model),
		InputTokens:        netInput,
		OutputTokens:       t.Output,
		CacheReadTokens:    cacheRead,
		ReasoningTokens:    reasoning,
		Source:             models.TokenSourceJSONL,
		Reliability:        models.ReliabilityApproximate,
		MessageID:          msgID,
	}
}

// joinResponses attaches every functionResponse part in a content array
// to its matching tool row and returns how many response parts it saw
// (NOT how many matched — the count answers "was this message a tool-
// result carrier?", which is what the caller needs to decide whether to
// suppress a prompt row).
func joinResponses(res *adapter.ParseResult, path string, parts []legacyPart, scrubber *scrub.Scrubber) int {
	seen := 0
	for _, part := range parts {
		if part.FunctionResponse == nil {
			continue
		}
		seen++
		joinResponse(res, path, part.FunctionResponse, scrubber)
	}
	return seen
}

// joinResponse attaches a functionResponse content part to the matching
// ToolEvent in res by call ID, and no-ops when the row already carries
// output — the live shape embeds the result on the call itself, which
// is the richer, already-unwrapped form.
//
// CROSS-BATCH FALLBACK. The call and its response are separate records,
// so an incremental parse window can end between them: the call lands
// in batch N and the response arrives in batch N+1 with the call NOT
// re-appended. In-memory lookup necessarily misses there, and the
// output would be lost forever. Instead of inventing pending state that
// would have to survive across parse calls (it cannot — the adapter is
// stateless per call), emit an [models.ActionOutcomeUpdate] keyed by the
// SAME (SourceFile, SourceEventID) pair the call row was inserted under.
// The watcher plumbs it into store.IngestOptions and
// Store.UpdateActionOutcome applies it after the batch insert, where
// raw_tool_output length-merges — so a redundant update (the live
// shape's already-embedded, richer result) can never regress the row,
// and an id that matches nothing is silently tolerated.
//
// LEGACY-SHAPE FAILURE VERDICT. The live shape carries its verdict on
// the call's own `status`, which toolCallEvent already reads. The LEGACY
// shape carries no status anywhere — its only failure signal is the
// `error` key inside this response body, and before B3 that signal was
// dropped on both branches: every legacy call stayed optimistically
// successful forever, and the store's evidence-gated success 1 → 0
// self-heal could never fire (it needs a non-empty error_message).
// So when — and ONLY when — the body carries a meaningful `error`
// ([responseErrorText]), both branches now record the failure:
// in-batch by mutating Success/ErrorMessage on the row, cross-batch by
// setting SuccessKnown+Success+ErrorMessage on the outcome update
// (store.UpdateActionOutcome writes success only under SuccessKnown and
// error_message only when non-empty, so a redundant update can't
// regress a row).
//
// When the body carries NO error key, SuccessKnown stays false and
// nothing but ToolOutput is touched — the invention-refusal contract:
// a response part that reports no verdict must not manufacture one.
// The failure verdict is deliberately NOT gated behind the
// already-has-output early return below: output richness and outcome
// evidence are independent, and a row whose output landed first must
// still be correctable.
func joinResponse(res *adapter.ParseResult, path string, fr *legacyFnResp, scrubber *scrub.Scrubber) {
	if fr == nil || fr.ID == "" {
		return
	}
	errText, failed := responseErrorText(fr.Response)
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID != fr.ID {
			continue
		}
		if failed {
			res.ToolEvents[i].Success = false
			res.ToolEvents[i].ErrorMessage = truncate(scrubber.String(errText), 4096)
		}
		if res.ToolEvents[i].ToolOutput != "" {
			return
		}
		res.ToolEvents[i].ToolOutput = responseOutput(fr, scrubber)
		return
	}
	upd := models.ActionOutcomeUpdate{
		SourceFile:    path,
		SourceEventID: fr.ID,
		ToolOutput:    responseOutput(fr, scrubber),
	}
	if failed {
		upd.SuccessKnown = true
		upd.Success = false
		upd.ErrorMessage = truncate(scrubber.String(errText), 4096)
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, upd)
}

// responseOutput renders a functionResponse body into the scrubbed,
// capped string both join paths store.
func responseOutput(fr *legacyFnResp, scrubber *scrub.Scrubber) string {
	body, _ := json.Marshal(fr.Response)
	return truncate(scrubber.RawJSON(body), 4096)
}

// concatText joins all `text` parts in a content array.
func concatText(parts []legacyPart) string {
	var out []string
	for _, p := range parts {
		if p.Type == "text" || p.Type == "" {
			if strings.TrimSpace(p.Text) != "" {
				out = append(out, p.Text)
			}
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// collectInlineImageAttachments builds the structured user-attachment
// metadata (Issue 1) for a user turn's inline images: one kind="image"
// entry per inlineData part, with MediaType read from inlineData.mimeType
// when present. Metadata only — the base64 `data` is never read. A part is
// treated as an image when it has a non-empty inlineData map or its declared
// type names an image/inline-data part; the image-attachment marker for
// image-only user turns is emitted from len() of the result.
func collectInlineImageAttachments(parts []legacyPart) []models.UserAttachment {
	var atts []models.UserAttachment
	for _, p := range parts {
		isImage := len(p.InlineData) > 0
		if !isImage {
			t := strings.ToLower(strings.TrimSpace(p.Type))
			isImage = t == "image" || t == "inlinedata" || t == "inline_data"
		}
		if !isImage {
			continue
		}
		mediaType := ""
		if mt, ok := p.InlineData["mimeType"].(string); ok {
			mediaType = mt
		}
		atts = append(atts, models.UserAttachment{Kind: "image", MediaType: mediaType})
	}
	return atts
}

// concatThought joins all `thought` parts (Gemini's CoT-style
// reasoning, separate from `text` parts).
func concatThought(parts []legacyPart) string {
	var out []string
	for _, p := range parts {
		if p.Type == "thought" && strings.TrimSpace(p.Thought) != "" {
			out = append(out, p.Thought)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// concatLiveThoughts renders a live assistant message's top-level
// `thoughts` array into one reasoning body. Each entry is a
// {subject, description} pair — the subject is a short headline, so it
// is kept as a leading line rather than dropped.
func concatLiveThoughts(thoughts []liveThought) string {
	var out []string
	for _, t := range thoughts {
		subject := strings.TrimSpace(t.Subject)
		description := strings.TrimSpace(t.Description)
		switch {
		case subject != "" && description != "":
			out = append(out, subject+"\n"+description)
		case description != "":
			out = append(out, description)
		case subject != "":
			out = append(out, subject)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n\n"))
}

// mapToolName collapses Gemini CLI's tool vocabulary onto the
// normalized actions in models. Both snake_case (modern) and
// camelCase (older builds) variants are accepted; matching is
// case-insensitive with underscores stripped.
func mapToolName(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	switch key {
	case "readfile", "read", "viewfile", "view":
		return models.ActionReadFile
	case "writefile", "write", "createfile", "create":
		return models.ActionWriteFile
	case "replace", "edit", "editfile", "applypatch", "patch":
		return models.ActionEditFile
	case "runshellcommand", "shell", "bash", "exec", "execute", "runcommand",
		"powershell", "pwsh", "cmd", "cmdexe":
		return models.ActionRunCommand
	case "googlewebsearch", "websearch", "search":
		return models.ActionWebSearch
	case "webfetch", "fetch", "fetchurl", "fetchwebpage":
		return models.ActionWebFetch
	case "grep", "searchtext", "findtext", "grepsearch":
		return models.ActionSearchText
	case "glob", "findfiles", "filesearch", "ls", "listfiles", "listdirectory":
		return models.ActionSearchFiles
	case "invokeagent":
		// invoke_agent hands off work to a sub-agent (live corpus args:
		// agent_name, prompt) — same family as claude-code Agent /
		// grok/qwen-code spawnagent.
		return models.ActionSpawnSubagent
	case "savememory", "memorize":
		return models.ActionMCPCall // closest existing semantic; defer dedicated type
	case "updatetopic":
		// update_topic sets the CLI's running conversation-topic label
		// (live corpus args: title, summary, strategic_intent — a
		// narrative, not a checklist). ActionTodoUpdate's contract is a
		// STRUCTURED todo-list / plan tool (models.go: "structured-todo-
		// list management call"; codex's update_plan and every other
		// adapter's todo_update row carry discrete items/status) —
		// update_topic carries neither, so it does not genuinely share
		// that semantic. No dedicated type exists for topic narration;
		// kept an explicit case (not the default branch) so this reads
		// as an ACKNOWLEDGED gap — see unclassifiedDomain in
		// tooltax_conformance_test.go — rather than a silently-unmapped
		// tool.
		return models.ActionUnknown
	default:
		// MCP tools land here too — names like
		// `mcp__server_name__tool_name` get mapped to ActionMCPCall.
		if strings.HasPrefix(key, "mcp"+"") || strings.Contains(name, "__") {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

// targetFromArgs picks a representative target string from a tool
// call's args map. Tries common path-shaped keys first; falls back to
// the call name.
//
// Key order is load-bearing: `content` (write_file) and `description`
// (run_shell_command) are deliberately absent so a file body or a
// paraphrase never becomes the target. dir_path / agent_name / title
// are the live-observed target keys of list_directory / invoke_agent /
// update_topic respectively (grounded in the 2026-07-31 corpus).
func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range []string{
		"absolute_path", "absolutePath", "path", "file_path", "filePath",
		"dir_path", "dirPath", "file", "command", "query", "url", "pattern",
		"agent_name", "title",
	} {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

func sessionIDFromPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return base
}

func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
