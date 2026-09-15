package zed

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

const (
	maxTargetLen    = 500
	maxReasoningLen = 2000
)

// zedThreadData is the decompressed thread JSON (schema "version":
// "0.3.0"). Only the fields this adapter actually uses are declared;
// everything else (profile, thinking_effort, speed, draft_prompt,
// ui_scroll_position, sandboxed_terminal_temp_dir, sandbox_grants, ...)
// is deliberately left undecoded.
type zedThreadData struct {
	Title                  string              `json:"title"`
	Messages               []json.RawMessage   `json:"messages"`
	UpdatedAt              string              `json:"updated_at"`
	Model                  zedModel            `json:"model"`
	RequestTokenUsage      map[string]zedUsage `json:"request_token_usage"`
	InitialProjectSnapshot *zedProjectSnapshot `json:"initial_project_snapshot"`
	// SubagentContext is read only to detect PRESENCE (non-null) for the
	// best-effort sidechain flag documented in doc.go; its shape is never
	// otherwise decoded.
	SubagentContext json.RawMessage `json:"subagent_context"`
}

type zedModel struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// zedUsage is one `request_token_usage` entry. InputTokens is ALREADY
// NET of CacheReadInputTokens (see doc.go) — never subtract here.
type zedUsage struct {
	InputTokens          int64 `json:"input_tokens"`
	OutputTokens         int64 `json:"output_tokens"`
	CacheReadInputTokens int64 `json:"cache_read_input_tokens"`
}

type zedProjectSnapshot struct {
	WorktreeSnapshots []zedWorktreeSnapshot `json:"worktree_snapshots"`
	Timestamp         string                `json:"timestamp"`
}

type zedWorktreeSnapshot struct {
	WorktreePath string      `json:"worktree_path"`
	GitState     zedGitState `json:"git_state"`
}

type zedGitState struct {
	RemoteURL     *string `json:"remote_url"`
	CurrentBranch string  `json:"current_branch"`
}

// zedUserMessage is the value of a `{"User": {...}}` messages entry.
type zedUserMessage struct {
	ID      string            `json:"id"`
	Content []json.RawMessage `json:"content"`
}

// zedAgentMessage is the value of a `{"Agent": {...}}` messages entry.
// ReasoningDetails is deliberately left undecoded past presence: its
// `reasoning_items[].encrypted_content` is an opaque provider-internal
// blob (the analogue of a thought_signature) that is never persisted —
// the human-readable summary is already available verbatim on the
// sibling `Thinking` content block.
type zedAgentMessage struct {
	Content     []json.RawMessage        `json:"content"`
	ToolResults map[string]zedToolResult `json:"tool_results"`
}

type zedToolResult struct {
	ToolName string         `json:"tool_name"`
	IsError  bool           `json:"is_error"`
	Content  []zedTextBlock `json:"content"`
}

// zedTextBlock decodes a `{"Text": "..."}` tagged block. Content arrays
// (both message content and tool_results content) are, in every live
// capture, entirely Text blocks; anything else fails this unmarshal
// silently (Text stays empty) rather than erroring the whole parse.
type zedTextBlock struct {
	Text string `json:"Text"`
}

// zedToolUse is the value of a `{"ToolUse": {...}}` content block.
type zedToolUse struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	RawInput        string `json:"raw_input"`
	IsInputComplete bool   `json:"is_input_complete"`
}

// zedThinking is the value of a `{"Thinking": {...}}` content block.
type zedThinking struct {
	Text string `json:"text"`
}

// emitThread turns one decoded thread into ToolEvents + TokenEvents + a
// surface stamp, appended onto res.
func (a *Adapter) emitThread(res *adapter.ParseResult, dbPath string, tr threadRow, data zedThreadData) {
	root, branch, remote := a.resolveProjectRoot(data)
	base := tr.CreatedAt
	if base.IsZero() && data.InitialProjectSnapshot != nil {
		if t, ok := parseRFC3339(data.InitialProjectSnapshot.Timestamp); ok {
			base = t
		}
	}
	sidechain := isSidechainThread(tr, data)

	for msgIdx, raw := range data.Messages {
		ts := base.Add(time.Duration(msgIdx) * time.Second)
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s message %d: %v", tr.ID, msgIdx, err))
			continue
		}
		switch {
		case wrapper["User"] != nil:
			var um zedUserMessage
			if err := json.Unmarshal(wrapper["User"], &um); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s message %d: User: %v", tr.ID, msgIdx, err))
				continue
			}
			a.emitUserMessage(res, dbPath, tr.ID, root, branch, remote, ts, msgIdx, um, data.Model.Model, sidechain)
		case wrapper["Agent"] != nil:
			var am zedAgentMessage
			if err := json.Unmarshal(wrapper["Agent"], &am); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s message %d: Agent: %v", tr.ID, msgIdx, err))
				continue
			}
			a.emitAgentMessage(res, dbPath, tr.ID, root, branch, remote, ts, msgIdx, am, data.Model.Model, sidechain)
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf("zed: thread %s message %d: unknown message kind", tr.ID, msgIdx))
		}
	}

	for reqID, usage := range data.RequestTokenUsage {
		if te, ok := a.tokenEvent(dbPath, tr.ID, root, branch, remote, base, data.Model.Model, reqID, usage, sidechain); ok {
			res.TokenEvents = append(res.TokenEvents, te)
		}
	}

	res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
		SessionID: tr.ID, Surface: models.SurfaceIDE, SurfaceHost: "zed",
	})
}

func (a *Adapter) emitUserMessage(res *adapter.ParseResult, path, sessID, root, branch, remote string,
	ts time.Time, msgIdx int, um zedUserMessage, model string, sidechain bool,
) {
	for i, raw := range um.Content {
		block, ok := decodeTaggedBlock(raw)
		if !ok || block.kind != blockText {
			continue
		}
		text := strings.TrimSpace(a.scrubber.String(block.text))
		if text == "" {
			continue
		}
		id := firstNonEmpty(um.ID, strconv.Itoa(msgIdx))
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile: path, SourceEventID: idFor("user", sessID, id+"."+strconv.Itoa(i)),
			SessionID: sessID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
			Timestamp: ts, Tool: models.ToolZed, Model: model,
			ActionType: models.ActionUserPrompt, Target: truncate(text, maxTargetLen),
			Success: true, IsSidechain: sidechain,
		})
	}
}

func (a *Adapter) emitAgentMessage(res *adapter.ParseResult, path, sessID, root, branch, remote string,
	ts time.Time, msgIdx int, am zedAgentMessage, model string, sidechain bool,
) {
	var reasoning string
	for i, raw := range am.Content {
		block, ok := decodeTaggedBlock(raw)
		if !ok {
			continue
		}
		switch block.kind {
		case blockThinking:
			reasoning = truncate(a.scrubber.String(firstNonEmpty(reasoning, block.text)), maxReasoningLen)
		case blockText:
			text := strings.TrimSpace(a.scrubber.String(block.text))
			if text == "" {
				continue
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: idFor("text", sessID, strconv.Itoa(msgIdx)+"."+strconv.Itoa(i)),
				SessionID: sessID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
				Timestamp: ts, Tool: models.ToolZed, Model: model,
				ActionType: models.ActionAssistantMessage, Target: truncate(text, maxTargetLen),
				Success: true, PrecedingReasoning: reasoning, IsSidechain: sidechain,
			})
			reasoning = ""
		case blockToolUse:
			a.emitToolUse(res, path, sessID, root, branch, remote, ts, msgIdx, i, block.toolUse, am.ToolResults, model, reasoning, sidechain)
			reasoning = ""
		default:
			// A block kind this adapter doesn't recognize — skipped, never
			// guessed. decodeTaggedBlock already recorded nothing to warn
			// on here (the block decoded fine, it's just not one of the
			// three kinds this adapter maps).
		}
	}
}

func (a *Adapter) emitToolUse(res *adapter.ParseResult, path, sessID, root, branch, remote string,
	ts time.Time, msgIdx, blockIdx int, tu zedToolUse, results map[string]zedToolResult,
	model, reasoning string, sidechain bool,
) {
	action := mapZedTool(tu.Name)
	target := targetFromRawInput(tu.RawInput)
	if target == "" {
		target = tu.Name
	}
	var rawToolInput string
	if strings.TrimSpace(tu.RawInput) != "" {
		rawToolInput = a.scrubber.RawJSON([]byte(tu.RawInput))
	}

	id := firstNonEmpty(tu.ID, strconv.Itoa(msgIdx)+"."+strconv.Itoa(blockIdx))
	success, errMsg, output, pending := outcomeFor(tu.ID, results)

	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile: path, SourceEventID: idFor("tool", sessID, id),
		SessionID: sessID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
		Timestamp: ts, Tool: models.ToolZed, Model: model,
		ActionType: action, RawToolName: tu.Name, RawToolInput: rawToolInput,
		Target:             truncate(a.scrubber.String(target), maxTargetLen),
		ToolOutput:         a.scrubber.String(output),
		Success:            success,
		ErrorMessage:       truncate(a.scrubber.String(errMsg), maxTargetLen),
		PrecedingReasoning: reasoning,
		IsSidechain:        sidechain,
		OutcomePending:     pending,
	})
}

// outcomeFor resolves a ToolUse's outcome from the message's own
// tool_results map. Because a Zed thread row is only ever parsed once
// it has been fully rewritten (the whole-file-rewrite watermark
// contract), a missing result is treated as pending rather than a
// guessed success — the same OutcomePending convention every other
// adapter uses for a genuinely unobserved outcome.
func outcomeFor(toolUseID string, results map[string]zedToolResult) (success bool, errMsg, output string, pending bool) {
	if toolUseID == "" {
		return true, "", "", true
	}
	r, ok := results[toolUseID]
	if !ok {
		return true, "", "", true
	}
	var texts []string
	for _, c := range r.Content {
		if c.Text != "" {
			texts = append(texts, c.Text)
		}
	}
	joined := strings.Join(texts, "\n")
	if r.IsError {
		return false, joined, joined, false
	}
	return true, "", joined, false
}

// tokenEvent builds the per-request token row from one
// request_token_usage entry.
func (a *Adapter) tokenEvent(path, sessID, root, branch, remote string, ts time.Time,
	model, reqID string, usage zedUsage, sidechain bool,
) (models.TokenEvent, bool) {
	if usage.InputTokens <= 0 && usage.OutputTokens <= 0 && usage.CacheReadInputTokens <= 0 {
		return models.TokenEvent{}, false
	}
	return models.TokenEvent{
		SourceFile: path, SourceEventID: idFor("tokens", sessID, reqID),
		SessionID: sessID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
		Timestamp: ts, Tool: models.ToolZed, Model: model,
		InputTokens:     usage.InputTokens,
		OutputTokens:    usage.OutputTokens,
		CacheReadTokens: usage.CacheReadInputTokens,
		Source:          models.TokenSourceJSONL,
		Reliability:     models.ReliabilityAccurate,
		MessageID:       reqID,
		IsSidechain:     sidechain,
	}, true
}

// resolveProjectRoot resolves the session's project root from
// initial_project_snapshot.worktree_snapshots[0]. Foreign-mount Windows
// paths are translated and STAT-GATED before git.Resolve (the goose /
// crush / freebuff precedent), so an unreachable path is returned
// verbatim instead of being CWD-prefixed onto the observer's own repo.
// git.Resolve's own read of the live repo wins over the JSON's own
// (point-in-time, possibly stale) git_state; the snapshot is only a
// fallback for a root that git.Resolve can't reach on this host.
func (a *Adapter) resolveProjectRoot(data zedThreadData) (root, branch, remote string) {
	if data.InitialProjectSnapshot == nil || len(data.InitialProjectSnapshot.WorktreeSnapshots) == 0 {
		return "[zed]", "", ""
	}
	snap := data.InitialProjectSnapshot.WorktreeSnapshots[0]
	cwd := strings.TrimSpace(snap.WorktreePath)
	if cwd == "" {
		return "[zed]", "", ""
	}
	fallbackBranch := snap.GitState.CurrentBranch
	fallbackRemote := git.NormalizeRemote(derefString(snap.GitState.RemoteURL))

	cwd = crossmount.TranslateForeignPath(cwd)
	if _, err := os.Stat(cwd); err != nil {
		return cwd, fallbackBranch, fallbackRemote
	}
	info, err := git.Resolve(cwd)
	if err != nil {
		return cwd, fallbackBranch, fallbackRemote
	}
	return info.Root, firstNonEmpty(info.Branch, fallbackBranch), firstNonEmpty(git.NormalizeRemote(info.Remote), fallbackRemote)
}

// isSidechainThread applies the best-effort sub-agent/fork detection
// documented in doc.go: either the DB row's own parent_id column or the
// JSON's subagent_context field being non-null marks every row this
// thread emits as a sidechain.
func isSidechainThread(tr threadRow, data zedThreadData) bool {
	if strings.TrimSpace(tr.ParentID) != "" {
		return true
	}
	raw := strings.TrimSpace(string(data.SubagentContext))
	return raw != "" && raw != "null"
}

// --- tagged-block decode -------------------------------------------

type blockKind int

const (
	blockUnknown blockKind = iota
	blockText
	blockToolUse
	blockThinking
)

type taggedBlock struct {
	kind    blockKind
	text    string
	toolUse zedToolUse
}

// decodeTaggedBlock decodes one externally-tagged content-block object
// (`{"Text":"..."}` / `{"ToolUse":{...}}` / `{"Thinking":{...}}`). ok is
// false only on a malformed (non-object) block; an object whose single
// key is none of the three known kinds decodes with kind=blockUnknown
// and ok=true, so the caller's default case can skip it without a
// warning — a genuinely new Zed block kind, not corruption.
func decodeTaggedBlock(raw json.RawMessage) (taggedBlock, bool) {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return taggedBlock{}, false
	}
	if v, ok := wrapper["Text"]; ok {
		var s string
		_ = json.Unmarshal(v, &s)
		return taggedBlock{kind: blockText, text: s}, true
	}
	if v, ok := wrapper["ToolUse"]; ok {
		var tu zedToolUse
		if err := json.Unmarshal(v, &tu); err != nil {
			return taggedBlock{}, false
		}
		return taggedBlock{kind: blockToolUse, toolUse: tu}, true
	}
	if v, ok := wrapper["Thinking"]; ok {
		var th zedThinking
		_ = json.Unmarshal(v, &th)
		return taggedBlock{kind: blockThinking, text: th.Text}, true
	}
	return taggedBlock{kind: blockUnknown}, true
}

// mapZedTool maps a Zed native tool name to a normalized action type.
// The 7 grounded names are the COMPLETE surface a live multi-call
// session exercised (see doc.go); an unrecognized name (a future Zed
// tool) falls through to ActionUnknown with RawToolName preserved,
// never guessed.
func mapZedTool(name string) string {
	switch name {
	case "read_file":
		return models.ActionReadFile
	case "write_file":
		return models.ActionWriteFile
	case "edit_file":
		return models.ActionEditFile
	case "delete_path":
		// No canonical delete action type exists; edit_file is the
		// established precedent (cursor `Delete`, copilot/grok
		// `deletefile`/`removefile` — see internal/tooltax/table.go).
		return models.ActionEditFile
	case "list_directory", "find_path":
		return models.ActionSearchFiles
	case "terminal":
		return models.ActionRunCommand
	default:
		return models.ActionUnknown
	}
}

// targetFromRawInput extracts the most useful human-readable argument
// out of a ToolUse's raw_input JSON-text: a file/dir path, a glob
// pattern, or a shell command, in that priority order.
func targetFromRawInput(rawInput string) string {
	rawInput = strings.TrimSpace(rawInput)
	if rawInput == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(rawInput), &m); err != nil {
		return ""
	}
	for _, k := range []string{"path", "glob", "command", "query"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
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

// idFor builds a stable, deterministic SourceEventID.
func idFor(kind, sessID, part string) string {
	return kind + ":" + sessID + ":" + part
}
