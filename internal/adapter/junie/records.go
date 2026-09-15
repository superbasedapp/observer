package junie

import "time"

// Top-level envelope kinds. Every line of events.jsonl is one JSON object
// discriminated by the top-level "kind" field. Only the kinds this adapter
// acts on are named here; anything else is informational bookkeeping
// (§ package doc "Known gaps") and is skipped silently by the dispatch
// switch in adapter.go.
const (
	kindUserPrompt        = "UserPromptEvent"
	kindTaskStarted       = "TaskStartedEvent"
	kindSessionA2ux       = "SessionA2uxEvent"
	kindMessagesCommitted = "UserMessagesCommittedToHistory"
	kindTaskState         = "TaskState"
	// kindCostTrajectorySnapshot — the standalone CLI's own end-of-task
	// cost breakdown, emitted once per completed task just before
	// TaskState. Carries no normalized-action counterpart (its
	// `snapshot` payload is a cost-attribution table, not an action);
	// its sole use is as the CLI capture-surface discriminator (see
	// surface.go). Never observed on either IDE-hosted fixture
	// (2026-08-16 plain plugin, 2026-09-03 AI-Assistant/MCP), both of
	// which completed (state.TaskState present) without emitting it.
	kindCostTrajectorySnapshot = "SessionCostTrajectorySnapshotEvent"
)

// agentEvent.kind discriminators — the INNER kind nested two levels under a
// SessionA2uxEvent envelope (envelope.event.agentEvent.kind). 13 distinct
// values were observed in the Phase-0 capture and 3 more (McpBlock,
// ViewFilesBlock, ToolBlock) in the 2026-09-03 IDE/MCP capture; only the
// ones with a normalized-action counterpart are named here — the MCP-lane
// three live in mcpblocks.go. The remainder
// (AgentCurrentStatusUpdatedEvent, EnvironmentVariablesUpdatedEvent,
// TipSuggestionCreatedEvent, AgentTaskNameUpdatedEvent,
// ContextWindowReportEvent, AgentPatchCreatedEvent,
// NextPromptSuggestionEvent) are scheduler / UI / diagnostic bookkeeping
// with no normalized-action counterpart and are skipped silently.
const (
	agentKindCurrentDirectory = "CurrentDirectoryUpdatedEvent"
	agentKindLlmResponseMeta  = "LlmResponseMetadataEvent"
	agentKindThoughtBlock     = "AgentThoughtBlockUpdatedEvent"
	agentKindTerminalBlock    = "TerminalBlockUpdatedEvent"
	agentKindFileChangesBlock = "FileChangesBlockUpdatedEvent"
	agentKindResultBlock      = "ResultBlockUpdatedEvent"
)

// Block status values Terminal / FileChanges blocks carry. A block is
// re-broadcast unchanged (see the package doc's rebroadcast-after-terminal
// finding) once its stepId's status first reaches COMPLETED or FAILED —
// both are terminal, and neither recurs with a DIFFERENT status afterward
// in the Phase-0 capture.
const (
	blockStatusInProgress = "IN_PROGRESS"
	blockStatusCompleted  = "COMPLETED"
	blockStatusFailed     = "FAILED"
)

// rawRecord is one JSONL line of a Junie events.jsonl.
//
// A single tolerant struct covers every top-level Kind: only the fields
// relevant to the record's own kind are ever populated, the rest stay
// zero. This keeps the dispatch table-driven and additive, mirroring
// internal/adapter/muse's sessionEvent pattern.
type rawRecord struct {
	Kind        string `json:"kind"`
	TimestampMs int64  `json:"timestampMs"`

	// UserPromptEvent — RequestId is the record's own deterministic
	// identity; Prompt is the operator's verbatim text. ExtraAttachments
	// is decoded down to each entry's `kind` plus its mcpServers[].env[]
	// KEY NAMES ONLY (see extraAttachmentRaw / surface.go) — the auth
	// token VALUE and every other mcpServers field stay undeclared.
	RequestID        string               `json:"requestId"`
	Prompt           string               `json:"prompt"`
	ExtraAttachments []extraAttachmentRaw `json:"extraAttachments"`

	// TaskStartedEvent / SessionA2uxEvent both carry the enclosing task's
	// id. SessionA2uxEvent's copy is not currently consumed (the block's
	// own StepId is the collapse key) but is decoded for completeness.
	TaskID string `json:"taskId"`

	// TaskState — the session-level lifecycle marker ("COMPLETED" observed;
	// treated as a session-end signal).
	State string `json:"state"`

	// UserMessagesCommittedToHistory — correlates prompt ids already
	// captured by UserPromptEvent; carries no new information and is
	// skipped silently (see the package doc).
	UserMessageIDs []string `json:"userMessageIds"`

	// SessionA2uxEvent — the wrapper around every agent-facing UI update.
	// Completion is a SIBLING of Event (not nested inside it), populated
	// only on a ResultBlockUpdatedEvent envelope.
	Event      *sessionA2uxEvent `json:"event"`
	Completion *completionInfo   `json:"completion"`
}

// sessionA2uxEvent is SessionA2uxEvent.event. State is the outer task-run
// state ("IN_PROGRESS" / "COMPLETED"); AgentEvent is the actual typed
// update, one level further in.
type sessionA2uxEvent struct {
	State      string         `json:"state"`
	AgentEvent *agentEventRaw `json:"agentEvent"`
}

// agentEventRaw is SessionA2uxEvent.event.agentEvent — the real inner
// discriminated union, keyed by Kind. As with rawRecord, one tolerant
// struct covers every observed kind; only the fields that kind populates
// are non-zero.
type agentEventRaw struct {
	Kind string `json:"kind"`

	// CurrentDirectoryUpdatedEvent — empty string on early occurrences
	// (before the harness has resolved a workspace), a real absolute path
	// once it has. See resolveProjectRoot in adapter.go.
	CurrentDirectory string `json:"currentDirectory"`

	// LlmResponseMetadataEvent — one entry per model invoked to produce
	// this turn.
	ModelUsage []modelUsageRaw `json:"modelUsage"`

	// AgentThoughtBlockUpdatedEvent / TerminalBlockUpdatedEvent /
	// FileChangesBlockUpdatedEvent / ResultBlockUpdatedEvent — all four
	// share a stable StepId that recurs across a block's IN_PROGRESS ->
	// terminal-status transitions and the completion rebroadcast.
	StepID string `json:"stepId"`

	// AgentThoughtBlockUpdatedEvent — first-person present-tense narration
	// of what the agent is about to do.
	Text string `json:"text"`

	// TerminalBlockUpdatedEvent / FileChangesBlockUpdatedEvent — the
	// block's own lifecycle status and, once terminal, a natural-language
	// summary.
	Status  string `json:"status"`
	Details string `json:"details"`

	// TerminalBlockUpdatedEvent
	Command          string `json:"command"`
	Output           string `json:"output"`
	OutputLinesCount int    `json:"outputLinesCount"`

	// FileChangesBlockUpdatedEvent / ResultBlockUpdatedEvent — Changes is
	// the set of file diffs; on a Result block it restates the changes the
	// task made overall, not new ones.
	Changes []fileChangeRaw `json:"changes"`

	// McpBlockUpdatedEvent — the vendor MCP tool name ("idea/apply_patch")
	// and the call's arguments, rendered as a pretty-printed JSON object
	// with a leading newline. `details` (declared above) mirrors Input
	// while the block is IN_PROGRESS and becomes the natural-language
	// outcome summary once it reaches a terminal status. See mcpblocks.go.
	ToolName string `json:"toolName"`
	Input    string `json:"input"`

	// McpBlockUpdatedEvent — the permission prompt the host raised
	// before dispatching this call. Present on the FIRST call of a
	// session only (the operator's answer then covers the rest).
	// `cancelRequest` is deliberately NOT decoded: it is the UI's
	// "cancel this running step" handle, present because the step is
	// running, never a cancellation record.
	ApprovalRequest *approvalRequestRaw `json:"approvalRequest"`

	// ViewFilesBlockUpdatedEvent — the files the agent opened/inspected.
	Files []viewFileRaw `json:"files"`

	// ResultBlockUpdatedEvent. ErrorCode is deliberately NOT decoded here:
	// "Submit" was observed on BOTH occurrences of an ordinary SUCCESSFUL
	// completion in the Phase-0 capture, so it names how the result was
	// delivered, not whether the task failed — using it as a failure
	// signal would misclassify every normal completion. Success/failure is
	// derived from Cancelled and the outer event.state alone.
	Cancelled bool   `json:"cancelled"`
	Result    string `json:"result"`
	Title     string `json:"title"`
}

// approvalRequestRaw is McpBlockUpdatedEvent.approvalRequest — the
// host's permission prompt for one MCP call. Id is the prompt's own
// identity (used for a deterministic SourceEventID); AllowListOptions
// are the "always allow" patterns the prompt offered, carried onto the
// emitted row's PrecedingReasoning so an analyst can see WHAT was
// proposed as the resolution (the ActionPermissionRequest contract).
type approvalRequestRaw struct {
	ID               string             `json:"id"`
	AllowListOptions []allowListOptions `json:"allowListOptions"`
}

// allowListOptions is one offered "always allow" choice.
type allowListOptions struct {
	Label         string   `json:"label"`
	PatternsToAdd []string `json:"patternsToAdd"`
}

// viewFileRaw is one entry of ViewFilesBlockUpdatedEvent.files. Only the
// path is carried — the block states no content, and Junie's own
// project-relative spelling is preserved verbatim.
type viewFileRaw struct {
	RelativePath string `json:"relativePath"`
}

// modelUsageRaw is one entry of LlmResponseMetadataEvent.modelUsage.
//
// InputTokens is already NET of CacheInputTokens — unlike Muse's
// input_tokens, no gross-vs-net subtraction is needed (both observed model
// rows in the Phase-0 capture carried CacheInputTokens: 0, and the field
// is documented by JetBrains as the cache PORTION already reflected in the
// billed input, not an additional charge on top of it). Cost is a
// genuine per-call dollar figure the log states directly — unlike Muse,
// which states none — so it is carried straight through to
// TokenEvent.EstimatedCostUSD rather than left for the cost engine to
// price against a rate card.
type modelUsageRaw struct {
	Model             string  `json:"model"`
	Cost              float64 `json:"cost"`
	InputTokens       int64   `json:"inputTokens"`
	CacheInputTokens  int64   `json:"cacheInputTokens"`
	CacheCreateTokens int64   `json:"cacheCreateTokens"`
	OutputTokens      int64   `json:"outputTokens"`
}

// isZero reports whether a modelUsage entry carries nothing worth
// persisting, so an all-zero entry never produces a phantom token row.
func (m modelUsageRaw) isZero() bool {
	return m.InputTokens == 0 && m.OutputTokens == 0 &&
		m.CacheInputTokens == 0 && m.CacheCreateTokens == 0
}

// fileChangeRaw is one entry of a FileChangesBlockUpdatedEvent's (or a
// ResultBlockUpdatedEvent's) Changes. A change with no BeforeContent is a
// NEW file (-> ActionWriteFile); one WITH BeforeContent is an edit of an
// existing file (-> ActionEditFile).
type fileChangeRaw struct {
	BeforeContent      *fileContentRaw `json:"beforeContent"`
	AfterContent       *fileContentRaw `json:"afterContent"`
	BeforeRelativePath string          `json:"beforeRelativePath"`
	AfterRelativePath  string          `json:"afterRelativePath"`
}

// fileContentRaw is a FileChanges change's before/after content envelope.
// Kind is always observed as "TextFileContent"; it is decoded but not
// branched on, since no other kind has been observed.
type fileContentRaw struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// completionInfo is SessionA2uxEvent.completion — a sibling of Event,
// present only on a ResultBlockUpdatedEvent envelope. TaskCostUSD is a
// TASK-level total (the sum of every modelUsage[].Cost billed across the
// whole task), distinct from — and never added to — the per-call Cost on
// an individual modelUsageRaw; it is not currently surfaced on any emitted
// event, only StartedAtMs/EndedAtMs (-> the completion action's
// DurationMs).
type completionInfo struct {
	StartedAtMs int64   `json:"startedAtMs"`
	EndedAtMs   int64   `json:"endedAtMs"`
	TaskCostUSD float64 `json:"taskCostUsd"`
}

// extraAttachmentRaw is one entry of UserPromptEvent.extraAttachments.
// Kind plus the mcpServers env KEY NAMES are decoded — see surface.go,
// which requires BOTH the "TaskRequestMcpServersAttachment" kind AND an
// mcpServers[].env[] entry keyed "IJ_MCP_AUTH_TOKEN" as the IDE
// capture-surface discriminator (a generic attachment-kind check alone
// is too weak — the CLI lane also runs MCP clients when the operator
// configures one). Every mcpServers FIELD OTHER than the env key names
// (the command path, the token VALUE, args) is deliberately NOT
// declared here, so no code path can decode, persist or emit it — the
// same structural guarantee agentEventRaw uses to keep
// EnvironmentVariablesUpdatedEvent's `env` off every code path.
type extraAttachmentRaw struct {
	Kind       string         `json:"kind"`
	MCPServers []mcpServerRaw `json:"mcpServers"`
}

// mcpServerRaw is one entry of extraAttachmentRaw.mcpServers. Only Env
// is decoded (key names only, via mcpEnvVarRaw) — see extraAttachmentRaw's
// doc for why every other field (command, args, name) stays undeclared.
type mcpServerRaw struct {
	Env []mcpEnvVarRaw `json:"env"`
}

// mcpEnvVarRaw is one key of an mcpServers[].env[] entry. Value is
// deliberately NOT declared: this adapter decodes env KEY NAMES only,
// never values, the same rule the off-limits-files doc states for
// EnvironmentVariablesUpdatedEvent.
type mcpEnvVarRaw struct {
	Key string `json:"key"`
}

// indexRow is one line of the sibling ~/.junie/sessions/index.jsonl — a
// per-session summary keyed by SessionID, used ONLY as a project-root
// fallback when a session's own events.jsonl never states a non-empty
// CurrentDirectoryUpdatedEvent.currentDirectory (an interrupted session
// with no terminal/file-change block, for instance).
type indexRow struct {
	SessionID  string `json:"sessionId"`
	ProjectDir string `json:"projectDir"`
}

// parseTimestamp decodes Junie's `timestampMs`. Every occurrence observed
// in the Phase-0 capture is a 13-digit millisecond value (year 2026), so
// this is a direct conversion rather than the magnitude ladder Muse's
// parser needs — Junie has only ever been observed to write one unit. A
// non-positive value yields the zero time.
func parseTimestamp(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
