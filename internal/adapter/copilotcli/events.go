package copilotcli

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
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// eventEnvelope is every events.jsonl line's wrapper.
//
// AgentID is a top-level field present on events emitted during a
// subagent's execution context — assistant.message,
// tool.execution_{start,complete}, subagent.{started,completed}, etc.
// Its value matches the spawning `task` tool's toolCallId. For
// events outside any subagent context, AgentID is empty. Used by
// dispatchState + emitEvent to resolve the subagent's model when
// the per-message data.model field is absent (which is the common
// case — only 14/3303 asst.message events in the operator sample
// carry data.model).
type eventEnvelope struct {
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	ID        string          `json:"id"`
	Timestamp string          `json:"timestamp"`
	ParentID  string          `json:"parentId"`
	AgentID   string          `json:"agentId"`
}

// session-start payload — carries the bootstrap context.
type sessionStartData struct {
	SessionID       string         `json:"sessionId"`
	Version         int            `json:"version"`
	Producer        string         `json:"producer"`
	CopilotVersion  string         `json:"copilotVersion"`
	StartTime       string         `json:"startTime"`
	SelectedModel   string         `json:"selectedModel"`
	Context         sessionContext `json:"context"`
	AlreadyInUse    bool           `json:"alreadyInUse"`
	RemoteSteerable bool           `json:"remoteSteerable"`
}

type sessionContext struct {
	CWD            string `json:"cwd"`
	GitRoot        string `json:"gitRoot"`
	Branch         string `json:"branch"`
	HeadCommit     string `json:"headCommit"`
	Repository     string `json:"repository"`
	HostType       string `json:"hostType"`
	RepositoryHost string `json:"repositoryHost"`
}

type modelChangeData struct {
	NewModel                string `json:"newModel"`
	PreviousReasoningEffort string `json:"previousReasoningEffort"`
	ReasoningEffort         string `json:"reasoningEffort"`
}

// sessionResumeData covers `session.resume.data`. Empirically every
// resume event in the operator specimen (2026-05-19, 9 of them)
// carries `selectedModel`, `reasoningEffort`, and `context.{cwd,
// gitRoot?, branch?, repository?}`. The pre-fix parser ignored all
// of these — for long-lived sessions where the model or cwd changes
// on resume without a later `session.model_change`, this caused
// latent mis-attribution of every subsequent assistant.message.
type sessionResumeData struct {
	ResumeTime      string         `json:"resumeTime"`
	EventCount      int64          `json:"eventCount"`
	SelectedModel   string         `json:"selectedModel"`
	ReasoningEffort string         `json:"reasoningEffort"`
	Context         sessionContext `json:"context"`
	AlreadyInUse    bool           `json:"alreadyInUse"`
	RemoteSteerable bool           `json:"remoteSteerable"`
}

type systemMessageData struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type userMessageData struct {
	Content            string `json:"content"`
	TransformedContent string `json:"transformedContent"`
	InteractionID      string `json:"interactionId"`
	AgentMode          string `json:"agentMode"`
}

type assistantMessageData struct {
	MessageID        string        `json:"messageId"`
	Model            string        `json:"model"`
	Content          string        `json:"content"`
	ToolRequests     []toolRequest `json:"toolRequests"`
	InteractionID    string        `json:"interactionId"`
	TurnID           string        `json:"turnId"`
	ReasoningOpaque  string        `json:"reasoningOpaque"`
	ReasoningText    string        `json:"reasoningText"`
	EncryptedContent string        `json:"encryptedContent"`
	OutputTokens     int64         `json:"outputTokens"`
	RequestID        string        `json:"requestId"`
}

type toolRequest struct {
	ToolCallID string          `json:"toolCallId"`
	Name       string          `json:"name"`
	Arguments  json.RawMessage `json:"arguments"`
	Type       string          `json:"type"`
}

type toolExecutionStartData struct {
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	Arguments  json.RawMessage `json:"arguments"`
	TurnID     string          `json:"turnId"`
	// MCPServerName + MCPToolName are populated when the tool was
	// dispatched through an MCP server. Empirically 84/4443 starts in
	// the operator specimen (2026-05-19) carry these. They matter
	// because:
	//   1. Some MCP-routed tools (e.g. `ide-get_selection`) don't
	//      match the github-mcp-server- prefix heuristic in
	//      mapToolName and would otherwise classify as ActionUnknown.
	//   2. Even MCP-routed tools that have a normalized action_type
	//      (e.g. `web_search` via `github-mcp-server`) benefit from
	//      explicit server-name preservation so dashboards can
	//      separate the MCP-routed call from the native built-in.
	MCPServerName string `json:"mcpServerName"`
	MCPToolName   string `json:"mcpToolName"`
}

type toolExecutionCompleteData struct {
	ToolCallID    string             `json:"toolCallId"`
	Model         string             `json:"model"`
	InteractionID string             `json:"interactionId"`
	TurnID        string             `json:"turnId"`
	Success       bool               `json:"success"`
	Result        toolResult         `json:"result"`
	Error         toolExecutionError `json:"error"`
	ToolTelemetry json.RawMessage    `json:"toolTelemetry"`
}

type toolResult struct {
	Content         string `json:"content"`
	DetailedContent string `json:"detailedContent"`
}

// toolExecutionError is the top-level `data.error` payload on a
// failed tool.execution_complete event. Empirically (operator
// specimen 2026-05-19) 158/158 failures carry the actual error
// text here, NOT in result.content. The parser must prefer this
// path on failure or the normalized error_message column stays
// empty.
type toolExecutionError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

type permissionRequestedData struct {
	RequestID         string            `json:"requestId"`
	PermissionRequest permissionRequest `json:"permissionRequest"`
}

// permissionRequest covers both shapes observed in the wild:
//   - file-oriented (older Copilot CLI / write-edit approvals):
//     kind="write"|"read"|"execute", FileName, Diff
//   - shell-oriented (current Copilot CLI / command approvals — the
//     only shape present in the operator specimen 2026-05-19):
//     kind="shell", FullCommandText, Commands, PossiblePaths,
//     PossibleURLs, HasWriteFileRedirection, CanOfferSessionApproval
//
// Both sets coexist on the struct so either shape parses cleanly.
// The emit handler picks the richest available description for
// Target / RawToolInput.
type permissionRequest struct {
	Kind       string `json:"kind"`
	ToolCallID string `json:"toolCallId"`
	Intention  string `json:"intention"`
	// File-oriented fields (older shape).
	FileName string `json:"fileName"`
	Diff     string `json:"diff"`
	// Shell-oriented fields (current shape, operator specimen 2026-05-19).
	FullCommandText         string                   `json:"fullCommandText"`
	Commands                []permissionCommandEntry `json:"commands"`
	PossiblePaths           []string                 `json:"possiblePaths"`
	PossibleURLs            []string                 `json:"possibleUrls"`
	HasWriteFileRedirection bool                     `json:"hasWriteFileRedirection"`
	CanOfferSessionApproval bool                     `json:"canOfferSessionApproval"`
}

// permissionCommandEntry is one row of permissionRequest.Commands —
// each entry names a binary or shell builtin invoked by the command.
// readOnly hints at whether running it could mutate state.
type permissionCommandEntry struct {
	Identifier string `json:"identifier"`
	ReadOnly   bool   `json:"readOnly"`
}

type permissionCompletedData struct {
	RequestID  string                  `json:"requestId"`
	ToolCallID string                  `json:"toolCallId"`
	Result     permissionResultPayload `json:"result"`
}

// subagentCompletedData covers the fields the adapter needs from a
// `subagent.completed` event. Only `model` is load-bearing — it's
// used by dispatchState to back-fill the model attribution of
// Tier-3 TokenEvents emitted under the subagent's context. The
// other fields are observable but currently ignored.
//
// Empirical note (operator sample, 2026-05-18): only 17 of 37
// subagent.completed events carry data.model — the other 20 are
// cancelled / short-lived subagents that never resolved a model.
// For those, the patch falls through and the parent's st.model is
// retained.
type subagentCompletedData struct {
	Model          string `json:"model"`
	TotalTokens    int64  `json:"totalTokens"`
	TotalToolCalls int    `json:"totalToolCalls"`
	DurationMs     int64  `json:"durationMs"`
}

// permissionResultPayload covers `permission.completed.data.result`.
// Observed kinds in operator specimen 2026-05-19:
//   - "approved" (generic single-call grant)
//   - "approved-for-location" (scoped to LocationKey; carries Approval
//     with the specific commands the user pre-approved within the scope)
//   - "denied" (presumed shape; not directly present in specimen but
//     the parser already routes on it via ActionPermissionDenied)
//
// "approved-for-session" is plausible given canOfferSessionApproval on
// the request side but unobserved in the specimen.
type permissionResultPayload struct {
	Kind        string                   `json:"kind"`
	LocationKey string                   `json:"locationKey"`
	Approval    permissionResultApproval `json:"approval"`
}

// permissionResultApproval is the nested grant detail on
// approved-for-location results. CommandIdentifiers lists the
// allow-listed commands within the LocationKey scope.
type permissionResultApproval struct {
	Kind               string   `json:"kind"`
	CommandIdentifiers []string `json:"commandIdentifiers"`
}

// sessionShutdownData covers the parts of `session.shutdown.data`
// that carry usage info we capture as Tier 0 TokenEvents.
// modelMetrics is a map of model-id → per-model usage envelope for
// the delta period between the most recent `session.resume` and this
// `session.shutdown`. Other fields on session.shutdown (shutdownType,
// codeChanges, currentTokens, etc.) are observable but not currently
// surfaced through the token pipeline.
type sessionShutdownData struct {
	ModelMetrics map[string]modelMetricsEntry `json:"modelMetrics"`
}

// modelMetricsEntry is the per-model envelope inside
// session.shutdown.data.modelMetrics. `requests.cost` is observable
// but ignored for cost computation — empirically it tracks GitHub
// Copilot "premium request" credits (gpt-5.4 reports cost=$0 across
// 200+ requests, claude-opus-4.7 reports cost=$1395 across 2k
// requests), not dollar cost. We bill via the standard pricing
// engine on the captured token columns instead.
type modelMetricsEntry struct {
	Usage modelMetricsUsage `json:"usage"`
}

// modelMetricsUsage maps the events.jsonl field names onto our
// internal column names. cacheWriteTokens maps to CacheCreationTokens
// (Anthropic-shape cache schema), matching the conventions used by
// the rest of the pipeline.
type modelMetricsUsage struct {
	InputTokens      int64 `json:"inputTokens"`
	OutputTokens     int64 `json:"outputTokens"`
	CacheReadTokens  int64 `json:"cacheReadTokens"`
	CacheWriteTokens int64 `json:"cacheWriteTokens"`
	ReasoningTokens  int64 `json:"reasoningTokens"`
}

// sessionCompactionCompleteData parses the fields we care about
// from `session.compaction_complete.data`. Empirically the compaction
// API call's usage is NOT included in `modelMetrics` (modelMetrics
// outputs sum matches Tier 3 assistant.message outputs within
// streaming noise; compaction outputs are additive on top). Without
// capturing here, every compaction call's input/output/cache silently
// disappears from cost rollups. For sessions with many summarizations
// across long contexts this can be a meaningful share of total spend.
//
// `compactionTokensUsed` has two observed schema variants in the
// wild: the older shape uses {input, output, cachedInput} (no
// "Tokens" suffix, no model field), the newer shape uses
// {inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens,
// model}. compactionTokens supports both — see resolveTokens.
type sessionCompactionCompleteData struct {
	RequestID string               `json:"requestId"`
	Tokens    compactionTokensUsed `json:"compactionTokensUsed"`
}

// compactionTokensUsed merges the two observed shapes by declaring
// both field-name conventions. compactionTokensUsed.resolveTokens()
// picks whichever set is populated. Empirically 38/39 events in the
// sample log use the older shape; 1/39 uses the newer.
type compactionTokensUsed struct {
	// New schema (Copilot CLI ≥ ~1.0.50 — empirical guess).
	InputTokens      int64 `json:"inputTokens"`
	OutputTokens     int64 `json:"outputTokens"`
	CacheReadTokens  int64 `json:"cacheReadTokens"`
	CacheWriteTokens int64 `json:"cacheWriteTokens"`
	// Old schema (most historical events).
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CachedInput int64 `json:"cachedInput"`
	// Model is populated only on the newer schema. When absent the
	// adapter falls back to the session's current model (st.model).
	Model string `json:"model"`
}

// resolveTokens returns (inputTokens, outputTokens, cacheReadTokens,
// cacheWriteTokens) by collapsing the two schema variants. Both
// fields are checked; non-zero wins. We don't try to detect "this
// event is schema X" — we just take whichever field has a value.
// On the off chance both are set (mixed schema), we prefer the
// new-schema name because that's what newer Copilot CLI versions
// emit canonically.
func (c compactionTokensUsed) resolveTokens() (in, out, cr, cw int64) {
	in = c.InputTokens
	if in == 0 {
		in = c.Input
	}
	out = c.OutputTokens
	if out == 0 {
		out = c.Output
	}
	cr = c.CacheReadTokens
	if cr == 0 {
		cr = c.CachedInput
	}
	cw = c.CacheWriteTokens
	return
}

// parserState carries per-file session-level context across line parses.
// Built up by re-scanning the whole file on each parse call (the file
// is bounded — typical Copilot CLI sessions are under a few MB).
type parserState struct {
	sessionID      string
	model          string
	copilotVersion string
	cwd            string
	gitRoot        string
	branch         string
	remote         string
	repository     string
	projectRoot    string
	// identity is the Project Identity Resolver v2 bundle (upstream
	// remote/owner hashes, workspace, worktree flag, content
	// fingerprint) resolved alongside projectRoot/remote by
	// resolveProjectRoot. Zero value when resolveProjectRoot never ran
	// or found no git repo (honest gap, not fabricated).
	identity git.Identity
	// effortLevel is the current session's reasoning-effort SETTING
	// ("low"/"medium"/"high", etc). Copilot CLI surfaces it as a
	// session-scoped knob (like st.model), never per-message: it rides
	// `session.model_change.data.reasoningEffort` and
	// `session.resume.data.reasoningEffort`, not any per-assistant-
	// message field. Threaded into ActionMetadata.EffortLevel on every
	// emitted ToolEvent, mirroring st.model's session-wide fallback.
	effortLevel string
	// toolCalls maps toolCallId → cached tool-execution-start payload
	// so we can pair it with tool.execution_complete and emit one
	// ToolEvent per call.
	toolCalls map[string]toolExecutionStartData
	// permRequests caches in-flight permission requests by requestId so
	// permission.completed can finalize them.
	permRequests map[string]permissionRequestedData
	// systemHashesSeen dedups system.message rows within the session
	// (Copilot CLI rewrites system prompt on every model_change).
	systemHashesSeen map[string]bool
	// subagentModels maps agentId → resolved model. Populated when
	// subagent.completed events parse (subagent.started does NOT carry
	// the model — only the completed event does). Used by the
	// post-loop patch to retroactively attribute Tier-3 emissions made
	// under that subagent's context. Empirically (operator sample)
	// 17/37 subagent.completed events carry data.model (the other 20
	// are cancelled or short-lived subagents); see audit doc §B4.
	subagentModels map[string]string
	// pendingSubagentTokenEmits buffers (event-index, agentId) tuples
	// for asst.message TokenEvents emitted under a subagent context
	// before its completion. The post-loop patch step walks this list
	// and rewrites Model when subagentModels resolves the agentId.
	// Subagent.completed always fires AFTER all its asst.messages, so
	// at emit time we can't know the subagent's model — we have to
	// defer.
	pendingSubagentTokenEmits []pendingSubagentEmit
	// pendingSubagentToolEmits is the parallel buffer for the
	// assistant_text ToolEvent (when an asst.message has free-text
	// content without tool_use blocks). Same deferral logic; same
	// post-loop patch.
	pendingSubagentToolEmits []pendingSubagentEmit
}

// pendingSubagentEmit pairs the index of an emitted event in
// `out.{Token,Tool}Events` with the agentId whose subagent context
// produced it. Resolved at end-of-parse against parserState.subagentModels.
type pendingSubagentEmit struct {
	idx     int
	agentID string
}

// parseEventsJSONL parses one events.jsonl file and emits the
// corresponding ToolEvents + TokenEvents. Always re-scans from byte 0
// to rebuild session context (cwd / model / sessionId), then emits
// only events whose source-byte-offset >= fromOffset for incremental
// callers. Dedup is enforced downstream by (SourceFile, SourceEventID).
func (a *Adapter) parseEventsJSONL(_ context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return adapter.ParseResult{NewOffset: fromOffset}, nil
		}
		return adapter.ParseResult{}, fmt.Errorf("copilotcli.parseEventsJSONL open %q: %w", path, err)
	}
	defer f.Close()

	st := &parserState{
		// Seed sessionID from directory basename — workspace.yaml::id
		// always matches the enclosing dir, even before session.start
		// is parsed.
		sessionID:        filepath.Base(filepath.Dir(path)),
		toolCalls:        map[string]toolExecutionStartData{},
		permRequests:     map[string]permissionRequestedData{},
		systemHashesSeen: map[string]bool{},
		subagentModels:   map[string]string{},
	}

	var (
		out      adapter.ParseResult
		offset   int64
		warnings []string
	)
	br := bufio.NewReader(f)
	for {
		line, readErr := br.ReadString('\n')
		// Track byte position. ReadString returns the line INCLUDING
		// the terminator (when present). On a clean read, advance
		// offset by len(line).
		hasTerminator := readErr == nil
		lineStart := offset
		offset += int64(len(line))

		// Trim CRLF / LF.
		clean := strings.TrimRight(line, "\r\n")
		if clean != "" {
			env, perr := decodeEnvelope(clean)
			if perr != nil {
				warnings = append(warnings, fmt.Sprintf("copilotcli: malformed line at offset %d: %v", lineStart, perr))
			} else {
				// Always advance state from every event so context is
				// correct for later emits.
				dispatchState(st, env, a.scrubber)
				// Only emit downstream events whose byte-offset is at
				// or past the cursor. (Re-emitting is safe — dedup is
				// downstream — but skipping saves cycles.)
				if lineStart >= fromOffset {
					emitEvent(st, env, path, &out, a.scrubber)
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if !hasTerminator && len(line) > 0 {
					// Partial trailing line — defer to next poll.
					// Rewind offset past the partial bytes.
					offset = lineStart
				}
				break
			}
			return adapter.ParseResult{}, fmt.Errorf("copilotcli.parseEventsJSONL read %q: %w", path, readErr)
		}
	}

	// Post-loop patch — subagent-context model attribution (v1.6.8 B4).
	// Asst.messages emitted under a subagent's context were attributed
	// to st.model (parent's selected model) at emit time because
	// subagent.completed (the only event carrying the subagent's
	// model) hadn't been parsed yet. Now that the full scan is done,
	// subagentModels is fully populated — walk the pending lists and
	// rewrite Model where the subagent has a resolved model.
	// Pending entries whose subagent never completed (or never
	// resolved a model — empirically 20/37 subagent.completed events
	// in the operator sample don't carry data.model) keep st.model as
	// the best-effort fallback.
	for _, p := range st.pendingSubagentTokenEmits {
		if m, ok := st.subagentModels[p.agentID]; ok && m != "" {
			out.TokenEvents[p.idx].Model = m
		}
	}
	for _, p := range st.pendingSubagentToolEmits {
		if m, ok := st.subagentModels[p.agentID]; ok && m != "" {
			out.ToolEvents[p.idx].Model = m
		}
	}
	// Resolve project root. Workspace.yaml wins if present: Copilot CLI
	// writes the authoritative repo root + branch to
	// `<copilot-root>/session-state/<sessionID>/workspace.yaml` at session
	// init, but the event stream itself sometimes only carries a drive-
	// root cwd (e.g. session.start.context.cwd="E:\\" while real edits
	// target "E:\\opencell\\..."). The pre-fix events.jsonl path
	// normalized action rows to the drive root because it consulted only
	// the in-stream context. Mirrors what parseProcessLog already does
	// for the log-file path.
	yamlPath := filepath.Join(filepath.Dir(path), "workspace.yaml")
	ws := resolveProjectFromWorkspaceYAML(yamlPath)
	if ws.ProjectRoot != "" {
		st.projectRoot = ws.ProjectRoot
		if ws.Branch != "" {
			st.branch = ws.Branch
		}
		if ws.Remote != "" {
			st.remote = ws.Remote
		}
		st.identity = ws.Identity
	} else {
		st.projectRoot, st.remote, st.identity = resolveProjectRoot(st)
	}
	// Capture surface — the same workspace.yaml read carries the
	// `client_name` of the client that drove the session (see
	// surface.go). Emitted on every parse call, including a resumed
	// one: SetSessionSurface is first-wins-unless-empty, so a repeat
	// stamp is a no-op, and a session whose events.jsonl grew after the
	// first poll still gets attributed.
	if surf, ok := surfaceForClientName(st.sessionID, ws.ClientName); ok {
		out.SessionSurfaces = append(out.SessionSurfaces, surf)
	}
	// Issue 2: captured Copilot CLI version from session.start
	// (dispatchState set st.copilotVersion above). first-wins-unless-
	// empty + bounded-token validation make a re-stamp / bad value
	// harmless.
	if st.sessionID != "" && st.copilotVersion != "" {
		out.SessionToolVersions = append(out.SessionToolVersions, models.SessionToolVersion{
			SessionID: st.sessionID,
			Version:   st.copilotVersion,
		})
	}
	// Backfill ProjectRoot on emitted events (we built them before
	// finalizing state).
	adapter.ApplyProjectIdentity(&out, st.identity)
	for i := range out.ToolEvents {
		if out.ToolEvents[i].ProjectRoot == "" {
			out.ToolEvents[i].ProjectRoot = st.projectRoot
		}
		if out.ToolEvents[i].GitBranch == "" {
			out.ToolEvents[i].GitBranch = st.branch
		}
		if out.ToolEvents[i].GitRemote == "" {
			out.ToolEvents[i].GitRemote = st.remote
		}
		if out.ToolEvents[i].SessionID == "" {
			out.ToolEvents[i].SessionID = st.sessionID
		}
	}
	for i := range out.TokenEvents {
		if out.TokenEvents[i].ProjectRoot == "" {
			out.TokenEvents[i].ProjectRoot = st.projectRoot
		}
		if out.TokenEvents[i].GitBranch == "" {
			out.TokenEvents[i].GitBranch = st.branch
		}
		if out.TokenEvents[i].GitRemote == "" {
			out.TokenEvents[i].GitRemote = st.remote
		}
		if out.TokenEvents[i].SessionID == "" {
			out.TokenEvents[i].SessionID = st.sessionID
		}
	}

	out.NewOffset = offset
	out.Warnings = warnings
	return out, nil
}

func decodeEnvelope(line string) (eventEnvelope, error) {
	var env eventEnvelope
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		return env, err
	}
	if env.Type == "" {
		return env, fmt.Errorf("missing type")
	}
	return env, nil
}

// dispatchState mutates parser state for events that carry session-level
// context. Called on EVERY line (even those before fromOffset) so
// context is correct for late emits.
func dispatchState(st *parserState, env eventEnvelope, sc *scrub.Scrubber) {
	switch env.Type {
	case "session.start":
		var d sessionStartData
		if err := json.Unmarshal(env.Data, &d); err == nil {
			if d.SessionID != "" {
				st.sessionID = d.SessionID
			}
			if d.SelectedModel != "" {
				st.model = d.SelectedModel
			}
			if d.CopilotVersion != "" {
				st.copilotVersion = d.CopilotVersion
			}
			if d.Context.CWD != "" {
				st.cwd = d.Context.CWD
			}
			if d.Context.GitRoot != "" {
				st.gitRoot = d.Context.GitRoot
			}
			if d.Context.Branch != "" {
				st.branch = d.Context.Branch
			}
			if d.Context.Repository != "" {
				st.repository = d.Context.Repository
			}
		}
	case "session.model_change":
		var d modelChangeData
		if err := json.Unmarshal(env.Data, &d); err == nil {
			if d.NewModel != "" {
				st.model = d.NewModel
			}
			if d.ReasoningEffort != "" {
				st.effortLevel = d.ReasoningEffort
			}
		}
	case "session.resume":
		// Refresh parser state from the resume payload. Without this,
		// long-lived sessions where the user re-opened on a different
		// model / cwd silently mis-attribute every assistant.message
		// emitted after the resume to the original model. Mirrors
		// session.start's field-by-field updates — non-empty wins,
		// empty leaves the prior value in place (resumes often omit
		// gitRoot/branch/repository, which we want to preserve).
		var d sessionResumeData
		if err := json.Unmarshal(env.Data, &d); err == nil {
			if d.SelectedModel != "" {
				st.model = d.SelectedModel
			}
			if d.ReasoningEffort != "" {
				st.effortLevel = d.ReasoningEffort
			}
			if d.Context.CWD != "" {
				st.cwd = d.Context.CWD
			}
			if d.Context.GitRoot != "" {
				st.gitRoot = d.Context.GitRoot
			}
			if d.Context.Branch != "" {
				st.branch = d.Context.Branch
			}
			if d.Context.Repository != "" {
				st.repository = d.Context.Repository
			}
		}
	case "tool.execution_start":
		var d toolExecutionStartData
		if err := json.Unmarshal(env.Data, &d); err == nil && d.ToolCallID != "" {
			st.toolCalls[d.ToolCallID] = d
		}
	case "permission.requested":
		var d permissionRequestedData
		if err := json.Unmarshal(env.Data, &d); err == nil && d.RequestID != "" {
			st.permRequests[d.RequestID] = d
		}
	case "subagent.completed":
		// subagent.completed.data.model is the AUTHORITATIVE source:
		// Copilot CLI's own final report of which model ran this
		// subagent. Empirically only 17/37 events carry it on the
		// operator sample — the other 20 are cancelled or
		// short-lived subagents that never resolved a model in the
		// completion event. For those, tool.execution_complete's
		// in-context data.model is the fallback (see
		// V6k handler below). Authoritative source ALWAYS wins —
		// overwrites whatever tool.execution_complete inferred earlier
		// within the same subagent context.
		var d subagentCompletedData
		if err := json.Unmarshal(env.Data, &d); err == nil && env.AgentID != "" && d.Model != "" {
			st.subagentModels[env.AgentID] = d.Model
		}
	case "tool.execution_complete":
		// V6k fallback (docs/copilot-cli-audit-2026-05-18.md §V6k).
		// When subagent.completed.data.model is absent (~54% of
		// subagents on the operator sample), every tool call made BY
		// the subagent emits tool.execution_complete with the
		// subagent's running model in data.model and the subagent's
		// agentId on the envelope. First-write-wins (only set if the
		// entry is still empty) so we don't churn the value across
		// the subagent's 50-100 tool calls; subagent.completed
		// (handled above) is allowed to overwrite if a later
		// authoritative model lands.
		//
		// Resolves 15 of the 20 previously-unresolved subagents on
		// the operator sample (the remaining 5 are pure no-tool
		// subagents — text-only output — that have no model-bearing
		// events anywhere in their context; they continue to fall
		// through to st.model as best-effort).
		if env.AgentID == "" {
			break
		}
		if _, already := st.subagentModels[env.AgentID]; already {
			break
		}
		var d toolExecutionCompleteData
		if err := json.Unmarshal(env.Data, &d); err == nil && d.Model != "" {
			st.subagentModels[env.AgentID] = d.Model
		}
	}
	_ = sc
}

// emitEvent appends ToolEvents / TokenEvents for events past the cursor.
func emitEvent(st *parserState, env eventEnvelope, path string, out *adapter.ParseResult, sc *scrub.Scrubber) {
	ts := parseTimestamp(env.Timestamp)
	// sidechain is true for every event carrying a non-empty AgentID —
	// i.e. anything emitted inside a subagent's execution context (see
	// eventEnvelope.AgentID doc comment). The spawning `task` tool call
	// itself is invoked in the PARENT session's context (AgentID==""),
	// so it never gets stamped — only the subagent's own work (its
	// assistant messages, and the tool calls it makes) does. Mirrors
	// claude-code's line.IsSidechain pass-through convention.
	sidechain := env.AgentID != ""
	switch env.Type {

	case "user.message":
		var d userMessageData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return
		}
		content := d.Content
		if content == "" {
			content = d.TransformedContent
		}
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         st.model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    models.ActionUserPrompt,
			Target:        truncate(content, 256),
			Success:       true,
			RawToolName:   "user",
			RawToolInput:  scrub.Truncate(sc.String(content)),
			MessageID:     env.ID,
			IsSidechain:   sidechain,
			Metadata:      effortMetadata(nil, st.effortLevel),
		})

	case "system.message":
		var d systemMessageData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return
		}
		// Dedup within session: Copilot rewrites the system prompt on
		// every model_change, but the content is largely the same.
		key := contentKey(d.Content)
		if st.systemHashesSeen[key] {
			return
		}
		st.systemHashesSeen[key] = true
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         st.model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    models.ActionSystemPrompt,
			Target:        truncate(d.Content, 128),
			Success:       true,
			RawToolName:   "system",
			RawToolInput:  scrub.Truncate(sc.String(d.Content)),
			MessageID:     env.ID,
			IsSidechain:   sidechain,
			Metadata:      effortMetadata(nil, st.effortLevel),
		})

	case "assistant.message":
		var d assistantMessageData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return
		}
		// Resolve model with three-step fallback:
		//   1. data.model (explicit per-message tag — rare, ~0.4%
		//      of asst.message events on the operator sample)
		//   2. subagentModels[env.AgentID] (this asst.message was
		//      emitted under a subagent, and we've already parsed
		//      that subagent's completion event)
		//   3. st.model (parent session's selected model)
		// Step 2 is the v1.6.8 B4 fix. Subagent.completed normally
		// fires AFTER all its asst.messages, so at emit time the
		// map is usually empty — that's what pendingSubagentTokenEmits
		// is for: defer the model resolution to post-loop.
		resolveSubagentModel := func() string {
			if env.AgentID == "" {
				return ""
			}
			return st.subagentModels[env.AgentID]
		}
		// Emit a TokenEvent for the output side (Tier 3 fallback).
		// MessageID is set to the requestId so the log-parser's Tier-1
		// usage rows upsert on (session_id, message_id).
		if d.OutputTokens > 0 || d.RequestID != "" {
			model := d.Model
			if model == "" {
				model = resolveSubagentModel()
			}
			if model == "" {
				model = st.model
			}
			idx := len(out.TokenEvents)
			out.TokenEvents = append(out.TokenEvents, models.TokenEvent{
				SourceFile:    path,
				SourceEventID: env.ID + ":token",
				SessionID:     st.sessionID,
				Timestamp:     ts,
				Tool:          models.ToolCopilotCLI,
				Model:         model,
				OutputTokens:  d.OutputTokens,
				Source:        models.TokenSourceJSONL,
				Reliability:   models.ReliabilityUnreliable,
				MessageID:     d.RequestID,
				IsSidechain:   sidechain,
			})
			// Buffer for post-loop patch when data.model is missing
			// AND we're under a subagent context but haven't yet seen
			// the subagent.completed event. Patch step at end-of-parse
			// rewrites Model from subagentModels[agentId] if resolved.
			if d.Model == "" && env.AgentID != "" {
				st.pendingSubagentTokenEmits = append(st.pendingSubagentTokenEmits, pendingSubagentEmit{idx: idx, agentID: env.AgentID})
			}
		}
		// If the assistant message has free-text content (no tool calls),
		// emit an assistant_text action so the row shows in the timeline.
		if strings.TrimSpace(d.Content) != "" && len(d.ToolRequests) == 0 {
			toolModel := d.Model
			if toolModel == "" {
				toolModel = resolveSubagentModel()
			}
			// (Note: parent st.model is NOT used here as a last fall-
			// back — the ToolEvent's Model column is informational and
			// has historically been left empty for unattributed actions.
			// We only fill it with d.Model or subagent-resolved model.)
			// B3 (2026-07-31): reasoning mints NO row of its own — it
			// briefly emitted a standalone `cline-cli`-style
			// `<tool>.reasoning` task_complete row, a phantom action for
			// something the model never did. The reasoning is a SIBLING
			// FIELD of the assistant message it belongs to
			// (data.reasoningText / .reasoningOpaque), so threading is
			// direct and unconditional — no pending state, no
			// consumption ordering: the assistant_text row below carries
			// it in PrecedingReasoning. A reasoning-only message (no
			// content, or one that carries tool requests instead)
			// therefore produces nothing here — there is no successor
			// row in this branch to carry it. An OPAQUE-ONLY reasoning
			// field carries nothing either (see threadableReasoning):
			// an encrypted blob is not content, uniformly with codex.
			reasoning := threadableReasoning(d.ReasoningText)
			idx := len(out.ToolEvents)
			out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
				SourceFile:    path,
				SourceEventID: env.ID,
				SessionID:     st.sessionID,
				Timestamp:     ts,
				Model:         toolModel,
				Tool:          models.ToolCopilotCLI,
				ActionType:    models.ActionAssistantMessage,
				Target:        truncate(d.Content, 256),
				Success:       true,
				// "<tool>.assistant_text" so the dashboard %.assistant_text
				// filter matches (the bare "assistant_text" never did).
				RawToolName:        models.ToolCopilotCLI + ".assistant_text",
				RawToolInput:       scrub.Truncate(sc.String(d.Content)),
				PrecedingReasoning: reasoning,
				MessageID:          d.MessageID,
				IsSidechain:        sidechain,
				Metadata:           effortMetadata(nil, st.effortLevel),
			})
			if d.Model == "" && env.AgentID != "" {
				st.pendingSubagentToolEmits = append(st.pendingSubagentToolEmits, pendingSubagentEmit{idx: idx, agentID: env.AgentID})
			}
		}

	case "tool.execution_complete":
		var d toolExecutionCompleteData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return
		}
		start, ok := st.toolCalls[d.ToolCallID]
		if !ok {
			// No matching start (cursor advanced past it on a prior
			// poll, or events arrived out-of-order). Synthesize with
			// what we have.
			start = toolExecutionStartData{ToolName: "unknown", ToolCallID: d.ToolCallID}
		}
		raw := string(start.Arguments)
		actionType := classifyToolName(start.ToolName, start.MCPServerName)
		target := deriveTarget(start.ToolName, start.Arguments)
		toolOutput := d.Result.DetailedContent
		if toolOutput == "" {
			toolOutput = d.Result.Content
		}
		errMsg := ""
		if !d.Success {
			// Prefer top-level data.error.message — empirically 158/158
			// failures in the operator specimen carry the real failure
			// text here, not in result.content. Fall back to result
			// fields only when the new path is empty (defensive against
			// future shape drift).
			errMsg = d.Error.Message
			if errMsg == "" {
				errMsg = d.Result.DetailedContent
			}
			if errMsg == "" {
				errMsg = d.Result.Content
			}
		}
		model := d.Model
		if model == "" {
			model = st.model
		}
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    actionType,
			Target:        target,
			Success:       d.Success,
			ErrorMessage:  scrub.Truncate(sc.String(errMsg)),
			RawToolName:   composeRawToolName(start.ToolName, start.MCPServerName, start.MCPToolName),
			RawToolInput:  scrub.Truncate(sc.RawJSON([]byte(raw))),
			ToolOutput:    scrub.Truncate(sc.String(toolOutput)),
			MessageID:     d.InteractionID,
			IsSidechain:   sidechain,
			Metadata:      effortMetadata(nil, st.effortLevel),
		})
		// Clear the cache entry — call complete.
		delete(st.toolCalls, d.ToolCallID)

	case "permission.completed":
		var d permissionCompletedData
		if err := json.Unmarshal(env.Data, &d); err != nil {
			return
		}
		req, ok := st.permRequests[d.RequestID]
		if !ok {
			return
		}
		pr := req.PermissionRequest
		// Action type: denied → Denied, anything else (approved, approved-
		// for-location, approved-for-session) → Request. Success follows
		// the same split — every "approved*" kind is a successful grant.
		actionType := models.ActionPermissionRequest
		if d.Result.Kind == "denied" {
			actionType = models.ActionPermissionDenied
		}
		success := strings.HasPrefix(d.Result.Kind, "approved")
		// RawToolInput priority: FullCommandText (shell-shaped current
		// specimen) > FileName (older file-shaped writes) > Intention
		// (fallback short label). The old code only read FileName, so
		// shell approvals (the only kind in the operator specimen)
		// silently emitted empty RawToolInput.
		rawInput := pr.FullCommandText
		if rawInput == "" {
			rawInput = pr.FileName
		}
		if rawInput == "" {
			rawInput = pr.Intention
		}
		// Metadata: capture approval granularity beyond plain "approved"
		// so downstream tooling can distinguish single-call grants from
		// scoped ones (approved-for-location / approved-for-session).
		var meta *models.ActionMetadata
		if d.Result.Kind != "" && d.Result.Kind != "approved" && d.Result.Kind != "denied" {
			meta = &models.ActionMetadata{
				PermissionApprovalKind: d.Result.Kind,
				PermissionLocationKey:  d.Result.LocationKey,
			}
		}
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         st.model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    actionType,
			Target:        pr.Intention,
			Success:       success,
			RawToolName:   pr.Kind,
			RawToolInput:  scrub.Truncate(sc.String(rawInput)),
			Metadata:      effortMetadata(meta, st.effortLevel),
			IsSidechain:   sidechain,
		})
		delete(st.permRequests, d.RequestID)

	case "session.resume":
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         st.model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    models.ActionSessionStart,
			Target:        "resume",
			Success:       true,
			RawToolName:   "session.resume",
			IsSidechain:   sidechain,
			Metadata:      effortMetadata(nil, st.effortLevel),
		})

	case "session.shutdown":
		out.ToolEvents = append(out.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: env.ID,
			SessionID:     st.sessionID,
			Timestamp:     ts,
			Model:         st.model,
			Tool:          models.ToolCopilotCLI,
			ActionType:    models.ActionSessionEnd,
			Target:        "shutdown",
			Success:       true,
			RawToolName:   "session.shutdown",
			IsSidechain:   sidechain,
			Metadata:      effortMetadata(nil, st.effortLevel),
		})
		// Tier 0 capture — `session.shutdown.data.modelMetrics` carries
		// the per-model cumulative usage delta for the work span between
		// the most recent `session.resume` and this shutdown. For users
		// not running `copilot --log-level debug` (Tier 1 unavailable),
		// this is the only place inputTokens / cacheReadTokens /
		// cacheWriteTokens / reasoningTokens are reported anywhere in
		// events.jsonl — without parsing here the adapter would capture
		// outputTokens via Tier 3 (assistant.message) and nothing else,
		// silently under-reporting cost by 90%+ for typical sessions.
		//
		// Emit one TokenEvent per model with non-zero usage. OutputTokens
		// stays zero because Tier 3 per-message rows already cover
		// output; doubling it here would over-count by ~2x. Each
		// shutdown's modelMetrics is a *delta* (verified empirically:
		// summing all shutdowns in a session matches Tier 3 outputs),
		// not a cumulative all-time snapshot, so each shutdown is
		// independently billable.
		//
		// MessageID is shutdown-event-id-scoped so re-parses upsert via
		// `idx_token_usage_session_message`. SourceEventID combines
		// shutdown id with model so each row has a unique
		// (source_file, source_event_id) pair under the UNIQUE
		// constraint. When Tier 1 (otel) rows exist for the same
		// session the store-layer dedup drops these (Tier 1 wins —
		// it has per-request granularity instead of per-shutdown).
		var sd sessionShutdownData
		if jsonErr := json.Unmarshal(env.Data, &sd); jsonErr == nil {
			for model, entry := range sd.ModelMetrics {
				u := entry.Usage
				if u.InputTokens == 0 && u.CacheReadTokens == 0 && u.CacheWriteTokens == 0 && u.ReasoningTokens == 0 {
					// Empty delta — shutdown fired without API activity
					// since the previous resume (compaction-only, idle
					// sleep, etc.). Skip emitting a zero row.
					continue
				}
				// Net non-cached input. Copilot CLI's session.shutdown
				// modelMetrics block reports `inputTokens` as the gross
				// prompt total INCLUDING the cached portion (same shape
				// as the debug-log Tier-1 path — see log.go). Net here
				// against `cacheReadTokens` to match the cost engine's
				// Anthropic-shape TokenBundle.Input contract; without
				// it the cached portion is billed at both rates. See
				// internal/intelligence/cost/engine.go.
				netInput := u.InputTokens - u.CacheReadTokens
				if netInput < 0 {
					netInput = 0
				}
				out.TokenEvents = append(out.TokenEvents, models.TokenEvent{
					SourceFile:          path,
					SourceEventID:       env.ID + ":" + model,
					SessionID:           st.sessionID,
					Timestamp:           ts,
					Tool:                models.ToolCopilotCLI,
					Model:               model,
					InputTokens:         netInput,
					OutputTokens:        0, // Tier 3 captures output per-message
					CacheReadTokens:     u.CacheReadTokens,
					CacheCreationTokens: u.CacheWriteTokens,
					ReasoningTokens:     u.ReasoningTokens,
					Source:              models.TokenSourceSessionSummary,
					Reliability:         models.ReliabilityApproximate,
					MessageID:           "session-shutdown:" + env.ID,
				})
			}
		}

	case "session.compaction_complete":
		// Compaction is a separately-billable API call (the assistant
		// summarises prior context). Its tokens are NOT included in
		// `session.shutdown.data.modelMetrics` — verified empirically:
		// summing all modelMetrics outputs across a session matches
		// Tier 3 assistant.message outputs within streaming noise, but
		// compactionTokensUsed.output is additive on top of both. For
		// summarization-heavy long sessions the omission can be a
		// meaningful share of total spend. Capture as a regular jsonl
		// TokenEvent with the compaction call's own requestId as
		// MessageID — joins to Tier 1 (otel) rows from process.log
		// when debug logging is on, via the v1.6.3 T1 dedup path.
		var cc sessionCompactionCompleteData
		if jsonErr := json.Unmarshal(env.Data, &cc); jsonErr == nil {
			inT, outT, crT, cwT := cc.Tokens.resolveTokens()
			if inT != 0 || outT != 0 || crT != 0 || cwT != 0 {
				model := cc.Tokens.Model
				if model == "" {
					// Older Copilot CLI schemas (most historical events)
					// don't tag the compaction model. Fall back to the
					// session's current model — empirically Copilot
					// compacts with whatever model is active when the
					// threshold trips, so this is the right approximation.
					model = st.model
				}
				msgID := cc.RequestID
				if msgID == "" {
					msgID = "compaction:" + env.ID
				}
				// Net non-cached input. The compaction event's
				// `inputTokens` follows the same OpenAI-gross convention
				// as the rest of Copilot CLI's token surfaces (verified
				// empirically against the operator's session DB; same
				// shape as the shutdown modelMetrics block above and
				// the log Tier-1 path). Net at emit time per the cost
				// engine's TokenBundle.Input contract.
				netInput := inT - crT
				if netInput < 0 {
					netInput = 0
				}
				out.TokenEvents = append(out.TokenEvents, models.TokenEvent{
					SourceFile:          path,
					SourceEventID:       env.ID + ":compaction",
					SessionID:           st.sessionID,
					Timestamp:           ts,
					Tool:                models.ToolCopilotCLI,
					Model:               model,
					InputTokens:         netInput,
					OutputTokens:        outT,
					CacheReadTokens:     crT,
					CacheCreationTokens: cwT,
					Source:              models.TokenSourceJSONL,
					Reliability:         models.ReliabilityApproximate,
					MessageID:           msgID,
				})
			}
		}

	// session.start and session.model_change feed state only — no
	// action row of their own (the resulting session row is upserted
	// when the first user/assistant event lands).
	// assistant.turn_start / assistant.turn_end / hook.* are
	// lifecycle markers we deliberately don't emit — they would clutter
	// the dashboard's per-action timeline without adding signal.

	default:
		// Unknown event type — skip silently. The list of known types
		// is enumerated above; new types added by upstream get logged
		// by the higher-level "unknown line" path.
	}
}

// resolveProjectRoot picks the best project root for the session.
// Prefers gitRoot from session.start.context; falls back to cwd. Both
// are translated through crossmount.TranslateForeignPath so a Windows-
// formatted path captured on WSL2 lands on the real /mnt/c/... mount
// instead of being CWD-prefixed by filepath.Abs. remote is the
// normalized "origin" remote when git.ResolveIdentity found a repo; ""
// when it didn't (honest gap, not fabricated). id carries the Project
// Identity Resolver v2 bundle (upstream remote/owner hashes,
// workspace, worktree flag, content fingerprint); the root-commit exec
// is intentionally left nil here (adapters never shell out to git for
// the lazy root-commit resolution — that runs once, store-side, behind
// Store.RootCommitNeedsCheck).
func resolveProjectRoot(st *parserState) (root, remote string, id git.Identity) {
	candidate := st.gitRoot
	if candidate == "" {
		candidate = st.cwd
	}
	if candidate == "" {
		return "", "", git.Identity{}
	}
	translated := crossmount.TranslateForeignPath(candidate)
	if translated == "" {
		translated = candidate
	}
	// STAT-GATE before git.ResolveIdentity (the goose / crush / freebuff
	// precedent): a (possibly cross-OS-translated) path that isn't locally
	// reachable falls through to the STATED path verbatim, not the /mnt
	// form. git.ResolveIdentity returns a non-existent path as its own
	// "root" with no error, so without this gate a Windows-side cwd
	// captured on a WSL host would persist as its /mnt/c translation.
	if _, err := os.Stat(translated); err != nil {
		return candidate, "", git.Identity{}
	}
	info, err := git.ResolveIdentity(translated, git.IdentityOptions{})
	if err == nil && info.Root != "" {
		// info.Remote/info.UpstreamRemote are already NormalizeRemote'd
		// by ResolveIdentity.
		return info.Root, info.Remote, info
	}
	return candidate, "", git.Identity{}
}

// classifyToolName picks an action_type using the bare toolName first,
// then promotes to ActionMCPCall when the call came through an MCP
// server but didn't otherwise classify. The MCP promotion catches the
// non-github-mcp-server-prefixed shapes (e.g. `ide-get_selection`) that
// the toolName-only heuristic in mapToolName would mark Unknown.
func classifyToolName(toolName, mcpServerName string) string {
	t := mapToolName(toolName)
	if t == models.ActionUnknown && mcpServerName != "" {
		return models.ActionMCPCall
	}
	return t
}

// composeRawToolName preserves the upstream MCP server attribution
// in the raw_tool_name column. When mcpServerName is set we emit
// `<server>:<tool>` (e.g. "github-mcp-server:get_file_contents") so
// the dashboard can separate MCP-routed calls from same-named native
// built-ins. When the bare toolName is already prefixed with the
// server name (the existing github-mcp-server-* convention) the prefix
// is stripped first to avoid double-tagging.
func composeRawToolName(toolName, mcpServerName, mcpToolName string) string {
	if mcpServerName == "" {
		return toolName
	}
	bareTool := mcpToolName
	if bareTool == "" {
		bareTool = strings.TrimPrefix(toolName, mcpServerName+"-")
	}
	if bareTool == "" {
		bareTool = toolName
	}
	return mcpServerName + ":" + bareTool
}

// mapToolName translates Copilot's built-in tool names + the
// github-mcp-server-* prefix family to normalized action types.
func mapToolName(name string) string {
	switch name {
	case "view", "read":
		return models.ActionReadFile
	case "create":
		return models.ActionWriteFile
	case "edit", "str_replace_editor":
		return models.ActionEditFile
	case "glob":
		return models.ActionSearchFiles
	case "grep":
		return models.ActionSearchText
	case "bash", "powershell", "pwsh", "cmd", "cmd.exe", "sh":
		return models.ActionRunCommand
	case "web_fetch":
		return models.ActionWebFetch
	case "web_search":
		return models.ActionWebSearch
	case "task":
		return models.ActionSpawnSubagent
	case "report_intent":
		return models.ActionUnknown // explicit: Copilot's mid-turn intent announcement
	}
	if strings.HasPrefix(name, "github-mcp-server-") || strings.Contains(name, "-mcp-server-") {
		return models.ActionMCPCall
	}
	return models.ActionUnknown
}

// deriveTarget pulls a short human-readable target string from a
// tool's arguments JSON. Best-effort — falls back to the first 64
// chars of the raw JSON if no recognized field is present.
func deriveTarget(name string, args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return truncate(string(args), 64)
	}
	for _, k := range []string{"path", "file_path", "filePath", "fileName", "file", "pattern", "query", "command", "url", "intent"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return truncate(s, 256)
			}
		}
	}
	_ = name
	return truncate(string(args), 64)
}

// threadableReasoning returns the reasoning text that may ride the
// successor event's PrecedingReasoning: `data.reasoningText` when the
// model surfaced readable thinking, and NOTHING otherwise.
//
// B3 uniform placeholder rule (2026-07-31): an opaque/encrypted
// reasoning blob is NOT content and is threaded nowhere. This helper
// used to render `data.reasoningOpaque` as a byte-count proxy
// ("[encrypted reasoning, N bytes]") mirroring codex's placeholder row;
// codex's placeholders were retired along with its phantom reasoning
// row, so copilot-cli's are too. An opaque-only assistant message
// therefore contributes nothing anywhere — no action row, and no
// `preceding_reasoning` on the assistant_text row that follows it. The
// blob's LENGTH is deliberately not surfaced: it told the operator
// nothing they could act on and read as if reasoning content had been
// captured.
// effortMetadata folds a session's reasoning-effort SETTING into an
// ActionMetadata, allocating one when meta is nil and preserving any
// fields already set on it (e.g. PermissionApprovalKind). Returns meta
// unchanged (possibly nil) when effort is empty, so rows from sessions
// that never surfaced session.model_change/session.resume with a
// reasoningEffort value keep a NULL metadata column rather than an
// empty-but-allocated one. Mirrors zcode's effortMetadata /
// codex's withEffort convention.
func effortMetadata(meta *models.ActionMetadata, effort string) *models.ActionMetadata {
	e := strings.TrimSpace(effort)
	if e == "" {
		return meta
	}
	if meta == nil {
		meta = &models.ActionMetadata{}
	} else {
		cp := *meta
		meta = &cp
	}
	meta.EffortLevel = e
	return meta
}

func threadableReasoning(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return scrub.Truncate(text)
}

func parseTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func contentKey(s string) string {
	// 32 chars + length is enough to dedup the system prompt within a
	// session without dragging in crypto/sha256 — the content is
	// stable across calls (Copilot rewrites the same prompt with
	// minor model-dependent suffixes; first 32 chars match).
	n := 32
	if len(s) < n {
		n = len(s)
	}
	return fmt.Sprintf("%d:%s", len(s), s[:n])
}
