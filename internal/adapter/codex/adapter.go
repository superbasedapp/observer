package codex

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Adapter parses OpenAI Codex CLI rollout JSONL files under
// ~/.codex/sessions/rollout-*.jsonl. See spec §4.2.
//
// The rollout format is event-based: session_configured / user_message /
// agent_message / tool_call / tool_output / token_count records. This
// adapter extracts tool_call + tool_output pairs into normalized ToolEvents
// and token_count events into TokenEvents.
type Adapter struct {
	scrubber  *scrub.Scrubber
	watchRoot string

	// name overrides the tool identity returned by Name() (and, via
	// the ParseSessionFile retag pass below, every ToolEvent/
	// TokenEvent this adapter instance emits). Empty means the
	// default codex identity, models.ToolCodex. Set by
	// NewOpenInterpreter for the Open Interpreter variant — see
	// docs/openinterpreter-adapter.md and
	// docs/plans/openinterpreter-adapter-plan-2026-07-29.md.
	//
	// CONSTRUCTION-ONLY, deliberately: there is no exported mutator.
	// An adapter instance is published to the watcher's registry at
	// startup and then used concurrently (Name() is read from the
	// dispatch path while ParseSessionFile runs), so a post-
	// registration setter would be an unsynchronized write against
	// live readers — a real -race failure, not a theoretical one. A
	// variant is a new constructor (NewOpenInterpreter), never a
	// mutation of an existing instance.
	name string

	// homeEnvVar overrides the single-explicit-root env var checked
	// by WatchPaths (default "CODEX_HOME"). Set to "INTERPRETER_HOME"
	// for the Open Interpreter variant.
	homeEnvVar string
	// homeDirName overrides the per-cross-mount-home subdirectory
	// name checked by WatchPaths (default ".codex"). Set to
	// ".openinterpreter" for the Open Interpreter variant.
	homeDirName string

	// desktopAppDir names the Electron userData directory of a DESKTOP
	// app that embeds this same Rust binary and drives it against its
	// OWN codex-home. Empty (codex proper) means there is no such app
	// and WatchPaths adds no desktop root. Set to "interpreter" by the
	// Open Interpreter variant — see desktopStoreRoots in
	// openinterpreter.go for the per-OS ladder and its grounding.
	desktopAppDir string

	// surface is this instance's capture-surface vocabulary: the
	// variant difference resolved into a capability at construction
	// (CLAUDE.md #3) instead of a name check on the resolve path. The
	// ZERO VALUE is codex proper's vocabulary — an empty overlay that
	// falls straight through to surface.go's shared tables — so every
	// pre-existing instance behaves exactly as before.
	//
	// CONSTRUCTION-ONLY for the same reason `name` is: a registered
	// adapter is read concurrently.
	surface surfaceVocabulary

	// readsServiceTier is the capability "the owning <root>/config.toml
	// carries an OpenAI service_tier worth reading" (Codex Fast mode).
	// True for codex proper only. The Open Interpreter variant leaves it
	// false: OpenAI service tiers mean nothing on its OpenRouter/Ollama
	// lane, and its desktop app's codex-home/config.toml holds plaintext
	// provider API keys (security ledger OI-1) — that file must never be
	// opened, so the tier read is gated here at construction rather than
	// by a name check on the parse path (CLAUDE.md #3).
	readsServiceTier bool
}

// New returns a Codex adapter with defaults.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), readsServiceTier: true}
}

// NewWithOptions customizes the scrubber and/or watch root.
func NewWithOptions(s *scrub.Scrubber, watchRoot string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{scrubber: s, watchRoot: watchRoot, readsServiceTier: true}
}

// Name implements adapter.Adapter.
func (a *Adapter) Name() string {
	if a.name != "" {
		return a.name
	}
	return models.ToolCodex
}

// homeEnv returns the env var WatchPaths checks for a single explicit
// session root. "CODEX_HOME" unless overridden (Open Interpreter
// variant: "INTERPRETER_HOME").
func (a *Adapter) homeEnv() string {
	if a.homeEnvVar != "" {
		return a.homeEnvVar
	}
	return "CODEX_HOME"
}

// homeDir returns the per-cross-mount-home subdirectory name
// WatchPaths expands. ".codex" unless overridden (Open Interpreter
// variant: ".openinterpreter").
func (a *Adapter) homeDir() string {
	if a.homeDirName != "" {
		return a.homeDirName
	}
	return ".codex"
}

// WatchPaths returns the canonical Codex sessions directory. Honors
// CODEX_HOME when set (single explicit path — cross-mount expansion
// is suppressed because the env var is the user telling us exactly
// where to look). Otherwise expands to ".codex/sessions" under every
// cross-mount-resolved $HOME so observer in WSL2 picks up sessions
// from /mnt/c/Users/<u>/.codex (and vice-versa).
//
// The Open Interpreter variant (NewOpenInterpreter) follows the exact
// same shape against INTERPRETER_HOME / ".openinterpreter" instead —
// see homeEnv/homeDir — and ADDITIONALLY watches the Interpreter
// desktop app's embedded codex-home under every cross-mount home (see
// desktopStoreRoots). Those desktop roots survive the env override:
// $INTERPRETER_HOME relocates the CLI's own home, and the desktop
// app's store is a DIFFERENT product's store at a fixed platform
// convention that no CLI env var moves. Suppressing it would silently
// zero desktop capture for an operator who only meant to redirect the
// CLI. The explicit watchRoot (test/backfill) still short-circuits to
// exactly one root.
//
// Roots are deduped by filesystem identity, so a home reachable under
// two spellings (a cross-mount bind of the native home, a symlink)
// contributes one root, not two.
func (a *Adapter) WatchPaths() []string {
	if a.watchRoot != "" {
		return []string{a.watchRoot}
	}
	var roots []string
	envHome := os.Getenv(a.homeEnv())
	if envHome != "" {
		roots = append(roots, filepath.Join(envHome, "sessions"))
	}
	for _, h := range crossmount.AllHomes() {
		// The env override replaces the per-home CLI root only.
		if envHome == "" {
			roots = append(roots, filepath.Join(h.Path, a.homeDir(), "sessions"))
		}
		roots = append(roots, a.desktopStoreRoots(h)...)
	}
	return adapter.DedupRootsByIdentity(roots)
}

// IsSessionFile matches rollout-*.jsonl files under one of this
// adapter's WatchPaths. The under-WatchPaths constraint enforces the
// v1.4.51 dispatch contract: predicates self-limit to paths the
// adapter could actually own, so a future broad-predicate adapter
// can't accidentally claim a Codex rollout file by alphabetical sort.
func (a *Adapter) IsSessionFile(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "rollout-") || filepath.Ext(base) != ".jsonl" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// actionMap translates Codex tool names to the normalized taxonomy.
// It is READ OUT of internal/tooltax, the one owner of the
// cross-adapter tool vocabulary (WP-T3 of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md). The
// hand-maintained literal that used to live here — core tools,
// newer-build synonyms (audit C2), the function_call names of current
// Codex Desktop builds, exec_command (>=v0.130) and the Windows
// interpreter names — is now the codex rows of tooltax's ordered
// canonical table. Add new native tool names THERE, not here.
//
// tooltax.For returns LITERAL rows only, so the `mcp__*` glob is not
// in this map; codex never relied on it (it allow-lists MCP names).
//
// TestActionMapPreservesPreTooltaxFixture pins every pre-conversion
// pair as still present and unchanged; TestActionMapTooltaxAdditions
// pins the intended additions so an unreviewed one is loud.
var actionMap = tooltax.For(models.ToolCodex)

// rawLine is the top-level envelope; payload is decoded per type.
type rawLine struct {
	ID        string          `json:"id"`
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// sessionContext is payload for session_configured / session_start events —
// we cache cwd + model + branch for the whole file.
type sessionContext struct {
	SessionID string `json:"session_id"`
	ID        string `json:"id"`
	TurnID    string `json:"turn_id"`
	Model     string `json:"model"`
	Cwd       string `json:"cwd"`
	GitBranch string `json:"git_branch"`
	// GitRemote is the normalized "origin" remote for Cwd. Unlike
	// GitBranch (sourced from the rollout JSONL's own git_branch
	// field), Codex's JSONL never carries a remote — this is resolved
	// via git.ResolveIdentity(Cwd) at the same call sites that already
	// resolve the project root (resolveProjectRoot / resolveProjectRemote,
	// cached by rootCache), never unmarshaled from JSON. `json:"-"`
	// keeps it out of the wire shape. The fuller Project Identity
	// Resolver v2 bundle (upstream remote/owner hashes, workspace,
	// worktree flag, content fingerprint) is applied separately at
	// ParseSessionFile's return points via
	// adapter.ApplyProjectIdentityByRoot(identitiesByRoot(rootCache)),
	// not threaded through sessionContext.
	GitRemote string `json:"-"`
	// EffortLevel is the per-turn reasoning effort the model was
	// asked to use (minimal | low | medium | high). Populated from
	// turn_context.payload.collaboration_mode.settings.reasoning_effort
	// — verified path on real codex 0.129+ JSONL fixtures. Not
	// JSON-parsed directly (the field doesn't ride on the same
	// flat envelope as the other context fields) — the
	// turn_context handler reads it out of the nested struct
	// and assigns it onto ctxState.
	EffortLevel string `json:"-"`
	// v1.4.52 added codex 0.130+ turn_context fields. All "sticky":
	// once seen, they ride every subsequent action until the next
	// turn_context updates them. Same pattern as EffortLevel.
	CollaborationMode string `json:"-"`
	Personality       string `json:"-"`
	RealtimeActive    bool   `json:"-"`
	TruncationMode    string `json:"-"`
	TruncationLimit   int64  `json:"-"`
	// ServiceTier is the operator's requested OpenAI processing tier
	// ("priority" = Codex Fast mode, "flex" = slow/discount, "default"/
	// "auto" = standard). It is NOT present anywhere in the rollout JSONL
	// (confirmed 2026-06-08: service_tier appears only as a tool-schema
	// definition, never a value), so the adapter reads it once per file
	// from the owning ~/.codex/config.toml — see codexServiceTier. Sticky
	// for the whole file; never updated from a parsed line. Drives the
	// per-message ServiceTier pill and TokenEvent.Fast (priority → fast).
	ServiceTier string `json:"-"`
}

type payloadEnvelope struct {
	Type string `json:"type"`
}

type userMessage struct {
	Message string `json:"message"`
}

// sessionMetaPayload extends sessionContext with the base_instructions
// system prompt the runtime baked into the conversation. The text is
// large (18KB+ in observed corpora) so the adapter hash-dedups across
// the parse to avoid emitting one row per session_meta replay.
type sessionMetaPayload struct {
	sessionContext
	BaseInstructions struct {
		Text string `json:"text"`
	} `json:"base_instructions"`
	// ForkedFromID / ParentThreadID / ThreadSource are the session
	// lineage markers codex 0.144+ stamps on the OWNING session_meta.
	// ForkedFromID is set on user forks AND subagent spawns;
	// ThreadSource is "user" (normal + user-fork) or "subagent".
	// Together they mark a rollout whose leading records are replayed
	// parent history (see forkReplayTracker). Persisted node-local per
	// Part B (migration 069).
	ForkedFromID   string `json:"forked_from_id"`
	ParentThreadID string `json:"parent_thread_id"`
	ThreadSource   string `json:"thread_source"`
	// Timestamp is the payload-level session creation time (distinct
	// from the envelope timestamp, which a fork RE-STAMPS to
	// fork-creation time on every replayed record). The owning
	// session_meta's payload timestamp is the reliable creation clock
	// the replay discriminator compares task_started.started_at
	// against.
	Timestamp string `json:"timestamp"`
	// Originator + Source are the client-identity discriminator codex
	// stamps on every session_meta (`codex_cli_rs` / `codex_exec` /
	// `codex_vscode` / "Codex Desktop" / ... paired with `cli` / `exec`
	// / `vscode`). Only the OWNING session_meta's values are used —
	// resolveCodexSurface (surface.go) turns them into the normalized
	// models.Surface* vocabulary for Part E capture-surface
	// attribution. See docs/plans/ide-surface-capture-remediation-
	// plan-2026-09-02.md §0/§3.
	Originator string `json:"originator"`
	Source     string `json:"source"`
	// CLIVersion is the codex CLI version the runtime stamped on the
	// OWNING session_meta ("0.150.0", "0.130.0-alpha.5"). Captured
	// node-local per Issue 2 (migration 125) and emitted as a
	// models.SessionToolVersion at the same owner-gated site as the
	// surface attribution below.
	CLIVersion string `json:"cli_version"`
}

// turnContextPayload extends sessionContext with developer_instructions —
// per-turn system-prompt-shaped overrides. In observed corpora this is
// 9KB+ and ALMOST ALWAYS identical across turns within a session, so
// hash dedup makes the difference between O(turns) and O(1) rows per
// session.
//
// CollaborationMode.Settings.ReasoningEffort is the canonical per-turn
// effort signal in codex 0.129+ JSONL: minimal | low | medium | high,
// or null when the user hasn't overridden the model default. Verified
// against a real local fixture; *string distinguishes "field absent"
// (no nesting at all) from "field present but null" (Codex sent the
// envelope but the user didn't override) — both collapse to the
// empty-string sentinel for our purposes downstream.
type turnContextPayload struct {
	sessionContext
	DeveloperInstructions string `json:"developer_instructions"`
	CollaborationMode     struct {
		// Mode discriminates the user-facing collaboration surface in
		// codex 0.130+: "default" (free-to-edit) vs "plan"
		// (think-only). High-signal because the same model in plan
		// mode produces zero side-effects — costs and apparent
		// quality should be interpreted differently from a default-
		// mode session.
		Mode     string `json:"mode"`
		Settings struct {
			ReasoningEffort *string `json:"reasoning_effort"`
		} `json:"settings"`
	} `json:"collaboration_mode"`
	// Personality is the active Codex Desktop persona ("friendly",
	// etc.) — controls the base-instructions tone.
	Personality string `json:"personality"`
	// RealtimeActive is true while codex 0.130+'s real-time/voice
	// surface is active. Currently rare; capture for future signals.
	RealtimeActive bool `json:"realtime_active"`
	// TruncationPolicy carries codex 0.130+'s per-turn truncation
	// strategy + budget (e.g. {mode:"tokens", limit:10000}). Useful
	// forensics when assistant output got cut short.
	TruncationPolicy struct {
		Mode  string `json:"mode"`
		Limit int64  `json:"limit"`
	} `json:"truncation_policy"`
}

// EffortFromPayload returns the effort string (minimal | low | medium
// | high) from the turn_context's collaboration_mode envelope, or ""
// when not set / explicit null. Helper so the parse loop reads
// cleanly.
func (p turnContextPayload) EffortFromPayload() string {
	if p.CollaborationMode.Settings.ReasoningEffort == nil {
		return ""
	}
	return *p.CollaborationMode.Settings.ReasoningEffort
}

// responseItemMessage covers response_item.payload when payload.type ==
// "message". Role discriminates assistant / user / developer; only
// developer-role messages route to ActionSystemPrompt (assistant +
// user are already covered by event_msg/agent_message and event_msg/
// user_message respectively, and re-emitting them here would
// double-count).
type responseItemMessage struct {
	Role    string                       `json:"role"`
	Content []responseItemMessageContent `json:"content"`
}

type responseItemMessageContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
	// ImageURL carries an `input_image` part's image reference. In the
	// Codex rollout it is a data URI string ("data:image/png;base64,...")
	// but the Responses schema also permits an object ({"url":"..."}), so
	// it is kept raw and only the media-type prefix is read (Issue 1
	// user-attachment capture). The base64 payload is NEVER decoded/stored.
	ImageURL json.RawMessage `json:"image_url"`
}

// agentMessage is the assistant's natural-language preamble that
// introduces a turn's tool work. Codex emits one or more of these
// per turn (`event_msg` payload type "agent_message"), interleaved
// with tool_call / function_call events. We capture them per-turn
// and propagate as PrecedingReasoning on every tool_call /
// exec_command_end / web_search_end that follows in the same turn,
// matching how claudecode threads assistant text through to its
// tool events.
type agentMessage struct {
	TurnID  string `json:"turn_id"`
	Message string `json:"message"`
}

// itemCompletedPayload covers event_msg.payload when payload.type ==
// "item_completed" — a newer Codex CLI wire format (observed live
// 2026-09-02) that wraps turn activity in a discriminated Item union
// (item.type: AgentMessage / Reasoning / CommandExecution /
// UserMessage) instead of the legacy flat event_msg types
// ("agent_message" / "user_message" above). On rollouts using this
// schema exclusively, the legacy types never fire, so without this
// case assistant text is silently dropped entirely (0 assistant_
// message rows) and every tool call falls back to the dashboard's
// "no recovered text" placeholder.
//
// Only item.type == "AgentMessage" is handled (mirroring the
// "agent_message" case below). Reasoning and CommandExecution items
// are exact-count duplicates of the response_item "reasoning" and
// "custom_tool_call"/"custom_tool_call_output" entries already
// captured elsewhere — handling them here would double-count.
// UserMessage is left alone too: it is not a confirmed gap (initial
// prompts have been observed captured via a different route on
// item_completed-only rollouts), and speculatively wiring it risks
// double-counting without a demonstrated need.
//
// The content-block shape ({"type":"Text","text":"..."} for
// AgentMessage, {"type":"text",...} for UserMessage — casing is
// inconsistent across item types) matches responseItemMessageContent
// closely enough to reuse it + concatMessageContent verbatim: only
// the "text" field is read, and its JSON key case is stable even
// though the "type" field's case is not.
type itemCompletedPayload struct {
	TurnID string `json:"turn_id"`
	Item   struct {
		Type    string                       `json:"type"`
		Content []responseItemMessageContent `json:"content"`
	} `json:"item"`
}

type taskStarted struct {
	TurnID string `json:"turn_id"`
	// StartedAt is the turn's wall-clock start in unix SECONDS. It is
	// the fork/subagent replay discriminator: a forked or subagent
	// rollout physically replays the parent's task_started events with
	// their ORIGINAL started_at (earlier than the child's own creation
	// time), while the first live turn's started_at equals session
	// creation to the second. See forkReplayTracker.
	StartedAt int64 `json:"started_at"`
}

type taskComplete struct {
	TurnID           string `json:"turn_id"`
	LastAgentMessage string `json:"last_agent_message"`
	CompletedAt      int64  `json:"completed_at"`
	DurationMs       int64  `json:"duration_ms"`
	// TimeToFirstTokenMS is codex 0.130+'s gap between task_started
	// and the first streamed assistant token. Captures model warmup +
	// upstream queue latency separately from total duration.
	TimeToFirstTokenMS int64 `json:"time_to_first_token_ms"`
}

// turnAborted is event_msg.payload for type="turn_aborted" — a turn
// interrupted before the model finishes generating (typically user
// pressed esc / cancelled). Same completed_at + duration_ms shape as
// taskComplete plus a `reason` discriminator (observed: "interrupted").
type turnAborted struct {
	TurnID      string `json:"turn_id"`
	Reason      string `json:"reason"`
	CompletedAt int64  `json:"completed_at"`
	DurationMs  int64  `json:"duration_ms"`
}

type execCommandEnd struct {
	CallID           string          `json:"call_id"`
	TurnID           string          `json:"turn_id"`
	Command          json.RawMessage `json:"command"`
	Cwd              string          `json:"cwd"`
	AggregatedOutput string          `json:"aggregated_output"`
	Stdout           string          `json:"stdout"`
	Stderr           string          `json:"stderr"`
	ExitCode         int             `json:"exit_code"`
	Duration         struct {
		Secs  int64 `json:"secs"`
		Nanos int64 `json:"nanos"`
	} `json:"duration"`
	Status string `json:"status"`
}

type webSearchEnd struct {
	CallID string `json:"call_id"`
	TurnID string `json:"turn_id"`
	Query  string `json:"query"`
	Action struct {
		Query   string   `json:"query"`
		Queries []string `json:"queries"`
	} `json:"action"`
}

// responseItemReasoning is response_item.payload when payload.type ==
// "reasoning". The `summary` array MAY contain text segments
// {type:"summary_text"|"text", text:"..."} in future Codex builds; the
// `encrypted_content` field is opaque and not extractable.
//
// B3 (2026-07-31): reasoning mints NO action row. Readable summary text
// is threaded through the turn's agentMessages cache so the next
// tool_call / agent_message carries it as PrecedingReasoning; an
// encrypted-only item (the overwhelming majority — 15,040 of the 15,369
// historical rows were the `(encrypted reasoning, N bytes)` placeholder)
// contributes NOTHING and simply vanishes. EncryptedContent is retained
// as a decode target so the field is documented against the wire shape
// and a future readable-content build has somewhere to land.
type responseItemReasoning struct {
	Summary          []reasoningSummaryPart `json:"summary"`
	EncryptedContent string                 `json:"encrypted_content"`
}

type reasoningSummaryPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mcpToolCallEnd is event_msg.payload for type="mcp_tool_call_end" —
// the executor result for an MCP tool call (typically paired with a
// response_item.function_call(list_mcp_resources*) intent emitted
// earlier in the same turn). The `invocation` block carries
// server/tool/arguments; `result` is a tagged-union {Ok|Err} where Ok
// carries content[*].text + isError, Err carries the failure message.
type mcpToolCallEnd struct {
	CallID     string        `json:"call_id"`
	TurnID     string        `json:"turn_id"`
	Invocation mcpInvocation `json:"invocation"`
	Duration   codexDuration `json:"duration"`
	Result     mcpCallResult `json:"result"`
}

type mcpInvocation struct {
	Server    string          `json:"server"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

type codexDuration struct {
	Secs  int64 `json:"secs"`
	Nanos int64 `json:"nanos"`
}

type mcpCallResult struct {
	Ok  *mcpCallResultOk  `json:"Ok"`
	Err *mcpCallResultErr `json:"Err"`
}

type mcpCallResultOk struct {
	Content []mcpCallContent `json:"content"`
	IsError bool             `json:"isError"`
}

type mcpCallContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpCallResultErr struct {
	Message string `json:"message"`
}

// compactedEvent is the top-level type="compacted" event Codex emits
// when the model decides to summarize earlier turns. The payload
// carries `message` (the runtime-substituted summary text) and
// `replacement_history` (the array of messages that got compacted
// away). Per user direction (2026-05-01): capture token/event
// information but do NOT make these rows searchable like file edits.
// One ActionContextCompacted row per event records msg-count + byte/
// token estimate so cost-analysis and compaction-frequency dashboards
// pick them up without polluting the file-edit browser.
type compactedEvent struct {
	Message            string                 `json:"message"`
	ReplacementHistory []compactedHistoryItem `json:"replacement_history"`
}

type compactedHistoryItem struct {
	Role    string                  `json:"role"`
	Content []compactedContentBlock `json:"content"`
}

type compactedContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// dynamicToolCallRequest is event_msg.payload for type=
// "dynamic_tool_call_request" — Codex's runtime-loaded tool invocation
// (e.g. load_workspace_dependencies). Note: this event uses camelCase
// `callId`/`turnId` field names, unlike the snake_case used elsewhere
// in event_msg payloads (the response variant uses snake_case). Both
// forms must be tolerated.
type dynamicToolCallRequest struct {
	CallID    string          `json:"callId"`
	CallIDAlt string          `json:"call_id"`
	TurnID    string          `json:"turnId"`
	TurnIDAlt string          `json:"turn_id"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

func (d dynamicToolCallRequest) callID() string { return firstNonEmpty(d.CallID, d.CallIDAlt) }
func (d dynamicToolCallRequest) turnID() string { return firstNonEmpty(d.TurnID, d.TurnIDAlt) }

// dynamicToolCallResponse is event_msg.payload for type=
// "dynamic_tool_call_response" — the executor-side result. Field
// names are snake_case in observed payloads, but we accept the
// camelCase form too for robustness.
type dynamicToolCallResponse struct {
	CallID       string                `json:"call_id"`
	CallIDAlt    string                `json:"callId"`
	TurnID       string                `json:"turn_id"`
	TurnIDAlt    string                `json:"turnId"`
	Tool         string                `json:"tool"`
	Arguments    json.RawMessage       `json:"arguments"`
	ContentItems []dynamicToolCallItem `json:"content_items"`
	Success      bool                  `json:"success"`
	Error        string                `json:"error"`
	Duration     codexDuration         `json:"duration"`
}

func (d dynamicToolCallResponse) callID() string { return firstNonEmpty(d.CallID, d.CallIDAlt) }

type dynamicToolCallItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// viewImageToolCall is event_msg.payload for type="view_image_tool_call"
// — the executor side-channel for Codex's view_image function tool.
// Carries the resolved file path (the response_item.function_call's
// arguments do too, but this event lands post-resolution and is
// authoritative when the call resolves through a layer that rewrites
// paths).
type viewImageToolCall struct {
	CallID string `json:"call_id"`
	TurnID string `json:"turn_id"`
	Path   string `json:"path"`
}

// codexError is event_msg.payload for type="error" — upstream API
// failures the rollout writes when a turn cannot complete (usage limit,
// rate limit, content-policy, malformed-request, etc.). Mirrors
// claudecode's ActionAPIError capture; pre-v1.4.21 these were silently
// dropped because the adapter only knew the structured success-path
// event types.
type codexError struct {
	Message        string `json:"message"`
	CodexErrorInfo string `json:"codex_error_info"`
}

type toolCall struct {
	CallID string          `json:"call_id"`
	ID     string          `json:"id"` // some Codex builds use "id" rather than "call_id"
	Tool   string          `json:"tool"`
	Name   string          `json:"name"` // newer builds use "name"
	Input  json.RawMessage `json:"input"`
}

type toolOutput struct {
	CallID  string          `json:"call_id"`
	ID      string          `json:"id"`
	Output  json.RawMessage `json:"output"`
	Success *bool           `json:"success"`
	IsError *bool           `json:"is_error"`
}

// responseItemFunctionCall is response_item.payload when payload.type ==
// "function_call". This is the assistant-side tool intent, emitted before
// the corresponding executor side-channel (event_msg/exec_command_end for
// shell_command, event_msg/web_search_end for web_search_call,
// event_msg/patch_apply_end for the apply_patch custom tool). The
// `arguments` field is a JSON-string-encoded object — unwrap once.
type responseItemFunctionCall struct {
	Name      string `json:"name"`
	CallID    string `json:"call_id"`
	Arguments string `json:"arguments"`
}

// responseItemFunctionCallOutput is response_item.payload when payload.type
// == "function_call_output". The output field is a string (often itself
// JSON-shaped) and lacks success/is_error metadata — when only this side
// of the pair is seen, we can attach the body but cannot infer success.
type responseItemFunctionCallOutput struct {
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

// responseItemCustomToolCall is response_item.payload when payload.type ==
// "custom_tool_call". In current Codex Desktop builds this is exclusively
// the `apply_patch` tool — input carries the raw patch text (not JSON),
// and the matching event_msg/patch_apply_end carries the structured
// `changes` map plus stdout/stderr/success.
type responseItemCustomToolCall struct {
	Status string `json:"status"`
	CallID string `json:"call_id"`
	Name   string `json:"name"`
	Input  string `json:"input"`
}

// responseItemCustomToolCallOutput is the matching output: a single
// string field that's typically itself a JSON object
// {"output":"...","metadata":{"exit_code":0,...}}.
type responseItemCustomToolCallOutput struct {
	CallID string `json:"call_id"`
	Output string `json:"output"`
}

// patchApplyEnd is event_msg.payload for type="patch_apply_end" — the
// executor-side result for an apply_patch custom_tool_call. `changes` is
// a map of absolute path → {type, content} for each file the patch
// touched. We only use the file paths and overall success in Tier 1.
type patchApplyEnd struct {
	CallID  string                      `json:"call_id"`
	TurnID  string                      `json:"turn_id"`
	Stdout  string                      `json:"stdout"`
	Stderr  string                      `json:"stderr"`
	Success bool                        `json:"success"`
	Changes map[string]patchApplyChange `json:"changes"`

	// ChangesRaw is the verbatim `changes` object, filled by
	// patchChangesRaw at the call site rather than decoded here — a
	// second field can't share the `changes` tag. The typed map above
	// drives Target and ContentBytes; the raw bytes are what
	// RawToolInput stores, so re-marshaling can't silently drop a
	// field this struct doesn't name.
	ChangesRaw json.RawMessage `json:"-"`
}

// patchApplyChange is one entry of patch_apply_end.changes. The producer
// uses a different payload per change type: `add` and `delete` carry the
// whole file in `content`, while `update` carries `unified_diff` (plus a
// `move_path` that is null outside a rename) and no `content` at all.
//
// `unified_diff` and `move_path` are deliberately NOT decoded. Nothing in
// Tier 1 reads them: RawToolInput stores the producer's verbatim bytes
// (see RenderPatchChangesInput), and the authored-byte count must not
// include the diff — see authoredBytesFromPatchChanges for why.
type patchApplyChange struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

type tokenCount struct {
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	TotalTokens  int64  `json:"total_tokens"`
	Cached       int64  `json:"cached_input_tokens"`
	Reasoning    int64  `json:"reasoning_tokens"`
	Model        string `json:"model"`
}

type modernTokenCount struct {
	Info struct {
		LastTokenUsage  tokenUsage `json:"last_token_usage"`
		TotalTokenUsage tokenUsage `json:"total_token_usage"`
	} `json:"info"`
	// RateLimits is the Codex 0.130+ envelope carried alongside
	// `info`. Present even when `info` is null (the startup
	// token_count fires with rate_limits-only). Emitted as
	// ActionRateLimit ToolEvent rows reusing the cowork-introduced
	// schema (RateLimitStatus / Type / ResetsAt / OverageStatus).
	RateLimits *codexRateLimits `json:"rate_limits"`
}

// codexRateLimits is the Codex 0.130+ token_count.rate_limits
// envelope. Two windows (primary / secondary) with
// used_percent + window_minutes + resets_at; plus a session-level
// plan_type ("plus" / "pro" / "team") and rate_limit_reached_type
// (null normally, set to "primary" / "secondary" when hit). Limit_id
// is the rate-limit family ("codex" today).
type codexRateLimits struct {
	LimitID              string                `json:"limit_id"`
	LimitName            *string               `json:"limit_name"`
	Primary              *codexRateLimitWindow `json:"primary"`
	Secondary            *codexRateLimitWindow `json:"secondary"`
	Credits              *json.RawMessage      `json:"credits"`
	PlanType             string                `json:"plan_type"`
	RateLimitReachedType *string               `json:"rate_limit_reached_type"`
}

type codexRateLimitWindow struct {
	UsedPercent   float64 `json:"used_percent"`
	WindowMinutes int64   `json:"window_minutes"`
	ResetsAt      int64   `json:"resets_at"`
}

type tokenUsage struct {
	InputTokens       int64 `json:"input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	TotalTokens       int64 `json:"total_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	ReasoningTokens   int64 `json:"reasoning_output_tokens"`
}

// ParseSessionFile implements adapter.Adapter.
// maxRecordBytes bounds the memory a single codex rollout JSONL record
// may consume while being read. It is a memory-safety bound, not a
// correctness limit. The previous reader (a bufio.Scanner with a 16 MiB
// token cap) failed the ENTIRE file the instant one record exceeded it
// ("bufio.Scanner: token too long") — issue #7: a valid 91 MiB rollout
// carrying a single 22.3 MiB token_count record was discarded whole,
// and raising watch.max_file_size_mb could not help because the scanner
// aborted before any accumulated results were ingested. This bound is
// 4× the old cap, comfortably above real-world records, and a record
// LARGER than it is SKIPPED (its bytes consumed and the cursor advanced
// past it) rather than aborting the file. Declared as a var so tests can
// lower it to exercise the skip path without allocating tens of
// megabytes; treat it as an immutable constant everywhere else.
var maxRecordBytes int64 = 64 * 1024 * 1024

// readRecord reads one '\n'-terminated record from r under the maxBytes
// memory-safety bound, growing its buffer only as far as the bound
// (never loading a pathologically large line whole). It returns the
// record bytes INCLUDING the terminating '\n' when one was present, the
// total bytes consumed from the stream for the record (used to advance
// the byte cursor even when the record is skipped), whether the record
// exceeded maxBytes (in which case data is nil and its bytes have been
// fully drained), and the terminating read error (io.EOF on the final
// read). A clean end of stream yields consumed == 0 (and io.EOF).
//
// The err return is the terminator signal callers rely on: bufio's
// ReadSlice reports a nil error the moment it locates '\n' and io.EOF
// only when the stream ends before one is found. So a record returned
// with consumed > 0 AND err == io.EOF is an UNTERMINATED trailing
// fragment (codex has not finished writing it); one returned with
// err == nil is '\n'-terminated and complete. Callers use this to defer
// unterminated trailing records uniformly — see ParseSessionFile.
//
// This replaces bufio.Scanner across the codex parse paths so a record
// larger than the old fixed token cap degrades to a per-record skip
// instead of a whole-file failure, while preserving ParseSessionFile's
// byte-cursor semantics: consumed is the exact terminator-inclusive
// length, so NewOffset arithmetic is unchanged on '\n'-terminated files
// (and is CRLF-correct, unlike the old +1 approximation).
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

// ParseSessionFile implements adapter.Adapter. It delegates to
// parseSessionFile (the ~20-site internal parser, unchanged since it
// still hardcodes models.ToolCodex throughout) and then retags every
// emitted ToolEvent/TokenEvent with this adapter instance's identity —
// the single-seam variant-retag pattern (docs/new-adapter-checklist.md
// §2.1(b), mirrors antigravity.Adapter.ParseSessionFile). For the
// default codex.New() instance a.Name() == models.ToolCodex, so the
// retag is a no-op and every pre-existing codex behavior is
// byte-identical. CacheObservations and SessionLineages carry no Tool
// field and need no retag.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res, err := a.parseSessionFile(ctx, path, fromOffset)
	name := a.Name()
	for i := range res.ToolEvents {
		res.ToolEvents[i].Tool = name
	}
	for i := range res.TokenEvents {
		res.TokenEvents[i].Tool = name
	}
	return res, err
}

func (a *Adapter) parseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("codex.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	res := adapter.ParseResult{NewOffset: fromOffset}

	// Fall back to the filename stem as session id if no real
	// session-bearing envelope ever lands (e.g. incremental parse
	// starting mid-file). This fallback is provisional only: the first
	// real SessionID from the file replaces it, and later replayed
	// session_meta records must not overwrite that real owner.
	fallbackSessionID := sessionIDFromPath(path)
	ctxState := sessionContext{}
	hasRealSessionID := false

	// On incremental resume (fromOffset > 0) the chunk we're about to
	// parse usually does NOT contain the leading session_meta /
	// session_configured / turn_context lines that carry SessionID, Cwd,
	// Model, GitBranch. Without those, every event emitted from the
	// resumed chunk lands with the date-prefixed filename as SessionID
	// and an empty ProjectRoot — store.Ingest then drops the lot
	// silently because empty ProjectRoot is a hard skip. Prefetch the
	// context-bearing leading lines so the resumed events inherit the
	// real session id and cwd. Bounded by `fromOffset` so the cost is at
	// most one extra read of the bytes already on disk before resume.
	// lineOffset tracks how many lines preceded fromOffset on
	// incremental resume. SourceEventIDs that embed `:L<linenum>:`
	// (user_prompt, task_complete, system_prompt, mcp, web, view_image,
	// patch, compacted, error, plus the call_id fallback paths) must
	// stay stable across re-parses of the same file — otherwise a full
	// rescan with `observer scan --force` produces duplicate rows
	// because the L-num is chunk-relative on resume but absolute on
	// rescan. prefetchSessionContext returns the count so the main
	// parse can resume from there. 2026-05-11 maintainer dogfood
	// surfaced this: a scan --force on today's sessions created 17
	// dup rows (user_prompt + task_complete + unknown + system_prompt)
	// before the fix landed.
	// forkTrack detects fork/subagent REPLAY: codex physically replays
	// the parent rollout's token_count telemetry into a fork/subagent
	// file. Replayed token_count events must NOT emit token_usage rows
	// (they double-count the parent's input) while their cumulative /
	// dedup state still advances. Fail-open for unmarked files, so a
	// normal rollout parses byte-identically. See forkReplayTracker.
	//
	// On incremental resume it is RECONSTRUCTED from the prefix scan
	// below (fed the leading session_meta + task_started records) so a
	// watcher poll that ends mid-replay-burst resumes with correct
	// fork-marking + turn governance — otherwise the remaining replayed
	// history would be misclassified as live and emitted.
	var forkTrack forkReplayTracker
	// sessionMetaObservedThisChunk gates lineage emission: append a
	// SessionLineage only when the owning session_meta is read in THIS
	// parse pass. An incremental resume reconstructs the tracker from
	// prefetch (owner already latched) yet reads no session_meta itself,
	// so it must NOT re-emit — the guarded SQL would fire every poll.
	sessionMetaObservedThisChunk := false
	// ownerOriginator / ownerSource carry the OWNING session_meta's
	// client-identity fields for Part E surface attribution — captured
	// alongside sessionMetaObservedThisChunk (same owner-only gate) and
	// resolved into a models.SessionSurface at the same emission site
	// as the lineage marker below.
	var ownerOriginator, ownerSource string
	// ownerCLIVersion carries the OWNING session_meta's cli_version for
	// Issue 2 tool-version capture — same owner-only gate as ownerSource.
	var ownerCLIVersion string

	// rootCache is declared here (rather than after the resume block
	// below) so the resume path can prime ctxState.GitRemote from the
	// same cache the live parse's per-event resolveProjectRoot /
	// resolveProjectRemote calls read from.
	rootCache := map[string]projectGitInfo{}

	// resumed carries the dedup state rebuilt from the pre-offset bytes
	// (token-total baseline + already-emitted system-prompt hashes). It
	// is applied to the seen* maps further down, where they're declared.
	var resumed resumePrefix
	lineOffset := 0
	if fromOffset > 0 {
		if pre, ok := prefetchSessionContext(f, fromOffset); ok {
			ctxState = mergeSessionContext(sessionContext{}, pre.ctx)
			hasRealSessionID = ctxState.SessionID != ""
			lineOffset = pre.lineCount
			forkTrack = pre.track
			resumed = pre
			// GitRemote is derived (not JSONL data), so
			// mergeSessionContext never populates it — resolve it here
			// from the prefetched Cwd, same as applyContext does for
			// the live parse below.
			if ctxState.Cwd != "" {
				a.resolveProjectRoot(ctxState.Cwd, rootCache)
				ctxState.GitRemote = a.resolveProjectRemote(ctxState.Cwd, rootCache)
			}
		}
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("codex.ParseSessionFile: seek: %w", err)
		}
	}
	if !hasRealSessionID {
		ctxState.SessionID = fallbackSessionID
	}
	// Codex Fast mode (service_tier:"priority") is never recorded in the
	// rollout JSONL, so read the operator's requested tier once from the
	// owning ~/.codex/config.toml. Sticky for the whole file; surfaces as
	// the per-message ServiceTier pill (via withEffort) and drives
	// TokenEvent.Fast (priority → fast → Pricing.FastMultiplier). Gated on
	// the readsServiceTier capability: the Open Interpreter variant never
	// opens its root's config.toml (see the field doc).
	if a.readsServiceTier {
		if tier := codexServiceTier(path); tier != "" {
			ctxState.ServiceTier = tier
		}
	}
	pending := map[string]int{} // call_id → res.ToolEvents index
	// patchInvocations is the SECONDARY index that lets a patch_apply_end
	// find its own invocation row when the call_id join cannot: modern
	// Codex runs apply_patch from inside an `exec` custom_tool_call, and
	// the executor stamps its own `exec-<uuid>` id while the response_item
	// carries `call_<hash>` — different namespaces, so pending[] misses by
	// construction. Without this, BOTH rows survive and the same patch is
	// counted twice (measured over 333 July rollouts: 838 invocation rows
	// vs 2,445 executor rows, with 57 rollouts carrying both).
	// Keyed by turn, ordered oldest-first — see claimPatchInvocation.
	patchInvocations := map[string][]patchInvocation{}
	lastInputByID := map[string]int64{}    // legacy gross-cumulative input tracker; preserved for the unused branch in case a fixture still drives it (see lastNetInputByID below for the net-cumulative variant the active math uses)
	lastNetInputByID := map[string]int64{} // tracks (gross_input - cached_input) cumulative per session so the per-turn delta we store excludes the cached portion (Anthropic-shape convention, see cost engine TokenBundle docstring)
	turnModels := map[string]string{}
	pendingToolModels := map[string][]int{}
	pendingTokenModels := map[string][]int{}
	pendingUserPromptIdx := -1
	pendingTurnlessTokenIdxs := []int{}
	// agentMessages caches the latest assistant preamble per turn so
	// every tool_call / exec_command_end / web_search_end inside that
	// turn picks it up as PrecedingReasoning. Keyed by turn_id; entries
	// stay around for the whole parse since one turn's preamble is
	// only valid for that turn's tool events.
	//
	// This is ALSO the sole destination of response_item.reasoning
	// summary text (B3, 2026-07-31): reasoning is never its own action
	// row, it only enriches the turn's successor events here. Semantics
	// are per-turn FAN-OUT + concatenate (every tool event of the turn
	// carries the same accumulated preamble) — deliberately unlike the
	// consumed-once grok default, because Codex's turn boundary
	// (turn_id) is explicit in the log and already scopes it.
	agentMessages := map[string]string{}
	// seenSystemPrompts dedups ActionSystemPrompt emissions across the
	// parse. Keyed by content hash (shortHash of the prompt body).
	// Codex repeats base_instructions in every session_meta and
	// developer_instructions in nearly every turn_context — without
	// dedup we'd emit 9KB+ rows N times per session.
	seenSystemPrompts := map[string]bool{}
	// seenModernTotal tracks the most recent total_token_usage per
	// session for the modern event_msg/token_count path. Codex
	// re-emits identical token_count records (same last_token_usage
	// AND total_token_usage) periodically — observed in real corpora
	// at lines 134/129 and 171/165 of one inspected rollout (user
	// reported 2026-05-01). The total is monotonic, so any new event
	// whose total matches a previously seen total is a re-emission;
	// summing both inflates session-wide token counts. Per-session map
	// keyed by SessionID; tokenUsage is a value-type struct so == is
	// correct.
	seenModernTotal := map[string]tokenUsage{}
	// Cross-parse seeding (incremental resume only). Both seen* maps
	// above are per-parse, so before this seeding a resumed parse
	// started with an EMPTY dedup state: a token_count Codex re-emits
	// 2-3s later (identical last_token_usage AND total_token_usage)
	// that happened to straddle the resume boundary re-emitted as a
	// fresh row, and the same base/developer instructions body
	// re-emitted an ActionSystemPrompt row. Neither is caught
	// downstream: SourceEventID (and, for token rows, MessageID) embeds
	// the LINE NUMBER, which differs between the original and the
	// re-emission, so store.InsertTokenEvents' UNIQUE(source_file,
	// source_event_id) upsert and its (tool, session_id, message_id)
	// tuple-dedup sweep both miss it. prefetchSessionContext replays the
	// pre-offset lines in STATE-ONLY mode (no emission) and hands back
	// exactly the state the same bytes would have produced in a
	// fromOffset==0 parse, so the duplicate suppresses identically.
	//
	// Rescan-safe by construction: this seeds state only, never
	// SourceEventIDs, so `observer scan --force` (fromOffset==0, no
	// prefetch) still produces byte-identical ids for every historical
	// row and keeps upserting onto them.
	if resumed.haveTotal {
		seenModernTotal[ctxState.SessionID] = resumed.modernTotal
	}
	for hash := range resumed.systemPrompts {
		seenSystemPrompts[hash] = true
	}
	// runningWebSearchCount tallies event_msg/web_search_end records
	// seen since the last NON-deduped token_count emission. Flushed
	// onto TokenEvent.WebSearchRequests when the next token_count row
	// is appended (so cost engine can apply OpenAI's per-request fee
	// via Pricing.WebSearchPerRequest). Reset to 0 after each
	// flushed emission. Cross-turn behavior: counts accumulate
	// across turns whose token_count was dedup-skipped, then attach
	// to the next surviving emission — under-counting is impossible,
	// double-counting is prevented by the reset. Live-watch
	// limitation: on incremental resume (fromOffset > 0) the
	// counter is fresh, so web_searches whose paired token_count is
	// in a later poll chunk will land with WebSearchRequests=0;
	// `observer backfill --codex-rescan` re-walks from offset 0 and
	// re-attributes them correctly.
	runningWebSearchCount := int64(0)

	applyContext := func(sc sessionContext) {
		// Session ownership is file-local: once a rollout establishes
		// the owning SessionID, later replayed context (notably the
		// parent session_meta in forked child rollouts) must NOT
		// overwrite it. Other fields still refresh normally.
		if !hasRealSessionID {
			if sc.ID != "" {
				ctxState.SessionID = sc.ID
				hasRealSessionID = true
			}
			if !hasRealSessionID && sc.SessionID != "" {
				ctxState.SessionID = sc.SessionID
				hasRealSessionID = true
			}
		}
		if sc.TurnID != "" {
			ctxState.TurnID = sc.TurnID
		}
		if sc.Model != "" {
			ctxState.Model = sc.Model
		}
		if sc.Cwd != "" {
			ctxState.Cwd = sc.Cwd
			// GitRemote is derived from Cwd (git.Resolve), not carried
			// on the JSONL envelope like GitBranch — re-resolve (cache
			// hit on repeat cwds) whenever cwd actually changes.
			a.resolveProjectRoot(ctxState.Cwd, rootCache)
			ctxState.GitRemote = a.resolveProjectRemote(ctxState.Cwd, rootCache)
		}
		if sc.GitBranch != "" {
			ctxState.GitBranch = sc.GitBranch
		}
		// EffortLevel is sticky: a later turn_context that omits
		// collaboration_mode (or sends null reasoning_effort) must NOT
		// wipe a previously-established value. Same precedence rule as
		// the other context fields above.
		if sc.EffortLevel != "" {
			ctxState.EffortLevel = sc.EffortLevel
		}
		// v1.4.52 codex 0.130+ turn_context fields. Sticky for the
		// string + int fields (zero-value means "not in this update"
		// so we don't wipe). RealtimeActive is handled directly in
		// the turn_context handler instead of here, because
		// applyContext is also called from task_started / exec_started
		// with a fresh sessionContext{TurnID:…} that would wrongly
		// reset RealtimeActive to false on every action.
		if sc.CollaborationMode != "" {
			ctxState.CollaborationMode = sc.CollaborationMode
		}
		if sc.Personality != "" {
			ctxState.Personality = sc.Personality
		}
		if sc.TruncationMode != "" {
			ctxState.TruncationMode = sc.TruncationMode
		}
		if sc.TruncationLimit > 0 {
			ctxState.TruncationLimit = sc.TruncationLimit
		}
		if ctxState.TurnID == "" || ctxState.Model == "" {
			return
		}
		turnModels[ctxState.TurnID] = ctxState.Model
		for _, idx := range pendingToolModels[ctxState.TurnID] {
			if res.ToolEvents[idx].Model == "" {
				res.ToolEvents[idx].Model = ctxState.Model
			}
		}
		delete(pendingToolModels, ctxState.TurnID)
		for _, idx := range pendingTokenModels[ctxState.TurnID] {
			if res.TokenEvents[idx].Model == "" {
				res.TokenEvents[idx].Model = ctxState.Model
			}
		}
		delete(pendingTokenModels, ctxState.TurnID)
		if len(pendingTurnlessTokenIdxs) > 0 {
			for _, idx := range pendingTurnlessTokenIdxs {
				// MessageID is per-event for codex (v1.7.24+ contract)
				// and was set at emit time; only the turn association
				// and (lazy-resolved) model need backfilling here.
				if res.TokenEvents[idx].TurnID == "" {
					res.TokenEvents[idx].TurnID = ctxState.TurnID
				}
				// Defensive: pre-v1.7.24 emitters set MessageID="" on
				// turnless events expecting the legacy turnID-as-message
				// backfill. Keep filling that case for any caller that
				// still emits without MessageID.
				if res.TokenEvents[idx].MessageID == "" {
					res.TokenEvents[idx].MessageID = ctxState.TurnID
				}
				if res.TokenEvents[idx].Model == "" {
					res.TokenEvents[idx].Model = ctxState.Model
				}
			}
			pendingTurnlessTokenIdxs = nil
		}
		if pendingUserPromptIdx >= 0 && pendingUserPromptIdx < len(res.ToolEvents) {
			if res.ToolEvents[pendingUserPromptIdx].ActionType == models.ActionUserPrompt {
				res.ToolEvents[pendingUserPromptIdx].MessageID = "user:" + ctxState.TurnID
				if res.ToolEvents[pendingUserPromptIdx].Model == "" {
					res.ToolEvents[pendingUserPromptIdx].Model = ctxState.Model
				}
			}
			pendingUserPromptIdx = -1
		}
	}

	assistantTurnID := func(explicitTurnID string) string {
		return firstNonEmpty(explicitTurnID, ctxState.TurnID)
	}

	userMessageID := func(message string, lineNum int) string {
		if turnID := assistantTurnID(""); turnID != "" {
			return "user:" + turnID
		}
		return fmt.Sprintf("user:%s:L%d:%s", filepath.Base(path), lineNum, shortHash(strings.TrimSpace(message)))
	}

	modelForTurn := func(turnID string) string {
		return firstNonEmpty(turnModels[turnID], ctxState.Model)
	}

	// withEffort stamps the current ctxState metadata fields onto an
	// outgoing ToolEvent's Metadata when the parser knows one (and
	// the event doesn't already carry one — defensive against future
	// builders that populate Metadata explicitly). Called at every
	// res.ToolEvents append site so per-turn attribution rides every
	// row that turn produced. Migration 017 added the column;
	// v1.4.52 extended it with codex 0.130+ turn_context fields.
	withEffort := func(ev models.ToolEvent) models.ToolEvent {
		hasMeta := ctxState.EffortLevel != "" || ctxState.CollaborationMode != "" ||
			ctxState.Personality != "" || ctxState.RealtimeActive ||
			ctxState.TruncationMode != "" || ctxState.TruncationLimit > 0 ||
			ctxState.ServiceTier != ""
		if !hasMeta {
			return ev
		}
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		if ev.Metadata.EffortLevel == "" && ctxState.EffortLevel != "" {
			ev.Metadata.EffortLevel = ctxState.EffortLevel
		}
		if ev.Metadata.CollaborationMode == "" && ctxState.CollaborationMode != "" {
			ev.Metadata.CollaborationMode = ctxState.CollaborationMode
		}
		if ev.Metadata.Personality == "" && ctxState.Personality != "" {
			ev.Metadata.Personality = ctxState.Personality
		}
		if !ev.Metadata.RealtimeActive && ctxState.RealtimeActive {
			ev.Metadata.RealtimeActive = true
		}
		if ev.Metadata.TruncationMode == "" && ctxState.TruncationMode != "" {
			ev.Metadata.TruncationMode = ctxState.TruncationMode
		}
		if ev.Metadata.TruncationLimit == 0 && ctxState.TruncationLimit > 0 {
			ev.Metadata.TruncationLimit = ctxState.TruncationLimit
		}
		// ServiceTier is the operator's requested OpenAI processing tier
		// ("priority" = Codex Fast mode). Read once per file from
		// ~/.codex/config.toml (the rollout JSONL never carries the value);
		// surfaced as a per-message pill, mirroring claudecode's
		// usage.service_tier capture.
		if ev.Metadata.ServiceTier == "" && ctxState.ServiceTier != "" {
			ev.Metadata.ServiceTier = ctxState.ServiceTier
		}
		return ev
	}

	reader := bufio.NewReaderSize(f, 64*1024)

	var bytesRead int64 = fromOffset
	// Seed from prefetch so :L<linenum>: SourceEventIDs are absolute-
	// file-line-number (stable across re-parses), not chunk-relative.
	lineNum := lineOffset
	for {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, ctx.Err()
		}
		lineStr, consumed, oversized, readErr := readRecord(reader, maxRecordBytes)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, fmt.Errorf("codex.ParseSessionFile: read %s: %w", path, readErr)
		}
		if consumed == 0 {
			break // clean end of stream
		}
		// UNIFIED TRAILING-RECORD DEFERRAL RULE. readRecord returns
		// io.EOF exactly when the record it just read carried NO '\n'
		// terminator: bufio.Reader.ReadSlice reports a nil error the
		// moment it locates the delimiter and io.EOF only when the stream
		// ends before one is found. So a non-zero-length record that
		// comes back with io.EOF is an unterminated final fragment — an
		// in-progress append codex has not finished writing. DEFER it
		// WHOLE: do not parse it, do not count its line (lineNum stays
		// put), and do not advance the byte cursor past its start
		// (res.NewOffset / bytesRead remain at the end of the last
		// terminated record). The next incremental pass re-reads it from
		// exactly here once the terminator lands. This one rule subsumes
		// all three at-EOF shapes that must never be committed early:
		//   - a malformed JSON fragment,
		//   - a SYNTACTICALLY VALID JSON record whose trailing newline is
		//     still pending (the corruption the adversarial review found —
		//     parsing it and committing the offset stranded the record for
		//     prefetch/governance),
		//   - an oversized record (its buffered bytes were drained to
		//     find the bound, but leaving the offset unmoved simply
		//     re-drains them next pass; the skip+warning fire only once
		//     the record is terminated).
		// A '\n'-terminated final record (readErr == nil) is complete and
		// ingests normally.
		if errors.Is(readErr, io.EOF) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("deferred unterminated trailing record at offset %d (%d bytes) pending terminator", bytesRead, consumed))
			break
		}
		nextOffset := bytesRead + consumed
		lineNum++

		if oversized {
			// A single record exceeded the memory-safety bound but IS
			// '\n'-terminated (the unterminated case was deferred above).
			// Skip it rather than aborting the whole file (issue #7):
			// advance the cursor past its bytes, still COUNT the line (the
			// L<line> in tk:<base>:L<line> source_event_ids must stay in
			// lockstep with ReplayedTokenLines), and CLEAR turn governance
			// exactly as a malformed envelope does below — fail-open,
			// since the skipped record could have been the live
			// task_started. Surfaced as a recoverable warning, once per
			// occurrence.
			forkTrack.observeTaskStarted(0, false)
			bytesRead = nextOffset
			if nextOffset > res.NewOffset {
				res.NewOffset = nextOffset
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: skipped oversized record: %d bytes exceeds %d-byte per-record bound", lineNum, consumed, maxRecordBytes))
			continue
		}

		raw := bytes.TrimRight(lineStr, "\r\n")

		if len(raw) == 0 {
			bytesRead = nextOffset
			if nextOffset > res.NewOffset {
				res.NewOffset = nextOffset
			}
			continue
		}
		var line rawLine
		if err := json.Unmarshal(raw, &line); err != nil {
			// A whole malformed envelope CLEARS turn governance: were
			// this line the live task_started, the token_counts that
			// follow must fail open as live rather than inherit the
			// prior (possibly replayed) turn's governance. Fails open —
			// the non-destructive direction. An in-progress trailing
			// append is NOT handled here: an unterminated final fragment
			// was already deferred by the io.EOF rule above (cursor left
			// at its start), so reaching this point means the record is
			// '\n'-terminated and genuinely corrupt — skip it with a
			// warning and advance past it.
			forkTrack.observeTaskStarted(0, false)
			bytesRead = nextOffset
			if nextOffset > res.NewOffset {
				res.NewOffset = nextOffset
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			continue
		}
		bytesRead = nextOffset
		res.NewOffset = nextOffset

		ts := parseTimestamp(line.Timestamp)
		payloadType := payloadType(line.Payload)

		switch line.Type {
		case "compacted":
			// Top-level type="compacted" event — emit one
			// ActionContextCompacted row carrying the message count and
			// byte estimate from replacement_history. The paired
			// event_msg/context_compacted (which has no payload) is a
			// marker for the same event; we no-op that to avoid
			// double-emission.
			var ce compactedEvent
			if err := json.Unmarshal(line.Payload, &ce); err != nil {
				continue
			}
			projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
			evt := a.buildCompactedEvent(path, ctxState, projectRoot, ts, ce, lineNum)
			if evt.Model == "" {
				if turnID := assistantTurnID(""); turnID != "" {
					evt.Model = modelForTurn(turnID)
					if evt.Model == "" {
						pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
					}
				}
			}
			res.ToolEvents = append(res.ToolEvents, withEffort(evt))

		case "session_meta":
			var meta sessionMetaPayload
			if err := json.Unmarshal(line.Payload, &meta); err == nil {
				// Only the OWNING (first) session_meta triggers lineage
				// emission — a replayed parent meta read mid-chunk on a
				// resume must not re-emit the owner's lineage row. The
				// same owner-only gate applies to originator/source: a
				// replayed parent's session_meta must not overwrite the
				// child rollout's own surface attribution.
				if !forkTrack.ownerLatched {
					sessionMetaObservedThisChunk = true
					ownerOriginator = meta.Originator
					ownerSource = meta.Source
					ownerCLIVersion = meta.CLIVersion
				}
				created, have := sessionMetaCreationSec(meta, line.Timestamp)
				forkTrack.observeSessionMeta(
					firstNonEmpty(meta.ID, meta.SessionID),
					meta.ForkedFromID, meta.ParentThreadID, meta.ThreadSource,
					created, have,
				)
				applyContext(meta.sessionContext)
				if body := strings.TrimSpace(meta.BaseInstructions.Text); body != "" {
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					if evt, ok := a.systemPromptEvent(path, "base", body, ts, ctxState, projectRoot, lineNum, seenSystemPrompts); ok {
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
				}
			}

		case "session_configured", "session_start", "turn_context":
			var meta turnContextPayload
			if err := json.Unmarshal(line.Payload, &meta); err == nil {
				// Lift the nested fields onto the context shape
				// applyContext consumes — they live on
				// collaboration_mode.{mode,settings.reasoning_effort},
				// personality, realtime_active, truncation_policy.*,
				// not on the flat envelope, so the embedded
				// sessionContext can't pick them up directly. v1.4.52
				// added the four non-effort fields after the codex
				// 0.130+ turn_context schema introduced them.
				sc := meta.sessionContext
				if effort := meta.EffortFromPayload(); effort != "" {
					sc.EffortLevel = effort
				}
				if mode := meta.CollaborationMode.Mode; mode != "" {
					sc.CollaborationMode = mode
				}
				if persona := meta.Personality; persona != "" {
					sc.Personality = persona
				}
				if tmode := meta.TruncationPolicy.Mode; tmode != "" {
					sc.TruncationMode = tmode
				}
				if tlimit := meta.TruncationPolicy.Limit; tlimit > 0 {
					sc.TruncationLimit = tlimit
				}
				applyContext(sc)
				// RealtimeActive: bool — can't distinguish absent vs
				// explicit false at JSON-decode time. Always write
				// here in the turn_context handler so each turn_context
				// authoritatively sets the value. Done OUTSIDE
				// applyContext because applyContext is called from
				// other handlers (task_started, exec_started) with a
				// zero-value sessionContext that would wrongly reset
				// it to false on every action.
				ctxState.RealtimeActive = meta.RealtimeActive
				if body := strings.TrimSpace(meta.DeveloperInstructions); body != "" {
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					if evt, ok := a.systemPromptEvent(path, "developer", body, ts, ctxState, projectRoot, lineNum, seenSystemPrompts); ok {
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
				}
			}

		case "event_msg":
			switch payloadType {
			case "task_started":
				var started taskStarted
				if err := json.Unmarshal(line.Payload, &started); err == nil {
					// Governs the token_count events that follow, for the
					// fork/subagent replay discriminator (started_at).
					forkTrack.observeTaskStarted(started.StartedAt, started.StartedAt != 0)
					if started.TurnID != "" {
						applyContext(sessionContext{TurnID: started.TurnID})
					}
				} else {
					// A malformed task_started CLEARS governance so the
					// token_counts that follow fail open as live rather
					// than inheriting the previous (possibly replayed)
					// turn's governance — which would misclassify live
					// rows as replayed and drop them at emit. Only
					// task_started governs; turn_context / other per-turn
					// records must NOT clear it (the real record order is
					// task_started → turn_context → user_message →
					// token_counts, so clearing on turn_context would
					// disable replay detection entirely).
					forkTrack.observeTaskStarted(0, false)
				}
			case "agent_message":
				var am agentMessage
				if err := json.Unmarshal(line.Payload, &am); err == nil {
					turnID := firstNonEmpty(am.TurnID, ctxState.TurnID)
					msg := strings.TrimSpace(am.Message)
					if turnID != "" && msg != "" {
						agentMessages[turnID] = msg
					}
					if msg != "" {
						projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
						sess := ctxState
						sess.TurnID = turnID
						evt := a.buildAgentMessageEvent(path, sess, projectRoot, ts, lineNum, msg)
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
				}
			case "item_completed":
				var ic itemCompletedPayload
				if err := json.Unmarshal(line.Payload, &ic); err == nil && ic.Item.Type == "AgentMessage" {
					turnID := firstNonEmpty(ic.TurnID, ctxState.TurnID)
					msg := strings.TrimSpace(concatMessageContent(ic.Item.Content))
					if turnID != "" && msg != "" {
						agentMessages[turnID] = msg
					}
					if msg != "" {
						projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
						sess := ctxState
						sess.TurnID = turnID
						evt := a.buildAgentMessageEvent(path, sess, projectRoot, ts, lineNum, msg)
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
				}
			case "user_message":
				var um userMessage
				if err := json.Unmarshal(line.Payload, &um); err == nil {
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					evt := a.buildUserPromptEvent(path, ctxState, projectRoot, ts, lineNum, um.Message)
					evt.MessageID = userMessageID(um.Message, lineNum)
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					if ctxState.TurnID == "" {
						pendingUserPromptIdx = len(res.ToolEvents) - 1
					}
				}
			case "exec_command_end":
				var ex execCommandEnd
				if err := json.Unmarshal(line.Payload, &ex); err == nil {
					if ex.TurnID != "" {
						applyContext(sessionContext{TurnID: ex.TurnID})
					}
					projectRoot := a.resolveProjectRoot(firstNonEmpty(ex.Cwd, ctxState.Cwd), rootCache)
					preceding := agentMessages[firstNonEmpty(ex.TurnID, ctxState.TurnID)]
					if idx, ok := pending[ex.CallID]; ok && idx < len(res.ToolEvents) {
						mergeExecIntoPending(&res.ToolEvents[idx], a, ex, ts)
						delete(pending, ex.CallID)
					} else {
						evt := a.buildExecCommandEvent(path, ctxState, projectRoot, ts, ex, preceding)
						if evt.Model == "" {
							if turnID := assistantTurnID(ex.TurnID); turnID != "" {
								evt.Model = modelForTurn(turnID)
								if evt.Model == "" {
									pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
								}
							}
						}
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
				}
			case "web_search_end":
				var ws webSearchEnd
				if err := json.Unmarshal(line.Payload, &ws); err == nil {
					if ws.TurnID != "" {
						applyContext(sessionContext{TurnID: ws.TurnID})
					}
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					preceding := agentMessages[firstNonEmpty(ws.TurnID, ctxState.TurnID)]
					if idx, ok := pending[ws.CallID]; ok && idx < len(res.ToolEvents) {
						mergeWebSearchIntoPending(&res.ToolEvents[idx], ws)
						delete(pending, ws.CallID)
					} else {
						evt := a.buildWebSearchEvent(path, ctxState, projectRoot, ts, ws, lineNum, preceding)
						if evt.Model == "" {
							if turnID := assistantTurnID(ws.TurnID); turnID != "" {
								evt.Model = modelForTurn(turnID)
								if evt.Model == "" {
									pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
								}
							}
						}
						res.ToolEvents = append(res.ToolEvents, withEffort(evt))
					}
					// Count for cost-engine billing via the next non-dedup
					// token_count emission's TokenEvent.WebSearchRequests
					// (see runningWebSearchCount declaration). Increment
					// whether the row was emitted standalone or merged
					// into a pending response_item/web_search_call — both
					// paths represent one billable Anthropic/OpenAI
					// server-side web_search call.
					runningWebSearchCount++
				}
			case "context_compacted":
				// Marker-only event paired with a top-level type="compacted"
				// in the same line range. No-op here — the top-level event
				// carries the data and emits the row.
			case "dynamic_tool_call_request":
				var dr dynamicToolCallRequest
				if err := json.Unmarshal(line.Payload, &dr); err != nil {
					continue
				}
				callID := firstNonEmpty(dr.callID(), fmt.Sprintf("%s:L%d", filepath.Base(path), lineNum))
				if dr.turnID() != "" {
					applyContext(sessionContext{TurnID: dr.turnID()})
				}
				if _, dupe := pending[callID]; dupe {
					continue
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[ctxState.TurnID]
				evt := a.buildToolEvent(path, callID, ctxState, projectRoot, ts, dr.Tool, dr.Arguments, preceding)
				evt.RawToolName = "dynamic_tool_call_request"
				if evt.Model == "" {
					if turnID := assistantTurnID(""); turnID != "" {
						evt.Model = modelForTurn(turnID)
						if evt.Model == "" {
							pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
						}
					}
				}
				pending[callID] = len(res.ToolEvents)
				res.ToolEvents = append(res.ToolEvents, withEffort(evt))
			case "dynamic_tool_call_response":
				var dp dynamicToolCallResponse
				if err := json.Unmarshal(line.Payload, &dp); err != nil {
					continue
				}
				idx, ok := pending[dp.callID()]
				if !ok || idx >= len(res.ToolEvents) {
					continue
				}
				row := &res.ToolEvents[idx]
				body := dynamicToolCallBody(dp.ContentItems)
				row.ToolOutput = a.scrubber.String(body)
				row.Success = dp.Success
				if !dp.Success {
					row.ErrorMessage = truncate(firstNonEmpty(dp.Error, body), 2048)
				}
				row.DurationMs = dp.Duration.Secs*1000 + dp.Duration.Nanos/1_000_000
				row.RawToolName = "dynamic_tool_call_response"
				delete(pending, dp.callID())
			case "view_image_tool_call":
				var vi viewImageToolCall
				if err := json.Unmarshal(line.Payload, &vi); err != nil {
					continue
				}
				if vi.TurnID != "" {
					applyContext(sessionContext{TurnID: vi.TurnID})
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[firstNonEmpty(vi.TurnID, ctxState.TurnID)]
				targetPath := vi.Path
				if targetPath != "" && projectRoot != "" {
					targetPath = git.RelativePath(projectRoot, targetPath)
				}
				if idx, ok := pending[vi.CallID]; ok && idx < len(res.ToolEvents) {
					row := &res.ToolEvents[idx]
					row.ActionType = models.ActionReadFile
					if targetPath != "" {
						row.Target = truncate(targetPath, 200)
					}
					row.RawToolName = "view_image_tool_call"
					delete(pending, vi.CallID)
				} else {
					evt := models.ToolEvent{
						SourceFile:         path,
						SourceEventID:      firstNonEmpty(vi.CallID, fmt.Sprintf("view_image:%s:L%d", filepath.Base(path), lineNum)),
						SessionID:          ctxState.SessionID,
						ProjectRoot:        projectRoot,
						Timestamp:          ts,
						GitBranch:          ctxState.GitBranch,
						GitRemote:          ctxState.GitRemote,
						Model:              ctxState.Model,
						Tool:               models.ToolCodex,
						ActionType:         models.ActionReadFile,
						Target:             truncate(targetPath, 200),
						Success:            true,
						PrecedingReasoning: truncate(preceding, 500),
						RawToolName:        "view_image_tool_call",
						MessageID:          firstNonEmpty(vi.TurnID, ctxState.TurnID),
					}
					if evt.Model == "" {
						if turnID := assistantTurnID(vi.TurnID); turnID != "" {
							evt.Model = modelForTurn(turnID)
							if evt.Model == "" {
								pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
							}
						}
					}
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
				}
			case "turn_aborted":
				var ta turnAborted
				if err := json.Unmarshal(line.Payload, &ta); err != nil {
					continue
				}
				if ta.TurnID != "" {
					applyContext(sessionContext{TurnID: ta.TurnID})
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				evt := a.buildTurnAbortedEvent(path, ctxState, projectRoot, ts, ta, lineNum)
				if evt.Model == "" {
					if turnID := assistantTurnID(ta.TurnID); turnID != "" {
						evt.Model = modelForTurn(turnID)
						if evt.Model == "" {
							pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
						}
					}
				}
				res.ToolEvents = append(res.ToolEvents, withEffort(evt))
			case "mcp_tool_call_end":
				var mc mcpToolCallEnd
				if err := json.Unmarshal(line.Payload, &mc); err != nil {
					continue
				}
				if mc.TurnID != "" {
					applyContext(sessionContext{TurnID: mc.TurnID})
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[firstNonEmpty(mc.TurnID, ctxState.TurnID)]
				if idx, ok := pending[mc.CallID]; ok && idx < len(res.ToolEvents) {
					mergeMCPCallEndIntoPending(&res.ToolEvents[idx], a, mc)
					delete(pending, mc.CallID)
				} else {
					evt := a.buildMCPCallEndStandaloneEvent(path, ctxState, projectRoot, ts, mc, lineNum, preceding)
					if evt.Model == "" {
						if turnID := assistantTurnID(mc.TurnID); turnID != "" {
							evt.Model = modelForTurn(turnID)
							if evt.Model == "" {
								pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
							}
						}
					}
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
				}
			case "error":
				var ce codexError
				if err := json.Unmarshal(line.Payload, &ce); err != nil {
					continue
				}
				if ce.Message == "" && ce.CodexErrorInfo == "" {
					continue
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				evt := a.buildCodexErrorEvent(path, ctxState, projectRoot, ts, ce, lineNum)
				if evt.Model == "" {
					if turnID := assistantTurnID(""); turnID != "" {
						evt.Model = modelForTurn(turnID)
						if evt.Model == "" {
							pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
						}
					}
				}
				res.ToolEvents = append(res.ToolEvents, withEffort(evt))
			case "patch_apply_end":
				var pa patchApplyEnd
				if err := json.Unmarshal(line.Payload, &pa); err != nil {
					continue
				}
				pa.ChangesRaw = patchChangesRaw(line.Payload)
				if pa.TurnID != "" {
					applyContext(sessionContext{TurnID: pa.TurnID})
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[firstNonEmpty(pa.TurnID, ctxState.TurnID)]
				turnKey := firstNonEmpty(pa.TurnID, ctxState.TurnID)
				claimedIdx, claimed := -1, false
				if idx, ok := pending[pa.CallID]; ok && idx < len(res.ToolEvents) {
					claimedIdx, claimed = idx, true
					delete(pending, pa.CallID)
					// The id join won, but this row may ALSO be sitting in
					// the fallback queue. Drop it there or a later
					// patch_apply_end could claim an already-merged row.
					dropPatchInvocation(patchInvocations, idx)
				} else if cand, ok := claimPatchInvocation(patchInvocations, turnKey, changesFileSet(pa.Changes)); ok && cand.idx < len(res.ToolEvents) {
					// The call_id join missed (the exec-uuid namespace).
					// Merging into the invocation row instead of emitting a
					// second one is what keeps ONE row per patch, and with
					// it one authored-byte count.
					claimedIdx, claimed = cand.idx, true
					// Symmetric to dropPatchInvocation above: this row is
					// no longer claimable by ANY route, so retire its
					// pending entry too. Without this, a later
					// patch_apply_end that DOES carry the call_hash would
					// merge the same row a second time.
					if cand.callID != "" {
						delete(pending, cand.callID)
					}
				}
				if claimed {
					mergePatchApplyIntoPending(&res.ToolEvents[claimedIdx], a, pa, projectRoot)
				} else {
					evt := a.buildPatchApplyStandaloneEvent(path, ctxState, projectRoot, ts, pa, lineNum, preceding)
					if evt.Model == "" {
						if turnID := assistantTurnID(pa.TurnID); turnID != "" {
							evt.Model = modelForTurn(turnID)
							if evt.Model == "" {
								pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
							}
						}
					}
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
				}
			case "task_complete":
				var done taskComplete
				if err := json.Unmarshal(line.Payload, &done); err == nil {
					if done.TurnID != "" {
						applyContext(sessionContext{TurnID: done.TurnID})
					}
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					evt := a.buildTaskCompleteEvent(path, ctxState, projectRoot, ts, done, lineNum)
					if evt.Model == "" {
						if turnID := assistantTurnID(done.TurnID); turnID != "" {
							evt.Model = modelForTurn(turnID)
							if evt.Model == "" {
								pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
							}
						}
					}
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
				}
			case "token_count":
				// Rate-limit snapshot is independent of token-usage: the
				// startup token_count fires with `info: null` but already
				// carries the per-window rate_limits envelope. Emit one
				// ActionRateLimit row per token_count line that carries
				// rate_limits, reusing the schema cowork introduced
				// (RateLimitStatus / Type / ResetsAt / OverageStatus).
				// Dedup is handled at store.Ingest via the stable
				// source_event_id below — re-parses are idempotent.
				if rl := parseModernRateLimits(line.Payload); rl != nil && rl.PlanType != "" {
					projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
					evt := buildCodexRateLimitEvent(path, ctxState, projectRoot, ts, rl, lineNum)
					res.ToolEvents = append(res.ToolEvents, withEffort(evt))
				}
				tk, total, ok := parseModernTokenCount(line.Payload)
				if !ok {
					continue
				}
				// Dedup re-emitted identical token_count events. Codex's
				// runtime sometimes writes the same event_msg/token_count
				// twice (observed at lines 134/129 and 171/165 of an
				// inspected rollout, ~2-3s apart, identical
				// last_token_usage AND total_token_usage). Total is
				// monotonic across a session — a non-advancing total
				// means re-emission, NOT a new model call. Skip
				// emission entirely so per-session sums match Codex's
				// own final cumulative figure.
				if total != (tokenUsage{}) {
					if prev, seen := seenModernTotal[ctxState.SessionID]; seen && total == prev {
						// A replayed duplicate-total token_count must
						// consume the running web-search tally exactly as
						// the replay-skip branch below does — this early
						// continue precedes it, so without the reset a
						// replayed web_search_end would leak onto the
						// first LIVE row ($0.01 phantom per request).
						if forkTrack.isReplayedTokenCount() {
							runningWebSearchCount = 0
						}
						continue
					}
					seenModernTotal[ctxState.SessionID] = total
				}
				// Fork/subagent REPLAY: this token_count is replayed
				// parent history (governing task_started predates the
				// owning session's creation). seenModernTotal is now
				// updated above, so the first LIVE event's dedup baseline
				// is the replayed cumulative total — but the replayed
				// event itself must NOT emit a token_usage row (it would
				// double-count the parent's input). Fail-open for
				// unmarked files.
				if forkTrack.isReplayedTokenCount() {
					// Consume the running web-search tally exactly as an
					// emitted row would have. Replayed web_search_end
					// events incremented it during the replay burst; if we
					// skipped without resetting, the first LIVE row would
					// absorb every replayed search and bill each at the
					// per-request fee ($0.01) — phantom cost. Attribute
					// replayed searches to nothing.
					runningWebSearchCount = 0
					continue
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				turnID := assistantTurnID("")
				// OpenAI / Codex `input_tokens` is the TOTAL prompt
				// count INCLUDING the cached portion; `cached_input_
				// tokens` is a subset of it. The cost engine treats
				// TokenBundle.Input as NET non-cached input (Anthropic
				// shape), so we net here at adapter-emit time to keep
				// the pricing math correct. Without this subtraction,
				// the cached portion gets billed at BOTH the full input
				// rate (as part of Input) AND the discounted cache_read
				// rate (as CacheRead) — observed ~3.4× over-billing on
				// short cached sessions (cost-engine audit 2026-05-24).
				netInput := tk.InputTokens - tk.Cached
				if netInput < 0 {
					netInput = 0
				}
				// OpenAI / Codex `output_tokens` is the GROSS response-
				// token count and ALREADY CONTAINS `reasoning_output_
				// tokens` (reasoning ⊂ output — verified 2026-07-09 on
				// live gpt-5.6 traffic: six token_count events all
				// satisfy input+output==total exactly, and OpenAI docs
				// concur). The cost engine bills TokenBundle.Reasoning
				// ADDITIVELY at the output rate ON TOP of Output
				// (cost.ComputeBreakdown), so TokenBundle.Output must be
				// the NON-reasoning response-token count. We net the
				// reasoning subset out here at adapter-emit time; without
				// it every codex reasoning token is billed twice.
				netOutput := tk.OutputTokens - tk.Reasoning
				if netOutput < 0 {
					netOutput = 0
				}
				// v1.7.24+ (migration 032): codex emits one token_count
				// event per model inference (last_token_usage is the
				// per-call delta, NOT cumulative). MessageID is set to
				// the per-event identifier so each inference becomes its
				// own row, matching claudecode's per-API-call MessageID
				// semantic. TurnID groups them back to the user-turn
				// for the dashboard's default rollup view. Pre-v1.7.24
				// rows have turn_id NULL; the dashboard's COALESCE
				// fallback (turn_id → message_id → source_event_id)
				// keeps them rendering correctly.
				perEventID := fmt.Sprintf("tk:%s:L%d", filepath.Base(path), lineNum)
				evt := models.TokenEvent{
					SourceFile:        path,
					SourceEventID:     perEventID,
					SessionID:         ctxState.SessionID,
					ProjectRoot:       projectRoot,
					GitBranch:         ctxState.GitBranch,
					GitRemote:         ctxState.GitRemote,
					Timestamp:         ts,
					Tool:              models.ToolCodex,
					Model:             modelForTurn(turnID),
					InputTokens:       netInput,
					OutputTokens:      netOutput,
					CacheReadTokens:   tk.Cached,
					ReasoningTokens:   tk.Reasoning,
					WebSearchRequests: runningWebSearchCount,
					Source:            models.TokenSourceJSONL,
					Reliability:       models.ReliabilityApproximate,
					MessageID:         perEventID,
					TurnID:            turnID,
					// Codex Fast mode: service_tier:"priority" (read from
					// config.toml) bills at Pricing.FastMultiplier (gpt-5.5
					// 2.5×, gpt-5.4 2×). This is the *requested* tier — the
					// proxy path (api_turns) captures the authoritative
					// served tier from the OpenAI response.
					Fast: ctxState.ServiceTier == "priority",
				}
				runningWebSearchCount = 0
				res.TokenEvents = append(res.TokenEvents, evt)
				// CACHETRACK §15.3 (was: §14.3 scaffold-only). Codex
				// Tier-2 emits CacheTurnObservation under
				// ImplicitCache=true so the engine dispatches to the
				// reduced attribution path
				// (cachetrack.attributeImplicit). Provider exposes
				// cached_input_tokens only (a single scalar) — no
				// cache_control markers, no cache_creation count;
				// the implicit-cache path consumes the scalar via
				// Usage.CacheReadTokens. BlockHashes is intentionally
				// EMPTY (the engine ignores it on the implicit path
				// — it skips the chain push entirely). Idempotency:
				// SourceFile + SourceEventID match the TokenEvent's
				// perEventID, so a re-parse of the same JSONL
				// produces a byte-identical CacheTurnObservation and
				// the cross-tier CacheEventExistsForMessage dedup
				// gate at store.Ingest catches replays.
				if evt.SessionID != "" && evt.Model != "" {
					res.CacheObservations = append(res.CacheObservations, models.CacheTurnObservation{
						SourceFile:    path,
						SourceEventID: perEventID,
						SessionID:     evt.SessionID,
						MessageID:     perEventID,
						Timestamp:     ts,
						Model:         evt.Model,
						Fast:          false, // codex has no speed flag
						BlockHashes:   nil,   // implicit path ignores this
						Usage: models.CacheUsage{
							NetInputTokens:        evt.InputTokens,
							OutputTokens:          evt.OutputTokens,
							CacheReadTokens:       evt.CacheReadTokens,
							CacheCreationTokens:   0,
							CacheCreation1hTokens: 0,
						},
						CompactionSeen: false,
						ImplicitCache:  true,
					})
				}
				if turnID == "" {
					// Token event arrived before the assistant turn
					// boundary (cold-resume or session-startup tokens).
					// Queue for retroactive TurnID + Model backfill once
					// the turn context arrives — see the prelude block.
					pendingTurnlessTokenIdxs = append(pendingTurnlessTokenIdxs, len(res.TokenEvents)-1)
				} else if evt.Model == "" {
					pendingTokenModels[turnID] = append(pendingTokenModels[turnID], len(res.TokenEvents)-1)
				}
			}

		case "response_item":
			// Codex Desktop wraps tool intent in a response_item envelope:
			// payload.type discriminates function_call (assistant intent),
			// function_call_output (executor result without success
			// metadata), reasoning (Tier 2), and message (Tier 3).
			//
			// Dedup design (per user requirement, 2026-05-01): when a
			// response_item.function_call lands first, we emit the row
			// and stash the index in pending[call_id]; the matching
			// side-channel event (event_msg/exec_command_end for shell,
			// event_msg/web_search_end for web_search_call) merges its
			// richer fields into that row instead of emitting a duplicate.
			// If the side-channel event was missed (e.g. mid-session
			// truncation, or this code path is mid-resume), the
			// function_call row stands alone — no double-counting, no
			// loss of the call itself.
			switch payloadType {
			case "function_call":
				var rc responseItemFunctionCall
				if err := json.Unmarshal(line.Payload, &rc); err != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: response_item.function_call: %v", lineNum, err))
					continue
				}
				callID := firstNonEmpty(rc.CallID, fmt.Sprintf("%s:L%d", filepath.Base(path), lineNum))
				if _, dupe := pending[callID]; dupe {
					// Same call_id already pending — this is a malformed
					// or replayed segment; skip the second intent.
					continue
				}
				rawInput := unwrapFunctionArguments(rc.Arguments)
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[ctxState.TurnID]
				evt := a.buildToolEvent(path, callID, ctxState, projectRoot, ts, rc.Name, rawInput, preceding)
				if evt.Model == "" {
					if turnID := assistantTurnID(""); turnID != "" {
						evt.Model = modelForTurn(turnID)
						if evt.Model == "" {
							pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
						}
					}
				}
				pending[callID] = len(res.ToolEvents)
				res.ToolEvents = append(res.ToolEvents, withEffort(evt))
			case "function_call_output":
				var ro responseItemFunctionCallOutput
				if err := json.Unmarshal(line.Payload, &ro); err != nil {
					continue
				}
				idx, ok := pending[ro.CallID]
				if !ok || idx >= len(res.ToolEvents) {
					continue
				}
				body := ro.Output
				// The output is sometimes itself a JSON object with
				// {"output":"...","metadata":{...}} (e.g. apply_patch).
				body = unwrapStructuredOutput(body)
				row := &res.ToolEvents[idx]
				if row.ToolOutput == "" {
					row.ToolOutput = a.scrubber.String(body)
				}
				// exec_command output carries a footer with the command's
				// TRUE wall time + numeric exit code (e.g. "Wall time: 0.6788
				// seconds\nProcess exited with code 0"). Prefer it over the
				// call->output gap below: the gap includes yield_time_ms +
				// model/queue latency, so it over-states a fast command's
				// runtime. The exit code also gives an accurate Success.
				if row.ActionType == models.ActionRunCommand {
					if wallMs, exitCode, ok := parseExecFooter(body); ok {
						if wallMs > 0 {
							row.DurationMs = wallMs
						}
						row.Success = exitCode == 0
					}
				}
				// Wall-clock duration: gap between when the function_call
				// was emitted and when its output arrived. Source-format
				// agnostic and works on every codex variant where the call
				// and output share a call_id (which is all of them).
				if row.DurationMs == 0 && !row.Timestamp.IsZero() && !ts.IsZero() {
					if d := ts.Sub(row.Timestamp).Milliseconds(); d > 0 {
						row.DurationMs = d
					}
				}
				delete(pending, ro.CallID)
			case "custom_tool_call":
				var rc responseItemCustomToolCall
				if err := json.Unmarshal(line.Payload, &rc); err != nil {
					res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: response_item.custom_tool_call: %v", lineNum, err))
					continue
				}
				callID := firstNonEmpty(rc.CallID, fmt.Sprintf("%s:L%d", filepath.Base(path), lineNum))
				if _, dupe := pending[callID]; dupe {
					continue
				}
				projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
				preceding := agentMessages[ctxState.TurnID]
				evt, patchText := a.buildCustomToolCallEvent(path, callID, ctxState, projectRoot, ts, rc, preceding)
				if evt.Model == "" {
					if turnID := assistantTurnID(""); turnID != "" {
						evt.Model = modelForTurn(turnID)
						if evt.Model == "" {
							pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
						}
					}
				}
				pending[callID] = len(res.ToolEvents)
				// Register the invocation for the id-less fallback join.
				// Both sides key on the turn the row itself carries
				// (MessageID), so the queue can never be keyed one way and
				// read another.
				if patchText != "" && evt.ActionType == models.ActionEditFile {
					if files := patchFileSet(patchText, ctxState.Cwd); len(files) > 0 {
						patchInvocations[evt.MessageID] = append(patchInvocations[evt.MessageID],
							patchInvocation{idx: len(res.ToolEvents), callID: callID, files: files})
					}
				}
				res.ToolEvents = append(res.ToolEvents, withEffort(evt))
			case "custom_tool_call_output":
				var ro responseItemCustomToolCallOutput
				if err := json.Unmarshal(line.Payload, &ro); err != nil {
					continue
				}
				idx, ok := pending[ro.CallID]
				if !ok || idx >= len(res.ToolEvents) {
					continue
				}
				row := &res.ToolEvents[idx]
				body := unwrapStructuredOutput(ro.Output)
				if row.ToolOutput == "" {
					row.ToolOutput = a.scrubber.String(body)
				}
				if row.DurationMs == 0 && !row.Timestamp.IsZero() && !ts.IsZero() {
					if d := ts.Sub(row.Timestamp).Milliseconds(); d > 0 {
						row.DurationMs = d
					}
				}
				// Deliberately do NOT delete pending here. For apply_patch
				// the terminal event is event_msg/patch_apply_end which can
				// land either before or after custom_tool_call_output —
				// leaving the pending entry keeps it mergeable. The single
				// in-memory entry that survives if patch_apply_end never
				// fires is harmless (one-pass scan).
			case "reasoning":
				// response_item.reasoning currently carries only opaque
				// `encrypted_content` plus an empty `summary` array in
				// every Codex Desktop build inspected (838 reasoning
				// items, 0% non-empty summary as of 2026-05).
				//
				// B3 (2026-07-31): reasoning is NEVER its own action
				// row. v1.4.53 minted one — including an opaque
				// "(encrypted reasoning, N bytes)" placeholder for the
				// unreadable majority — and that produced 15,369
				// phantom task_complete rows, 15,040 of them content-
				// free. The ONLY thing that happens here is the
				// pre-existing threading: readable summary text is
				// concatenated into the per-turn agentMessages cache so
				// the next tool_call / agent_message of the same turn
				// carries it as PrecedingReasoning (see the
				// agentMessages declaration). An item with no readable
				// summary contributes nothing at all — a placeholder is
				// never threaded and never stored.
				var rr responseItemReasoning
				if err := json.Unmarshal(line.Payload, &rr); err == nil {
					if text := reasoningSummaryText(rr.Summary); text != "" {
						turnID := assistantTurnID("")
						if turnID != "" {
							existing := agentMessages[turnID]
							if existing == "" {
								agentMessages[turnID] = text
							} else {
								agentMessages[turnID] = existing + "\n" + text
							}
						}
					}
				}
			case "message":
				// response_item.payload.type=message — role discriminates.
				// role=assistant is captured via event_msg/agent_message
				// (and would duplicate here). role=developer is the
				// system-prompt-shaped channel for permissions/sandbox
				// context Codex Desktop injects mid-turn.
				//
				// role=user is mostly REAL user prompts (already captured
				// via event_msg/user_message — duplicating would
				// double-count). BUT a meaningful subset are XML-envelope
				// synthetic context injections — `<environment_context>`
				// (cwd, shell, current_date, timezone),
				// `<user_instructions>`, etc. — that look like user
				// messages to the model but originate from the runtime,
				// not the user. Capture those as system_prompt; skip the
				// plain-text and markdown ones (those are real user
				// prompts already covered by event_msg/user_message).
				var rm responseItemMessage
				if err := json.Unmarshal(line.Payload, &rm); err == nil {
					body := concatMessageContent(rm.Content)
					// User-attachment capture (Issue 1): a role=user
					// response_item carries the API-side input parts, which
					// include the image/file attachments the user sent (the
					// event_msg/user_message record carries only the text).
					// Merge the attachment metadata onto the most recent
					// user_prompt event so the turn is flagged without
					// double-counting the prompt text.
					if rm.Role == "user" {
						if atts := userAttachmentsFromContent(rm.Content); len(atts) > 0 {
							attachToRecentUserPrompt(res.ToolEvents, atts)
						}
					}
					emit := false
					role := rm.Role
					switch rm.Role {
					case "developer":
						emit = body != ""
					case "user":
						// Envelope detection — body must START with `<`
						// (after trim) to qualify as synthetic injection.
						// Plain text and markdown headers are real user
						// prompts and stay with event_msg/user_message.
						trimmed := strings.TrimLeft(body, " \t\n\r")
						if strings.HasPrefix(trimmed, "<") {
							emit = true
							role = "user-envelope"
						}
					}
					if emit {
						projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
						if evt, ok := a.systemPromptEvent(path, role, body, ts, ctxState, projectRoot, lineNum, seenSystemPrompts); ok {
							res.ToolEvents = append(res.ToolEvents, withEffort(evt))
						}
					}
				}
			case "web_search_call":
				// Has a paired event_msg/web_search_end that emits the row.
			}

		case "tool_call", "function_call":
			var tc toolCall
			if err := json.Unmarshal(line.Payload, &tc); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: tool_call: %v", lineNum, err))
				continue
			}
			toolName := firstNonEmpty(tc.Tool, tc.Name)
			callID := firstNonEmpty(tc.CallID, tc.ID)
			if callID == "" {
				// Fall back to rawLine.ID or a line-number synthesis.
				callID = firstNonEmpty(line.ID, fmt.Sprintf("%s:L%d", filepath.Base(path), lineNum))
			}
			projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
			preceding := agentMessages[ctxState.TurnID]
			evt := a.buildToolEvent(path, callID, ctxState, projectRoot, ts, toolName, tc.Input, preceding)
			if evt.Model == "" {
				if turnID := assistantTurnID(""); turnID != "" {
					evt.Model = modelForTurn(turnID)
					if evt.Model == "" {
						pendingToolModels[turnID] = append(pendingToolModels[turnID], len(res.ToolEvents))
					}
				}
			}
			pending[callID] = len(res.ToolEvents)
			res.ToolEvents = append(res.ToolEvents, withEffort(evt))

		case "tool_output", "function_call_output":
			var to toolOutput
			if err := json.Unmarshal(line.Payload, &to); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: tool_output: %v", lineNum, err))
				continue
			}
			callID := firstNonEmpty(to.CallID, to.ID)
			idx, ok := pending[callID]
			if !ok {
				continue
			}
			body := decodeOutput(to.Output)
			scrubbed := a.scrubber.String(body)
			res.ToolEvents[idx].ToolOutput = scrubbed
			failed := (to.IsError != nil && *to.IsError) || (to.Success != nil && !*to.Success)
			if failed {
				res.ToolEvents[idx].Success = false
				res.ToolEvents[idx].ErrorMessage = truncate(scrubbed, 2048)
			}
			delete(pending, callID)

		case "token_count", "usage":
			var tk tokenCount
			if err := json.Unmarshal(line.Payload, &tk); err != nil {
				continue
			}
			// Codex emits cumulative totals. Convert to per-turn delta by
			// subtracting the running total we've seen in this session.
			//
			// Cold-start handling (audit C1): when fromOffset>0 we're
			// resuming an incremental parse and the in-memory
			// lastInputByID map starts empty even though prior turns
			// already landed in the DB. Treating tk.InputTokens as the
			// delta in that case would emit a single huge over-count
			// (the cumulative total minus zero). Instead, emit 0 for the
			// first event we see in a resume, then compute correct deltas
			// from there. We lose the true delta for that one event but
			// avoid a much larger over-report.
			// Net-cumulative input (= gross_input - cached_input) is
			// what we want to delta-track per session. Subtracting
			// cached BEFORE deltaing matches the cost engine's
			// Anthropic-shape contract (TokenBundle.Input is NET
			// non-cached). Otherwise the cached portion gets billed at
			// BOTH the full input rate AND the cache_read rate — see
			// internal/intelligence/cost/engine.go TokenBundle docs and
			// the cost-engine audit 2026-05-24.
			netCum := tk.InputTokens - tk.Cached
			if netCum < 0 {
				netCum = 0
			}
			prev, hasPrev := lastNetInputByID[ctxState.SessionID]
			var netIn int64
			switch {
			case !hasPrev && fromOffset == 0:
				// Fresh parse from start of file — first cumulative IS
				// the delta.
				netIn = netCum
			case !hasPrev && fromOffset > 0:
				// Resume — baseline this event's cumulative net as prev
				// so subsequent events compute correct deltas.
				netIn = 0
			case netCum >= prev:
				netIn = netCum - prev
			default:
				// Negative delta — session reset or upstream resequencing.
				netIn = netCum
			}
			lastNetInputByID[ctxState.SessionID] = netCum
			// Keep the legacy gross tracker live as well so it doesn't
			// drift if any future code path reads it; cheap to update.
			lastInputByID[ctxState.SessionID] = tk.InputTokens

			// Fork/subagent REPLAY (legacy top-level path, dormant for
			// modern rollout files): skip emission AFTER the delta state
			// updates above, so the first live event deltas against the
			// replayed cumulative total. Same guard as the modern path.
			if forkTrack.isReplayedTokenCount() {
				// Consume the web-search tally like an emitted row would
				// (see the modern path) so replayed searches don't pile
				// onto the first live row's WebSearchRequests.
				runningWebSearchCount = 0
				continue
			}

			projectRoot := a.resolveProjectRoot(ctxState.Cwd, rootCache)
			turnID := assistantTurnID("")
			model := firstNonEmpty(tk.Model, modelForTurn(turnID))
			// OpenAI / Codex `output_tokens` is GROSS and ALREADY
			// CONTAINS `reasoning_output_tokens` (reasoning ⊂ output —
			// verified 2026-07-09 on live gpt-5.6 traffic). The cost
			// engine bills TokenBundle.Reasoning ADDITIVELY at the output
			// rate on top of Output, so Output must be the non-reasoning
			// response-token count. Net the reasoning subset out here
			// else every codex reasoning token is billed twice. Mirrors
			// the netInput subtraction on the modern path.
			netOutput := tk.OutputTokens - tk.Reasoning
			if netOutput < 0 {
				netOutput = 0
			}
			// v1.7.24+ (migration 032): legacy codex token_count is
			// already delta'd at line 1668-1673 (netCum - prev). The
			// per-event MessageID + turn-grouping TurnID match the
			// modern path's contract — one row per token_count event,
			// each row a per-inference delta. See the modern-path
			// comment at the `tk` emission site for the full rationale.
			perEventID := fmt.Sprintf("tk:%s:L%d", filepath.Base(path), lineNum)
			evt := models.TokenEvent{
				SourceFile:        path,
				SourceEventID:     perEventID,
				SessionID:         ctxState.SessionID,
				ProjectRoot:       projectRoot,
				GitBranch:         ctxState.GitBranch,
				GitRemote:         ctxState.GitRemote,
				Timestamp:         ts,
				Tool:              models.ToolCodex,
				Model:             model,
				InputTokens:       netIn,
				OutputTokens:      netOutput,
				CacheReadTokens:   tk.Cached,
				ReasoningTokens:   tk.Reasoning,
				WebSearchRequests: runningWebSearchCount,
				Source:            models.TokenSourceJSONL,
				Reliability:       models.ReliabilityApproximate,
				MessageID:         perEventID,
				TurnID:            turnID,
			}
			runningWebSearchCount = 0
			res.TokenEvents = append(res.TokenEvents, evt)
			// CACHETRACK §15.3 (was: §14.3 scaffold-only). Legacy
			// codex transcripts emit cumulative input_tokens that the
			// adapter pre-deltas at the netCum subtraction above
			// (line ~1668-1673); tk.Cached is fed verbatim per
			// codex's audit doc rationale. See modern-path emission
			// site above for the full ImplicitCache wiring rationale.
			if evt.SessionID != "" && evt.Model != "" {
				res.CacheObservations = append(res.CacheObservations, models.CacheTurnObservation{
					SourceFile:    path,
					SourceEventID: perEventID,
					SessionID:     evt.SessionID,
					MessageID:     perEventID,
					Timestamp:     ts,
					Model:         evt.Model,
					Fast:          false,
					BlockHashes:   nil,
					Usage: models.CacheUsage{
						NetInputTokens:        evt.InputTokens,
						OutputTokens:          evt.OutputTokens,
						CacheReadTokens:       evt.CacheReadTokens,
						CacheCreationTokens:   0,
						CacheCreation1hTokens: 0,
					},
					CompactionSeen: false,
					ImplicitCache:  true,
				})
			}
			if turnID == "" {
				pendingTurnlessTokenIdxs = append(pendingTurnlessTokenIdxs, len(res.TokenEvents)-1)
			} else if evt.Model == "" {
				pendingTokenModels[turnID] = append(pendingTokenModels[turnID], len(res.TokenEvents)-1)
			}
		}
	}
	// Part B: persist codex session lineage (fork/subagent markers)
	// node-local. Emitted only when the owning session_meta was actually
	// read in this parse chunk and carries a non-empty marker, so
	// incremental resumes (tracker reconstructed by prefetch) don't
	// redundantly re-stamp it every poll.
	if lin, ok := forkTrack.lineageMarker(); ok && sessionMetaObservedThisChunk && ctxState.SessionID != "" {
		res.SessionLineages = append(res.SessionLineages, models.SessionLineage{
			SessionID:      ctxState.SessionID,
			ForkedFromID:   lin.ForkedFromID,
			ParentThreadID: lin.ParentThreadID,
			ThreadSource:   lin.ThreadSource,
		})
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	// Part E: capture-surface attribution (IDE-15 provenance half).
	// Same owner-only gate as the lineage marker above — a resumed
	// chunk that never read the owning session_meta must not re-stamp.
	// The store write is first-wins-unless-empty (models.SessionSurface
	// doc), so re-stamping the same value on a later full parse is
	// harmless; this gate just avoids a needless write every poll.
	if sessionMetaObservedThisChunk && ctxState.SessionID != "" {
		// a.surface is the per-VARIANT vocabulary set at construction
		// (zero value == codex proper's shared tables), so the Open
		// Interpreter desktop's own originator resolves to
		// desktop/"open-interpreter" without any tool-identity branch
		// on this path.
		if kind, host, ok := a.surface.resolve(ownerSource, ownerOriginator); ok {
			res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
				SessionID:   ctxState.SessionID,
				Surface:     kind,
				SurfaceHost: host,
			})
		}
		// Issue 2: captured CLI version from the owning session_meta.
		// The store write is first-wins-unless-empty and bounded-token
		// validated, so a re-stamp or malformed value is harmless.
		if ownerCLIVersion != "" {
			res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{
				SessionID: ctxState.SessionID,
				Version:   ownerCLIVersion,
			})
		}
	}
	return res, nil
}

// buildCustomToolCallEvent emits the assistant-side row for a
// response_item/custom_tool_call.
//
// Two shapes reach here. The legacy one names the tool directly
// ("apply_patch") and puts the raw patch text in `input`. The modern
// one (and the Open Interpreter rebadge) names EVERY call "exec" and
// puts a JavaScript program in `input` that dispatches to the real
// tool — see unifiedexec.go for the measured vocabulary. Both are
// resolved to a native tool name first, then routed through actionMap
// (the tooltax-sourced table) exactly like every other codex path, so
// an unseen name lands as ActionUnknown instead of being absorbed into
// run_command, and the emit site never contradicts the taxonomy table.
//
// The patch text — inline for the legacy shape, decoded out of the JS
// program for the modern one — is parsed for the first changed file
// path so the row's Target is meaningful even without the matching
// patch_apply_end.
func (a *Adapter) buildCustomToolCallEvent(
	sourceFile, callID string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	rc responseItemCustomToolCall,
	preceding string,
) (models.ToolEvent, string) {
	name, target, patchText, provablyNoCall := a.resolveCustomToolCall(rc)

	actionType, ok := actionMap[name]
	if !ok {
		actionType = models.ActionUnknown
	}
	// Residual class 1: an `exec` program PROVABLY dispatching to no
	// tools.* call at all (3 of 7,087 live rows, all harness
	// introspection over the injected ALL_TOOLS array). It ran no
	// command, so it keeps neither the dispatcher's run_command row
	// nor a fabricated target.
	//
	// FAIL CLOSED. The downgrade needs the parser's PROOF, not merely
	// its silence — a program the scanner could not resolve
	// (`tools["exec_command"](…)`, a call inside a template literal,
	// tomorrow's syntax) may well have run a real command, and typing
	// that harness_call would drop it out of run_command analytics AND
	// out of target-based safety classification. Unresolved therefore
	// keeps the taxonomy's own conservative `exec` row (run_command)
	// with an empty Target — the pre-fix behaviour, which under-informs
	// rather than mis-asserts. See unifiedexec.go RESIDUAL CLASS 1.
	if rc.Name == unifiedExecToolName && name == unifiedExecToolName && provablyNoCall {
		actionType = models.ActionHarnessCall
		target = ""
	}
	if patchText != "" {
		if p := applyPatchTarget(patchText); p != "" {
			target = p
		}
	}
	if target != "" && (actionType == models.ActionEditFile) && projectRoot != "" {
		target = git.RelativePath(projectRoot, target)
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      callID,
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         actionType,
		Target:             truncate(target, 200),
		Success:            true,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        name,
		RawToolInput:       a.scrubber.String(rc.Input),
		ContentBytes:       customToolCallAuthoredBytes(actionType, rc, target, patchText),
		MessageID:          sess.TurnID,
	}, patchText
}

// resolveCustomToolCall turns a custom_tool_call payload into (native
// tool name, target, patch text, provably-no-call). The legacy shape is
// already named; the modern unified-exec shape is resolved by parsing
// its JavaScript program (unifiedexec.go). Returning the dispatcher
// name "exec" unchanged is how the caller recognises an unresolved
// program; the fourth result separates the two reasons a program can be
// unresolved — PROVED tool-free (the residual class) versus merely
// beyond the scanner's syntax (fall back to the taxonomy's exec row).
func (a *Adapter) resolveCustomToolCall(
	rc responseItemCustomToolCall,
) (name, target, patchText string, provablyNoCall bool) {
	if rc.Name != unifiedExecToolName {
		if rc.Name == "apply_patch" {
			return rc.Name, "", rc.Input, false
		}
		return rc.Name, "", "", false
	}
	call := parseUnifiedExec(rc.Input)
	if call.Name == "" {
		return rc.Name, "", "", call.NoToolCall
	}
	// The command / written chars / plan explanation are agent-authored
	// free text that can carry credentials, exactly like the
	// exec_command_end path's command string — scrub before it becomes
	// a queryable column.
	return call.Name, a.scrubber.String(call.Target), call.PatchText, false
}

// customToolCallAuthoredBytes counts what the AGENT authored in a
// custom_tool_call. The legacy shape can be measured straight off the
// payload, but a unified-exec payload is a JavaScript program: passing
// it to authoredBytes would either fail to parse (edit rows silently
// scoring 0) or count the whole wrapper as if it were the command.
// Measure the resolved inner argument instead — the command string for
// a shell run, the added patch lines for an edit, nothing for plan
// updates and stdin writes, which author no content.
func customToolCallAuthoredBytes(actionType string, rc responseItemCustomToolCall, target, patchText string) int64 {
	if rc.Name != unifiedExecToolName {
		return authoredBytes(actionType, []byte(rc.Input))
	}
	switch actionType {
	case models.ActionRunCommand:
		return int64(len(target))
	case models.ActionWriteFile, models.ActionEditFile:
		return authoredBytesFromPatch(patchText)
	default:
		return 0
	}
}

// buildPatchApplyStandaloneEvent emits a row when patch_apply_end lands
// without a matching pending custom_tool_call. Carries the structured
// `changes` summary as the authoritative source.
//
// This is the DOMINANT path on current builds, not the rare recovery
// case its name suggests. Codex now invokes apply_patch from inside an
// `exec` custom_tool_call (`tools.apply_patch(patch)` in the sandbox
// script), and the executor stamps patch_apply_end with its own
// `exec-<uuid>` id — a different namespace from the response_item's
// `call_<hash>`, so pending[pa.CallID] cannot match by construction.
// Measured over a 393-rollout corpus: 2,059 exec-uuid vs 416 call_hash.
// There is no id join to repair, which is why the row's RawToolInput is
// reconstructed from `changes` here instead.
func (a *Adapter) buildPatchApplyStandaloneEvent(
	sourceFile string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	pa patchApplyEnd,
	lineNum int,
	preceding string,
) models.ToolEvent {
	target := patchApplyTargetFromChanges(pa.Changes, projectRoot)
	output := strings.TrimSpace(pa.Stdout + pa.Stderr)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(pa.CallID, fmt.Sprintf("patch:%s:L%d", filepath.Base(sourceFile), lineNum)),
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionEditFile,
		Target:             truncate(target, 200),
		Success:            pa.Success,
		ErrorMessage:       errorIfFailed(pa.Success, output),
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        "patch_apply_end",
		RawToolInput:       RenderPatchChangesInput(a.scrubber, pa.ChangesRaw),
		ToolOutput:         a.scrubber.String(output),
		ContentBytes:       authoredBytesFromPatchChanges(pa.Changes),
		MessageID:          firstNonEmpty(pa.TurnID, sess.TurnID),
	}
}

// mergePatchApplyIntoPending merges a patch_apply_end side-channel into
// an already-emitted custom_tool_call row. The Changes map's first key
// is preferred over whatever applyPatchTarget extracted from the patch
// text, since it's the post-execution canonical path list.
func mergePatchApplyIntoPending(row *models.ToolEvent, a *Adapter, pa patchApplyEnd, projectRoot string) {
	row.ActionType = models.ActionEditFile
	row.Success = pa.Success
	output := strings.TrimSpace(pa.Stdout + pa.Stderr)
	row.ToolOutput = a.scrubber.String(output)
	row.ErrorMessage = errorIfFailed(pa.Success, output)
	row.RawToolName = "patch_apply_end"
	// The executor's count wins where it exists, because for an `add` it
	// is the EXACT file content while the patch-text measure drops every
	// line terminator (a 29-byte file counts 26 from its `+` lines).
	//
	// KNOWN LIMITATION, unquantified: a MIXED envelope (one `add` plus
	// one `update`) therefore reports only the add — the update carries
	// no `content`, so its `+` lines are lost from the merged row. The
	// honest fix is not to special-case this here but to make the
	// patch-text measure exact by counting line terminators, after which
	// it covers every change kind and can simply win outright. That
	// moves ContentBytes on every codex patch row, so it is a separate
	// decision, not a side effect of collapsing the duplicate row.
	if n := authoredBytesFromPatchChanges(pa.Changes); n > 0 {
		row.ContentBytes = n
	}
	if t := patchApplyTargetFromChanges(pa.Changes, projectRoot); t != "" {
		row.Target = truncate(t, 200)
	}
	// The pending row already holds the model's own `*** Begin Patch`
	// text, which is a richer input than the post-execution summary —
	// only fill from `changes` when there is nothing to preserve.
	if row.RawToolInput == "" {
		row.RawToolInput = RenderPatchChangesInput(a.scrubber, pa.ChangesRaw)
	}
}

// patchChangesRaw returns the verbatim `changes` object of a
// patch_apply_end payload, or nil when the payload does not parse.
func patchChangesRaw(payload []byte) json.RawMessage {
	var probe struct {
		Changes json.RawMessage `json:"changes"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil
	}
	return probe.Changes
}

// RenderPatchChangesInput renders a patch_apply_end `changes` object for
// storage in raw_tool_input, scrubbed. Absent, JSON null and the empty
// object all render "" — a patch_apply_end that recorded no changes has
// no input to store, and "{}" is a value the producer never wrote.
//
// This is the ONE owner of that rendering. The live parse path and
// `observer backfill --codex-tool-input` both call it, so a row captured
// live and the same row recovered from disk are byte-identical.
func RenderPatchChangesInput(sc *scrub.Scrubber, raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return ""
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil || len(probe) == 0 {
		return ""
	}
	return sc.RawJSON(raw)
}

// dynamicToolCallBody concatenates text content_items into a single
// string for the row's ToolOutput.
func dynamicToolCallBody(items []dynamicToolCallItem) string {
	var pieces []string
	for _, it := range items {
		text := strings.TrimSpace(it.Text)
		if text != "" {
			pieces = append(pieces, text)
		}
	}
	return strings.Join(pieces, "\n")
}

// systemPromptEvent emits an ActionSystemPrompt row for a piece of
// system-prompt-shaped content. Returns (zero, false) when the body is
// empty or its content hash has already been seen in this parse —
// codex repeats large (~9-18KB) base_instructions and
// developer_instructions across nearly every session_meta and
// turn_context, so dedup is mandatory or we'd emit thousands of
// duplicate rows.
//
// Body lives in RawToolInput (scrubbed). Target carries a 200-char
// preview. MessageID is "system:<hash>" so cross-row joins can group
// occurrences of the same prompt body. role discriminates 'base'
// (session-level system prompt) vs 'developer' (turn-level or
// response_item.message.role=developer instructions).
func (a *Adapter) systemPromptEvent(
	sourceFile, role, body string,
	ts time.Time,
	sess sessionContext,
	projectRoot string,
	lineNum int,
	seen map[string]bool,
) (models.ToolEvent, bool) {
	body = strings.TrimSpace(body)
	if body == "" {
		return models.ToolEvent{}, false
	}
	hash := shortHash(body)
	if seen[hash] {
		return models.ToolEvent{}, false
	}
	seen[hash] = true
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("sysprompt:%s:%s:L%d", role, hash, lineNum),
		SessionID:     sess.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		ActionType:    models.ActionSystemPrompt,
		Target:        preview,
		Success:       true,
		RawToolName:   "system_prompt." + role,
		RawToolInput:  a.scrubber.String(body),
		MessageID:     "system:" + hash,
	}, true
}

// concatMessageContent flattens a response_item.message content array
// into a single string. Joins the `text` field of every part (Codex
// developer-role messages use type="input_text"; assistant-role would
// use "output_text", but those are skipped at the call site).
func concatMessageContent(parts []responseItemMessageContent) string {
	var pieces []string
	for _, p := range parts {
		text := strings.TrimSpace(p.Text)
		if text != "" {
			pieces = append(pieces, text)
		}
	}
	return strings.Join(pieces, "\n")
}

// userAttachmentsFromContent scans a role=user response_item message's
// content parts for the files/images the user attached (Issue 1):
// `input_image` / `image_url` / `image` parts become kind "image" (with
// the media_type read from the data-URI prefix when present), and
// `input_file` / `file` parts become kind "file". Metadata only — the
// base64 payload and any filename are never read. Returns nil when the
// message carried no attachment parts.
func userAttachmentsFromContent(parts []responseItemMessageContent) []models.UserAttachment {
	var atts []models.UserAttachment
	for _, p := range parts {
		switch p.Type {
		case "input_image", "image_url", "image":
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: mediaTypeFromImageURL(p.ImageURL)})
		case "input_file", "file":
			atts = append(atts, models.UserAttachment{Kind: "file"})
		}
	}
	return atts
}

// attachToRecentUserPrompt stamps user-attachment metadata onto the most
// recent user_prompt event in evs (best-effort correlation: the role=user
// response_item that carries the attachment parts is emitted alongside the
// event_msg/user_message that produced the prompt row). Scans backward and
// stops at the first user_prompt; a no-op when none exists yet or the row
// already carries attachments (idempotent re-parse).
func attachToRecentUserPrompt(evs []models.ToolEvent, atts []models.UserAttachment) {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].ActionType != models.ActionUserPrompt {
			continue
		}
		if len(evs[i].UserAttachments) == 0 {
			evs[i].UserAttachments = atts
		}
		return
	}
}

// mediaTypeFromImageURL extracts the IANA media type from an
// `input_image` part's image_url — a data URI ("data:image/png;base64,…")
// carried either as a bare JSON string or as an object {"url":"…"}. Reads
// ONLY the media-type prefix; the base64 body is never decoded. Returns
// "" when the reference is not a typed data URI.
func mediaTypeFromImageURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var url string
	if err := json.Unmarshal(raw, &url); err != nil {
		var obj struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return ""
		}
		url = obj.URL
	}
	if !strings.HasPrefix(url, "data:") {
		return ""
	}
	rest := url[len("data:"):]
	// media type runs up to the first ';' or ',' ("image/png;base64,…").
	if i := strings.IndexAny(rest, ";,"); i >= 0 {
		return rest[:i]
	}
	return ""
}

// buildCompactedEvent emits an ActionContextCompacted row summarizing
// what got compacted: message count + byte estimate (sum of text
// content) + token estimate (bytes/4, matching the rest of the
// codebase's char-count → token heuristic for non-tokenized estimates).
// Per user direction (2026-05-01) these rows are not searchable like
// file edits — the action_type discriminator lets the dashboard
// suppress them from action-type browsers while keeping them
// available for cost / compaction-frequency analytics.
func (a *Adapter) buildCompactedEvent(
	sourceFile string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	ce compactedEvent,
	lineNum int,
) models.ToolEvent {
	msgCount := len(ce.ReplacementHistory)
	bytesEst := 0
	for _, msg := range ce.ReplacementHistory {
		for _, blk := range msg.Content {
			bytesEst += len(blk.Text)
		}
	}
	tokensEst := bytesEst / 4
	target := fmt.Sprintf("%d msgs, ~%d tokens", msgCount, tokensEst)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("compacted:%s:L%d", filepath.Base(sourceFile), lineNum),
		SessionID:     sess.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		ActionType:    models.ActionContextCompacted,
		Target:        truncate(target, 200),
		Success:       true,
		RawToolName:   "compacted",
		RawToolInput:  fmt.Sprintf(`{"messages":%d,"bytes_estimate":%d,"tokens_estimate":%d}`, msgCount, bytesEst, tokensEst),
		ToolOutput:    a.scrubber.String(truncate(ce.Message, 2048)),
		MessageID:     sess.TurnID,
	}
}

// buildTurnAbortedEvent emits an ActionTurnAborted row for a Codex
// turn that was interrupted before completing. Distinct from a
// task_complete with success=false: aborted turns never finished
// generating, so the model output is partial — analysts filtering
// for completed turns vs aborts need the action_type discriminator.
func (a *Adapter) buildTurnAbortedEvent(
	sourceFile string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	ta turnAborted,
	lineNum int,
) models.ToolEvent {
	if ta.CompletedAt > 0 {
		ts = time.Unix(ta.CompletedAt, 0).UTC()
	}
	reason := firstNonEmpty(ta.Reason, "interrupted")
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("aborted:%s:%d", firstNonEmpty(ta.TurnID, sess.SessionID, filepath.Base(sourceFile)), lineNum),
		SessionID:     firstNonEmpty(sess.SessionID, ta.TurnID),
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		ActionType:    models.ActionTurnAborted,
		Target:        truncate(reason, 200),
		Success:       false,
		ErrorMessage:  "turn aborted: " + reason,
		DurationMs:    ta.DurationMs,
		RawToolName:   "turn_aborted",
		MessageID:     firstNonEmpty(ta.TurnID, sess.TurnID),
	}
}

// mergeMCPCallEndIntoPending overwrites the pending function_call row
// with structured MCP call result data: server:tool target, content
// text as ToolOutput, success/error from the Ok|Err tagged union, and
// duration. Promotes the ActionType to ActionMCPCall if it wasn't
// already (response_item.function_call may have routed list_mcp_*
// names to mcp_call via actionMap, but other server-defined tool
// names fall to Unknown without this).
func mergeMCPCallEndIntoPending(row *models.ToolEvent, a *Adapter, mc mcpToolCallEnd) {
	row.ActionType = models.ActionMCPCall
	row.Target = truncate(mcpCallTarget(mc.Invocation), 200)
	output, success, errMsg := mcpCallResultBody(mc.Result)
	row.ToolOutput = a.scrubber.String(output)
	row.Success = success
	if !success {
		row.ErrorMessage = truncate(errMsg, 2048)
	} else {
		row.ErrorMessage = ""
	}
	row.DurationMs = mc.Duration.Secs*1000 + mc.Duration.Nanos/1_000_000
	row.RawToolName = "mcp_tool_call_end"
}

// buildMCPCallEndStandaloneEvent emits a row when mcp_tool_call_end
// fires without a preceding response_item.function_call (mid-session
// resume, or the response_item never landed). Carries everything the
// merge would have populated.
func (a *Adapter) buildMCPCallEndStandaloneEvent(
	sourceFile string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	mc mcpToolCallEnd,
	lineNum int,
	preceding string,
) models.ToolEvent {
	output, success, errMsg := mcpCallResultBody(mc.Result)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(mc.CallID, fmt.Sprintf("mcp:%s:L%d", filepath.Base(sourceFile), lineNum)),
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionMCPCall,
		Target:             truncate(mcpCallTarget(mc.Invocation), 200),
		Success:            success,
		ErrorMessage:       errorIfFailed(success, errMsg),
		DurationMs:         mc.Duration.Secs*1000 + mc.Duration.Nanos/1_000_000,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        "mcp_tool_call_end",
		RawToolInput:       a.scrubber.RawJSON(mc.Invocation.Arguments),
		ToolOutput:         a.scrubber.String(output),
		MessageID:          firstNonEmpty(mc.TurnID, sess.TurnID),
	}
}

// mcpCallTarget formats "server:tool" for the row's Target field, with
// safe fallbacks when one or the other is empty.
func mcpCallTarget(inv mcpInvocation) string {
	switch {
	case inv.Server != "" && inv.Tool != "":
		return inv.Server + ":" + inv.Tool
	case inv.Tool != "":
		return inv.Tool
	default:
		return inv.Server
	}
}

// mcpCallResultBody flattens the Ok|Err tagged union into (output,
// success, errorMessage). Success requires Ok present and isError
// false; if Ok.isError is true the success is false but we still
// surface the content text as the error body. If Err is present that
// message wins.
func mcpCallResultBody(r mcpCallResult) (string, bool, string) {
	if r.Err != nil {
		return r.Err.Message, false, r.Err.Message
	}
	if r.Ok != nil {
		var pieces []string
		for _, c := range r.Ok.Content {
			if c.Type == "text" && c.Text != "" {
				pieces = append(pieces, c.Text)
			}
		}
		body := strings.Join(pieces, "\n")
		if r.Ok.IsError {
			return body, false, body
		}
		return body, true, ""
	}
	// Neither Ok nor Err — defensively succeed-empty.
	return "", true, ""
}

// buildCodexErrorEvent emits an ActionAPIError row from event_msg/error.
// Maps to the same shape claudecode uses for type=system / subtype=api_error
// records: Target carries the error class (`codex_error_info`),
// ErrorMessage carries the human-readable body, RawToolName preserves
// the upstream class for filtering, Success is always false.
func (a *Adapter) buildCodexErrorEvent(
	sourceFile string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	ce codexError,
	lineNum int,
) models.ToolEvent {
	class := firstNonEmpty(ce.CodexErrorInfo, "api_error")
	scrubbed := a.scrubber.String(ce.Message)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("error:%s:L%d:%s", filepath.Base(sourceFile), lineNum, shortHash(class+":"+ce.Message)),
		SessionID:     sess.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		ActionType:    models.ActionAPIError,
		Target:        truncate(class, 200),
		Success:       false,
		ErrorMessage:  truncate(scrubbed, 2048),
		RawToolName:   class,
		MessageID:     sess.TurnID,
	}
}

// reasoningSummaryText concatenates any text fields present in a
// response_item.reasoning summary array. Returns "" when the array is
// empty or carries no text segments — current Codex Desktop emits
// {summary:[], encrypted_content:"..."} so the typical return is "".
func reasoningSummaryText(parts []reasoningSummaryPart) string {
	var pieces []string
	for _, p := range parts {
		text := strings.TrimSpace(p.Text)
		if text == "" {
			continue
		}
		pieces = append(pieces, text)
	}
	return strings.Join(pieces, "\n")
}

// applyPatchTarget pulls the first changed file path out of the
// pseudo-diff format Codex apply_patch uses. Looks for `*** Add File:`,
// `*** Update File:`, `*** Delete File:`, or `*** Move File:` headers.
// Returns "" if the patch text doesn't follow that format.
func applyPatchTarget(patch string) string {
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		const prefix = "*** "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		for _, header := range []string{"Add File:", "Update File:", "Delete File:", "Move File:"} {
			if strings.HasPrefix(rest, header) {
				return strings.TrimSpace(rest[len(header):])
			}
		}
	}
	return ""
}

// patchInvocation is one unclaimed apply_patch custom_tool_call row,
// held so a later patch_apply_end that cannot join on call_id can still
// merge into it instead of emitting a duplicate row. `files` is the set
// of paths the invocation's own patch text declares.
type patchInvocation struct {
	idx int
	// callID is carried so a FALLBACK claim can invalidate this row's
	// pending[] entry too. Claimability is otherwise represented in two
	// places — pending and this queue — and invalidating only one leaves
	// the mirror of the bug dropPatchInvocation closes: a later
	// patch_apply_end that DOES carry the call_hash would merge a row the
	// fallback already merged.
	callID string
	files  map[string]struct{}
}

// patchFileSet extracts the set of paths an apply_patch envelope
// touches, from its `*** Add/Update/Delete/Move File:` headers. This is
// the invocation side of the pairing guard in claimPatchInvocation.
//
// A RELATIVE header is resolved against `base` (the session cwd) before
// cleaning, because the executor always reports ABSOLUTE paths — a bare
// `*** Update File: main.go` could otherwise never equal
// `/repo/main.go`, and the guard would abstain on a real shape rather
// than a doubtful one. Resolution is pure lexical joining, never a
// filesystem lookup. With no base to resolve against, a relative header
// is still emitted cleaned, so it simply fails to match and falls back
// to the standalone row.
func patchFileSet(patch, base string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		const prefix = "*** "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		for _, header := range []string{"Add File:", "Update File:", "Delete File:", "Move File:"} {
			if strings.HasPrefix(rest, header) {
				if p := strings.TrimSpace(rest[len(header):]); p != "" {
					if !isAbsAnyOS(p) && base != "" {
						p = filepath.Join(base, p)
					}
					out[filepath.Clean(p)] = struct{}{}
				}
				break
			}
		}
	}
	return out
}

// isAbsAnyOS reports whether a path is absolute in EITHER convention,
// which filepath.IsAbs alone cannot: it answers for the HOST os only, so
// a WSL/Linux daemon parsing a Windows rollout sees `C:\repo\a.go` as
// relative and a Windows host parsing a Linux rollout sees `/repo/a.go`
// the same way. Either mistake would send an already-absolute header
// through filepath.Join and destroy a pair that used to match — the
// adapter deliberately supports foreign-OS rollouts (see
// internal/platform/crossmount), so this is a live shape, not a
// hypothetical.
//
// Detection only: no normalization, no drive-letter rewriting. Both
// sides of the comparison keep the producer's own spelling, so they
// match each other exactly as they did before relative resolution
// existed.
func isAbsAnyOS(p string) bool {
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") {
		return true
	}
	// UNC (`\\server\share`) and Windows drive-letter (`C:\`, `c:/`).
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return false
}

// changesFileSet is the executor side of the same guard: the paths a
// patch_apply_end reports it actually wrote.
func changesFileSet(changes map[string]patchApplyChange) map[string]struct{} {
	out := map[string]struct{}{}
	for p := range changes {
		if p != "" {
			out[filepath.Clean(p)] = struct{}{}
		}
	}
	return out
}

// sameFileSet reports whether two path sets are equal. Equality — not
// overlap — is the safety property: it is what makes a wrong pairing
// structurally impossible rather than merely unlikely.
func sameFileSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	for p := range a {
		if _, ok := b[p]; !ok {
			return false
		}
	}
	return true
}

// claimPatchInvocation finds the invocation row a patch_apply_end
// belongs to when the call_id join has already missed, and REMOVES it
// from the queue so it can never be claimed twice.
//
// The match is oldest-first within the SAME TURN, gated on exact
// file-set equality. Order is what disambiguates the common case of one
// turn patching the same file repeatedly (every such invocation has an
// identical file set, so only sequence can tell them apart); the
// equality gate is what stops order from mis-pairing anything else. A
// turn is the right scope because sub-agents carry their own turn ids,
// so their patches cannot interleave into this queue.
//
// Known bound, accepted: if an invocation's own patch_apply_end never
// arrives (an aborted apply), the NEXT executor event for an identical
// file set in the same turn claims it instead. The row count stays
// correct and only the association shifts by one, between two patches
// of the same file in the same turn. Returning false (no claim) always
// degrades to the standalone row — this function never merges on doubt.
func claimPatchInvocation(queues map[string][]patchInvocation, turn string, files map[string]struct{}) (patchInvocation, bool) {
	q := queues[turn]
	for i, cand := range q {
		if !sameFileSet(cand.files, files) {
			continue
		}
		queues[turn] = append(q[:i:i], q[i+1:]...)
		return cand, true
	}
	return patchInvocation{}, false
}

// dropPatchInvocation removes the queue entry for a row index that has
// already been merged through another path, so it cannot be claimed a
// second time. Scans every turn because the queue is keyed on the
// invocation row's own turn, which need not equal the turn the
// executor event reports.
func dropPatchInvocation(queues map[string][]patchInvocation, idx int) {
	for turn, q := range queues {
		for i, cand := range q {
			if cand.idx == idx {
				queues[turn] = append(q[:i:i], q[i+1:]...)
				return
			}
		}
	}
}

// patchApplyTargetFromChanges picks the first key from a patch_apply_end
// changes map. Maps in Go have non-deterministic iteration order, but
// the codex executor typically emits a single-file patch — when there
// are multiple, any one is reasonable for the row's Target field.
func patchApplyTargetFromChanges(changes map[string]patchApplyChange, projectRoot string) string {
	for path := range changes {
		if path == "" {
			continue
		}
		if projectRoot != "" {
			return git.RelativePath(projectRoot, path)
		}
		return path
	}
	return ""
}

// mergeExecIntoPending overwrites the pending function_call row with the
// richer data from event_msg/exec_command_end. The row keeps its
// source_event_id (the call_id) and Tool/SessionID/MessageID/Model from
// the function_call side; everything else is updated.
func mergeExecIntoPending(row *models.ToolEvent, a *Adapter, ex execCommandEnd, endTS time.Time) {
	command := commandString(ex.Command)
	output := firstNonEmpty(ex.AggregatedOutput, ex.Stdout+ex.Stderr)
	scrubbedOutput := a.scrubber.String(output)
	success := ex.Status != "failed" && ex.ExitCode == 0
	row.ActionType = models.ActionRunCommand
	row.Target = truncate(a.scrubber.String(command), 200)
	row.Success = success
	row.ErrorMessage = errorIfFailed(success, scrubbedOutput)
	row.DurationMs = ex.Duration.Secs*1000 + ex.Duration.Nanos/1_000_000
	// When exec_command_end omits its structured duration (some Codex builds
	// emit a zero Duration), fall back to the begin(function_call)→end gap, the
	// same fallback the modern function_call_output path uses (§3.2). row's
	// Timestamp is the call's begin time; endTS is this exec_command_end's.
	if row.DurationMs == 0 && !row.Timestamp.IsZero() && !endTS.IsZero() {
		if d := endTS.Sub(row.Timestamp).Milliseconds(); d > 0 {
			row.DurationMs = d
		}
	}
	row.ToolOutput = scrubbedOutput
	row.RawToolName = "exec_command_end"
	row.RawToolInput = a.scrubber.RawJSON(ex.Command)
	row.ContentBytes = authoredBytes(models.ActionRunCommand, ex.Command)
}

// mergeWebSearchIntoPending overwrites the pending function_call row's
// Target field with the resolved query from event_msg/web_search_end. The
// call-side intent does not include the query text, so this merge is
// strictly additive.
func mergeWebSearchIntoPending(row *models.ToolEvent, ws webSearchEnd) {
	query := firstNonEmpty(ws.Query, ws.Action.Query, strings.Join(ws.Action.Queries, "; "))
	if query != "" {
		row.Target = truncate(query, 200)
	}
	row.ActionType = models.ActionWebSearch
	row.RawToolName = "web_search_end"
	if raw := webSearchRawInput(ws); raw != "" {
		row.RawToolInput = raw
	}
}

// unwrapFunctionArguments converts Codex's `arguments` field (a JSON
// string containing a JSON object, e.g. `"{\"command\":\"...\"}"` decoded
// to the Go string `{"command":"..."}`) into a json.RawMessage suitable
// for buildToolEvent. Empty input returns nil.
func unwrapFunctionArguments(args string) json.RawMessage {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	return json.RawMessage(args)
}

// unwrapStructuredOutput peels one level of JSON-string wrapping when the
// output payload is itself a JSON object with an "output" key (the codex
// custom_tool_call_output convention). Falls back to the raw string.
func unwrapStructuredOutput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '{' {
		return s
	}
	var m struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(s), &m); err == nil && m.Output != "" {
		return m.Output
	}
	return s
}

// parseExecFooter extracts the command's true wall time (in ms) and numeric
// exit code from an exec_command output footer, which Codex appends as plain
// text lines: "Wall time: 0.6788 seconds" and "Process exited with code 0".
// ok is false when neither line is present (a non-exec output, or a build that
// omits the footer) — the caller then falls back to the call->output gap. The
// scan is tolerant of surrounding output and case.
func parseExecFooter(output string) (wallMs int64, exitCode int, ok bool) {
	if output == "" {
		return 0, 0, false
	}
	for _, ln := range strings.Split(output, "\n") {
		ln = strings.TrimSpace(ln)
		lower := strings.ToLower(ln)
		switch {
		case strings.HasPrefix(lower, "wall time:"):
			f := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(ln[len("wall time:"):]), "seconds"))
			f = strings.TrimSpace(strings.TrimSuffix(f, "s"))
			if secs, err := strconv.ParseFloat(f, 64); err == nil && secs >= 0 {
				wallMs = int64(secs * 1000)
				ok = true
			}
		case strings.HasPrefix(lower, "process exited with code"):
			fields := strings.Fields(ln)
			if n := len(fields); n > 0 {
				if code, err := strconv.Atoi(strings.TrimRight(fields[n-1], ".")); err == nil {
					exitCode = code
					ok = true
				}
			}
		}
	}
	return wallMs, exitCode, ok
}

func payloadType(raw json.RawMessage) string {
	var env payloadEnvelope
	_ = json.Unmarshal(raw, &env)
	return env.Type
}

func (a *Adapter) buildUserPromptEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, lineNum int, message string) models.ToolEvent {
	message = strings.TrimSpace(message)
	msgID := ""
	if sess.TurnID != "" {
		msgID = "user:" + sess.TurnID
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      fmt.Sprintf("user:%s:L%d:%s", filepath.Base(sourceFile), lineNum, shortHash(message)),
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionUserPrompt,
		Target:             truncate(message, 200),
		Success:            true,
		PrecedingReasoning: truncate(message, 200),
		RawToolName:        "user_message",
		RawToolInput:       a.scrubber.String(message),
		MessageID:          msgID,
	}
}

// buildAgentMessageEvent emits a standalone assistant-text row for each
// `event_msg`/`agent_message` line in the rollout. Codex can emit multiple
// agent_messages per turn, so MessageID is content-hash-distinguished within
// the turn (turn_id alone collides on multi-message turns). SourceEventID
// uses the `:L<lineNum>:` format that's stable across re-parses (invariant
// 42). No token/cost fields are set — these rows are observability-only,
// not pricing inputs. Mirrors the Antigravity precedent at
// internal/adapter/antigravity/structured.go:443-461.
// codexServiceTier returns the operator's requested OpenAI processing tier
// ("priority" = Codex Fast mode, "flex" = slow/discount, "default"/"auto"
// = standard) read from the ~/.codex/config.toml that owns the given
// rollout file. The served tier is never recorded in the rollout JSONL
// (confirmed 2026-06-08: service_tier appears only as a tool-schema
// definition there, never a value), so config.toml is the sole node-local
// source on the watcher path; the proxy captures the authoritative served
// tier from the OpenAI response separately. Returns "" when the .codex
// root can't be located or no top-level service_tier is set. Cheap enough
// to call once per rollout file (config is a few KB).
func codexServiceTier(rolloutPath string) string {
	root := codexRootFromRollout(rolloutPath)
	if root == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(root, "config.toml"))
	if err != nil {
		return ""
	}
	return topLevelTomlString(string(data), "service_tier")
}

// codexRootFromRollout walks up from a rollout path
// (<root>/sessions/YYYY/MM/DD/rollout-*.jsonl) to the directory that holds
// the sessions/ tree — i.e. the .codex root that also holds config.toml.
// Returns "" if no sessions ancestor is found.
func codexRootFromRollout(rolloutPath string) string {
	dir := filepath.Dir(rolloutPath)
	for {
		if filepath.Base(dir) == "sessions" {
			return filepath.Dir(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "" // reached the filesystem root without finding sessions/
		}
		dir = parent
	}
}

// topLevelTomlString extracts a top-level (pre-first-table) string key from
// a TOML document without pulling in a full parser. TOML requires bare root
// keys to appear before any [table] header, so the scan stops at the first
// '['. Handles a trailing inline comment (" #...") and single/double
// quotes. Returns "" when the key is absent at the top level.
func topLevelTomlString(doc, key string) string {
	sc := bufio.NewScanner(strings.NewReader(doc))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			break // entered a table; root keys are done
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		return strings.Trim(v, `"'`)
	}
	return ""
}

func (a *Adapter) buildAgentMessageEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, lineNum int, message string) models.ToolEvent {
	turnID := sess.TurnID
	preview := truncate(a.scrubber.String(message), 200)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("agent:%s:L%d:%s", filepath.Base(sourceFile), lineNum, shortHash(message)),
		SessionID:     sess.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		// One row per agent_message event — codex emits several per turn
		// (see buildAgentMessageEvent's caller), so this is per-message
		// assistant text, not a turn terminus. The genuine terminus is
		// the `task_complete` event_msg row (buildTaskCompleteEvent).
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "codex.assistant_text",
		ToolOutput:         a.scrubber.String(contentcap.Cap(message, contentcap.DefaultMaxBytes)),
		MessageID:          "codex:agent:" + turnID + ":" + shortHash(message),
	}
}

func (a *Adapter) buildExecCommandEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, ex execCommandEnd, preceding string) models.ToolEvent {
	command := commandString(ex.Command)
	output := firstNonEmpty(ex.AggregatedOutput, ex.Stdout+ex.Stderr)
	scrubbedOutput := a.scrubber.String(output)
	success := ex.Status != "failed" && ex.ExitCode == 0
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(ex.CallID, "exec:"+shortHash(command+ts.String())),
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionRunCommand,
		Target:             truncate(a.scrubber.String(command), 200),
		Success:            success,
		ErrorMessage:       errorIfFailed(success, scrubbedOutput),
		DurationMs:         ex.Duration.Secs*1000 + ex.Duration.Nanos/1_000_000,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        "exec_command_end",
		RawToolInput:       a.scrubber.RawJSON(ex.Command),
		ToolOutput:         scrubbedOutput,
		ContentBytes:       authoredBytes(models.ActionRunCommand, ex.Command),
		MessageID:          firstNonEmpty(ex.TurnID, sess.TurnID),
	}
}

// buildCodexRateLimitEvent emits an ActionRateLimit ToolEvent from a
// Codex token_count.rate_limits envelope, reusing the generic
// schema the cowork adapter introduced (RateLimitStatus / Type /
// ResetsAt / OverageStatus on ActionMetadata). Codex emits two
// windows (primary / secondary) per snapshot — primary's resets_at
// goes onto the dedicated metadata field; the full envelope is
// preserved verbatim in RawToolInput so the dashboard can render
// the dual-window state without losing the secondary window.
//
// Stable source_event_id uses the filename + line number so
// re-parses are idempotent and the unique index dedups across
// scans without us having to track in-memory seenRateLimits state.
func buildCodexRateLimitEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, rl *codexRateLimits, lineNum int) models.ToolEvent {
	status := "ok"
	if rl.RateLimitReachedType != nil && *rl.RateLimitReachedType != "" {
		status = *rl.RateLimitReachedType
	}
	var primaryResetsAt int64
	if rl.Primary != nil {
		primaryResetsAt = rl.Primary.ResetsAt
	}
	meta := &models.ActionMetadata{
		RateLimitStatus:        status,
		RateLimitType:          rl.LimitID,
		RateLimitResetsAt:      primaryResetsAt,
		RateLimitOverageStatus: rl.PlanType,
	}
	rawJSON, _ := json.Marshal(rl)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("ratelimit:%s:L%d", filepath.Base(sourceFile), lineNum),
		SessionID:     sess.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     sess.GitBranch,
		GitRemote:     sess.GitRemote,
		Model:         sess.Model,
		Tool:          models.ToolCodex,
		ActionType:    models.ActionRateLimit,
		Target:        rl.LimitID,
		Success:       rl.RateLimitReachedType == nil || *rl.RateLimitReachedType == "",
		RawToolName:   status,
		RawToolInput:  string(rawJSON),
		MessageID:     fmt.Sprintf("ratelimit:%s:L%d", filepath.Base(sourceFile), lineNum),
		Metadata:      meta,
	}
}

func (a *Adapter) buildWebSearchEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, ws webSearchEnd, lineNum int, preceding string) models.ToolEvent {
	query := firstNonEmpty(ws.Query, ws.Action.Query, strings.Join(ws.Action.Queries, "; "))
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(ws.CallID, fmt.Sprintf("web:%s:L%d:%s", filepath.Base(sourceFile), lineNum, shortHash(query))),
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionWebSearch,
		Target:             truncate(query, 200),
		Success:            true,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        "web_search_end",
		RawToolInput:       a.scrubber.String(webSearchRawInput(ws)),
		MessageID:          firstNonEmpty(ws.TurnID, sess.TurnID),
	}
}

// webSearchRawInput serializes the full web_search_end action payload
// so the dashboard's RawToolInput render shows the multi-query
// fan-out — Codex's web_search tool issues 3-4 sub-queries per
// model-facing call (action.queries[]) and historically only the
// top-level Query string was preserved. Emit JSON when a fan-out
// exists; fall back to the bare query string otherwise so legacy
// renders stay readable for single-query calls.
func webSearchRawInput(ws webSearchEnd) string {
	if len(ws.Action.Queries) > 1 {
		payload := struct {
			Query   string   `json:"query"`
			Queries []string `json:"queries"`
		}{
			Query:   firstNonEmpty(ws.Query, ws.Action.Query),
			Queries: ws.Action.Queries,
		}
		if b, err := json.Marshal(payload); err == nil {
			return string(b)
		}
	}
	return firstNonEmpty(ws.Query, ws.Action.Query, strings.Join(ws.Action.Queries, "; "))
}

func (a *Adapter) buildTaskCompleteEvent(sourceFile string, sess sessionContext, projectRoot string, ts time.Time, done taskComplete, lineNum int) models.ToolEvent {
	if done.CompletedAt > 0 {
		ts = time.Unix(done.CompletedAt, 0).UTC()
	}
	evt := models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      fmt.Sprintf("complete:%s:%d", firstNonEmpty(done.TurnID, sess.SessionID, filepath.Base(sourceFile)), lineNum),
		SessionID:          firstNonEmpty(sess.SessionID, done.TurnID),
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         models.ActionTaskComplete,
		Target:             "task_complete",
		Success:            true,
		DurationMs:         done.DurationMs,
		PrecedingReasoning: truncate(done.LastAgentMessage, 200),
		RawToolName:        "task_complete",
		MessageID:          firstNonEmpty(done.TurnID, sess.TurnID),
	}
	// time_to_first_token_ms — codex 0.130+ only. Attaches to the
	// task_complete row's metadata so the dashboard's per-action
	// detail view + downstream queries can read it without a schema
	// change. Skipped when zero (older sessions / non-Desktop runs).
	if done.TimeToFirstTokenMS > 0 {
		if evt.Metadata == nil {
			evt.Metadata = &models.ActionMetadata{}
		}
		evt.Metadata.TimeToFirstTokenMS = done.TimeToFirstTokenMS
	}
	return evt
}

func (a *Adapter) buildToolEvent(
	sourceFile, callID string,
	sess sessionContext,
	projectRoot string,
	ts time.Time,
	toolName string,
	rawInput json.RawMessage,
	preceding string,
) models.ToolEvent {
	actionType, ok := actionMap[toolName]
	if !ok {
		actionType = models.ActionUnknown
	}
	scrubbedInput := a.scrubber.RawJSON(rawInput)
	target := a.extractTarget(toolName, rawInput, projectRoot)

	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      callID,
		SessionID:          sess.SessionID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		GitBranch:          sess.GitBranch,
		GitRemote:          sess.GitRemote,
		Model:              sess.Model,
		Tool:               models.ToolCodex,
		ActionType:         actionType,
		Target:             target,
		Success:            true,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        toolName,
		RawToolInput:       firstNonEmpty(scrubbedInput, scrub.Truncate(string(rawInput))),
		ContentBytes:       authoredBytes(actionType, rawInput),
		MessageID:          sess.TurnID,
	}
}

func (a *Adapter) extractTarget(toolName string, rawInput json.RawMessage, projectRoot string) string {
	if len(rawInput) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(rawInput, &m); err != nil {
		return ""
	}
	pickStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	// Run-command-class tools (shell / shell_command / exec_command / powershell
	// / pwsh / cmd.exe / …) carry the command in {"command": [...]|"..."} or
	// {"cmd":"..."}. Branch on the MAPPED ACTION rather than enumerating each
	// tool name, so a new shell alias in actionMap is covered automatically.
	// (exec_command — the modern Codex Desktop / CLI shell tool — was missing
	// from the old name list, leaving Target empty and breaking the
	// process→action message mapping that CorrelateActions keys on.)
	if actionMap[toolName] == models.ActionRunCommand {
		// Codex shell inputs: {"command": ["bash", "-lc", "..."]} or
		// {"command": "..."} (shell/shell_command) or {"cmd": "..."} (exec_command).
		if arr, ok := m["command"].([]any); ok && len(arr) > 0 {
			parts := make([]string, 0, len(arr))
			for _, p := range arr {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			return a.scrubber.String(strings.Join(parts, " "))
		}
		return a.scrubber.String(pickStr("command", "cmd"))
	}
	switch toolName {
	case "file_read", "file_write", "apply_patch", "view_image":
		fp := pickStr("path", "file_path", "filename", "target")
		if fp == "" {
			return ""
		}
		if projectRoot != "" {
			return git.RelativePath(projectRoot, fp)
		}
		return fp
	case "web_search":
		return pickStr("query", "q")
	}
	return ""
}

// projectGitInfo is the per-cwd cache entry for resolveProjectRoot /
// resolveProjectRemote: the resolved project root and its normalized
// "origin" remote, captured together from a single git.ResolveIdentity
// call so the two never drift and the filesystem walk never happens
// twice for the same cwd. Identity carries the fuller Project Identity
// Resolver v2 bundle from the same call.
type projectGitInfo struct {
	Root     string
	Remote   string
	Identity git.Identity
}

func (a *Adapter) resolveProjectRoot(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return ""
	}
	// Codex on Windows records cwd as a Windows-style path (e.g.
	// "c:\programsx\regulation"). When that JSONL is parsed by an
	// observer running in WSL2, filepath.Abs treats the string as
	// relative because Linux doesn't recognise the drive prefix —
	// which prepends the observer's CWD and then findGitRoot walks UP
	// looking for .git. In the worst case it lands on observer's own
	// repo and every codex action gets misattributed. Translate to
	// the WSL2 mount equivalent ("/mnt/c/programsx/regulation") so
	// git.Resolve operates on the actual cross-mount path. No-op on
	// Windows hosts and on cwds that already look like native paths.
	cwd = crossmount.TranslateForeignPath(cwd)
	if entry, ok := cache[cwd]; ok {
		return entry.Root
	}
	// RootCommit is left nil: the lazy, cached root-commit exec belongs
	// only in the store-side path (Store.maybeRunLazyRootCommit), never
	// on a per-line adapter hot path.
	info, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		cache[cwd] = projectGitInfo{Root: cwd}
		return cwd
	}
	// info.Remote is already NormalizeRemote'd by ResolveIdentity.
	cache[cwd] = projectGitInfo{Root: info.Root, Remote: info.Remote, Identity: info}
	return info.Root
}

// resolveProjectRemote returns the normalized git remote for cwd, cached
// alongside the project root by resolveProjectRoot. Callers must invoke
// resolveProjectRoot for the same cwd first so the cache entry exists —
// this never triggers its own git.Resolve call, to avoid resolving the
// same cwd twice.
func (a *Adapter) resolveProjectRemote(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	return cache[cwd].Remote
}

// identitiesByRoot flattens a per-cwd projectGitInfo cache into a
// per-root git.Identity map suitable for
// adapter.ApplyProjectIdentityByRoot. Multiple cwds resolving to the
// same repo root collapse to one entry (they carry identical
// identity, since ResolveIdentity is keyed off the discovered root).
func identitiesByRoot(cache map[string]projectGitInfo) map[string]git.Identity {
	out := make(map[string]git.Identity, len(cache))
	for _, entry := range cache {
		if entry.Root == "" {
			continue
		}
		out[entry.Root] = entry.Identity
	}
	return out
}

func decodeOutput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	if trimmed[0] == '"' {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	var m struct {
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
		Output string `json:"output"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal(raw, &m); err == nil {
		switch {
		case m.Output != "":
			return m.Output
		case m.Text != "":
			return m.Text
		case m.Stdout != "" || m.Stderr != "":
			return m.Stdout + m.Stderr
		}
	}
	return string(raw)
}

// parseModernTokenCount extracts the per-call usage (last_token_usage)
// AND the cumulative session total (total_token_usage) from a Codex
// modern event_msg/token_count payload. The total is returned for
// dedup purposes — Codex sometimes re-emits an identical token_count
// record (same last + same total) which, if not skipped, double-counts
// that turn's usage in the database. Caller uses the total as a
// fingerprint and skips emission when it matches the previous total
// for the same session. Total is monotonic, so a non-advancing total
// is always a re-emission.
func parseModernTokenCount(raw json.RawMessage) (tokenCount, tokenUsage, bool) {
	var mt modernTokenCount
	if err := json.Unmarshal(raw, &mt); err != nil {
		return tokenCount{}, tokenUsage{}, false
	}
	usage := mt.Info.LastTokenUsage
	if usage.InputTokens == 0 && usage.OutputTokens == 0 && usage.TotalTokens == 0 &&
		usage.CachedInputTokens == 0 && usage.ReasoningTokens == 0 {
		return tokenCount{}, tokenUsage{}, false
	}
	return tokenCount{
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		TotalTokens:  usage.TotalTokens,
		Cached:       usage.CachedInputTokens,
		Reasoning:    usage.ReasoningTokens,
	}, mt.Info.TotalTokenUsage, true
}

// parseModernRateLimits extracts the rate_limits envelope from a
// token_count event_msg payload. Returns nil when the field is
// absent. Independent of the token-usage path because Codex emits
// the startup token_count with `info: null` but rate_limits already
// populated — we want to capture that snapshot too.
func parseModernRateLimits(raw json.RawMessage) *codexRateLimits {
	var probe struct {
		RateLimits *codexRateLimits `json:"rate_limits"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil
	}
	return probe.RateLimits
}

func commandString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []string
	if err := json.Unmarshal(raw, &parts); err == nil {
		return strings.Join(parts, " ")
	}
	return string(raw)
}

// authoredBytes returns the byte length of code/commands authored by the
// model in a Codex tool input. It measures the original untruncated payload
// and never stores the authored body.
func authoredBytes(actionType string, rawInput []byte) int64 {
	if len(rawInput) == 0 {
		return 0
	}
	switch actionType {
	case models.ActionRunCommand:
		var in struct {
			Command any    `json:"command"`
			Cmd     string `json:"cmd"`
		}
		if err := json.Unmarshal(rawInput, &in); err == nil {
			if in.Cmd != "" {
				return int64(len(in.Cmd))
			}
			if in.Command != nil {
				if b, err := json.Marshal(in.Command); err == nil {
					return int64(len(commandString(b)))
				}
			}
		}
		return int64(len(commandString(json.RawMessage(rawInput))))
	case models.ActionWriteFile, models.ActionEditFile:
	default:
		return 0
	}

	trimmed := strings.TrimSpace(string(rawInput))
	if strings.HasPrefix(trimmed, "*** Begin Patch") {
		return authoredBytesFromPatch(trimmed)
	}
	var in struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		NewSource string `json:"new_source"`
		Input     string `json:"input"`
		Patch     string `json:"patch"`
		Command   string `json:"command"`
		Cmd       string `json:"cmd"`
		Edits     []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(rawInput, &in); err != nil {
		return 0
	}
	switch actionType {
	case models.ActionWriteFile:
		return int64(len(in.Content))
	case models.ActionEditFile:
		n := int64(len(in.NewString) + len(in.NewSource))
		for _, e := range in.Edits {
			n += int64(len(e.NewString))
		}
		for _, patch := range []string{in.Patch, in.Input} {
			if strings.HasPrefix(strings.TrimSpace(patch), "*** Begin Patch") {
				n += authoredBytesFromPatch(patch)
			}
		}
		return n
	default:
		return 0
	}
}

func authoredBytesFromPatch(patch string) int64 {
	var n int64
	for _, line := range strings.Split(patch, "\n") {
		// No "+++" exclusion. Every caller is gated on the apply_patch
		// envelope (`*** Begin Patch`), which uses `*** Add/Update File:`
		// headers and never unified-diff `+++ b/file` ones — so the skip
		// guarded a construct that cannot arrive here, while silently
		// dropping real added source whose own text begins "++" (a C-style
		// increment: source `++n` encodes as `+++n`, and source `++ n` as
		// `+++ n`, so narrowing the predicate to require the space did not
		// fix it either). Zero lines beginning "+++" of any kind exist in
		// the reference corpus, so removing this changes no historical
		// count — it only stops a future undercount.
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "+") {
			n += int64(len(strings.TrimPrefix(line, "+")))
		}
	}
	return n
}

func authoredBytesFromPatchChanges(changes map[string]patchApplyChange) int64 {
	var n int64
	for _, ch := range changes {
		if ch.Type == "delete" {
			continue
		}
		// UnifiedDiff is deliberately NOT counted, and this is the second
		// time that needs saying: an `update` change carries only
		// `unified_diff` (2,746 of the 3,492 changes in the reference
		// corpus), so it scores zero here and that LOOKS like a bug.
		//
		// It is not — in the overwhelmingly common case. A patch normally
		// ALSO emits an INVOCATION row from its custom_tool_call, and that
		// row already counts the same authored bytes from its own
		// `*** Begin Patch` text: measured on a live rollout, 107
		// invocation rows / 142,823 B alongside 95 executor rows. Counting
		// the diff here too double-counts authored output on every update,
		// which is exactly what happened when this line was briefly added.
		//
		// The honest caveat: an executor row with NO invocation row (a
		// truncated or mid-session-resumed rollout) therefore reports 0
		// authored bytes for an update-only patch. That is real measurement
		// loss on the recovery path, accepted because the recovery path is
		// rare and the double-count was not.
		//
		// Note `add` content below is STILL double-counted for the same
		// structural reason (~4.0 MB across the reference corpus). Fixing
		// that properly means collapsing the duplicate ROW, not making one
		// of the two rows lie about what it measured.
		n += int64(len(ch.Content))
	}
	return n
}

func errorIfFailed(success bool, output string) string {
	if success {
		return ""
	}
	if output == "" {
		return "(no output)"
	}
	return truncate(output, 2048)
}

func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end {
		c := b[start]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			start++
			continue
		}
		break
	}
	for end > start {
		c := b[end-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			end--
			continue
		}
		break
	}
	return b[start:end]
}

func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

func sessionIDFromPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".jsonl")
	base = strings.TrimPrefix(base, "rollout-")
	return base
}

// resumePrefix is the state prefetchSessionContext reconstructs from
// the bytes preceding an incremental resume offset. Everything in it
// is state a fromOffset==0 parse would have accumulated by the time it
// reached that offset — it never carries emitted events, so replaying
// the prefix stays side-effect-free.
type resumePrefix struct {
	// ctx is the session context (SessionID, Cwd, Model, GitBranch,
	// EffortLevel) latched from the leading session_meta/turn_context.
	ctx sessionContext
	// track is the fork-replay tracker (owner latch + fork mark + turn
	// governance) rebuilt from the same prefix lines.
	track forkReplayTracker
	// lineCount is the number of terminated records that fit entirely
	// before the resume offset; the resumed parse continues its
	// absolute lineNum from here so `:L<n>:` SourceEventIDs stay stable
	// against a full rescan.
	lineCount int
	// modernTotal / haveTotal carry the last non-zero
	// total_token_usage seen in the prefix — the baseline the resumed
	// parse's seenModernTotal must start from so a token_count Codex
	// re-emits across the poll boundary is recognized as the
	// duplicate it is.
	modernTotal tokenUsage
	haveTotal   bool
	// systemPrompts holds shortHash values of system-prompt bodies
	// (session_meta base_instructions, turn_context
	// developer_instructions) already emitted before the offset, so the
	// resumed parse's seenSystemPrompts suppresses the repeats exactly
	// as an uninterrupted parse would. Response-item developer/user-
	// envelope bodies are deliberately NOT seeded here — see the
	// docstring of prefetchSessionContext.
	systemPrompts map[string]bool
}

// noteSystemPrompt records the hash of a system-prompt body under the
// exact same trim + hash rules systemPromptEvent applies, so a seeded
// hash always matches the one the live parse would have stored. No-op
// for empty bodies.
func (p *resumePrefix) noteSystemPrompt(body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	if p.systemPrompts == nil {
		p.systemPrompts = map[string]bool{}
	}
	p.systemPrompts[shortHash(body)] = true
}

// prefetchSessionContext scans the file's leading bytes (up to `until`)
// for session_meta / session_configured / turn_context lines and returns
// the most recent context fields seen before the resume offset, a
// reconstructed forkReplayTracker, plus the count of lines that preceded
// the offset. Used by ParseSessionFile when fromOffset > 0 so resumed
// parses inherit:
//
//  1. The SessionID, Cwd, Model, GitBranch, and EffortLevel from the
//     leading session_meta / turn_context — without them every emitted
//     event would be dropped by store.Ingest (empty ProjectRoot is a
//     hard skip) and effort_level metadata would never populate on
//     resumed cycles.
//
//  2. The absolute line count up to the resume offset. SourceEventIDs
//     that embed `:L<linenum>:` need this to be stable across re-parses
//     — without it, a chunk-relative line number drifts from the
//     absolute one and `observer scan --force` creates duplicate rows.
//
//  3. The forkReplayTracker state (owner latch + fork mark + turn
//     governance) rebuilt from the same prefix lines, so a watcher poll
//     that ends mid-replay-burst resumes with correct fork-replay
//     classification instead of emitting the rest of the replayed
//     history as live. Rebuilt from the bytes already read — no second
//     file pass.
//
//  4. The cross-parse DEDUP state — the last non-zero
//     total_token_usage (seenModernTotal's baseline) and the set of
//     system-prompt body hashes already emitted (seenSystemPrompts).
//     Both are per-parse maps, so without this a re-emitted
//     token_count / instructions body that straddles the resume
//     boundary produced a duplicate row that no store-side key could
//     collapse (their ids embed the line number). Replayed in
//     STATE-ONLY mode: nothing is emitted, and the only extra decode
//     work is parseModernTokenCount on token_count payloads — the
//     instruction hashes come from the session_meta / turn_context
//     payloads this scan already unmarshals. The third system-prompt
//     source (response_item messages with role developer / a `<`-
//     prefixed user envelope) is deliberately NOT seeded: harvesting
//     it would mean deep-decoding every response_item message line of
//     the prefix on EVERY watcher poll, and unlike
//     developer_instructions those bodies don't repeat per turn. A
//     missing seed only costs a duplicate row, never a lost one.
//
// The function leaves the file cursor positioned wherever Seek-by-caller
// chooses; ParseSessionFile re-seeks to fromOffset right after this
// returns. Returns ok=false only if the file cannot be re-read from
// the start; in that case the caller falls back to the filename-derived
// SessionID, empty cwd, and lineNum starting at 0 (the pre-fix
// behavior — accepting the duplication risk).
func prefetchSessionContext(f *os.File, until int64) (resumePrefix, bool) {
	var pre resumePrefix
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return resumePrefix{}, false
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	var (
		bytesRead int64
		lineNum   int
		out       sessionContext
		track     forkReplayTracker
	)
	for {
		lineStr, consumed, oversized, err := readRecord(reader, maxRecordBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			// Best-effort prefetch: a mid-scan read error just stops the
			// context reconstruction early. ok stays true — the main
			// parse re-seeks to fromOffset and re-reads regardless.
			break
		}
		if consumed == 0 {
			break
		}
		// Same unified deferral rule as ParseSessionFile: an io.EOF from
		// readRecord marks an unterminated final fragment (no '\n'). The
		// live parse defers it whole, so prefetch must NOT count or apply
		// it either — line-number lockstep requires prefetch classify the
		// exact same set of terminated records the parser does.
		if errors.Is(err, io.EOF) {
			break
		}
		bytesRead += consumed // terminator-inclusive; matches ParseSessionFile
		if bytesRead > until {
			// Don't apply context from a line that straddles the resume
			// offset — the resumed parse will see (and apply) it itself.
			// Also don't bump lineNum for the straddling line — the
			// resumed parse will increment its own counter for it.
			break
		}
		// Count every line that fits before `until`, including empty
		// (and oversized-skipped) lines, to mirror ParseSessionFile's
		// lineNum semantics (it increments before the empty-line skip).
		lineNum++
		if oversized {
			// Mirror the live parse: a skipped oversized record CLEARS
			// governance (fail-open to live) so a following token_count
			// isn't misclassified against stale governance on resume.
			track.observeTaskStarted(0, false)
			continue
		}
		raw := bytes.TrimRight(lineStr, "\r\n")
		var line rawLine
		if err := json.Unmarshal(raw, &line); err != nil {
			// A whole malformed envelope CLEARS governance (fail-open to
			// live), mirroring the live parse: were this the replayed
			// task_started, leaving governance stale would misclassify a
			// following live token_count as replayed on resume.
			track.observeTaskStarted(0, false)
			continue
		}
		switch line.Type {
		case "session_meta":
			var meta sessionMetaPayload
			if err := json.Unmarshal(line.Payload, &meta); err == nil {
				// Reconstruct fork-replay state so an incremental resume
				// mid-burst keeps correct owner-latching + fork-marking.
				created, have := sessionMetaCreationSec(meta, line.Timestamp)
				track.observeSessionMeta(
					firstNonEmpty(meta.ID, meta.SessionID),
					meta.ForkedFromID, meta.ParentThreadID, meta.ThreadSource,
					created, have,
				)
				out = mergeSessionContext(out, meta.sessionContext)
				// Same source + same trim as the live parse's
				// systemPromptEvent call site, so the seeded hash
				// matches byte-for-byte what a fromOffset==0 parse
				// would have recorded.
				pre.noteSystemPrompt(meta.BaseInstructions.Text)
			}
		case "event_msg":
			// Feed task_started governance into the reconstructed tracker
			// so a resume starting after a replayed task_started (but
			// before its token_counts) still classifies them as replayed.
			// Mirror the live parse: a malformed task_started CLEARS
			// governance (fail-open to live); other event_msg payloads are
			// context-irrelevant to the tracker and skipped here — except
			// token_count, whose cumulative total seeds the dedup baseline
			// (see resumePrefix).
			switch payloadType(line.Payload) {
			case "task_started":
				var started taskStarted
				if err := json.Unmarshal(line.Payload, &started); err == nil {
					track.observeTaskStarted(started.StartedAt, started.StartedAt != 0)
				} else {
					track.observeTaskStarted(0, false)
				}
			case "token_count":
				// State-only: mirror the live parse's
				// seenModernTotal update (same parse function, same
				// non-zero-total gate) WITHOUT emitting anything.
				// The live parse updates the baseline for replayed
				// token_counts too, so no fork-replay branch here.
				if _, total, ok := parseModernTokenCount(line.Payload); ok && total != (tokenUsage{}) {
					pre.modernTotal = total
					pre.haveTotal = true
				}
			}
		case "session_configured", "session_start", "turn_context":
			var meta turnContextPayload
			if err := json.Unmarshal(line.Payload, &meta); err == nil {
				// Lift effort from the nested envelope BEFORE merge —
				// EffortLevel is tagged `json:"-"` so it never populates
				// from the unmarshal directly. Mirrors the live-parse
				// path at line 779-791. Without this, every watcher
				// resume past a `reasoning_effort: "medium"` turn_context
				// dropped effort_level on subsequent events (verified
				// 2026-05-11 on session 019e1743 — empty effort even
				// though the JSONL had medium set).
				sc := meta.sessionContext
				if effort := meta.EffortFromPayload(); effort != "" {
					sc.EffortLevel = effort
				}
				out = mergeSessionContext(out, sc)
				pre.noteSystemPrompt(meta.DeveloperInstructions)
			}
		}
	}
	pre.ctx = out
	pre.track = track
	pre.lineCount = lineNum
	return pre, true
}

// mergeSessionContext copies non-empty fields from `from` over `into`
// using the same precedence rules ParseSessionFile's applyContext
// closure follows for the parsing pass. Pure value semantics — no
// side effects on pending model maps or queued tool events (those are
// only valid during the live parse).
func mergeSessionContext(into, from sessionContext) sessionContext {
	// Mirror ParseSessionFile's file-ownership rule: first non-empty
	// SessionID seen in the file wins. Required for watcher resumes,
	// where prefetchSessionContext may see both the child session_meta
	// and a replayed parent session_meta before the resumed parse
	// starts emitting rows.
	if into.SessionID == "" {
		if from.ID != "" {
			into.SessionID = from.ID
		}
		if into.SessionID == "" && from.SessionID != "" {
			into.SessionID = from.SessionID
		}
	}
	if from.TurnID != "" {
		into.TurnID = from.TurnID
	}
	if from.Model != "" {
		into.Model = from.Model
	}
	if from.Cwd != "" {
		into.Cwd = from.Cwd
	}
	if from.GitBranch != "" {
		into.GitBranch = from.GitBranch
	}
	if from.GitRemote != "" {
		into.GitRemote = from.GitRemote
	}
	// EffortLevel follows the same sticky rule as applyContext — a
	// later non-empty value wins, empty does NOT wipe a prior value.
	// Required for watcher-cycle continuity: when the leading
	// turn_context with `reasoning_effort: "medium"` lives before the
	// resume offset, this is the only path that propagates it into
	// the resumed parse's ctxState.
	if from.EffortLevel != "" {
		into.EffortLevel = from.EffortLevel
	}
	return into
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
