package codebuddy

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// rawLine is one JSONL line of a CodeBuddy Code transcript. Every line
// is a serialized @openai/agents-core `AgentInputItem` (the vendor ships
// agents-core 0.5.2) plus CodeBuddy's own envelope fields (`sessionId`,
// `cwd`, `timestamp`, `parentId`, `_meta`, `__codebuddyLocal`), or one of
// CodeBuddy's own bookkeeping records (`session-meta`,
// `file-history-snapshot`, `summary`). All shapes share one struct,
// discriminated by Type; fields absent on a given shape stay zero.
//
// GROUNDED from the 2026-10-21 captures (both OSes): type, id, parentId,
// sessionId, timestamp (epoch MILLISECONDS), cwd, role, status, content
// parts `input_text` / `output_text`, providerData.{skipRun, agent,
// conversationRequestId, error}. Also GROUNDED by the 2026-10-21
// hook-probe sessions (a loopback mock model drove real CLI tool
// execution, so the RECORD SHAPES are real CLI output while the model
// text, token numbers and call ids are mock values): callId, name,
// arguments (JSON string), output ({type:"text",text}), status
// (completed / incomplete) and providerData.{messageId, stepSeq, model,
// requestModelId, requestModelName, traceId, usage, rawUsage, toolResult}.
// Grounded only from the vendor's own agents-core schema / bundle (no live
// line): hosted_tool_call, reasoning, input_image / input_file parts,
// _fromSubAgent, compaction summaries.
type rawLine struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	ParentID  string          `json:"parentId"`
	SessionID string          `json:"sessionId"`
	Timestamp msTime          `json:"timestamp"`
	Cwd       string          `json:"cwd"`
	Role      string          `json:"role"`
	Status    string          `json:"status"`
	Content   json.RawMessage `json:"content"`
	// function_call / function_call_result (shape LIVE, hook probe);
	// hosted_tool_call (UNVERIFIED — agents-core schema, no live line).
	CallID    string          `json:"callId"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Output    json.RawMessage `json:"output"`
	IsError   *bool           `json:"isError"`
	// RawContent is the reasoning item's `reasoning_text` parts
	// (UNVERIFIED — agents-core schema; the mock model never reasons),
	// read when `content` is empty.
	RawContent json.RawMessage `json:"rawContent"`
	// FromSubAgent is CodeBuddy's in-memory marker on an item a sub-agent
	// forwarded into the main session's input stream (vendor bundle:
	// `mainSession.inputSubject.next({...item,_fromSubAgent:!0})`). Whether
	// it survives into the persisted line is UNVERIFIED; when present it
	// flags the row as a sidechain.
	FromSubAgent bool             `json:"_fromSubAgent"`
	ProviderData *rawProviderData `json:"providerData"`
}

// rawProviderData is the per-item `providerData` record. CodeBuddy
// stores its turn id, generation id, model, usage and error here.
type rawProviderData struct {
	// SkipRun marks a record that was never sent to the model: local
	// slash-command bookkeeping (`<command-name>/model</command-name>`,
	// `<local-command-stdout>…`) and locally synthesized errors. GROUNDED.
	SkipRun bool `json:"skipRun"`
	// Agent is the agent that produced the item (`ptc`, the main agent,
	// on every grounded line). GROUNDED.
	Agent string `json:"agent"`
	// ConversationRequestID is the user-turn id (the vendor's hooks
	// `generation_id`). GROUNDED.
	ConversationRequestID string `json:"conversationRequestId"`
	// MessageID groups every item of ONE model generation (vendor
	// CHANGELOG: "model generation continues to be grouped by
	// providerData.messageId"). LIVE (hook probe): a function_call, its
	// function_call_result and the next assistant message each carry the
	// messageId of the generation that produced them.
	MessageID string `json:"messageId"`
	// Model / RequestModelID — the vendor's readExecutedModelId reads
	// `requestModelId ?? model`. LIVE (hook probe): both carry the model id
	// the CLI REQUESTED ("hy3"); because the probe upstream was a mock this
	// proves the field positions, not that a real provider echoes the
	// executed model back.
	Model          string `json:"model"`
	RequestModelID string `json:"requestModelId"`
	// Usage is the agents-core Usage instance; RawUsage the provider's own
	// usage object, which the vendor prefers for cache counts. LIVE shape:
	// both ride EVERY item of a generation (each function_call and the
	// assistant message), not only the last, so the per-messageId MAX merge
	// in emitTokens is what keeps one row per generation. The NUMBERS were
	// mock values (10 in / 5 out).
	Usage    *rawUsage `json:"usage"`
	RawUsage *rawUsage `json:"rawUsage"`
	// Source is a summary record's origin: "initial-user-message" (the
	// session title seed, LIVE) or "pre-compact" / "periodic" (a context
	// compaction summary, vendor bundle only, never observed live).
	Source string `json:"source"`
	// HookEvent / HookStatus / BlockingDetails describe a hook-BLOCKED user
	// prompt: CodeBuddy persists the block as an assistant message
	// (skipRun:true, hookStatus:"blocked"). LIVE (hook probe).
	HookEvent       string `json:"hookEvent"`
	HookStatus      string `json:"hookStatus"`
	BlockingDetails []struct {
		Reason string `json:"reason"`
	} `json:"blockingDetails"`
	// Error is an object `{message,isNetworkError,isStreamTimeout,
	// isRetryable}` on an errored assistant record (GROUNDED) and a
	// string-or-object on an errored tool result (vendor
	// createToolCallResultItem). LIVE on a permission-denied call: both
	// toolResult.content and toolResult.error carry the denial text.
	Error      json.RawMessage `json:"error"`
	ToolResult *struct {
		Error json.RawMessage `json:"error"`
		// RawResponse is the Bash tool's structured outcome (LIVE, hook
		// probe): {exitCode, signal, interrupted, sandboxDenied, ...}.
		RawResponse *struct {
			ExitCode    *int `json:"exitCode"`
			Interrupted bool `json:"interrupted"`
		} `json:"rawResponse"`
	} `json:"toolResult"`
}

// sourceOf returns a summary record's providerData.source, nil-safe.
func (pd *rawProviderData) sourceOf() string {
	if pd == nil {
		return ""
	}
	return strings.TrimSpace(pd.Source)
}

// rawUsage decodes both the agents-core Usage instance (camelCase:
// requests / inputTokens / outputTokens / totalTokens /
// inputTokensDetails / outputTokensDetails, the details either an array
// of records or one record) and a raw provider usage object
// (snake_case Anthropic / OpenAI / DeepSeek spellings), because the
// vendor reads cache counts off `rawUsage || usage` with the same
// first-positive ladder. LIVE shapes (hook probe): usage {requests,
// inputTokens, outputTokens, totalTokens, inputTokensDetails:[{cached_tokens}],
// outputTokensDetails:[{reasoning_tokens}]} and rawUsage {prompt_tokens,
// completion_tokens, total_tokens}; the numbers were mock values, and no
// cache-write or provider-reasoning field has been seen with a non-zero
// value.
type rawUsage struct {
	InputTokens         int64           `json:"inputTokens"`
	OutputTokens        int64           `json:"outputTokens"`
	InputTokensSnake    int64           `json:"input_tokens"`
	OutputTokensSnake   int64           `json:"output_tokens"`
	PromptTokens        int64           `json:"prompt_tokens"`
	CompletionTokens    int64           `json:"completion_tokens"`
	InputTokensDetails  json.RawMessage `json:"inputTokensDetails"`
	OutputTokensDetails json.RawMessage `json:"outputTokensDetails"`
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	CompletionTokensDetails *struct {
		ReasoningTokens int64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
	CacheReadInputTokens      int64 `json:"cache_read_input_tokens"`
	CacheReadInputTokensCamel int64 `json:"cacheReadInputTokens"`
	PromptCacheHitTokens      int64 `json:"prompt_cache_hit_tokens"`
	CacheCreationInputTokens  int64 `json:"cache_creation_input_tokens"`
	CacheCreationTokensCamel  int64 `json:"cacheCreationInputTokens"`
	PromptCacheWriteTokens    int64 `json:"prompt_cache_write_tokens"`
}

// msTime decodes CodeBuddy's `timestamp`: epoch MILLISECONDS as a JSON
// number on every grounded line. A numeric string or an RFC3339 string
// is tolerated defensively; anything else decodes to the zero time
// without failing the line.
type msTime struct{ t time.Time }

// UnmarshalJSON implements json.Unmarshaler. It never returns an error,
// so a malformed timestamp costs only the timestamp, never the line.
func (m *msTime) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	s := string(b)
	if b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return nil
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, str); err == nil {
				m.t = t.UTC()
				return nil
			}
		}
		s = str
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return nil
	}
	m.t = time.UnixMilli(int64(f)).UTC()
	return nil
}

// rawPart is one message content part. Grounded: input_text (user) and
// output_text (assistant). input_image / input_file / refusal come from
// the agents-core schema.
type rawPart struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Refusal string          `json:"refusal"`
	Image   json.RawMessage `json:"image"`
}

// parts decodes a message's content: an array of parts on every grounded
// line, with a bare string tolerated (agents-core allows string content
// on a user message) by folding it into one input_text part.
func parts(raw json.RawMessage) []rawPart {
	if len(raw) == 0 {
		return nil
	}
	var ps []rawPart
	if err := json.Unmarshal(raw, &ps); err == nil {
		return ps
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && strings.TrimSpace(s) != "" {
		return []rawPart{{Type: "input_text", Text: s}}
	}
	return nil
}

// partsText concatenates the text-bearing parts of a message.
func partsText(ps []rawPart) string {
	var b strings.Builder
	for _, p := range ps {
		text := p.Text
		if p.Type == "refusal" && text == "" {
			text = p.Refusal
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(text)
	}
	return b.String()
}

// userAttachments resolves a user message's non-text parts into
// PRESENCE + KIND (+ media type from a data-URI prefix) — never a
// filename and never bytes. UNVERIFIED: no attachment line captured; the
// part names come from the agents-core schema.
func userAttachments(ps []rawPart) []models.UserAttachment {
	var atts []models.UserAttachment
	for _, p := range ps {
		switch p.Type {
		case "input_image", "image":
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: dataURIMediaType(p.Image)})
		case "input_file", "file":
			atts = append(atts, models.UserAttachment{Kind: "file"})
		case "audio", "input_audio":
			atts = append(atts, models.UserAttachment{Kind: "audio"})
		}
	}
	return atts
}

// dataURIMediaType returns the IANA media type of a `data:<type>;…`
// image string, reading only the prefix (the base64 payload is never
// decoded). Empty for a URL, a file id or anything else.
func dataURIMediaType(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	if !strings.HasPrefix(s, "data:") {
		return ""
	}
	rest := s[len("data:"):]
	end := strings.IndexAny(rest, ";,")
	if end <= 0 {
		return ""
	}
	return rest[:end]
}

// metaUserPrefixes mark harness-injected user text: the local-command
// caveat wrapper, slash-command envelopes and command stdout, all of
// which CodeBuddy writes as role:"user" messages (GROUNDED, with
// providerData.skipRun:true). They are the harness talking, not the
// operator, and never become user_prompt rows.
var metaUserPrefixes = []string{
	"<system-reminder",
	"<command-name>",
	"<command-message>",
	"<command-args>",
	"<local-command-stdout>",
	"<local-command-stderr>",
	"<local-command-caveat>",
	"<bash-input>",
	"<bash-stdout>",
	"<bash-stderr>",
}

// isMetaUserText reports whether s is a harness-injected user record.
func isMetaUserText(s string) bool {
	s = strings.TrimSpace(s)
	for _, p := range metaUserPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// errorMessage extracts a human-readable message from a providerData
// `error` value: a bare string, or an object carrying `message`. Empty
// for null / false / an empty value.
func errorMessage(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "false" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if m := strings.TrimSpace(obj.Message); m != "" {
			return m
		}
		if m := strings.TrimSpace(obj.Error); m != "" {
			return m
		}
	}
	return string(raw)
}

// errorClass returns a short class for a grounded assistant error
// object, from its boolean flags. "error" when none is set.
func errorClass(raw json.RawMessage) string {
	var obj struct {
		IsNetworkError  bool `json:"isNetworkError"`
		IsStreamTimeout bool `json:"isStreamTimeout"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "error"
	}
	switch {
	case obj.IsStreamTimeout:
		return "stream_timeout"
	case obj.IsNetworkError:
		return "network_error"
	default:
		return "error"
	}
}

// resultFailed reports whether a function_call_result records a failed
// call, by the vendor's own rules (bundle 2.171.0): status `incomplete`
// (what createToolCallResultItem writes whenever it is given an error;
// LIVE on every permission-denied call), `error` or `failed`;
// `isError: true`; a non-empty providerData.error; a non-empty
// providerData.toolResult.error (LIVE on a denied call); or a Bash
// rawResponse that was interrupted or exited non-zero (shape LIVE with
// exitCode 0; the mock never produced a non-zero exit).
func resultFailed(rec *rawLine) (bool, string) {
	switch rec.Status {
	case "incomplete", "error", "failed":
		msg := ""
		if rec.ProviderData != nil {
			msg = errorMessage(rec.ProviderData.Error)
		}
		return true, msg
	}
	if rec.IsError != nil && *rec.IsError {
		return true, ""
	}
	if pd := rec.ProviderData; pd != nil {
		if m := errorMessage(pd.Error); m != "" {
			return true, m
		}
		if pd.ToolResult != nil {
			if m := errorMessage(pd.ToolResult.Error); m != "" {
				return true, m
			}
			if rr := pd.ToolResult.RawResponse; rr != nil {
				if rr.Interrupted {
					return true, "interrupted"
				}
				if rr.ExitCode != nil && *rr.ExitCode != 0 {
					return true, "exit code " + strconv.Itoa(*rr.ExitCode)
				}
			}
		}
	}
	return false, ""
}

// outputText flattens a function_call_result `output` (a bare string, a
// `{type:"text",text}` object, or an array of `{type:"input_text",text}`
// parts per the agents-core schema) into plain text. Image / file parts
// contribute nothing.
func outputText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var one rawPart
	if raw[0] == '{' {
		if err := json.Unmarshal(raw, &one); err == nil {
			return one.Text
		}
		return ""
	}
	var many []rawPart
	if err := json.Unmarshal(raw, &many); err == nil {
		return partsText(many)
	}
	return ""
}

// tokenParts is the NET-token view derived from a usage envelope.
type tokenParts struct {
	inputNet  int64
	output    int64
	cacheRead int64
	cacheWrit int64
	reasoning int64
}

// isZero reports whether the derived parts carry nothing worth a row.
func (p tokenParts) isZero() bool {
	return p.inputNet == 0 && p.output == 0 && p.cacheRead == 0 &&
		p.cacheWrit == 0 && p.reasoning == 0
}

// tokenBundle converts a CodeBuddy usage pair into NET token counts.
// The usage envelope SHAPES (agents-core camelCase Usage with
// array-shaped inputTokensDetails / outputTokensDetails, plus the
// provider's snake_case rawUsage) are LIVE from the 2026-10-21 hook-probe
// sessions, but the upstream was a mock returning constant 10 / 5 tokens,
// so the NUMBERS and the cache / reasoning splits are unproven against a
// real provider: the netting rules below are grounded on the vendor bundle
// (2.171.0).
//
//   - input: the agents-core `inputTokens` is GROSS of cache reads. The
//     vendor's own mod-API conversion (usageOf) computes
//     `input_tokens = max(0, inputTokens - inputTokensDetails[0].cached_tokens)`,
//     and its status line describes the same `inputTokens` as "uncached,
//     cache-written and cache-read together". So cache-read is
//     subtracted and clamped at zero, exactly as for every other
//     OpenAI-shaped source (§8.3).
//   - cache read: the vendor's getCacheReadTokens ladder over
//     `rawUsage || usage` — cache_read_input_tokens, cacheReadInputTokens,
//     the summed inputTokensDetails[].cached_tokens,
//     prompt_tokens_details.cached_tokens, prompt_cache_hit_tokens; first
//     positive wins.
//   - cache write: the vendor's getCacheCreationTokens ladder minus
//     `prompt_cache_miss_tokens` (DeepSeek's UNCACHED input, which the
//     vendor folds into "creation" but which is not a cache write and is
//     already inside the gross input). Whether cache writes are also
//     folded into the gross input is unknown, so they are carried
//     through and NOT subtracted.
//   - reasoning: summed outputTokensDetails reasoning_tokens /
//     reasoningTokens / thought_tokens / thoughtTokens (the vendor's own
//     key list). OpenAI-shaped completion counts INCLUDE reasoning, so
//     it is subtracted from output and carried separately (§8.4) — the
//     cost engine bills ReasoningTokens at the output rate, so keeping
//     both would double-bill it.
func tokenBundle(usage, raw *rawUsage) tokenParts {
	if usage == nil && raw == nil {
		return tokenParts{}
	}
	primary := usage
	if primary == nil {
		primary = raw
	}
	gross := firstPositive(primary.InputTokens, primary.InputTokensSnake, primary.PromptTokens)
	output := firstPositive(primary.OutputTokens, primary.OutputTokensSnake, primary.CompletionTokens)
	cacheRead := cacheReadOf(raw)
	if cacheRead == 0 {
		cacheRead = cacheReadOf(usage)
	}
	cacheWrite := cacheWriteOf(raw)
	if cacheWrite == 0 {
		cacheWrite = cacheWriteOf(usage)
	}
	reasoning := reasoningOf(primary)
	net := gross - cacheRead
	if net < 0 {
		net = 0
	}
	outNet := output - reasoning
	if outNet < 0 {
		outNet = 0
	}
	return tokenParts{
		inputNet:  net,
		output:    outNet,
		cacheRead: cacheRead,
		cacheWrit: cacheWrite,
		reasoning: reasoning,
	}
}

// firstPositive returns the first strictly positive value, else 0.
func firstPositive(vs ...int64) int64 {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	return 0
}

// cacheReadOf applies the vendor's cache-read ladder to one usage object.
func cacheReadOf(u *rawUsage) int64 {
	if u == nil {
		return 0
	}
	var promptCached int64
	if u.PromptTokensDetails != nil {
		promptCached = u.PromptTokensDetails.CachedTokens
	}
	return firstPositive(
		u.CacheReadInputTokens,
		u.CacheReadInputTokensCamel,
		sumDetail(u.InputTokensDetails, "cached_tokens", "cachedTokens"),
		promptCached,
		u.PromptCacheHitTokens,
	)
}

// cacheWriteOf applies the vendor's cache-creation ladder (minus the
// DeepSeek miss count — see tokenBundle) to one usage object.
func cacheWriteOf(u *rawUsage) int64 {
	if u == nil {
		return 0
	}
	return firstPositive(u.CacheCreationInputTokens, u.CacheCreationTokensCamel, u.PromptCacheWriteTokens)
}

// reasoningOf sums the reasoning-token keys the vendor recognises.
func reasoningOf(u *rawUsage) int64 {
	if u == nil {
		return 0
	}
	n := sumDetail(u.OutputTokensDetails, "reasoning_tokens", "reasoningTokens", "thought_tokens", "thoughtTokens")
	if n == 0 && u.CompletionTokensDetails != nil {
		n = u.CompletionTokensDetails.ReasoningTokens
	}
	return n
}

// sumDetail sums the named keys across a details value that is either
// one record or an array of records (agents-core serializes both).
func sumDetail(raw json.RawMessage, keys ...string) int64 {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return 0
	}
	var recs []map[string]float64
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &recs); err != nil {
			return 0
		}
	} else {
		var one map[string]float64
		if err := json.Unmarshal(raw, &one); err != nil {
			return 0
		}
		recs = []map[string]float64{one}
	}
	var total int64
	for _, rec := range recs {
		for _, k := range keys {
			if v, ok := rec[k]; ok && v > 0 {
				total += int64(v)
				break
			}
		}
	}
	return total
}

// actionMap translates CodeBuddy Code's native tool names onto the
// normalized taxonomy. Keys are the EXACT native names.
//
// GROUNDED from the vendor bundle (2.171.0): every key is a member of
// the CLI's built-in tool-name enum (Read, LS, Write, Edit, MultiEdit,
// NotebookRead, NotebookEdit, Bash, Glob, Grep, TodoWrite, WebFetch,
// WebSearch, Agent, Task*, EnterPlanMode, ExitPlanMode, Skill,
// AskUserQuestion, ToolSearch, SendMessage, EnterWorktree,
// LeaveWorktree, Cron*, PushNotification, PowerShell, Monitor,
// ListMcpResources, ReadMcpResource, REPL, …), and Bash / PowerShell /
// Write / Edit / MultiEdit / NotebookEdit / Read / Glob / Grep /
// WebFetch / WebSearch are the eleven `genieBuiltinIdentity` tools. The
// vocabulary is Claude-Code-compatible by design, so every name shared
// with claude-code maps to the same action. Only Read / Bash / Edit have
// been observed in a transcript so far (hook probe, 2026-10-21). Enum members not
// listed here (ImageGen, TeamCreate, Component, …) are deliberately left
// unmapped rather than guessed: they become ActionUnknown with the raw
// name preserved and a one-shot parse warning.
var actionMap = map[string]string{
	"Read":         models.ActionReadFile,
	"NotebookRead": models.ActionReadFile,
	"Write":        models.ActionWriteFile,
	"Edit":         models.ActionEditFile,
	"MultiEdit":    models.ActionEditFile,
	"NotebookEdit": models.ActionEditFile,
	"Bash":         models.ActionRunCommand,
	"PowerShell":   models.ActionRunCommand,
	// REPL is the programmatic-tool-calling ("ptc", the main agent on
	// every grounded line) code cell: the model's code runs in it and may
	// call other tools from inside. It executes code, so run_command.
	"REPL":                      models.ActionRunCommand,
	"Grep":                      models.ActionSearchText,
	"Glob":                      models.ActionSearchFiles,
	"LS":                        models.ActionSearchFiles,
	"WebSearch":                 models.ActionWebSearch,
	"WebFetch":                  models.ActionWebFetch,
	"Agent":                     models.ActionSpawnSubagent,
	"TodoWrite":                 models.ActionTodoUpdate,
	"TaskCreate":                models.ActionTodoUpdate,
	"TaskGet":                   models.ActionTodoUpdate,
	"TaskUpdate":                models.ActionTodoUpdate,
	"TaskList":                  models.ActionTodoUpdate,
	"TaskOutput":                models.ActionTodoUpdate,
	"TaskStop":                  models.ActionTodoUpdate,
	"AskUserQuestion":           models.ActionAskUser,
	"EnterPlanMode":             models.ActionPermissionMode,
	"ExitPlanMode":              models.ActionPermissionMode,
	"SendMessage":               models.ActionAgentMessage,
	"Monitor":                   models.ActionAgentControl,
	"Skill":                     models.ActionSkillInvoke,
	"ToolSearch":                models.ActionToolSearch,
	"CronCreate":                models.ActionSchedule,
	"CronDelete":                models.ActionSchedule,
	"CronList":                  models.ActionSchedule,
	"PushNotification":          models.ActionNotification,
	"EnterWorktree":             models.ActionWorktreeCreate,
	"LeaveWorktree":             models.ActionWorktreeRemove,
	"StructuredOutput":          models.ActionHarnessCall,
	"Artifact":                  models.ActionHarnessCall,
	"Workflow":                  models.ActionHarnessCall,
	"ListMcpResources":          models.ActionMCPCall,
	"ReadMcpResource":           models.ActionMCPCall,
	"AskUserForStructuredInput": models.ActionAskUser,
}

// mapToolName resolves a native tool name onto a normalized action,
// reporting whether it was recognised. An exact match wins; an
// MCP-routed call (`mcp__<server>__<tool>`, the Claude-Code-compatible
// spelling) maps to ActionMCPCall; everything else is ActionUnknown with
// recognised=false so the caller warns once. The raw name is always kept
// on ToolEvent.RawToolName.
func mapToolName(name string) (action string, recognised bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return models.ActionUnknown, false
	}
	if a, ok := actionMap[name]; ok {
		return a, true
	}
	if strings.HasPrefix(strings.ToLower(name), "mcp__") {
		return models.ActionMCPCall, true
	}
	return models.ActionUnknown, false
}

// targetKeys are the tool-input keys tried, in order, for an action's
// representative target. They follow the Claude-Code-compatible input
// schemas the vendor bundle declares (`file_path`, `notebook_path`,
// `command`, `pattern`, `url`, `query`, …).
var targetKeys = []string{
	"file_path", "notebook_path", "path", "command", "pattern",
	"url", "query", "skill", "description", "prompt", "subagent_type",
}

// targetFromInput picks a representative target from a decoded tool
// input object, falling back to the tool name.
func targetFromInput(input json.RawMessage, fallback string) string {
	if len(input) == 0 {
		return fallback
	}
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return fallback
	}
	for _, key := range targetKeys {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// argumentsJSON returns a function_call's `arguments` as raw JSON. The
// agents-core schema types it as a JSON-ENCODED STRING, which is unwrapped
// and kept when it parses; an object value (a provider that skipped the
// encoding) is kept as is. Anything else yields nil.
func argumentsJSON(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		s = strings.TrimSpace(s)
		if s == "" || !json.Valid([]byte(s)) {
			return nil
		}
		return json.RawMessage(s)
	case '{', '[':
		return raw
	}
	return nil
}

// authoredBytes returns the byte length of the code the model authored
// in a write / edit / run action, read from the untruncated input, using
// the Claude-Code-compatible input keys (`content`, `new_string`,
// `edits[].new_string`, `new_source`, `command`, REPL `code`). Zero for
// read-only or unrecognised actions.
func authoredBytes(actionType string, input json.RawMessage) int64 {
	if len(input) == 0 {
		return 0
	}
	var in struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		NewSource string `json:"new_source"`
		Command   string `json:"command"`
		Code      string `json:"code"`
		Edits     []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
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
		return n
	case models.ActionRunCommand:
		return int64(len(in.Command) + len(in.Code))
	default:
		return 0
	}
}

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
