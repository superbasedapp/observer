package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// providerForPath routes a request path to the upstream provider. Anthropic's
// Messages API lives under /v1/messages; everything else under /v1 (chat
// completions, responses, embeddings, models) goes to OpenAI. The default is
// anthropic — Claude Code sets ANTHROPIC_BASE_URL to the root of the proxy
// and hits paths that don't always begin with /v1 (e.g. health probes).
func providerForPath(path string) string {
	if strings.HasPrefix(path, "/v1/messages") {
		return models.ProviderAnthropic
	}
	// Google Gemini generateContent: paths look like
	// /v1beta/models/<model>:generateContent (or :streamGenerateContent /
	// :countTokens). Detected before the OpenAI /v1 checks so the shared
	// /…/models prefix doesn't misclassify it as OpenAI.
	if isGeminiPath(path) {
		return models.ProviderGoogle
	}
	if isChatGPTBackendPath(path) {
		return models.ProviderOpenAI
	}
	if isOpenAIPath(path) {
		return models.ProviderOpenAI
	}
	return models.ProviderAnthropic
}

// isOpenAIPath reports whether path is an OpenAI-compatible endpoint. It
// matches both the canonical `/v1/<endpoint>` prefix AND the distinctive
// endpoint SEGMENT anywhere in the path — the latter is required for
// custom-upstream routing (Phase C `/up/<id>`): an OpenAI-compatible host
// whose base carries its own version prefix (e.g. OpenRouter's
// `https://openrouter.ai/api/v1`) leaves a stripped path of
// `/api/v1/chat/completions`, which has no leading `/v1`. The endpoint names
// (`/chat/completions`, `/responses`) are distinctive enough that a Contains
// match won't collide with Anthropic (`/v1/messages`) or Gemini (handled by
// isGeminiPath before this is reached).
func isOpenAIPath(path string) bool {
	if strings.HasPrefix(path, "/v1/chat/completions") ||
		strings.HasPrefix(path, "/v1/responses") ||
		strings.HasPrefix(path, "/v1/completions") ||
		strings.HasPrefix(path, "/v1/embeddings") ||
		strings.HasPrefix(path, "/v1/models") ||
		strings.HasPrefix(path, "/v1/realtime") {
		return true
	}
	return strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/responses") ||
		strings.Contains(path, "/embeddings") ||
		strings.Contains(path, "/v1/realtime")
}

func isChatGPTBackendPath(path string) bool {
	return strings.HasPrefix(path, "/backend-api/")
}

// isGeminiPath reports whether path is a Google Gemini generateContent-family
// request. Gemini encodes the action as a `:method` suffix on the model
// resource (…/models/<model>:generateContent), so the discriminator is the
// `:generateContent` / `:streamGenerateContent` / `:countTokens` suffix
// rather than a fixed prefix (the version segment is /v1beta or /v1).
func isGeminiPath(path string) bool {
	return strings.Contains(path, ":generateContent") ||
		strings.Contains(path, ":streamGenerateContent") ||
		strings.Contains(path, ":countTokens")
}

// parseGeminiResponse extracts usage and metadata from a Google Gemini
// generateContent response. Gemini reports usage under `usageMetadata`
// ({promptTokenCount, candidatesTokenCount, cachedContentTokenCount,
// thoughtsTokenCount}) and the model under `modelVersion`. Non-streaming
// responses are a single JSON object; the non-SSE streaming variant returns a
// JSON ARRAY of chunks — parseGeminiResponse handles both by taking the LAST
// element's usageMetadata (the terminal chunk carries the cumulative totals).
//
// Token mapping follows the cross-provider convention used by
// parseOpenAIResponse: InputTokens is NET of the cached prefix
// (promptTokenCount − cachedContentTokenCount), CacheReadTokens is the cached
// portion, and reasoning (`thoughtsTokenCount`, billed at the output rate) is
// folded into OutputTokens alongside the visible candidate tokens.
func parseGeminiResponse(body []byte) responseShape {
	if obj, ok := lastGeminiObject(body); ok {
		body = obj
	}
	var raw geminiResponseRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		return responseShape{}
	}
	return raw.toShape()
}

// geminiResponseRaw is the subset of a Gemini generateContent response we read.
type geminiResponseRaw struct {
	ModelVersion string `json:"modelVersion"`
	ResponseID   string `json:"responseId"`
	Candidates   []struct {
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount        int64 `json:"promptTokenCount"`
		CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
		CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
		ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
	} `json:"usageMetadata"`
}

func (raw geminiResponseRaw) toShape() responseShape {
	netInput := raw.UsageMetadata.PromptTokenCount - raw.UsageMetadata.CachedContentTokenCount
	if netInput < 0 {
		netInput = 0
	}
	shape := responseShape{
		Model:           raw.ModelVersion,
		RequestID:       raw.ResponseID,
		InputTokens:     netInput,
		OutputTokens:    raw.UsageMetadata.CandidatesTokenCount + raw.UsageMetadata.ThoughtsTokenCount,
		CacheReadTokens: raw.UsageMetadata.CachedContentTokenCount,
	}
	if len(raw.Candidates) > 0 {
		shape.StopReason = raw.Candidates[0].FinishReason
	}
	return shape
}

// lastGeminiObject returns the last element of a top-level JSON array body
// (the streaming-chunk shape) so the caller parses the terminal chunk's
// cumulative usageMetadata. Returns ok=false when the body is not a JSON
// array (a plain object passes through unchanged).
func lastGeminiObject(body []byte) (obj []byte, ok bool) {
	trimmed := bytesTrimLeadingSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil || len(arr) == 0 {
		return nil, false
	}
	return arr[len(arr)-1], true
}

// bytesTrimLeadingSpace returns body with leading ASCII whitespace removed,
// without allocating a copy.
func bytesTrimLeadingSpace(body []byte) []byte {
	i := 0
	for i < len(body) {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return body[i:]
		}
	}
	return body[i:]
}

// isChatGPTAuthRequest reports whether the inbound request is using
// ChatGPT-plan credentials (a JWT) rather than a regular OpenAI Platform
// API key. Codex 0.128.0 with `requires_openai_auth = true` on a custom
// model_provider hits `/v1/responses` directly with the user's ChatGPT
// JWT in the Authorization header; the proxy must route that traffic to
// chatgpt.com (not api.openai.com) or upstream rejects with 401
// "Missing scopes: api.responses.write".
//
// Detection: ChatGPT JWTs start with "eyJ" (base64-encoded JSON header).
// OpenAI Platform API keys start with "sk-". Anthropic keys never use
// the Authorization: Bearer header (x-api-key instead) so any Bearer
// here is OpenAI-side.
func isChatGPTAuthRequest(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	const bearer = "Bearer "
	if !strings.HasPrefix(authz, bearer) {
		return false
	}
	token := authz[len(bearer):]
	if strings.HasPrefix(token, "sk-") {
		return false
	}
	return strings.HasPrefix(token, "eyJ")
}

// translateChatGPTPath rewrites canonical OpenAI Responses-API paths
// (/v1/responses, /v1/models) into the chatgpt.com codex backend
// equivalents (/backend-api/codex/...). Paths already in the
// /backend-api/ scheme pass through unchanged. Anthropic paths
// (/v1/messages) are also untouched — ChatGPT routing only applies
// when both the auth header AND the path indicate an OpenAI-side call.
func translateChatGPTPath(path string) string {
	if isChatGPTBackendPath(path) {
		return path
	}
	if strings.HasPrefix(path, "/v1/messages") {
		return path
	}
	if strings.HasPrefix(path, "/v1/") {
		return "/backend-api/codex" + path[len("/v1"):]
	}
	return path
}

// isModelsPath matches the OpenAI /v1/models listing endpoint and the
// translated ChatGPT-auth equivalent. Used to short-circuit codex's
// model-list refresher when running on ChatGPT credentials, since
// chatgpt.com doesn't serve that path.
func isModelsPath(path string) bool {
	return path == "/v1/models" || path == "/backend-api/codex/models"
}

// requestShape captures the fields extracted from the client's request body
// before forwarding. All fields are optional — a body that doesn't parse is
// not an error; we just store less metadata.
type requestShape struct {
	Model            string
	MessageCount     int
	ToolUseCount     int
	SystemPromptHash string
	Stream           bool
	// Speed mirrors Anthropic's request-body `speed` parameter
	// ("fast" enables Opus 4.8's low-latency premium tier at 2× rates).
	// Empty when the body didn't carry the field. The proxy's APITurn
	// emit translates Speed == "fast" → APITurn.Fast = true so the cost
	// engine applies Pricing.FastMultiplier at insert time.
	Speed string
	// ServiceTier mirrors OpenAI's request-body `service_tier` parameter
	// ("priority" is Codex Fast mode — a per-token premium; "flex" is the
	// slow/discount tier; "default"/"auto" are standard). Codex sets this
	// from `~/.codex/config.toml`. The served tier echoed on the response
	// is authoritative (OpenAI may downgrade priority→default under load);
	// this request-side value is the fallback. service_tier == "priority"
	// → APITurn.Fast = true (see isFastTurn). Empty for Anthropic.
	ServiceTier string
	// CacheBlocks is the in-order flat block sequence
	// (tools → system → messages) for cache-tracking (spec §8
	// + R1(a)). Populated for Anthropic requests only; empty
	// for OpenAI or when the body didn't parse. The engine
	// (cachetrack.Engine.ObserveTurn) consumes this alongside
	// Breakpoints; the proxy itself does not branch on contents.
	CacheBlocks []cachetrack.ObserveBlock
	// CacheBreakpoints names the cache_control marker positions
	// in CacheBlocks. R1(a) confirmed a typical Claude Code 2.1+
	// request carries 3 of the 4 max markers (2 system + 1
	// rolling last-message); the engine enumerates whatever it
	// finds, up to the provider's MaxBreakpoints cap.
	CacheBreakpoints []cachetrack.ObserveBreakpoint
	// HandoffMarker is true when the raw request body carries the
	// session-handoff marker (`superbased-handoff <id>`). The
	// marker rides into a handoff TARGET session on its first
	// prompt (inject_prompt / inject_hook / an early HANDOFF-<id>.md
	// file read) and then persists in the conversation history on
	// every subsequent request — cachetrack only consults it when
	// Prior == nil, so the by-design first-turn cold write
	// attributes as cause=handoff_rehydration instead of reanchor.
	HandoffMarker bool
}

// parseRequest inspects the JSON request body and extracts the pieces we want
// to log with the turn. Both Anthropic and OpenAI use {model, messages,
// tools, stream, system} at the top level; we treat them uniformly.
func parseRequest(body []byte) requestShape {
	var shape requestShape
	if len(body) == 0 {
		return shape
	}
	// Session-handoff marker: a single cheap scan of the raw body,
	// done up-front so it survives a body that later fails to parse
	// (the marker is a raw-bytes protocol signal, owned by
	// internal/handoff). cachetrack consults it only on the first
	// observed turn (Prior == nil); harmless on later turns where the
	// marker persists in the conversation history.
	shape.HandoffMarker = bytes.Contains(body, []byte(handoff.MarkerPrefix))
	var raw struct {
		Model    string            `json:"model"`
		Stream   bool              `json:"stream"`
		Messages []json.RawMessage `json:"messages"`
		Input    []json.RawMessage `json:"input"`
		Tools    []json.RawMessage `json:"tools"`
		System   json.RawMessage   `json:"system"`
		// Speed is Anthropic's Messages API low-latency tier selector
		// ("fast" enables Opus 4.8's premium tier at 2× per-token rates).
		// Empty when the body didn't carry it.
		Speed string `json:"speed"`
		// ServiceTier is OpenAI's request-side processing tier selector
		// ("priority" = Codex Fast mode premium). Codex/OpenAI only;
		// empty for Anthropic. The response's served tier wins over this.
		ServiceTier string `json:"service_tier"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return shape
	}
	shape.Model = raw.Model
	shape.MessageCount = len(raw.Messages)
	if shape.MessageCount == 0 {
		shape.MessageCount = len(raw.Input)
	}
	shape.ToolUseCount = len(raw.Tools)
	shape.Stream = raw.Stream
	shape.Speed = raw.Speed
	shape.ServiceTier = raw.ServiceTier
	if len(raw.System) > 0 && string(raw.System) != "null" {
		shape.SystemPromptHash = sha256Hex(raw.System)
	}
	// Cache-tracking Tier-1 enumeration (spec §8, C8). Reuses the
	// already-unmarshaled raw.Tools / raw.System / raw.Messages
	// from this single pass — no second parse. Returns empty
	// slices for OpenAI / cache-cold / unparseable bodies, which
	// the engine handles as a no-op (zero blocks → no segments,
	// no entries).
	shape.CacheBlocks, shape.CacheBreakpoints = cachetrack.EnumerateAnthropicBlocks(raw.Tools, raw.System, raw.Messages)
	return shape
}

// extractAnthropicSessionID pulls Claude Code SDK's per-session UUID from an
// Anthropic Messages API request body. The SDK encodes a JSON blob into
// metadata.user_id of the form
//
//	{"device_id":"...","account_uuid":"...","session_id":"<uuid>"}
//
// The session_id is stable for the duration of one Claude Code invocation
// (every /v1/messages POST in the same process carries it), giving the
// proxy a per-session grouping key without needing a hook installer or
// launcher-side header injection. Returns "" on any parse failure or
// missing field — callers should fall back to existing session sources.
func extractAnthropicSessionID(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var top struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	if top.Metadata.UserID == "" {
		return ""
	}
	var inner struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(top.Metadata.UserID), &inner); err != nil {
		return ""
	}
	return inner.SessionID
}

// extractOpenAISessionID pulls codex's per-session UUID from an OpenAI
// Responses API request body. Codex sets a top-level `prompt_cache_key`
// field equal to the session UUID — same value also appears on the
// `session_id` HTTP header. Both forms are equivalent; we read from the
// body so the surface mirrors extractAnthropicSessionID and tests that
// don't have an http.Request handy keep working.
//
// The session_id is stable for the duration of one codex CLI invocation.
// Returns "" on any parse failure or missing field — callers should
// fall back to header-based extraction or session-less degradation.
//
// Verified 2026-05-08 via codex 0.129.0 capture: `prompt_cache_key` is a
// UUIDv7 (e.g. `019e05fc-dfe7-77a1-8db0-c7d13f8be248`); equals the
// `session_id`, `thread_id`, and `x-client-request-id` HTTP headers.
func extractOpenAISessionID(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var top struct {
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	return top.PromptCacheKey
}

// extractOpenAIModel reads the top-level `model` string from an
// OpenAI-shape request body (Chat Completions, Responses API, and
// codex's Responses-shape envelope all share this field). Returns ""
// on any parse failure or missing field. Used by the V7-2 codex-variant
// compression warning at internal/proxy/proxy.go.
func extractOpenAIModel(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var top struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return ""
	}
	return top.Model
}

func summarizeResponsesInput(body []byte) []string {
	var raw struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || len(raw.Input) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw.Input))
	for _, item := range raw.Input {
		var obj struct {
			Type   string `json:"type"`
			Role   string `json:"role"`
			ID     string `json:"id"`
			CallID string `json:"call_id"`
		}
		if err := json.Unmarshal(item, &obj); err != nil {
			out = append(out, "unparseable")
			continue
		}
		parts := []string{}
		if obj.Type != "" {
			parts = append(parts, obj.Type)
		}
		if obj.Role != "" {
			parts = append(parts, "role="+obj.Role)
		}
		if obj.ID != "" {
			parts = append(parts, "id="+obj.ID)
		}
		if obj.CallID != "" {
			parts = append(parts, "call_id="+obj.CallID)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// responseShape is the usage+meta extracted from a non-streaming response
// body. Fields are 0/"" when the provider didn't supply them.
type responseShape struct {
	Model                 string
	RequestID             string
	InputTokens           int64
	OutputTokens          int64
	CacheReadTokens       int64
	CacheCreationTokens   int64
	CacheCreation1hTokens int64
	StopReason            string
	// ServiceTier is the tier OpenAI actually served the request on
	// ("priority"/"flex"/"default"). Authoritative for fast-mode billing
	// (OpenAI may downgrade a requested priority turn). Empty for Anthropic
	// and for OpenAI responses that didn't echo the field.
	ServiceTier string
}

// parseAnthropicResponse extracts usage and metadata from a non-streaming
// Anthropic Messages API response body. Unknown JSON is tolerated — the
// returned shape just carries zero values.
//
// Anthropic exposes the cache-creation tier breakdown via
// usage.cache_creation.{ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}.
// usage.cache_creation_input_tokens (legacy single field) carries the total.
// We capture the total in CacheCreationTokens and the 1h subset in
// CacheCreation1hTokens — the engine subtracts to get the 5m portion.
func parseAnthropicResponse(body []byte) responseShape {
	var raw struct {
		ID         string `json:"id"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens              int64 `json:"input_tokens"`
			OutputTokens             int64 `json:"output_tokens"`
			CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
			CacheCreation            struct {
				Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
				Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
			} `json:"cache_creation"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return responseShape{}
	}
	total := raw.Usage.CacheCreationInputTokens
	if total == 0 {
		// Newer API builds may emit only the breakdown, not the total.
		total = raw.Usage.CacheCreation.Ephemeral5mInputTokens +
			raw.Usage.CacheCreation.Ephemeral1hInputTokens
	}
	return responseShape{
		Model:                 raw.Model,
		RequestID:             raw.ID,
		InputTokens:           raw.Usage.InputTokens,
		OutputTokens:          raw.Usage.OutputTokens,
		CacheReadTokens:       raw.Usage.CacheReadInputTokens,
		CacheCreationTokens:   total,
		CacheCreation1hTokens: raw.Usage.CacheCreation.Ephemeral1hInputTokens,
		StopReason:            raw.StopReason,
	}
}

// parseOpenAIResponse extracts usage and metadata from a non-streaming OpenAI
// Chat Completions response body. OpenAI uses {usage: {prompt_tokens,
// completion_tokens}} at the top level. The /v1/responses endpoint uses
// {usage: {input_tokens, output_tokens}} so both key sets are tried.
func parseOpenAIResponse(body []byte) responseShape {
	var raw struct {
		ID          string `json:"id"`
		Model       string `json:"model"`
		ServiceTier string `json:"service_tier"`
		Choices     []struct {
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens        int64 `json:"prompt_tokens"`
			CompletionTokens    int64 `json:"completion_tokens"`
			InputTokens         int64 `json:"input_tokens"`
			OutputTokens        int64 `json:"output_tokens"`
			PromptTokensDetails struct {
				CachedTokens     int64 `json:"cached_tokens"`
				CacheWriteTokens int64 `json:"cache_write_tokens"`
			} `json:"prompt_tokens_details"`
			// The Responses API nests the same read/write split under
			// input_tokens_details (grounded on captured gpt-5.6 raw
			// bodies); Chat Completions uses prompt_tokens_details.
			// Parse both and prefer prompt_* then fall back to input_*,
			// matching applyOpenAIUsage in streaming.go.
			InputTokensDetails struct {
				CachedTokens     int64 `json:"cached_tokens"`
				CacheWriteTokens int64 `json:"cache_write_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return responseShape{}
	}
	cacheRead := raw.Usage.PromptTokensDetails.CachedTokens
	if cacheRead == 0 {
		// input_tokens_details fallback (added 2026-07-16): before this,
		// non-streaming /v1/responses bodies (Responses API) nested the
		// cached-read count under input_tokens_details, which this parser
		// never read — so CacheReadTokens stayed 0, Input stayed GROSS,
		// and cached reads were silently over-billed at the full input
		// rate (e.g. the grounded gpt-5.6 sample billed Input=31841 /
		// CacheRead=0 instead of the correct Input=1377 / CacheRead=30464).
		// The fallback only fires when the preferred prompt_tokens_details
		// shape reports 0, so it never shadows a real Chat-Completions read.
		cacheRead = raw.Usage.InputTokensDetails.CachedTokens
	}
	// cache_write_tokens is billed at the 1.25× cache-creation rate and is
	// a SUBSET of the non-cached input (DISJOINT from cached_tokens — never
	// additive, never subtracted from input a second time). Always 0 on the
	// ChatGPT-plan lane; goes live automatically on a metered API-key turn.
	cacheWrite := raw.Usage.PromptTokensDetails.CacheWriteTokens
	if cacheWrite == 0 {
		cacheWrite = raw.Usage.InputTokensDetails.CacheWriteTokens
	}
	shape := responseShape{
		Model:           raw.Model,
		RequestID:       raw.ID,
		ServiceTier:     raw.ServiceTier,
		CacheReadTokens: cacheRead,
		// OpenAI cache writes are untiered: the whole write count goes in
		// CacheCreationTokens with CacheCreation1hTokens left at 0, so the
		// cost engine bills it exactly once at the base CacheCreation rate
		// (cc5m = CacheCreation - cc1h = write - 0). Anthropic's 1h subset
		// has no OpenAI analog.
		CacheCreationTokens: cacheWrite,
	}
	// OpenAI's prompt_tokens / input_tokens is the TOTAL prompt
	// count INCLUDING cached_tokens (a subset). The cost engine and
	// every downstream consumer treats responseShape.InputTokens as
	// NET non-cached input (Anthropic convention — that adapter
	// pre-subtracts at provider.go:281 above). Net here so the proxy
	// stays consistent and the cached portion isn't billed at BOTH
	// the full input rate (as part of InputTokens) AND the discounted
	// cache_read rate (as CacheReadTokens). Clamp at 0 against any
	// upstream anomaly where CachedTokens > prompt total.
	grossInput := raw.Usage.PromptTokens
	if grossInput == 0 {
		grossInput = raw.Usage.InputTokens
	}
	netInput := grossInput - shape.CacheReadTokens
	if netInput < 0 {
		netInput = 0
	}
	shape.InputTokens = netInput
	if raw.Usage.CompletionTokens > 0 {
		shape.OutputTokens = raw.Usage.CompletionTokens
	} else {
		shape.OutputTokens = raw.Usage.OutputTokens
	}
	if len(raw.Choices) > 0 {
		shape.StopReason = raw.Choices[0].FinishReason
	}
	return shape
}

// isFastTurn reports whether a turn should be billed at the provider's
// low-latency "fast" premium tier, so the cost engine applies
// Pricing.FastMultiplier at insert time.
//
//   - Anthropic signals fast mode request-side via `speed:"fast"`
//     (Opus 4.8). req.Speed carries it.
//   - OpenAI / Codex signal it via `service_tier:"priority"`. The tier
//     OpenAI *actually served* (echoed on the response) is authoritative,
//     since OpenAI may downgrade a requested priority turn to "default"
//     under capacity/ramp limits and bill at the standard rate. servedTier
//     wins; req.ServiceTier (what the client asked for) is the fallback
//     for paths with no parsed response (errors).
func isFastTurn(req requestShape, servedTier string) bool {
	if req.Speed == "fast" {
		return true
	}
	tier := servedTier
	if tier == "" {
		tier = req.ServiceTier
	}
	return tier == "priority"
}
