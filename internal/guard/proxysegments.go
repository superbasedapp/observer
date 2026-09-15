package guard

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Request-body content extraction for the §8.4 injection scan. The
// guard layer owns MEANING (which content is new, which tool produced
// it, which taint source class it maps to); the proxy owns only the
// wire (it hands the raw final body across). Parsing here is
// tolerant: any shape mismatch yields fewer segments, never an error.
//
// Scope rule: only the TRAILING run of inbound items — everything
// after the last assistant turn — is scanned. Request bodies carry
// the whole conversation, so earlier content was already scanned on
// the turn it arrived; rescanning it every turn would duplicate work
// and re-fire marks for content the session already absorbed.

// maxInjectionSegments bounds the segments scanned per request
// (parallel tool batches rarely exceed single digits).
const maxInjectionSegments = 16

// maxSegmentBytes bounds one segment's analyzed text. Injection
// patterns sit anywhere in a result, so the cap is generous; beyond
// it analysis takes the prefix (documented approximation).
const maxSegmentBytes = 64 * 1024

// attachmentMinBytes is the user-text paste threshold: a typed user
// message instructing the agent is the USER's prerogative (no
// injection scan); a multi-KB text block is paste-shaped content of
// uncertain provenance (§4.5 attachment source). 2 KiB separates the
// two in practice (documented approximation).
const attachmentMinBytes = 2048

// proxySegment is one inbound content segment to scan.
type proxySegment struct {
	// text is the bounded content.
	text string
	// origin is the content-free descriptor recorded on verdicts and
	// taint marks ("tool_result:WebFetch", "user_attachment").
	origin string
	// taintSource is the §4.5 source class an injection hit marks.
	taintSource string
	// mcpServer is the producing MCP server name when taintSource is
	// mcp_unpinned ("" otherwise) — the §9.2 pin lookup's key at the
	// injection mark site.
	mcpServer string
}

// maxMCPDecls bounds the MCP tool declarations extracted per request
// (claude-code sends the full tools array every turn; MCP-heavy
// setups run to dozens, not hundreds).
const maxMCPDecls = 256

// proxyParsedBody is the guard-relevant view of an outbound request
// body.
type proxyParsedBody struct {
	model    string
	segments []proxySegment
	// mcpDecls are the MCP-prefixed tool declarations from the
	// request's tools array (§9.2 "observed MCP tool-call metadata" —
	// the only place tool descriptions exist on this side of the
	// MCP handshake). Populated only when the parse was asked for
	// them (wantTools).
	mcpDecls []mcpsec.ToolDecl
	// latestUserText / latestUserTextOK are the prompt-submit
	// intervention PROXY LANE's own extraction (contract §3.2),
	// computed from the SAME decoded message/item slice the segment
	// walk above already built. F6 (phase-3b review): threading this
	// out of the Anthropic/OpenAI parse functions below means a
	// proxy-routed request is unmarshaled ONCE per scan instead of
	// twice (parseProxyBody + a separate extractLatestUserPromptText
	// call) — scanPrompt falls back to extractLatestUserPromptText
	// only when latestUserTextOK is false (Gemini, which parseProxyBody
	// never covers, or a shape parseProxyBody's stricter structs failed
	// to decode).
	latestUserText   string
	latestUserTextOK bool
}

// parseProxyBody dispatches on the wire shape — a body-format branch
// (the proxy's parseAnthropicResponse/parseOpenAIResponse precedent),
// not source-identity branching: provider names a JSON schema, not a
// client. Unknown shapes return the zero view (egress scanning needs
// no structure). wantTools additionally decodes the request's tools
// array into MCP declarations — gated so installs with [guard.mcp]
// off never pay the extra decode.
func parseProxyBody(provider string, body []byte, wantTools bool) proxyParsedBody {
	var out proxyParsedBody
	switch provider {
	case models.ProviderAnthropic:
		out = parseAnthropicProxyBody(body)
	case models.ProviderOpenAI:
		out = parseOpenAIProxyBody(body)
	default:
		return proxyParsedBody{}
	}
	if wantTools {
		out.mcpDecls = parseMCPToolDecls(body)
	}
	return out
}

// proxyToolEntry is the tolerant tools-array entry shape across the
// three wires: Anthropic ({name, description, input_schema}), OpenAI
// chat ({type:"function", function:{name, description, parameters}}),
// and the Responses API ({type:"function", name, description,
// parameters} — flattened).
type proxyToolEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Parameters  json.RawMessage `json:"parameters"`
	Function    *struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// parseMCPToolDecls extracts MCP-prefixed tool declarations from the
// request body's top-level tools array. Names that don't parse to an
// MCP server (policy.MCPServerFromTarget — the same extraction the
// taint marks use, so both sides agree) are skipped: built-in tool
// declarations are the client's own business.
func parseMCPToolDecls(body []byte) []mcpsec.ToolDecl {
	var raw struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(body, &raw) != nil || len(raw.Tools) == 0 {
		return nil
	}
	var out []mcpsec.ToolDecl
	for _, t := range raw.Tools {
		if len(out) >= maxMCPDecls {
			break
		}
		var e proxyToolEntry
		if json.Unmarshal(t, &e) != nil {
			continue
		}
		name, desc, params := e.Name, e.Description, e.InputSchema
		if name == "" && e.Function != nil {
			name, desc, params = e.Function.Name, e.Function.Description, e.Function.Parameters
		}
		if len(params) == 0 {
			params = e.Parameters
		}
		server := policy.MCPServerFromTarget(name)
		if server == "" {
			continue
		}
		tool := policy.MCPToolFromTarget(name)
		if tool == "" {
			tool = name
		}
		out = append(out, mcpsec.ToolDecl{
			Server:      server,
			Name:        tool,
			Description: desc,
			ParamDoc:    schemaParamDoc(params),
		})
	}
	return out
}

// schemaParamDoc flattens a JSON-schema object's depth-1 property
// descriptions into "param: description" lines (sorted for hash
// stability). Nested schemas are not walked — documented
// approximation; §9.3's exfil-shaped-parameter heuristic targets
// top-level parameter prose.
func schemaParamDoc(schema json.RawMessage) string {
	if len(schema) == 0 {
		return ""
	}
	var s struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	if json.Unmarshal(schema, &s) != nil || len(s.Properties) == 0 {
		return ""
	}
	names := make([]string, 0, len(s.Properties))
	for name, p := range s.Properties {
		if p.Description != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(s.Properties[name].Description)
	}
	return b.String()
}

// anthropicMessage is the minimal Messages-API message shape.
type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// anthropicBlock is the minimal content-block shape (tool_use on
// assistant messages, tool_result/text on user messages).
type anthropicBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
}

// parseAnthropicProxyBody extracts the trailing inbound segments from
// an Anthropic Messages API body. Tool names resolve through the
// tool_use id → name map built from assistant messages, so a
// tool_result's origin can say WHICH tool produced the content.
func parseAnthropicProxyBody(body []byte) proxyParsedBody {
	var raw struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return proxyParsedBody{}
	}
	out := proxyParsedBody{model: raw.Model}

	msgs := make([]anthropicMessage, 0, len(raw.Messages))
	for _, m := range raw.Messages {
		var am anthropicMessage
		if json.Unmarshal(m, &am) == nil {
			msgs = append(msgs, am)
		}
	}
	lastAssistant := -1
	toolNames := map[string]string{} // tool_use id → name
	for i := range msgs {
		if msgs[i].Role != "assistant" {
			continue
		}
		lastAssistant = i
		var blocks []anthropicBlock
		if json.Unmarshal(msgs[i].Content, &blocks) == nil {
			for _, b := range blocks {
				if b.Type == "tool_use" && b.ID != "" {
					toolNames[b.ID] = b.Name
				}
			}
		}
	}
	for i := lastAssistant + 1; i < len(msgs); i++ {
		if msgs[i].Role != "user" {
			continue
		}
		appendAnthropicSegments(&out, msgs[i].Content, toolNames)
	}
	out.latestUserText, out.latestUserTextOK = latestUserTextFromAnthropicMessages(msgs)
	return out
}

// appendAnthropicSegments walks one user message's content (string or
// block array) into segments.
func appendAnthropicSegments(out *proxyParsedBody, content json.RawMessage, toolNames map[string]string) {
	if len(out.segments) >= maxInjectionSegments {
		return
	}
	// String-form content: a plain user message — paste threshold
	// applies.
	var s string
	if json.Unmarshal(content, &s) == nil {
		out.addUserText(s)
		return
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return
	}
	for _, b := range blocks {
		if len(out.segments) >= maxInjectionSegments {
			return
		}
		switch b.Type {
		case "tool_result":
			text := anthropicResultText(b.Content)
			if text == "" {
				continue
			}
			name := toolNames[b.ToolUseID]
			out.addToolResult(name, text)
		case "text":
			out.addUserText(b.Text)
		}
	}
}

// anthropicResultText flattens a tool_result's content (string, or an
// array of text blocks) into one string.
func anthropicResultText(content json.RawMessage) string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type == "text" && blk.Text != "" {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(blk.Text)
		}
	}
	return b.String()
}

// parseOpenAIProxyBody extracts the trailing inbound segments from an
// OpenAI-shape body: Chat Completions (messages, role=tool results)
// or the Responses API (input items, function_call_output). Both key
// sets are tried — the body tells us which is populated.
func parseOpenAIProxyBody(body []byte) proxyParsedBody {
	var raw struct {
		Model    string            `json:"model"`
		Messages []json.RawMessage `json:"messages"`
		Input    []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return proxyParsedBody{}
	}
	out := proxyParsedBody{model: raw.Model}
	if len(raw.Messages) > 0 {
		parseOpenAIChatSegments(&out, raw.Messages)
		return out
	}
	parseOpenAIResponsesSegments(&out, raw.Input)
	return out
}

// openAIChatMessage is the minimal Chat Completions message shape.
type openAIChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"tool_call_id"`
	ToolCalls  []struct {
		ID       string `json:"id"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	} `json:"tool_calls"`
}

// parseOpenAIChatSegments walks Chat Completions messages: trailing
// role=tool results (+ trailing user pastes) after the last assistant
// message.
func parseOpenAIChatSegments(out *proxyParsedBody, rawMsgs []json.RawMessage) {
	msgs := make([]openAIChatMessage, 0, len(rawMsgs))
	for _, m := range rawMsgs {
		var cm openAIChatMessage
		if json.Unmarshal(m, &cm) == nil {
			msgs = append(msgs, cm)
		}
	}
	lastAssistant := -1
	toolNames := map[string]string{}
	for i := range msgs {
		if msgs[i].Role != "assistant" {
			continue
		}
		lastAssistant = i
		for _, tc := range msgs[i].ToolCalls {
			if tc.ID != "" {
				toolNames[tc.ID] = tc.Function.Name
			}
		}
	}
	for i := lastAssistant + 1; i < len(msgs); i++ {
		if len(out.segments) >= maxInjectionSegments {
			break
		}
		var text string
		if json.Unmarshal(msgs[i].Content, &text) != nil || text == "" {
			continue
		}
		switch msgs[i].Role {
		case "tool":
			out.addToolResult(toolNames[msgs[i].ToolCallID], text)
		case "user":
			out.addUserText(text)
		}
	}
	out.latestUserText, out.latestUserTextOK = latestUserTextFromChatMessages(msgs)
}

// openAIResponsesItem is the minimal Responses-API input-item shape.
type openAIResponsesItem struct {
	Type    string          `json:"type"`
	Role    string          `json:"role"`
	Name    string          `json:"name"`
	CallID  string          `json:"call_id"`
	Output  json.RawMessage `json:"output"`
	Content json.RawMessage `json:"content"`
}

// parseOpenAIResponsesSegments walks Responses-API input items:
// trailing function_call_output items (+ trailing user messages)
// after the last assistant-side item.
func parseOpenAIResponsesSegments(out *proxyParsedBody, rawItems []json.RawMessage) {
	items := make([]openAIResponsesItem, 0, len(rawItems))
	for _, it := range rawItems {
		var ri openAIResponsesItem
		if json.Unmarshal(it, &ri) == nil {
			items = append(items, ri)
		}
	}
	lastAssistant := -1
	callNames := map[string]string{}
	for i := range items {
		switch {
		case items[i].Type == "function_call":
			lastAssistant = i
			if items[i].CallID != "" {
				callNames[items[i].CallID] = items[i].Name
			}
		case items[i].Role == "assistant", items[i].Type == "reasoning":
			lastAssistant = i
		}
	}
	for i := lastAssistant + 1; i < len(items); i++ {
		if len(out.segments) >= maxInjectionSegments {
			break
		}
		it := &items[i]
		switch {
		case it.Type == "function_call_output":
			var text string
			if json.Unmarshal(it.Output, &text) != nil {
				text = string(it.Output) // structured output: scan the JSON form
			}
			out.addToolResult(callNames[it.CallID], text)
		case it.Type == "message" && it.Role == "user":
			var text string
			if json.Unmarshal(it.Content, &text) != nil {
				text = flattenResponsesContent(it.Content)
			}
			out.addUserText(text)
		}
	}
	out.latestUserText, out.latestUserTextOK = latestUserTextFromResponsesItems(items)
}

// flattenResponsesContent flattens a Responses-API content array
// ([{type:"input_text", text:...}]) into one string.
func flattenResponsesContent(content json.RawMessage) string {
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(blk.Text)
	}
	return b.String()
}

// addToolResult appends a tool-result segment, classifying the taint
// source by the producing tool: web tools mark web_fetch, MCP tools
// mark mcp_unpinned with the server as origin, everything else (and
// unresolvable names) marks attachment — all untrusted-content
// classes, so T-501 arms regardless; the class only shades the
// origin reporting (documented approximation).
func (p *proxyParsedBody) addToolResult(toolName, text string) {
	if text == "" || len(p.segments) >= maxInjectionSegments {
		return
	}
	seg := proxySegment{
		text:        boundSegment(text),
		origin:      "tool_result",
		taintSource: policy.TaintSourceAttachment,
	}
	switch {
	case toolName == "":
	case strings.HasPrefix(toolName, "mcp__"):
		seg.origin = "tool_result:" + toolName
		seg.taintSource = policy.TaintSourceMCPUnpinned
		if server := policy.MCPServerFromTarget(toolName); server != "" {
			seg.origin = "tool_result:mcp:" + server
			seg.mcpServer = server
		}
	case isWebToolName(toolName):
		seg.origin = "tool_result:" + toolName
		seg.taintSource = policy.TaintSourceWebFetch
	default:
		seg.origin = "tool_result:" + toolName
	}
	p.segments = append(p.segments, seg)
}

// addUserText appends a paste-shaped user text segment when it clears
// the attachment threshold.
func (p *proxyParsedBody) addUserText(text string) {
	if len(text) < attachmentMinBytes || len(p.segments) >= maxInjectionSegments {
		return
	}
	p.segments = append(p.segments, proxySegment{
		text:        boundSegment(text),
		origin:      "user_attachment",
		taintSource: policy.TaintSourceAttachment,
	})
}

// isWebToolName reports web-content tools across the proxy-routed
// clients' vocabularies.
func isWebToolName(name string) bool {
	switch strings.ToLower(name) {
	case "webfetch", "web_fetch", "fetch", "websearch", "web_search", "browser", "browser_action":
		return true
	}
	return false
}

// boundSegment caps a segment at maxSegmentBytes without splitting a
// UTF-8 sequence.
func boundSegment(s string) string {
	if len(s) <= maxSegmentBytes {
		return s
	}
	cut := maxSegmentBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

// --- Prompt-submit intervention, PROXY LANE (contract §3.2,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md).
// Distinct from the injection-scan segment extraction above (which
// walks the TRAILING tool-result/paste run for T-501): this pulls the
// SINGLE latest user turn — the developer's own typed text, with
// tool_result blocks explicitly EXCLUDED (§10 item 2: the developer
// did not type a tool's output, so it must never trip a prompt-submit
// interrupt) — for guard.EvaluatePrompt, mirroring what each hook
// dialect's own extractor (internal/hook/promptsubmit.go) hands the
// same seam on that lane. One extractor per WIRE SHAPE, dispatched by
// provider (a body-format branch, never a tool-name branch — CLAUDE.md
// rule 3); tolerant like every other parser in this file — a shape
// mismatch or an absent user turn yields ok=false, never an error.

// extractLatestUserPromptText returns the developer's latest user-role
// turn as plain text for the four wire shapes the proxy serves.
// ok=false means no recognizable user turn was found on this request
// (an unsupported provider lane, or a request shape with no
// messages/contents at all — e.g. a model-list or count-tokens call) —
// the caller treats this as "nothing to scan", never a degrade; a
// genuinely oversize or field-missing PROMPT (once one is found) is
// scrub.DetectPromptFindings' / policy.Event's own concern downstream,
// not this function's.
func extractLatestUserPromptText(provider string, body []byte) (text string, ok bool) {
	switch provider {
	case models.ProviderAnthropic:
		return latestUserTextAnthropic(body)
	case models.ProviderOpenAI:
		return latestUserTextOpenAI(body)
	case models.ProviderGoogle:
		return latestUserTextGemini(body)
	default:
		return "", false
	}
}

// latestUserTextAnthropic implements the Anthropic Messages API row of
// contract §3.2: the LAST messages[] entry with role:"user" — not the
// trailing post-assistant run parseAnthropicProxyBody walks for the
// injection scan (an intervention only ever judges the NEWEST
// submission; earlier turns were already judged when THEY were
// newest). Content is a string or a block array; only type:"text"
// blocks count toward the scanned text — tool_result (and any other
// block type) contributes nothing, reusing the same anthropicMessage/
// anthropicBlock wire-shape structs the injection-scan parser above
// already defines.
func latestUserTextAnthropic(body []byte) (string, bool) {
	var raw struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return "", false
	}
	msgs := make([]anthropicMessage, 0, len(raw.Messages))
	for _, m := range raw.Messages {
		var am anthropicMessage
		if json.Unmarshal(m, &am) == nil {
			msgs = append(msgs, am)
		}
	}
	return latestUserTextFromAnthropicMessages(msgs)
}

// latestUserTextFromAnthropicMessages implements the Anthropic Messages
// row of contract §3.2 over an ALREADY-DECODED message slice — shared
// by latestUserTextAnthropic (which decodes the body itself, the
// standalone extractLatestUserPromptText call path) and
// parseAnthropicProxyBody (F6, phase-3b review: reuses the SAME decode
// the §8.4 segment walk already performed, so a proxy-routed Anthropic
// request is unmarshaled once per scan, not twice).
func latestUserTextFromAnthropicMessages(msgs []anthropicMessage) (string, bool) {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != "user" {
			continue
		}
		return anthropicUserPromptText(msgs[i].Content), true
	}
	return "", false
}

// anthropicUserPromptText flattens one user message's content into
// plain text for the prompt-submit scan: text blocks only, in order;
// tool_result (and any other block type) is skipped outright — the
// developer did not type a tool's output.
func anthropicUserPromptText(content json.RawMessage) string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		if blk.Type != "text" || blk.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(blk.Text)
	}
	return b.String()
}

// latestUserTextOpenAI dispatches between the two OpenAI wire shapes
// the proxy serves, exactly like parseOpenAIProxyBody: Chat Completions
// (messages[]) when populated, else the Responses API (input).
func latestUserTextOpenAI(body []byte) (string, bool) {
	var raw struct {
		Messages []json.RawMessage `json:"messages"`
		Input    json.RawMessage   `json:"input"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return "", false
	}
	if len(raw.Messages) > 0 {
		return latestUserTextChatMessages(raw.Messages)
	}
	return latestUserTextResponsesInput(raw.Input)
}

// latestUserTextChatMessages implements the Chat Completions row: the
// last messages[] entry with role:"user"; content is a string or a
// [{"type":"text","text":…}] parts array (flattenResponsesContent only
// reads each element's "text" field, so it applies unchanged to this
// shape too).
func latestUserTextChatMessages(rawMsgs []json.RawMessage) (string, bool) {
	msgs := make([]openAIChatMessage, 0, len(rawMsgs))
	for _, m := range rawMsgs {
		var cm openAIChatMessage
		if json.Unmarshal(m, &cm) == nil {
			msgs = append(msgs, cm)
		}
	}
	return latestUserTextFromChatMessages(msgs)
}

// latestUserTextFromChatMessages implements the Chat Completions row of
// contract §3.2 over an ALREADY-DECODED message slice — shared by
// latestUserTextChatMessages and parseOpenAIChatSegments (F6).
//
// F3 (phase-3b review): a role:"tool" message AFTER the last
// role:"user" message means this request is mid-tool-loop — a
// continuation re-sending the SAME original prompt (Chat Completions
// carries the WHOLE conversation on every request; a tool result only
// ever follows the assistant's own tool call, never a fresh user
// submission), not a new one. Without this guard the scanner would
// re-extract and re-fire an already-resolved interrupt against stale
// text on every subsequent turn of the tool loop. ok=false here means
// "nothing NEW to scan", exactly like an absent user turn.
func latestUserTextFromChatMessages(msgs []openAIChatMessage) (string, bool) {
	lastUser := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			lastUser = i
			break
		}
	}
	if lastUser < 0 {
		return "", false
	}
	for i := lastUser + 1; i < len(msgs); i++ {
		if msgs[i].Role == "tool" {
			return "", false
		}
	}
	m := msgs[lastUser]
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		return s, true
	}
	return flattenResponsesContent(m.Content), true
}

// latestUserTextResponsesInput implements the Responses API row:
// `input` is either a bare string (the whole prompt) or an array of
// items, the last role:"user" one's content parts.
func latestUserTextResponsesInput(input json.RawMessage) (string, bool) {
	if len(input) == 0 {
		return "", false
	}
	var whole string
	if json.Unmarshal(input, &whole) == nil {
		return whole, true
	}
	var rawItems []json.RawMessage
	if json.Unmarshal(input, &rawItems) != nil {
		return "", false
	}
	items := make([]openAIResponsesItem, 0, len(rawItems))
	for _, it := range rawItems {
		var ri openAIResponsesItem
		if json.Unmarshal(it, &ri) == nil {
			items = append(items, ri)
		}
	}
	return latestUserTextFromResponsesItems(items)
}

// latestUserTextFromResponsesItems implements the Responses-API array
// row of contract §3.2 over an ALREADY-DECODED item slice — shared by
// latestUserTextResponsesInput and parseOpenAIResponsesSegments (F6).
//
// F3 (phase-3b review): a function_call_output item AFTER the last
// role:"user" item means this request is mid-tool-loop, re-sending the
// SAME original prompt — see latestUserTextFromChatMessages's doc
// comment for the identical rationale applied to this wire shape.
func latestUserTextFromResponsesItems(items []openAIResponsesItem) (string, bool) {
	lastUser := -1
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Role == "user" {
			lastUser = i
			break
		}
	}
	if lastUser < 0 {
		return "", false
	}
	for i := lastUser + 1; i < len(items); i++ {
		if items[i].Type == "function_call_output" {
			return "", false
		}
	}
	it := items[lastUser]
	var part string
	if json.Unmarshal(it.Content, &part) == nil {
		return part, true
	}
	return flattenResponsesContent(it.Content), true
}

// geminiRequestContentPart / geminiRequestContent are the minimal
// generateContent REQUEST shapes for contract §3.2's Gemini row (the
// request, not geminiResponseRaw's response shape in internal/proxy).
type geminiRequestContentPart struct {
	Text string `json:"text"`
}

type geminiRequestContent struct {
	Role  string                     `json:"role"`
	Parts []geminiRequestContentPart `json:"parts"`
}

// latestUserTextGemini implements the Gemini generateContent row: the
// last contents[] entry with role:"user" (or role OMITTED — F4,
// phase-3b review: the generateContent API allows a single-turn
// request to drop `role` entirely, defaulting it to "user" server-side;
// treating a role-less entry as unscanned silently skipped that valid
// shape) — Gemini's own turns always carry an EXPLICIT role:"model",
// never "user" and never omitted, so this can never misclassify a
// model turn — parts[].text joined in order.
func latestUserTextGemini(body []byte) (string, bool) {
	var raw struct {
		Contents []geminiRequestContent `json:"contents"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return "", false
	}
	for i := len(raw.Contents) - 1; i >= 0; i-- {
		c := raw.Contents[i]
		if c.Role != "" && c.Role != "user" {
			continue
		}
		var b strings.Builder
		for _, p := range c.Parts {
			if p.Text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(p.Text)
		}
		return b.String(), true
	}
	return "", false
}

// jsonStringField returns the first present string field from a JSON
// object, trying names in order. Used by the response-side tool_use
// classifier.
func jsonStringField(obj []byte, names []string) string {
	if len(obj) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(obj, &m) != nil {
		return ""
	}
	for _, n := range names {
		raw, ok := m[n]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}
