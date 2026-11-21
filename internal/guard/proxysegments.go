package guard

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/promptturn"
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
	// generated is the newest exchange's model and tool content
	// (promptturn.Turn.Generated), from the same decode. Empty for a
	// shape parseProxyBody does not cover (scanPrompt classifies those
	// itself).
	generated string
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

// anthropicMessage is the minimal Messages-API message shape, owned by
// internal/promptturn so the latest-user-turn classification and this
// package's segment walk share one decode.
type anthropicMessage = promptturn.AnthropicMessage

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
	out.setTurn(promptturn.FromAnthropicMessages(msgs))
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

// openAIChatMessage is the minimal Chat Completions message shape (owned by
// internal/promptturn, see anthropicMessage).
type openAIChatMessage = promptturn.ChatMessage

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
	out.setTurn(promptturn.FromChatMessages(msgs))
}

// openAIResponsesItem is the minimal Responses-API input-item shape (owned
// by internal/promptturn, see anthropicMessage).
type openAIResponsesItem = promptturn.ResponsesItem

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
	out.setTurn(promptturn.FromResponsesItems(items))
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
// interrupt), for guard.EvaluatePrompt. The classification itself is
// owned by internal/promptturn (P-228), shared with the org AI gateway's
// and the node proxy's coding-agent admission judge so the three can
// never disagree on what "the developer's newest prompt" is.

// extractLatestUserPromptText returns the developer's latest user-role
// turn as plain text for the four wire shapes the proxy serves.
// ok=false means there is nothing NEW to scan on this request: no
// recognizable user turn (an unsupported provider lane, a model-list or
// count-tokens call), or a tool-loop continuation whose prompt was
// already scanned when it was newest. A genuinely oversize or
// field-missing PROMPT (once one is found) is
// scrub.DetectPromptFindings' / policy.Event's own concern downstream.
func extractLatestUserPromptText(provider string, body []byte) (text string, ok bool) {
	text, ok, _ = classifyPromptTurn(provider, body)
	return text, ok
}

// classifyPromptTurn is extractLatestUserPromptText plus the newest
// exchange's generated content (promptturn.Turn.Generated), which the
// prompt lane notes even when there is no prompt to judge.
func classifyPromptTurn(provider string, body []byte) (text string, ok bool, generated string) {
	t := promptturn.ClassifyProvider(provider, body)
	text, ok = promptTurnText(t)
	return text, ok, t.Generated
}

// promptTurnText maps a promptturn classification onto the prompt
// lane's (text, ok) contract: only a user_prompt turn is scanned.
func promptTurnText(t promptturn.Turn) (string, bool) {
	if t.Kind != promptturn.KindUserPrompt {
		return "", false
	}
	return t.Text, true
}

// setTurn records a promptturn classification of an ALREADY-DECODED
// message/item slice on the parsed view (F6, phase-3b review: the parse
// functions reuse the decode the §8.4 segment walk performed): the
// prompt lane's (text, ok) pair and the newest exchange's generated
// content (promptturn.Turn.Generated), which scanPrompt notes so a value
// the conversation already carried is never judged as typed. F3
// (phase-3b review): a role:"tool" message or a function_call_output
// after the newest user turn is a mid-tool-loop continuation, never
// re-scanned.
func (out *proxyParsedBody) setTurn(t promptturn.Turn) {
	out.latestUserText, out.latestUserTextOK = promptTurnText(t)
	out.generated = t.Generated
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
