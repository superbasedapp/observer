package promptturn

import (
	"encoding/json"
	"strings"
)

// Shape is a request body's wire shape.
type Shape int

// The closed shape vocabulary.
const (
	// ShapeUnknown is a body none of the extractors understand.
	ShapeUnknown Shape = iota
	// ShapeAnthropicMessages is the Anthropic Messages API (messages[] with
	// tool_result blocks inside user messages).
	ShapeAnthropicMessages
	// ShapeOpenAIChat is OpenAI Chat Completions (messages[] with role:"tool"
	// results).
	ShapeOpenAIChat
	// ShapeOpenAIResponses is the OpenAI Responses API (input string or
	// input[] items with function_call_output results).
	ShapeOpenAIResponses
	// ShapeGemini is Gemini generateContent (contents[] with functionResponse
	// parts).
	ShapeGemini
	// ShapeEmbeddings is the OpenAI embeddings API (an input string, a list
	// of strings, or token ids). Only AdmissionView reads it; Classify
	// answers KindNone.
	ShapeEmbeddings
)

// String names the shape for logs and audit reasons.
func (s Shape) String() string {
	switch s {
	case ShapeAnthropicMessages:
		return "anthropic_messages"
	case ShapeOpenAIChat:
		return "openai_chat"
	case ShapeOpenAIResponses:
		return "openai_responses"
	case ShapeGemini:
		return "gemini"
	case ShapeEmbeddings:
		return "embeddings"
	default:
		return "unknown"
	}
}

// Kind classifies the newest turn of a request.
type Kind string

// The closed kind vocabulary.
const (
	// KindNone means no user turn was found (or the body did not parse).
	KindNone Kind = "none"
	// KindUserPrompt means the newest turn is the developer's own input.
	KindUserPrompt Kind = "user_prompt"
	// KindContinuation means the newest turn is a tool result fed back
	// mid-loop; the prompt that started the loop was judged when it was new.
	KindContinuation Kind = "continuation"
)

// MaxTrailingBytes bounds Turn.Trailing. A tool loop can carry megabytes of
// tool output; past the cap the prefix is kept (cut on a UTF-8 boundary).
const MaxTrailingBytes = 256 << 10

// Turn is the classification of one request body.
type Turn struct {
	// Kind is the newest turn's class.
	Kind Kind
	// Text is the developer's text of a KindUserPrompt turn: text blocks
	// only, joined with newlines. Empty for the other kinds, and may be
	// empty for a user turn that carried only non-text content (an image).
	Text string
	// Trailing is every new inbound item after the last assistant turn:
	// user text and tool results, joined with newlines, capped at
	// MaxTrailingBytes. It is what an all_calls admission scope judges.
	Trailing string
	// Opening is, for a KindContinuation turn, the text of the newest
	// earlier user turn that carried text: the prompt that opened the tool
	// loop. Empty when the body holds no such turn (a loop with no typed
	// prompt at all). A user_prompts admission seam judges it (through its
	// verdict cache) so a hand-built body cannot skip the judge by dressing
	// a prompt up as a tool loop.
	Opening string
	// Blocks is, for a KindUserPrompt turn, each non-blank text block of the
	// user message Text joins, in order (a string content is one block). A
	// seam that already judged one exact block elsewhere (the hook lane)
	// matches it here by equality, never by substring. Nil for other kinds.
	Blocks []string
	// Generated is the content the model or a tool produced in the newest
	// exchange, never anything the developer typed: the newest assistant
	// turn (its text and its tool-call inputs) and every tool result in the
	// trailing run (Anthropic tool_result blocks, Chat Completions role:"tool"
	// messages, Responses function_call_output items, Gemini functionResponse
	// parts), joined with newlines and capped at MaxTrailingBytes. Every
	// model turn and tool result is newest in exactly one request of a
	// conversation, so a caller that notes Generated on every request sees
	// all of it once. The prompt guard uses it to tell a value the
	// conversation already carried from one the developer typed: a side
	// request (an agent's own safety classifier, a summarizer) re-sends
	// tool output as the text of a fresh user message (live 2026-11-15).
	// The developer's typed text, including text riding next to a
	// tool_result, is never part of it.
	Generated string
}

// Provider names as the node proxy resolves them (models.Provider*). They are
// duplicated here as literals so this pure package needs no models import.
const (
	providerAnthropic = "anthropic"
	providerOpenAI    = "openai"
	providerGoogle    = "google"
)

// ShapeFor maps the node proxy's resolved provider lane onto a wire shape.
// The OpenAI lane carries two shapes; the body says which (messages[] is Chat
// Completions, otherwise the Responses API). An unknown provider is
// ShapeUnknown.
func ShapeFor(provider string, body []byte) Shape {
	switch provider {
	case providerAnthropic:
		return ShapeAnthropicMessages
	case providerGoogle:
		return ShapeGemini
	case providerOpenAI:
		var probe struct {
			Messages json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(body, &probe) == nil && len(probe.Messages) > 0 && string(probe.Messages) != "null" {
			return ShapeOpenAIChat
		}
		return ShapeOpenAIResponses
	default:
		return ShapeUnknown
	}
}

// Classify decodes body as shape and classifies its newest turn. A body that
// does not decode, or an unknown shape, is KindNone.
func Classify(shape Shape, body []byte) Turn {
	switch shape {
	case ShapeAnthropicMessages:
		var raw struct {
			Messages []json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(body, &raw) != nil {
			return Turn{Kind: KindNone}
		}
		msgs := make([]AnthropicMessage, 0, len(raw.Messages))
		for _, m := range raw.Messages {
			var am AnthropicMessage
			if json.Unmarshal(m, &am) == nil {
				msgs = append(msgs, am)
			}
		}
		return FromAnthropicMessages(msgs)
	case ShapeOpenAIChat:
		var raw struct {
			Messages []json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(body, &raw) != nil {
			return Turn{Kind: KindNone}
		}
		msgs := make([]ChatMessage, 0, len(raw.Messages))
		for _, m := range raw.Messages {
			var cm ChatMessage
			if json.Unmarshal(m, &cm) == nil {
				msgs = append(msgs, cm)
			}
		}
		return FromChatMessages(msgs)
	case ShapeOpenAIResponses:
		var raw struct {
			Input json.RawMessage `json:"input"`
		}
		if json.Unmarshal(body, &raw) != nil {
			return Turn{Kind: KindNone}
		}
		return fromResponsesInput(raw.Input)
	case ShapeGemini:
		var raw struct {
			Contents []GeminiContent `json:"contents"`
		}
		if json.Unmarshal(body, &raw) != nil {
			return Turn{Kind: KindNone}
		}
		return FromGeminiContents(raw.Contents)
	default:
		return Turn{Kind: KindNone}
	}
}

// ClassifyProvider is Classify(ShapeFor(provider, body), body): the node
// proxy's entry point.
func ClassifyProvider(provider string, body []byte) Turn {
	return Classify(ShapeFor(provider, body), body)
}

// --- Anthropic Messages ----------------------------------------------------

// AnthropicMessage is the minimal Messages-API message shape. Exported so a
// caller that already decoded the messages (the guard's injection-scan walk)
// classifies the same slice without a second decode.
type AnthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// anthropicBlock is the minimal content-block shape.
type anthropicBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Content json.RawMessage `json:"content"`
	Input   json.RawMessage `json:"input"`
}

// FromAnthropicMessages classifies an already-decoded Messages-API slice.
// The newest role:"user" message decides: tool_result blocks with no text
// block is a continuation; anything else is a user_prompt whose text is its
// text blocks. A user message carrying BOTH a tool_result and text blocks is a
// user_prompt (the text is new input riding the tool result; documented
// heuristic, docs/guard-prompt.md "proxy lane").
func FromAnthropicMessages(msgs []AnthropicMessage) Turn {
	t := Turn{Kind: KindNone}
	lastAssistant := -1
	for i := range msgs {
		if msgs[i].Role == "assistant" {
			lastAssistant = i
		}
	}
	var trail, gen textJoiner
	if lastAssistant >= 0 {
		anthropicModelContent(&gen, msgs[lastAssistant].Content)
	}
	for i := lastAssistant + 1; i < len(msgs); i++ {
		if msgs[i].Role == "user" {
			anthropicTrailing(&trail, msgs[i].Content)
			anthropicToolResults(&gen, msgs[i].Content)
		}
	}
	t.Trailing = capTrailing(trail.String())
	t.Generated = capTrailing(gen.String())
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != "user" {
			continue
		}
		text, hasToolResult, hasText := anthropicUserText(msgs[i].Content)
		if hasToolResult && !hasText {
			t.Kind = KindContinuation
			for j := i - 1; j >= 0; j-- {
				if msgs[j].Role != "user" {
					continue
				}
				if opening, _, ok := anthropicUserText(msgs[j].Content); ok {
					t.Opening = opening
					break
				}
			}
			return t
		}
		t.Kind, t.Text, t.Blocks = KindUserPrompt, text, anthropicTextBlocks(msgs[i].Content)
		return t
	}
	return t
}

// anthropicTextBlocks lists one user message's non-blank text blocks.
func anthropicTextBlocks(content json.RawMessage) []string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return nonBlank(s)
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return nil
	}
	var out []string
	for _, b := range blocks {
		if b.Type == "text" {
			out = append(out, nonBlank(b.Text)...)
		}
	}
	return out
}

// anthropicUserText flattens one user message's text blocks and reports
// whether the message carried a tool_result block and a text block that is
// not blank. A whitespace-only text block next to a tool_result does not make
// the message a prompt (fix round 2, N2).
func anthropicUserText(content json.RawMessage) (text string, hasToolResult, hasText bool) {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s, false, strings.TrimSpace(s) != ""
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return "", false, false
	}
	var j textJoiner
	for _, b := range blocks {
		switch {
		case b.Type == "tool_result":
			hasToolResult = true
		case b.Type == "text" && b.Text != "":
			j.add(b.Text)
			if strings.TrimSpace(b.Text) != "" {
				hasText = true
			}
		}
	}
	return j.String(), hasToolResult, hasText
}

// anthropicTrailing adds one user message's text and tool_result content.
func anthropicTrailing(j *textJoiner, content json.RawMessage) {
	var s string
	if json.Unmarshal(content, &s) == nil {
		j.add(s)
		return
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return
	}
	for _, b := range blocks {
		switch b.Type {
		case "text":
			j.add(b.Text)
		case "tool_result":
			j.add(blockContentText(b.Content))
		}
	}
}

// anthropicModelContent adds one assistant message's own output: its text
// blocks and each tool_use block's input (the call the model wrote).
// Thinking blocks are skipped.
func anthropicModelContent(j *textJoiner, content json.RawMessage) {
	var s string
	if json.Unmarshal(content, &s) == nil {
		j.add(s)
		return
	}
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return
	}
	for _, b := range blocks {
		switch b.Type {
		case "text":
			j.add(b.Text)
		case "tool_use", "server_tool_use":
			j.add(rawJSONText(b.Input))
		}
	}
}

// anthropicToolResults adds one user message's tool_result content, never its
// text blocks (those are the developer's, or ride with the developer's turn).
func anthropicToolResults(j *textJoiner, content json.RawMessage) {
	var blocks []anthropicBlock
	if json.Unmarshal(content, &blocks) != nil {
		return
	}
	for _, b := range blocks {
		if b.Type == "tool_result" {
			j.add(blockContentText(b.Content))
		}
	}
}

// rawJSONText renders a raw JSON value for scanning: a string's own text,
// else the value's JSON form; null or absent is empty.
func rawJSONText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// blockContentText flattens a content field that is a string or an array of
// blocks carrying "text".
func blockContentText(content json.RawMessage) string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var j textJoiner
	for _, b := range blocks {
		j.add(b.Text)
	}
	return j.String()
}

// --- OpenAI Chat Completions -----------------------------------------------

// ChatToolCall is one assistant tool call in a Chat Completions message.
type ChatToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ChatMessage is the minimal Chat Completions message shape (exported for
// the same single-decode reason as AnthropicMessage).
type ChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"tool_call_id"`
	ToolCalls  []ChatToolCall  `json:"tool_calls"`
}

// FromChatMessages classifies an already-decoded Chat Completions slice. The
// newest role:"user" message is the prompt unless a role:"tool" message
// follows it: a tool result only ever answers the assistant's own tool call,
// so that request is a continuation re-sending the same original prompt.
func FromChatMessages(msgs []ChatMessage) Turn {
	t := Turn{Kind: KindNone}
	lastAssistant := -1
	for i := range msgs {
		if msgs[i].Role == "assistant" {
			lastAssistant = i
		}
	}
	var trail, gen textJoiner
	if lastAssistant >= 0 {
		gen.add(blockContentText(msgs[lastAssistant].Content))
		for _, tc := range msgs[lastAssistant].ToolCalls {
			gen.add(tc.Function.Arguments)
		}
	}
	for i := lastAssistant + 1; i < len(msgs); i++ {
		if msgs[i].Role == "user" || msgs[i].Role == "tool" {
			trail.add(blockContentText(msgs[i].Content))
		}
		if msgs[i].Role == "tool" {
			gen.add(blockContentText(msgs[i].Content))
		}
	}
	t.Trailing = capTrailing(trail.String())
	t.Generated = capTrailing(gen.String())
	lastUser := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			lastUser = i
			break
		}
	}
	for i := lastUser + 1; i < len(msgs); i++ {
		if msgs[i].Role == "tool" {
			// A tool result after the newest user message (or with no user
			// message at all): a continuation of the loop that message opened.
			t.Kind = KindContinuation
			if lastUser >= 0 {
				t.Opening = blockContentText(msgs[lastUser].Content)
			}
			return t
		}
	}
	if lastUser < 0 {
		return t
	}
	t.Kind, t.Text, t.Blocks = KindUserPrompt, blockContentText(msgs[lastUser].Content), contentTextBlocks(msgs[lastUser].Content)
	return t
}

// --- OpenAI Responses API --------------------------------------------------

// ResponsesItem is the minimal Responses-API input item shape (exported for
// the same single-decode reason as AnthropicMessage).
type ResponsesItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Name      string          `json:"name"`
	CallID    string          `json:"call_id"`
	Output    json.RawMessage `json:"output"`
	Content   json.RawMessage `json:"content"`
	Arguments json.RawMessage `json:"arguments"`
}

// fromResponsesInput classifies a Responses-API input field: a bare string
// is the whole prompt; an array is FromResponsesItems.
func fromResponsesInput(input json.RawMessage) Turn {
	if len(input) == 0 {
		return Turn{Kind: KindNone}
	}
	var whole string
	if json.Unmarshal(input, &whole) == nil {
		return Turn{Kind: KindUserPrompt, Text: whole, Trailing: capTrailing(whole), Blocks: nonBlank(whole)}
	}
	var rawItems []json.RawMessage
	if json.Unmarshal(input, &rawItems) != nil {
		return Turn{Kind: KindNone}
	}
	items := make([]ResponsesItem, 0, len(rawItems))
	for _, it := range rawItems {
		var ri ResponsesItem
		if json.Unmarshal(it, &ri) == nil {
			items = append(items, ri)
		}
	}
	return FromResponsesItems(items)
}

// FromResponsesItems classifies an already-decoded Responses-API item slice.
// The newest role:"user" item is the prompt unless a function_call_output
// item follows it (the same continuation rule as Chat Completions).
func FromResponsesItems(items []ResponsesItem) Turn {
	t := Turn{Kind: KindNone}
	lastAssistant := -1
	for i := range items {
		if items[i].Type == "function_call" || items[i].Role == "assistant" || items[i].Type == "reasoning" {
			lastAssistant = i
		}
	}
	var trail, gen textJoiner
	// The newest assistant-side run: the contiguous model items that end at
	// lastAssistant (calls, assistant messages; reasoning is skipped).
	first := lastAssistant
	for first > 0 && responsesModelItem(&items[first-1]) {
		first--
	}
	for i := first; i >= 0 && i <= lastAssistant; i++ {
		switch {
		case items[i].Type == "function_call":
			gen.add(rawJSONText(items[i].Arguments))
		case items[i].Role == "assistant":
			gen.add(blockContentText(items[i].Content))
		}
	}
	for i := lastAssistant + 1; i < len(items); i++ {
		switch {
		case items[i].Type == "function_call_output":
			out := responsesOutputText(items[i].Output)
			trail.add(out)
			gen.add(out)
		case items[i].Role == "user":
			trail.add(blockContentText(items[i].Content))
		}
	}
	t.Trailing = capTrailing(trail.String())
	t.Generated = capTrailing(gen.String())
	lastUser := -1
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Role == "user" {
			lastUser = i
			break
		}
	}
	for i := lastUser + 1; i < len(items); i++ {
		if items[i].Type == "function_call_output" {
			// A tool output after the newest user item, or with no user item
			// at all (a stateful Responses call that sends only the outputs
			// plus previous_response_id): a continuation.
			t.Kind = KindContinuation
			if lastUser >= 0 {
				t.Opening = blockContentText(items[lastUser].Content)
			}
			return t
		}
	}
	if lastUser < 0 {
		return t
	}
	t.Kind, t.Text, t.Blocks = KindUserPrompt, blockContentText(items[lastUser].Content), contentTextBlocks(items[lastUser].Content)
	return t
}

// responsesModelItem reports whether a Responses-API item is the model's own
// (the same set FromResponsesItems counts as assistant-side).
func responsesModelItem(it *ResponsesItem) bool {
	return it.Type == "function_call" || it.Role == "assistant" || it.Type == "reasoning"
}

// responsesOutputText renders a function_call_output: a string, else the
// structured output's JSON form.
func responsesOutputText(out json.RawMessage) string {
	var s string
	if json.Unmarshal(out, &s) == nil {
		return s
	}
	if len(out) == 0 || string(out) == "null" {
		return ""
	}
	return string(out)
}

// --- Gemini generateContent ------------------------------------------------

// GeminiPart is the minimal generateContent request part shape.
type GeminiPart struct {
	Text             string          `json:"text"`
	FunctionResponse json.RawMessage `json:"functionResponse"`
	FunctionCall     json.RawMessage `json:"functionCall"`
}

// GeminiContent is the minimal generateContent request content shape.
type GeminiContent struct {
	Role  string       `json:"role"`
	Parts []GeminiPart `json:"parts"`
}

// FromGeminiContents classifies an already-decoded contents slice. A content
// with role "user" OR no role (the API defaults an omitted role to user;
// Gemini's own turns always say "model") is a user turn; one whose parts are
// functionResponse only, or a role:"function" content after it, is a
// continuation.
func FromGeminiContents(contents []GeminiContent) Turn {
	t := Turn{Kind: KindNone}
	lastModel := -1
	for i := range contents {
		if contents[i].Role == "model" {
			lastModel = i
		}
	}
	var trail, gen textJoiner
	if lastModel >= 0 {
		for _, p := range contents[lastModel].Parts {
			gen.add(p.Text)
			gen.add(rawJSONText(p.FunctionCall))
		}
	}
	for i := lastModel + 1; i < len(contents); i++ {
		for _, p := range contents[i].Parts {
			trail.add(p.Text)
			if len(p.FunctionResponse) > 0 && string(p.FunctionResponse) != "null" {
				trail.add(string(p.FunctionResponse))
				gen.add(string(p.FunctionResponse))
			}
		}
	}
	t.Trailing = capTrailing(trail.String())
	t.Generated = capTrailing(gen.String())
	for i := len(contents) - 1; i >= 0; i-- {
		c := contents[i]
		switch c.Role {
		case "function", "tool":
			t.Kind = KindContinuation
			t.Opening = geminiOpening(contents[:i])
			return t
		case "", "user":
		default:
			continue
		}
		var j textJoiner
		var blocks []string
		hasFunctionResponse, hasText := false, false
		for _, p := range c.Parts {
			if len(p.FunctionResponse) > 0 && string(p.FunctionResponse) != "null" {
				hasFunctionResponse = true
			}
			if p.Text != "" {
				j.add(p.Text)
				blocks = append(blocks, nonBlank(p.Text)...)
				if strings.TrimSpace(p.Text) != "" {
					hasText = true
				}
			}
		}
		if hasFunctionResponse && !hasText {
			t.Kind = KindContinuation
			t.Opening = geminiOpening(contents[:i])
			return t
		}
		t.Kind, t.Text, t.Blocks = KindUserPrompt, j.String(), blocks
		return t
	}
	return t
}

// geminiOpening is the text of the newest user (or role-less) content in
// contents that carries text: the prompt that opened a function-call loop.
func geminiOpening(contents []GeminiContent) string {
	for i := len(contents) - 1; i >= 0; i-- {
		if r := contents[i].Role; r != "" && r != "user" {
			continue
		}
		var j textJoiner
		for _, p := range contents[i].Parts {
			j.add(p.Text)
		}
		if text := j.String(); strings.TrimSpace(text) != "" {
			return text
		}
	}
	return ""
}

// --- helpers ---------------------------------------------------------------

// contentTextBlocks lists a content field's non-blank text pieces: a string
// is one block, an array of parts carrying "text" is one block per part.
func contentTextBlocks(content json.RawMessage) []string {
	var s string
	if json.Unmarshal(content, &s) == nil {
		return nonBlank(s)
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &parts) != nil {
		return nil
	}
	var out []string
	for _, p := range parts {
		out = append(out, nonBlank(p.Text)...)
	}
	return out
}

// nonBlank is s as a one-element list, or nil when s is blank.
func nonBlank(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}

// textJoiner joins non-empty pieces with newlines.
type textJoiner struct{ b strings.Builder }

func (j *textJoiner) add(s string) {
	if s == "" {
		return
	}
	if j.b.Len() > 0 {
		j.b.WriteByte('\n')
	}
	j.b.WriteString(s)
}

func (j *textJoiner) String() string { return j.b.String() }

// capTrailing caps s at MaxTrailingBytes without splitting a UTF-8 sequence.
func capTrailing(s string) string {
	if len(s) <= MaxTrailingBytes {
		return s
	}
	cut := MaxTrailingBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}
