package promptturn

import (
	"encoding/json"
	"sort"
	"strings"
)

// admission.go is the ONE owner of the admission accounting rule (hosted AI
// gateway security review, finding H1, lead decision L-180): what text an
// admission judge reads in a request body, and which user-supplied content in
// it no extractor can render as text. The AI gateway's app gate
// (internal/orgserver/appadmit) and the node proxy's hosted-app admission
// (internal/proxy/admission.go) both call AdmissionView; neither keeps a copy.
//
// The rule: content the judge cannot read is never admitted as if there were
// nothing to judge. A caller refuses a body whose Unaccounted list is not
// empty under an enforcing policy and flags it under an observing one, and
// treats a view with no Units and nothing Unaccounted as "no user content at
// all".

// AdmissionScope selects how much of a conversation an admission view reads.
// It mirrors the admission policy's scope (policyfam/admission.Scope), kept
// as its own type so this pure package imports no policy family.
type AdmissionScope int

// The closed scope vocabulary.
const (
	// AdmissionLastTurn reads the newest user turn: every user message after
	// the model's last turn (consecutive user messages are one turn), or,
	// when that run carries only tool results, the user turn that opened the
	// tool loop.
	AdmissionLastTurn AdmissionScope = iota
	// AdmissionConversation reads every user turn and every tool result.
	AdmissionConversation
)

// Admission is the admission view of one request body.
type Admission struct {
	// Units are the texts to judge, in body order, each non-blank. Under
	// AdmissionLastTurn there is at most one; under AdmissionConversation one
	// per user message and one per tool result.
	Units []string
	// Unaccounted names, sorted and distinct, the user-supplied content in
	// the turns the scope reads that no extractor renders as text. Names are
	// content-free type labels: "block:<type>" (a content block or part),
	// "part:<key>" (a Gemini part), "item:<type>" (a Responses input item),
	// "field:<name>" (a top-level content field the shape does not read, or
	// one of the wrong JSON type), "input:tokens" (embeddings sent as token
	// ids), "body:unparsed" (a non-empty body that is not a JSON object) and
	// "shape:unknown" (a body whose wire shape is not known).
	Unaccounted []string
}

// Empty reports a view with nothing to judge and nothing unaccounted: a body
// with no user content at all.
func (a Admission) Empty() bool { return len(a.Units) == 0 && len(a.Unaccounted) == 0 }

// Unaccounted-content names that are not a block or field label.
const (
	UnaccountedUnparsed     = "body:unparsed"
	UnaccountedUnknownShape = "shape:unknown"
	UnaccountedTokens       = "input:tokens"
)

// AdmissionView builds the admission view of body as shape under scope. An
// empty body has no user content. A body of an unknown shape, or one that is
// not a JSON object, is entirely unaccounted.
func AdmissionView(shape Shape, body []byte, scope AdmissionScope) Admission {
	if len(strings.TrimSpace(string(body))) == 0 {
		return Admission{}
	}
	dec, ok := admissionDecoders[shape]
	if !ok {
		return Admission{Unaccounted: []string{UnaccountedUnknownShape}}
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || top == nil {
		return Admission{Unaccounted: []string{UnaccountedUnparsed}}
	}
	acc := newAccounting()
	// A top-level content field this shape does not read carries text no
	// judge sees (a legacy completions prompt, a Responses stored prompt, a
	// messages list on an input-shaped endpoint).
	for _, f := range contentFields {
		if f == dec.field {
			continue
		}
		if present(top[f]) {
			acc.unaccounted("field:" + f)
		}
	}
	msgs := dec.decode(top[dec.field], acc)
	return acc.view(msgs, scope)
}

// contentFields are the top-level fields any supported wire shape reads its
// conversation from. A shape reads exactly one of them.
var contentFields = []string{"messages", "input", "contents", "prompt"}

// admissionDecoder is one shape's row: the content field it reads and the
// function that normalises it into messages.
type admissionDecoder struct {
	field  string
	decode func(raw json.RawMessage, acc *accounting) []admMsg
}

// admissionDecoders is the shape table (CLAUDE.md rule 5).
var admissionDecoders = map[Shape]admissionDecoder{
	ShapeAnthropicMessages: {field: "messages", decode: decodeAnthropicAdmission},
	ShapeOpenAIChat:        {field: "messages", decode: decodeChatAdmission},
	ShapeOpenAIResponses:   {field: "input", decode: decodeResponsesAdmission},
	ShapeGemini:            {field: "contents", decode: decodeGeminiAdmission},
	ShapeEmbeddings:        {field: "input", decode: decodeEmbeddingsAdmission},
}

// --- decode targets ------------------------------------------------------------

// The structs the view decodes into. Go's encoding/json matches a struct
// field's name case-insensitively (and under Unicode folding), so their json
// tags are part of KnownFields: the AI gateway's strict reader refuses a key
// that equals one of them only under folding.
type (
	admMessage struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	admBlock struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
		Title   string          `json:"title"`
		Context string          `json:"context"`
		Source  json.RawMessage `json:"source"`
	}
	admSource struct {
		Type    string          `json:"type"`
		Data    json.RawMessage `json:"data"`
		Content json.RawMessage `json:"content"`
	}
	admTypedText struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	admGeminiContent struct {
		Role  string                       `json:"role"`
		Parts []map[string]json.RawMessage `json:"parts"`
	}
)

// --- normalised messages -----------------------------------------------------

// admRole is a normalised message role.
type admRole int

const (
	roleOther admRole = iota // a role whose content is not user input (system, developer)
	roleUser
	roleModel
	roleTool
)

// admPartKind is what one part of a message is to admission.
type admPartKind int

const (
	partText  admPartKind = iota // user-supplied text the judge reads
	partTool                     // a tool result's text
	partOther                    // user-supplied content no extractor reads
)

type admPart struct {
	kind admPartKind
	text string // partText, partTool
	name string // partOther: the unaccounted label
}

type admMsg struct {
	role  admRole
	parts []admPart
}

// accounting collects the unaccounted labels found outside any message (a
// malformed field) while the decoders run.
type accounting struct {
	global map[string]bool
}

func newAccounting() *accounting { return &accounting{global: map[string]bool{}} }

func (a *accounting) unaccounted(name string) { a.global[name] = true }

// view walks the normalised messages under scope (shape-independent).
func (a *accounting) view(msgs []admMsg, scope AdmissionScope) Admission {
	unacc := map[string]bool{}
	for k := range a.global {
		unacc[k] = true
	}
	var units []string
	if scope == AdmissionConversation {
		units = conversationUnits(msgs, unacc)
	} else {
		units = lastTurnUnits(msgs, unacc)
	}
	return Admission{Units: units, Unaccounted: sortedKeys(unacc)}
}

// lastTurnUnits is the newest user turn's text: every user message after the
// model's last message. A run that carries tool results and no user text is a
// tool-loop continuation, judged by the text of the user message that opened
// the loop (the newest earlier one with text).
func lastTurnUnits(msgs []admMsg, unacc map[string]bool) []string {
	lastModel := -1
	for i := range msgs {
		if msgs[i].role == roleModel {
			lastModel = i
		}
	}
	var text textJoiner
	hasTool := false
	for _, m := range msgs[lastModel+1:] {
		switch m.role {
		case roleUser:
			addUserParts(&text, m, unacc)
			for _, p := range m.parts {
				if p.kind == partTool {
					hasTool = true
				}
			}
		case roleTool:
			hasTool = true
		}
	}
	if t := text.String(); strings.TrimSpace(t) != "" {
		return []string{t}
	}
	if !hasTool {
		return nil
	}
	for i := lastModel; i >= 0; i-- {
		if msgs[i].role != roleUser {
			continue
		}
		var opening textJoiner
		found := map[string]bool{}
		addUserParts(&opening, msgs[i], found)
		if t := opening.String(); strings.TrimSpace(t) != "" {
			for k := range found {
				unacc[k] = true
			}
			return []string{t}
		}
	}
	return nil
}

// conversationUnits is one unit per user message (its text parts joined) and
// one per tool result, in body order.
func conversationUnits(msgs []admMsg, unacc map[string]bool) []string {
	var units []string
	for _, m := range msgs {
		if m.role != roleUser && m.role != roleTool {
			continue
		}
		var text textJoiner
		addUserParts(&text, m, unacc)
		if t := text.String(); strings.TrimSpace(t) != "" {
			units = append(units, t)
		}
		for _, p := range m.parts {
			if p.kind == partTool && strings.TrimSpace(p.text) != "" {
				units = append(units, p.text)
			}
		}
	}
	return units
}

// addUserParts joins a message's text parts into j and notes its other parts.
func addUserParts(j *textJoiner, m admMsg, unacc map[string]bool) {
	for _, p := range m.parts {
		switch p.kind {
		case partText:
			if strings.TrimSpace(p.text) != "" {
				j.add(p.text)
			}
		case partOther:
			unacc[p.name] = true
		}
	}
}

// --- Anthropic Messages --------------------------------------------------------

// anthropicPlumbing are block types a user message may replay that are the
// model's own output, not user content (the node proxy's G1 exclusions).
var anthropicPlumbing = map[string]bool{
	"thinking": true, "redacted_thinking": true, "tool_use": true, "server_tool_use": true,
}

func decodeAnthropicAdmission(raw json.RawMessage, acc *accounting) []admMsg {
	items, ok := rawArray(raw, "messages", acc)
	if !ok {
		return nil
	}
	msgs := make([]admMsg, 0, len(items))
	for _, it := range items {
		var m admMessage
		if json.Unmarshal(it, &m) != nil {
			acc.unaccounted("field:messages")
			continue
		}
		switch m.Role {
		case "assistant":
			msgs = append(msgs, admMsg{role: roleModel})
		case "user":
			msgs = append(msgs, admMsg{role: roleUser, parts: anthropicUserParts(m.Content)})
		default:
			msgs = append(msgs, admMsg{role: roleOther})
		}
	}
	return msgs
}

// anthropicUserParts normalises one user message's content.
func anthropicUserParts(content json.RawMessage) []admPart {
	if !present(content) {
		return nil
	}
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []admPart{{kind: partText, text: s}}
	}
	var blocks []json.RawMessage
	if json.Unmarshal(content, &blocks) != nil {
		return []admPart{{kind: partOther, name: "field:content"}}
	}
	var parts []admPart
	for _, raw := range blocks {
		var b admBlock
		if json.Unmarshal(raw, &b) != nil {
			parts = append(parts, admPart{kind: partOther, name: "block:malformed"})
			continue
		}
		switch {
		case b.Type == "text":
			parts = append(parts, admPart{kind: partText, text: b.Text})
		case b.Type == "tool_result" || strings.HasSuffix(b.Type, "_tool_result"):
			parts = append(parts, admPart{kind: partTool, text: blockContentText(b.Content)})
		case b.Type == "document":
			parts = append(parts, anthropicDocumentParts(b.Title, b.Context, b.Source)...)
		case b.Type == "search_result":
			parts = append(parts, admPart{kind: partText, text: b.Title})
			parts = append(parts, textBlockParts(b.Content, "block:search_result")...)
		case anthropicPlumbing[b.Type]:
		default:
			parts = append(parts, admPart{kind: partOther, name: "block:" + typeLabel(b.Type)})
		}
	}
	return parts
}

// anthropicDocumentParts reads a document block: its title and context, and
// the text of a "text" source (data) or a "content" source (a string, or text
// blocks). A base64, URL or file source (a PDF, an uploaded file) is content
// no extractor reads.
func anthropicDocumentParts(title, docContext string, source json.RawMessage) []admPart {
	parts := []admPart{{kind: partText, text: title}, {kind: partText, text: docContext}}
	var src admSource
	if json.Unmarshal(source, &src) != nil {
		return append(parts, admPart{kind: partOther, name: "block:document"})
	}
	switch src.Type {
	case "text":
		var data string
		if json.Unmarshal(src.Data, &data) != nil {
			return append(parts, admPart{kind: partOther, name: "block:document"})
		}
		return append(parts, admPart{kind: partText, text: data})
	case "content":
		return append(parts, textBlockParts(src.Content, "block:document")...)
	default:
		return append(parts, admPart{kind: partOther, name: "block:document:" + typeLabel(src.Type)})
	}
}

// textBlockParts reads a content value that is a string or a list of blocks:
// text blocks are text, anything else (an image inside a document) is
// unaccounted under the given label's family.
func textBlockParts(content json.RawMessage, label string) []admPart {
	if !present(content) {
		return nil
	}
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []admPart{{kind: partText, text: s}}
	}
	var blocks []admTypedText
	if json.Unmarshal(content, &blocks) != nil {
		return []admPart{{kind: partOther, name: label}}
	}
	var parts []admPart
	for _, b := range blocks {
		if b.Type == "text" {
			parts = append(parts, admPart{kind: partText, text: b.Text})
			continue
		}
		parts = append(parts, admPart{kind: partOther, name: label + ":" + typeLabel(b.Type)})
	}
	return parts
}

// --- OpenAI Chat Completions ---------------------------------------------------

func decodeChatAdmission(raw json.RawMessage, acc *accounting) []admMsg {
	items, ok := rawArray(raw, "messages", acc)
	if !ok {
		return nil
	}
	msgs := make([]admMsg, 0, len(items))
	for _, it := range items {
		var m admMessage
		if json.Unmarshal(it, &m) != nil {
			acc.unaccounted("field:messages")
			continue
		}
		switch m.Role {
		case "assistant":
			msgs = append(msgs, admMsg{role: roleModel})
		case "tool", "function":
			msgs = append(msgs, admMsg{role: roleTool, parts: []admPart{{kind: partTool, text: blockContentText(m.Content)}}})
		case "user":
			msgs = append(msgs, admMsg{role: roleUser, parts: openAIUserParts(m.Content, chatTextTypes)})
		default:
			msgs = append(msgs, admMsg{role: roleOther})
		}
	}
	return msgs
}

// chatTextTypes / responsesTextTypes are the content-part types each OpenAI
// wire carries user text in.
var (
	chatTextTypes      = map[string]bool{"text": true}
	responsesTextTypes = map[string]bool{"input_text": true, "text": true, "output_text": true}
)

// openAIUserParts normalises one OpenAI user content value: a string, or a
// list of typed parts.
func openAIUserParts(content json.RawMessage, textTypes map[string]bool) []admPart {
	if !present(content) {
		return nil
	}
	var s string
	if json.Unmarshal(content, &s) == nil {
		return []admPart{{kind: partText, text: s}}
	}
	var blocks []admTypedText
	if json.Unmarshal(content, &blocks) != nil {
		return []admPart{{kind: partOther, name: "field:content"}}
	}
	parts := make([]admPart, 0, len(blocks))
	for _, b := range blocks {
		if textTypes[b.Type] {
			parts = append(parts, admPart{kind: partText, text: b.Text})
			continue
		}
		parts = append(parts, admPart{kind: partOther, name: "block:" + typeLabel(b.Type)})
	}
	return parts
}

// --- OpenAI Responses API ------------------------------------------------------

// responsesItemRule classifies one Responses input item by its type (an
// ordered rule table, first match wins; CLAUDE.md rule 5).
type responsesItemRule struct {
	match func(itemType string) bool
	role  admRole
}

var responsesItemRules = []responsesItemRule{
	{match: func(t string) bool { return t == "message" || t == "" }, role: roleUser}, // role decides below
	{match: func(t string) bool { return strings.HasSuffix(t, "_call_output") || t == "mcp_approval_response" }, role: roleTool},
	{match: func(t string) bool {
		return t == "reasoning" || strings.HasSuffix(t, "_call") || strings.HasPrefix(t, "mcp_")
	}, role: roleModel},
}

func decodeResponsesAdmission(raw json.RawMessage, acc *accounting) []admMsg {
	if !present(raw) {
		return nil
	}
	var whole string
	if json.Unmarshal(raw, &whole) == nil {
		return []admMsg{{role: roleUser, parts: []admPart{{kind: partText, text: whole}}}}
	}
	items, ok := rawArray(raw, "input", acc)
	if !ok {
		return nil
	}
	msgs := make([]admMsg, 0, len(items))
	for _, it := range items {
		var ri ResponsesItem
		if json.Unmarshal(it, &ri) != nil {
			acc.unaccounted("field:input")
			continue
		}
		msgs = append(msgs, responsesMsg(ri))
	}
	return msgs
}

// responsesMsg normalises one Responses input item.
func responsesMsg(ri ResponsesItem) admMsg {
	for _, rule := range responsesItemRules {
		if !rule.match(ri.Type) {
			continue
		}
		switch rule.role {
		case roleTool:
			return admMsg{role: roleTool, parts: []admPart{{kind: partTool, text: responsesOutputText(ri.Output)}}}
		case roleModel:
			return admMsg{role: roleModel}
		}
		switch ri.Role {
		case "user":
			return admMsg{role: roleUser, parts: openAIUserParts(ri.Content, responsesTextTypes)}
		case "assistant":
			return admMsg{role: roleModel}
		case "system", "developer":
			return admMsg{role: roleOther}
		}
		return unknownResponsesItem(ri)
	}
	return unknownResponsesItem(ri)
}

// unknownResponsesItem is an item no rule names (an item_reference to stored
// content, an unknown type, a message with no known role): it carries content
// the view cannot see, so it counts as an unaccounted user item where it
// stands.
func unknownResponsesItem(ri ResponsesItem) admMsg {
	name := "item:" + typeLabel(ri.Type)
	if ri.Type == "message" || ri.Type == "" {
		name = "item:message:" + typeLabel(ri.Role)
	}
	return admMsg{role: roleUser, parts: []admPart{{kind: partOther, name: name}}}
}

// --- Gemini generateContent ----------------------------------------------------

// geminiPartKinds maps a Gemini part key to what it is in a user content.
var geminiPartKinds = map[string]admPartKind{
	"text":             partText,
	"functionResponse": partTool,
}

// geminiPartMetadata are part keys that carry no content.
var geminiPartMetadata = map[string]bool{
	"thought": true, "thoughtSignature": true, "videoMetadata": true, "partMetadata": true, "mediaResolution": true,
}

func decodeGeminiAdmission(raw json.RawMessage, acc *accounting) []admMsg {
	items, ok := rawArray(raw, "contents", acc)
	if !ok {
		return nil
	}
	msgs := make([]admMsg, 0, len(items))
	for _, it := range items {
		var c admGeminiContent
		if json.Unmarshal(it, &c) != nil {
			acc.unaccounted("field:contents")
			continue
		}
		switch c.Role {
		case "model":
			msgs = append(msgs, admMsg{role: roleModel})
			continue
		case "", "user", "function", "tool":
		default:
			msgs = append(msgs, admMsg{role: roleOther})
			continue
		}
		role := roleUser
		if c.Role == "function" || c.Role == "tool" {
			role = roleTool
		}
		msgs = append(msgs, admMsg{role: role, parts: geminiParts(c.Parts)})
	}
	return msgs
}

// geminiParts normalises one user content's parts.
func geminiParts(parts []map[string]json.RawMessage) []admPart {
	var out []admPart
	for _, p := range parts {
		keys := make([]string, 0, len(p))
		for k := range p {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if geminiPartMetadata[k] {
				continue
			}
			kind, known := geminiPartKinds[k]
			switch {
			case !known:
				out = append(out, admPart{kind: partOther, name: "part:" + typeLabel(k)})
			case kind == partText:
				var s string
				if json.Unmarshal(p[k], &s) != nil {
					out = append(out, admPart{kind: partOther, name: "part:text"})
					continue
				}
				out = append(out, admPart{kind: partText, text: s})
			default:
				out = append(out, admPart{kind: partTool, text: rawJSONText(p[k])})
			}
		}
	}
	return out
}

// --- OpenAI embeddings ---------------------------------------------------------

// decodeEmbeddingsAdmission reads an embeddings input: a string or a list of
// strings is text; token ids (a list of numbers or of lists) are not.
func decodeEmbeddingsAdmission(raw json.RawMessage, acc *accounting) []admMsg {
	if !present(raw) {
		return nil
	}
	var whole string
	if json.Unmarshal(raw, &whole) == nil {
		return []admMsg{{role: roleUser, parts: []admPart{{kind: partText, text: whole}}}}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		parts := make([]admPart, 0, len(many))
		for _, s := range many {
			parts = append(parts, admPart{kind: partText, text: s})
		}
		return []admMsg{{role: roleUser, parts: parts}}
	}
	acc.unaccounted(UnaccountedTokens)
	return nil
}

// --- helpers -------------------------------------------------------------------

// present reports a field that is set to something other than null.
func present(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t != "" && t != "null"
}

// rawArray decodes a content field that must be a JSON array; a field of any
// other type is unaccounted (the provider may read it in a way this view
// does not).
func rawArray(raw json.RawMessage, field string, acc *accounting) ([]json.RawMessage, bool) {
	if !present(raw) {
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		acc.unaccounted("field:" + field)
		return nil, false
	}
	return items, true
}

// typeLabel bounds a client-chosen type name used in a label: at most 40
// bytes of [a-z0-9_:.-], anything else replaced, so a label never carries
// request content.
func typeLabel(t string) string {
	if t == "" {
		return "untyped"
	}
	if len(t) > 40 {
		t = t[:40]
	}
	b := []byte(t)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		case c >= 'A' && c <= 'Z':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
