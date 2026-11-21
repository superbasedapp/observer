package genaiattr

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Usage is a span's normalised token usage. Every bucket is nil when no key
// of it is present (an honest NULL, never a fabricated 0). The bucket
// semantics are the package doc's "Token buckets": Input is gross (CacheRead
// and CacheWrite are subsets of it), Output includes Reasoning, and a derived
// Total is Input + Output only.
type Usage struct {
	Input, Output, Total             *int64
	CacheRead, CacheWrite, Reasoning *int64
	// TotalDerived is true when Total was not reported but derived as
	// Input + Output (finding F16).
	TotalDerived bool
	// InputShape and OutputShape say whether Input and Output were reported
	// as the vocabulary defines them (ShapeGross, the zero value) or net of
	// their subsets (ShapeNet), as the reported total reveals (shape.go).
	// The buckets are kept as reported; a pricer nets or adds by the shape.
	InputShape, OutputShape CountShape
}

// ReadUsage resolves the usage buckets of one span, first present key per
// bucket. When the span carries no flat usage key at all, a usage_details
// blob (the langfuse dialect, langfuse.go) is decoded instead: the two are
// never mixed bucket by bucket. When no total is present and at least one of
// Input / Output is, Total = Input + Output (an absent half counts 0: an
// embedding call reports input only) and TotalDerived is set. Cache and
// reasoning counts are never added to the total: they are already inside
// Input / Output.
func ReadUsage(a Attrs) Usage {
	u := Usage{
		Input:      a.Int(Keys(FieldInputTokens)),
		Output:     a.Int(Keys(FieldOutputTokens)),
		Total:      a.Int(Keys(FieldTotalTokens)),
		CacheRead:  a.Int(Keys(FieldCacheReadTokens)),
		CacheWrite: a.Int(Keys(FieldCacheWriteTokens)),
		Reasoning:  a.Int(Keys(FieldReasoningTokens)),
	}
	if u.empty() {
		u = usageFromDetails(a.First(Keys(FieldUsageDetails)))
	}
	// LangChain's serialized usage_metadata carries a cache write the
	// LangChain.js instrumentation never maps (normalize.go).
	fillCacheFromLangChain(a, &u)
	if u.Total == nil && (u.Input != nil || u.Output != nil) {
		var t int64
		if u.Input != nil {
			t += *u.Input
		}
		if u.Output != nil {
			t += *u.Output
		}
		u.Total = &t
		u.TotalDerived = true
	}
	resolveShapes(&u)
	return u
}

// Cost is a span's REPORTED cost in USD, as emitted: Total is the reported
// total (nil when none), the components the reported breakdown. Nothing is
// computed here.
type Cost struct {
	Total, Input, Output, CacheRead, CacheWrite, Reasoning, Tool *float64
}

// Empty reports whether no cost, total or component, was reported.
func (c Cost) Empty() bool {
	return c.Total == nil && c.Input == nil && c.Output == nil && c.CacheRead == nil &&
		c.CacheWrite == nil && c.Reasoning == nil && c.Tool == nil
}

// ReadCost resolves the reported cost of one span: the flat cost keys, else
// (when none is present) a cost_details blob (the langfuse dialect). Either
// way it is a REPORTED cost (D24: a computed cost wins when the model is
// priced; that decision is the caller's).
func ReadCost(a Attrs) Cost {
	if c := readFlatCost(a); !c.Empty() {
		return c
	}
	return costFromDetails(a.First(Keys(FieldCostDetails)))
}

func readFlatCost(a Attrs) Cost {
	return Cost{
		Total:      a.Float(Keys(FieldCostTotal)),
		Input:      a.Float(Keys(FieldCostInput)),
		Output:     a.Float(Keys(FieldCostOutput)),
		CacheRead:  a.Float(Keys(FieldCostCacheRead)),
		CacheWrite: a.Float(Keys(FieldCostCacheWrite)),
		Reasoning:  a.Float(Keys(FieldCostReasoning)),
		Tool:       a.Float(Keys(FieldCostTool)),
	}
}

// Fields is one span's attributes normalised onto the canonical vocabulary.
// A string field is "" when absent. Message and parameter fields hold JSON
// text.
type Fields struct {
	Model, RequestModel, ResponseModel string
	Provider, Operation, RequestType   string

	Usage Usage
	Cost  Cost

	RequestID, ResponseID string

	ToolName, ToolCallID, ToolArguments, ToolResult string

	AgentName, AgentID, EntityName string

	// InputMessages / OutputMessages are the structured message lists: the
	// pinned gen_ai.input.messages / gen_ai.output.messages value, else an
	// indexed list (OpenInference, then legacy GenAI / Traceloop) rendered
	// as a JSON array of messages. SystemInstructions is
	// gen_ai.system_instructions.
	InputMessages, OutputMessages, SystemInstructions string
	// PromptValue / ResponseValue are the serialized request / response blob
	// fallbacks of an LLM span.
	PromptValue, ResponseValue string
	// InputValue / OutputValue are any span's serialized input / output
	// (agent, chain, retriever and tool spans included).
	InputValue, OutputValue string

	ErrorType     string
	FinishReasons []string
	// RequestParams is the request parameters as a canonical (sorted) JSON
	// object, "" when none is present.
	RequestParams string

	// ObservationType is the Langfuse observation type, lowercased
	// (ObservationTypes; ObservationKind maps it to a kind class).
	ObservationType string
	// StatusMessage is a status message carried as an attribute; a mapper
	// uses it only when the OTLP status has none.
	StatusMessage string
}

// Read normalises one span's attributes.
func Read(a Attrs) Fields {
	model, rawModel := SpanModel(a, Keys(FieldModel))
	f := Fields{
		Model:              model,
		RequestModel:       a.First(Keys(FieldRequestModel)),
		ResponseModel:      a.First(Keys(FieldResponseModel)),
		Provider:           a.First(Keys(FieldProvider)),
		Operation:          a.First(Keys(FieldOperation)),
		RequestType:        a.First(Keys(FieldRequestType)),
		Usage:              ReadUsage(a),
		Cost:               ReadCost(a),
		RequestID:          a.First(Keys(FieldRequestID)),
		ResponseID:         a.First(Keys(FieldResponseID)),
		ToolName:           a.First(Keys(FieldToolName)),
		ToolCallID:         a.First(Keys(FieldToolCallID)),
		ToolArguments:      a.First(Keys(FieldToolArguments)),
		ToolResult:         a.First(Keys(FieldToolResult)),
		AgentName:          a.First(Keys(FieldAgentName)),
		AgentID:            a.First(Keys(FieldAgentID)),
		EntityName:         a.First(Keys(FieldEntityName)),
		InputMessages:      Messages(a, FieldInputMessages, IndexedInput),
		OutputMessages:     Messages(a, FieldOutputMessages, IndexedOutput),
		SystemInstructions: a.First(Keys(FieldSystemInstructions)),
		PromptValue:        a.First(Keys(FieldPromptValue)),
		ResponseValue:      a.First(Keys(FieldResponseValue)),
		InputValue:         a.First(Keys(FieldInputValue)),
		OutputValue:        a.First(Keys(FieldOutputValue)),
		ErrorType:          a.First(Keys(FieldErrorType)),
		FinishReasons:      FinishReasons(a),
		RequestParams:      RequestParams(a),
		ObservationType:    strings.ToLower(strings.TrimSpace(a.First(Keys(FieldObservationType)))),
		StatusMessage:      strings.TrimSpace(a.First(Keys(FieldStatusMessage))),
	}
	// The request model: a router-prefixed name is kept as emitted there
	// (the model is normalised), else OpenInference's invocation parameters.
	if f.RequestModel == "" && rawModel != model {
		f.RequestModel = rawModel
	}
	if f.RequestModel == "" {
		f.RequestModel = requestModelFromParams(a)
	}
	f.ResponseModel = NormalizeModel(f.ResponseModel)
	if f.AgentName == "" {
		f.AgentName = agentNameFallback(a)
	}
	if f.InputValue == "" {
		// An OpenInference embedding span without input.value still carries
		// its inputs as embedding.embeddings.<i>.embedding.text.
		f.InputValue = EmbeddingTexts(a)
	}
	return f
}

// The OpenInference embedding input list: embedding.embeddings.<i> with the
// text under .embedding.text (the vector under .embedding.vector is never
// content and is not read).
const (
	EmbeddingListPrefix = "embedding.embeddings"
	EmbeddingTextSuffix = ".embedding.text"
)

// EmbeddingTexts renders an embedding span's input texts as a JSON array of
// strings, "" when none is present. The walk stops at the first absent index.
// It is raw content: scrubbing and the capture gate are the caller's.
func EmbeddingTexts(a Attrs) string {
	var texts []string
	for i := 0; i < maxIndexed; i++ {
		t := a.Str(EmbeddingListPrefix + "." + strconv.Itoa(i) + EmbeddingTextSuffix)
		if t == "" {
			break
		}
		texts = append(texts, t)
	}
	if len(texts) == 0 {
		return ""
	}
	b, err := json.Marshal(texts)
	if err != nil {
		return ""
	}
	return string(b)
}

// Messages resolves a structured message list: the field's own key (a
// structured value renders as JSON, a JSON string stays verbatim), else the
// first indexed list present, rendered as a JSON array. "" when none.
func Messages(a Attrs, f Field, lists []IndexedList) string {
	if s := strings.TrimSpace(a.First(Keys(f))); s != "" {
		return s
	}
	for _, l := range lists {
		if s := collectIndexed(a, l); s != "" {
			return s
		}
	}
	return ""
}

// IndexedMessages renders the first indexed list of lists present on a span
// as a JSON array, "" when none is.
func IndexedMessages(a Attrs, lists []IndexedList) string {
	for _, l := range lists {
		if s := collectIndexed(a, l); s != "" {
			return s
		}
	}
	return ""
}

// maxIndexed bounds an indexed list's length (messages, parts, tool calls).
const maxIndexed = 512

type indexedPart struct {
	Type  string `json:"type,omitempty"`
	Text  string `json:"text,omitempty"`
	Image string `json:"image,omitempty"`
}

type indexedToolCall struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type indexedMessage struct {
	Role       string            `json:"role,omitempty"`
	Content    string            `json:"content,omitempty"`
	Parts      []indexedPart     `json:"parts,omitempty"`
	ToolCalls  []indexedToolCall `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
}

// collectIndexed folds one flattened "<prefix>.<i>..." message list into a
// JSON array. A message is present when its role, content, first part or
// first tool call is; the walk stops at the first absent index.
func collectIndexed(a Attrs, l IndexedList) string {
	sh := l.shape()
	var msgs []indexedMessage
	for i := 0; i < maxIndexed; i++ {
		idx := l.Prefix + "." + strconv.Itoa(i)
		m := indexedMessage{
			Role:       a.Str(idx + l.Role),
			Content:    a.Str(idx + l.Content),
			ToolCallID: a.Str(idx + sh.toolCallID),
		}
		for j := 0; j < maxIndexed; j++ {
			p := idx + sh.parts + "." + strconv.Itoa(j)
			part := indexedPart{
				Type:  a.Str(p + sh.partType),
				Text:  a.Str(p + sh.partText),
				Image: a.Str(p + sh.partImage),
			}
			if part == (indexedPart{}) {
				break
			}
			m.Parts = append(m.Parts, part)
		}
		for j := 0; j < maxIndexed; j++ {
			p := idx + sh.calls + "." + strconv.Itoa(j)
			tc := indexedToolCall{
				ID:        a.Str(p + sh.callID),
				Name:      a.Str(p + sh.callName),
				Arguments: a.Str(p + sh.callArgs),
			}
			if tc == (indexedToolCall{}) {
				break
			}
			m.ToolCalls = append(m.ToolCalls, tc)
		}
		if m.Role == "" && m.Content == "" && len(m.Parts) == 0 && len(m.ToolCalls) == 0 {
			break
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return ""
	}
	b, err := json.Marshal(msgs)
	if err != nil {
		return ""
	}
	return string(b)
}

// indexedShape is the per-dialect sub-key layout of one indexed message.
type indexedShape struct {
	parts, partType, partText, partImage string
	calls, callID, callName, callArgs    string
	toolCallID                           string
}

// shapes: OpenInference nests every member under ".message."; the legacy
// GenAI / Traceloop lists are flat.
var (
	oiShape = indexedShape{
		parts: ".message.contents", partType: ".message_content.type",
		partText: ".message_content.text", partImage: ".message_content.image.image.url",
		calls: ".message.tool_calls", callID: ".tool_call.id",
		callName: ".tool_call.function.name", callArgs: ".tool_call.function.arguments",
		toolCallID: ".message.tool_call_id",
	}
	flatShape = indexedShape{
		parts: ".contents", partType: ".type", partText: ".text", partImage: ".image_url",
		calls: ".tool_calls", callID: ".id", callName: ".name", callArgs: ".arguments",
		toolCallID: ".tool_call_id",
	}
)

func (l IndexedList) shape() indexedShape {
	if l.Dialect == DialectOpenInference {
		return oiShape
	}
	return flatShape
}

// FinishReasons resolves a span's finish reasons: the pinned
// gen_ai.response.finish_reasons (a string array) or a Traceloop scalar,
// else Traceloop's per-choice gen_ai.completion.<i>.finish_reason. Nil when
// none.
func FinishReasons(a Attrs) []string {
	if v := a.Value(Keys(FieldFinishReasons)); v != nil {
		if out := Strings(v); len(out) > 0 {
			return out
		}
	}
	var out []string
	for _, l := range IndexedOutput {
		if l.Dialect == DialectOpenInference {
			continue
		}
		for i := 0; i < maxIndexed; i++ {
			s := strings.TrimSpace(a.Str(l.Prefix + "." + strconv.Itoa(i) + IndexedFinishReason))
			if s == "" {
				break
			}
			out = append(out, s)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// Request-parameter merge bounds for OpenInference's llm.invocation_parameters
// blob: only scalar members (and short arrays of scalars) are merged, so a
// blob that carries messages, tools or a system prompt never leaks content
// into the parameter column.
const (
	maxParamString = 128
	maxParamArray  = 16
)

// contentParamNames are invocation-parameter members that carry content, never
// merged.
var contentParamNames = map[string]bool{
	"messages": true, "prompt": true, "input": true, "system": true, "tools": true,
	"functions": true, "tool_choice": true, "response_format": true, "contents": true,
}

// RequestParams renders a span's request parameters as a canonical JSON
// object (sorted keys): every Params key present (first key per name wins),
// then the safe scalar members of each ParamBlobKeys blob a Params key or an
// earlier blob has not already set. "" when no parameter is present.
func RequestParams(a Attrs) string {
	out := map[string]any{}
	for _, p := range Params {
		if _, set := out[p.Name]; set {
			continue
		}
		if v := a.Value([]string{p.Key}); v != nil {
			if jv := JSONValue(v); jv != nil {
				out[p.Name] = jv
			}
		}
	}
	for _, key := range ParamBlobKeys {
		mergeParamBlob(out, a.Str(key))
	}
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

// mergeParamBlob merges the safe scalar members of one JSON-object blob into
// out; a member out already holds is kept.
func mergeParamBlob(out map[string]any, raw string) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "{") {
		return
	}
	var blob map[string]any
	if err := json.Unmarshal([]byte(raw), &blob); err != nil {
		return
	}
	liftEffort(out, blob)
	for k, v := range blob {
		if _, set := out[k]; set || contentParamNames[k] || !safeParam(v) {
			continue
		}
		out[k] = v
	}
}

// safeParam admits a scalar parameter value (number, bool, short string) or
// a short array of them.
func safeParam(v any) bool {
	switch x := v.(type) {
	case float64, bool, nil:
		return true
	case string:
		return len(x) <= maxParamString
	case []any:
		if len(x) > maxParamArray {
			return false
		}
		for _, e := range x {
			if _, nested := e.([]any); nested || !safeParam(e) {
				return false
			}
		}
		return true
	}
	return false
}
