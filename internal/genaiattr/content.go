package genaiattr

import (
	"encoding/json"
	"strings"
)

// ContentKind names one stored body of a span (the obs_content kind
// vocabulary both the node and the org server store and read).
type ContentKind string

// The content kinds.
const (
	ContentPrompt             ContentKind = "prompt"
	ContentResponse           ContentKind = "response"
	ContentToolIO             ContentKind = "tool_io"
	ContentSystemInstructions ContentKind = "system_instructions"
	ContentSpanIO             ContentKind = "span_io"
)

// Span kind classes Bodies dispatches on (the canonical kind of a span, a
// capability classification, never a source identity).
const (
	SpanKindLLM  = "llm"
	SpanKindTool = "tool"
)

// Body is one content body of a span, trimmed and non-empty.
type Body struct {
	Kind ContentKind
	Raw  string
}

// Bodies returns a span's content bodies from its normalised attributes: an
// LLM span's prompt, response and system instructions; a tool span's
// arguments and result as one {input, output} JSON object; any other span's
// serialized input/output the same way (agent, chain, retriever: F19). It is
// the one extraction rule of the node mapper and the gateway mapper. It
// returns raw (unscrubbed) text: scrubbing and the capture gate are the
// caller's. Total: a content-less span yields nil.
func Bodies(f Fields, spanKind string) []Body {
	var out []Body
	add := func(k ContentKind, raw string) {
		if raw = strings.TrimSpace(raw); raw != "" {
			out = append(out, Body{Kind: k, Raw: raw})
		}
	}
	switch spanKind {
	case SpanKindTool:
		add(ContentToolIO, IOJSON(f.ToolArguments, f.ToolResult))
	case SpanKindLLM:
		add(ContentPrompt, firstNonEmpty(f.InputMessages, f.PromptValue))
		add(ContentResponse, firstNonEmpty(f.OutputMessages, f.ResponseValue))
		add(ContentSystemInstructions, f.SystemInstructions)
	default:
		add(ContentSpanIO, IOJSON(f.InputValue, f.OutputValue))
	}
	return out
}

// IOJSON renders an input and an output as one {input, output} JSON object
// with only the present halves; "" when both are empty.
func IOJSON(in, out string) string {
	m := make(map[string]string, 2)
	if in != "" {
		m["input"] = in
	}
	if out != "" {
		m["output"] = out
	}
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// ReportedTotal is the reported total cost of c: the total when reported,
// else the sum of the reported components, nil when nothing was reported.
func (c Cost) ReportedTotal() *float64 {
	if c.Total != nil {
		v := *c.Total
		return &v
	}
	if c.Empty() {
		return nil
	}
	var sum float64
	for _, p := range []*float64{c.Input, c.Output, c.CacheRead, c.CacheWrite, c.Reasoning, c.Tool} {
		if p != nil {
			sum += *p
		}
	}
	return &sum
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// contentFields are the fields whose values are customer content (a message
// list, a prompt or completion blob, a tool's arguments or result, a span's
// serialized input or output). Their keys are what a classifier must treat as
// content before any vocabulary-prefix rule (E-03).
var contentFields = []Field{
	FieldInputMessages, FieldOutputMessages, FieldSystemInstructions,
	FieldPromptValue, FieldResponseValue, FieldInputValue, FieldOutputValue,
	FieldToolArguments, FieldToolResult,
}

// extraContentKeys are content keys no field reads but a known emitter
// writes: OpenInference's completion-API prompt list and prompt template, the
// GenAI semconv's tool definitions (opt-in, marked sensitive) and
// OpenInference's tool schemas.
var extraContentKeys = []string{
	"llm.prompts", "llm.prompt_template.template", "llm.prompt_template.variables",
	"gen_ai.tool.definitions", "llm.tools",
}

// ContentAttributeKeys returns every attribute key whose value is customer
// content, as a fresh set: the keys of the content fields plus the known
// unread content keys. Indexed message lists are matched by
// ContentAttributePrefixes.
func ContentAttributeKeys() map[string]struct{} {
	out := KeySet(contentFields...)
	for _, k := range extraContentKeys {
		out[k] = struct{}{}
	}
	return out
}

// ContentAttributePrefixes returns the key prefixes (each ending in ".") under
// which a flattened attribute is customer content: the indexed message lists
// (IndexedInput, IndexedOutput) and the flattened forms of the list-valued
// content keys.
func ContentAttributePrefixes() []string {
	var out []string
	for _, l := range IndexedInput {
		out = append(out, l.Prefix+".")
	}
	for _, l := range IndexedOutput {
		out = append(out, l.Prefix+".")
	}
	return append(out, "llm.prompts.", "llm.prompt_template.", "llm.tools.")
}
