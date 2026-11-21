package genaiattr

import (
	"encoding/json"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// GenAI log events (plan-of-record W3-7, finding F21). The GenAI semantic
// conventions move prompt and completion content off the span onto log
// events correlated with it by trace and span id. Two generations are in the
// wild, and the mappers accept both (principle 8):
//
//   - the pinned convention's one event per inference,
//     gen_ai.client.inference.operation.details, carrying the structured
//     gen_ai.input.messages, gen_ai.output.messages and
//     gen_ai.system_instructions as event ATTRIBUTES (the same keys a span
//     carries, read through Read);
//   - the legacy one-event-per-message names (gen_ai.system.message,
//     gen_ai.user.message, gen_ai.assistant.message, gen_ai.tool.message,
//     gen_ai.choice), each carrying one message in the event BODY (a kvlist
//     such as {content, role, tool_calls} or a bare string), still emitted by
//     many OpenLLMetry and OpenTelemetry Python instrumentations.
//
// gen_ai.evaluation.result is a GenAI event too, but it carries a score, not
// content: it is task W3-1's (the scores mapping), so it yields no body here.

// The GenAI event names.
const (
	EventInferenceDetails = "gen_ai.client.inference.operation.details"
	EventSystemMessage    = "gen_ai.system.message"
	EventUserMessage      = "gen_ai.user.message"
	EventAssistantMessage = "gen_ai.assistant.message"
	EventToolMessage      = "gen_ai.tool.message"
	EventChoice           = "gen_ai.choice"
	EventEvaluationResult = "gen_ai.evaluation.result"
)

// EventNameKey is the attribute an older SDK names a log event with (before
// OTLP's LogRecord.event_name field).
const EventNameKey = "event.name"

// eventSource says where an event's content lives.
type eventSource int

const (
	// fromNone: the event carries no content (a score).
	fromNone eventSource = iota
	// fromAttributes: the structured message attributes, read like a span's.
	fromAttributes
	// fromBody: one message in the event body.
	fromBody
)

// EventRule is one row of the event table.
type EventRule struct {
	// Name is the event name.
	Name string
	// Dialect is the convention generation it belongs to.
	Dialect Dialect
	// Kind is the content kind a body-carried message lands in (unused for
	// an attribute-carried event, whose keys decide).
	Kind ContentKind
	// Role is the message role a legacy event implies when its body names
	// none.
	Role string
	// source is where the content lives.
	source eventSource
}

// eventRules is THE event table; one conformance case per row
// (testdata/conformance/genai_events.json).
var eventRules = []EventRule{
	{Name: EventInferenceDetails, Dialect: DialectGenAI, source: fromAttributes},
	{Name: EventSystemMessage, Dialect: DialectGenAILegacy, Kind: ContentSystemInstructions, Role: "system", source: fromBody},
	{Name: EventUserMessage, Dialect: DialectGenAILegacy, Kind: ContentPrompt, Role: "user", source: fromBody},
	{Name: EventAssistantMessage, Dialect: DialectGenAILegacy, Kind: ContentPrompt, Role: "assistant", source: fromBody},
	{Name: EventToolMessage, Dialect: DialectGenAILegacy, Kind: ContentPrompt, Role: "tool", source: fromBody},
	{Name: EventChoice, Dialect: DialectGenAILegacy, Kind: ContentResponse, Role: "assistant", source: fromBody},
	{Name: EventEvaluationResult, Dialect: DialectGenAI, source: fromNone},
}

// EventRules returns the event table (a copy), in table order.
func EventRules() []EventRule { return append([]EventRule(nil), eventRules...) }

// EventRuleFor returns the row of an event name.
func EventRuleFor(name string) (EventRule, bool) {
	for _, r := range eventRules {
		if r.Name == name {
			return r, true
		}
	}
	return EventRule{}, false
}

// EventName returns a log record's event name: the record's own event_name
// field, else its event.name attribute.
func EventName(recordEventName string, a Attrs) string {
	if n := strings.TrimSpace(recordEventName); n != "" {
		return n
	}
	return strings.TrimSpace(Text(a[EventNameKey]))
}

// EventMessage is one message a legacy per-message event carries, for the
// caller that joins several events of one span into a message list.
type EventMessage struct {
	Kind ContentKind
	// JSON is the message as a JSON object (role added when the body names
	// none), or the body's JSON rendering when it is not an object.
	JSON json.RawMessage
}

// EventContent is what one GenAI log event contributes: whole bodies (the
// inference event, ready to store) or single messages (a legacy event, to be
// joined per span and kind by the caller). Raw, unscrubbed text: scrubbing
// and the capture gate are the caller's, as for Bodies.
type EventContent struct {
	Bodies   []Body
	Messages []EventMessage
}

// Event extracts the content of one log event. A name with no row, or a row
// that carries no content, yields the zero value.
func Event(name string, a Attrs, body *commonpb.AnyValue) EventContent {
	r, ok := EventRuleFor(name)
	if !ok {
		return EventContent{}
	}
	switch r.source {
	case fromAttributes:
		f := Read(a)
		var out []Body
		add := func(k ContentKind, raw string) {
			if raw = strings.TrimSpace(raw); raw != "" {
				out = append(out, Body{Kind: k, Raw: raw})
			}
		}
		add(ContentPrompt, f.InputMessages)
		add(ContentResponse, f.OutputMessages)
		add(ContentSystemInstructions, f.SystemInstructions)
		return EventContent{Bodies: out}
	case fromBody:
		if m, ok := eventMessage(r, body); ok {
			return EventContent{Messages: []EventMessage{m}}
		}
	}
	return EventContent{}
}

// eventMessage renders a legacy event body as one message: a kvlist becomes a
// JSON object with the implied role added when absent; a bare string becomes
// {"role", "content"}; anything else its JSON rendering.
func eventMessage(r EventRule, body *commonpb.AnyValue) (EventMessage, bool) {
	if body == nil || body.GetValue() == nil {
		return EventMessage{}, false
	}
	var v any
	switch x := body.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		if strings.TrimSpace(x.StringValue) == "" {
			return EventMessage{}, false
		}
		v = map[string]any{"role": r.Role, "content": x.StringValue}
	case *commonpb.AnyValue_KvlistValue:
		obj, _ := JSONValue(body).(map[string]any)
		if len(obj) == 0 {
			return EventMessage{}, false
		}
		if _, has := obj["role"]; !has && r.Role != "" {
			obj["role"] = r.Role
		}
		v = obj
	default:
		v = JSONValue(body)
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return EventMessage{}, false
	}
	return EventMessage{Kind: r.Kind, JSON: b}, true
}

// JoinMessages renders the messages of one kind, in order, as one JSON array
// (the shape of a span's gen_ai.input.messages); "" when there are none.
func JoinMessages(ms []json.RawMessage) string {
	if len(ms) == 0 {
		return ""
	}
	b, err := json.Marshal(ms)
	if err != nil {
		return ""
	}
	return string(b)
}
