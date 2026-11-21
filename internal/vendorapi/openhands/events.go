package openhands

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceEvents is the catalog id of the conversation event search.
const SurfaceEvents vs.SurfaceID = "openhands.cloud.events_search"

// Event vocabulary.
const (
	EventsContract = "openhands.cloud.events_search/v1 cloud-api v1 reference 2026-10-31"

	// EventNamespace is the namespace of the metadata-only event rows (tool
	// calls, tool results, errors, state changes) of a conversation.
	EventNamespace = "openhands.event"
	// ActionOther is the action of an event kind outside eventKinds (the
	// canary reports it; its kind name is never carried).
	ActionOther = "other"
	// ParamConversationID names the conversation whose events a request
	// reads.
	ParamConversationID = "conversation_id"
	// messageKind is the event kind whose text lands as content.
	messageKind = "MessageEvent"
)

// eventKinds maps a documented event kind to the action its metadata row
// carries. The reference lists the families (message, action, observation,
// LLM completion logs, token events, hook execution, deltas, errors); the
// class names follow the OpenHands software-agent-sdk event types and are
// Inferred until a live response is observed.
var eventKinds = map[string]string{
	"ActionEvent":                  "tool_call",
	"ObservationEvent":             "tool_result",
	"UserRejectObservation":        "tool_rejected",
	"AgentErrorEvent":              "agent_error",
	"ConversationErrorEvent":       "conversation_error",
	"SystemPromptEvent":            "system_prompt",
	"ConversationStateUpdateEvent": "state_update",
	"PauseEvent":                   "pause",
	"Condensation":                 "condensation",
	"CondensationRequest":          "condensation_request",
	"CondensationSummaryEvent":     "condensation_summary",
	"LLMCompletionLogEvent":        "llm_completion",
	"TokenEvent":                   "llm_usage",
	"HookExecutionEvent":           "hook_execution",
}

// messageRoles maps a MessageEvent source to a content role. A message from
// any other source lands as a metadata row only.
var messageRoles = map[string]string{
	"user":  "prompt",
	"agent": "response",
}

// Events returns the driver of openhands.cloud.events_search.
//
// Contract (OpenHands Cloud V1, "Search Events", reference source OH08): GET
// /api/v1/conversation/{conversation_id}/events/search with limit (at most
// 100), page_id and sort_order=TIMESTAMP (ascending, so a replay reads oldest
// first); for an incremental run the window is sent as timestamp__gte and
// timestamp__lt (filter names Inferred). Response {items: [{id, timestamp,
// source, kind, ...}], next_page_id}. A MessageEvent from the user or the
// agent lands as one content item (the text parts of llm_message.content);
// every other event lands as one metadata row in namespace openhands.event
// whose action names the kind (tool_call, tool_result, agent_error, ...),
// with the tool name and call id and never the action arguments or the
// observation output, which the closed DTO does not decode. The
// conversation id comes from the conversation_id parameter.
func Events() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceEvents,
		Build:           buildEvents,
		ParseResponse:   parseEvents,
		Canary:          canaryEvents,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassContent, vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: EventsContract,
		Tool:            Tool,
		KnownPaths:      eventsKnownPaths,
	}
}

func buildEvents(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	cid := p[ParamConversationID]
	if !idRE.MatchString(cid) {
		return vendorapi.Request{}, fmt.Errorf("%s: parameter %s must be a conversation id", SurfaceEvents, ParamConversationID)
	}
	q := map[string][]string{"sort_order": {"TIMESTAMP"}}
	if err := windowQuery(SurfaceEvents, q, "timestamp", w); err != nil {
		return vendorapi.Request{}, err
	}
	if err := pageQuery(SurfaceEvents, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{
		Method: "GET", Path: "/api/v1/conversation/" + url.PathEscape(cid) + "/events/search", Query: q,
	}, nil
}

// event is the closed DTO of one event: action, observation and every other
// kind-specific body are deliberately absent.
type event struct {
	ID         *string `json:"id"`
	Timestamp  *string `json:"timestamp"`
	Source     *string `json:"source"`
	Kind       *string `json:"kind"`
	ToolName   *string `json:"tool_name"`
	ToolCallID *string `json:"tool_call_id"`
	LLMMessage *struct {
		Role    *string `json:"role"`
		Content *[]struct {
			Type *string `json:"type"`
			Text *string `json:"text"`
		} `json:"content"`
	} `json:"llm_message"`
}

// messageText joins the text parts of a message; ok is false when the
// content is not the documented part list.
func messageText(e event) (string, bool) {
	if e.LLMMessage == nil || e.LLMMessage.Content == nil {
		return "", false
	}
	var parts []string
	for _, c := range *e.LLMMessage.Content {
		if str(c.Type) == "text" && c.Text != nil {
			parts = append(parts, *c.Text)
		}
	}
	return strings.Join(parts, "\n"), true
}

func parseEvents(r vendorapi.Response) (vendorapi.Page, error) {
	var doc page[event]
	next, err := envelope(SurfaceEvents, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	cid := r.Params[ParamConversationID]
	if !idRE.MatchString(cid) {
		return vendorapi.Page{}, drift(SurfaceEvents, "the request's %s parameter is not a conversation id", ParamConversationID)
	}
	out := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Items)}
	seen := map[string]bool{}
	for i, e := range *doc.Items {
		id := str(e.ID)
		if !idRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceEvents, "items[%d].id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceEvents, "items[%d] repeats an event", i)
		}
		seen[id] = true
		at, ok := isoTime(e.Timestamp)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceEvents, "items[%d].timestamp is not an ISO timestamp", i)
		}
		kind, source := str(e.Kind), str(e.Source)
		if kind == "" || source == "" {
			return vendorapi.Page{}, drift(SurfaceEvents, "items[%d] misses kind or source", i)
		}
		if role, ok := messageRoles[source]; ok && kind == messageKind {
			text, ok := messageText(e)
			if !ok || !utf8.ValidString(text) {
				return vendorapi.Page{}, drift(SurfaceEvents, "items[%d].llm_message.content is not the documented part list", i)
			}
			text, cut := capText(text, vendorapi.MaxContentBytes)
			out.Content = append(out.Content, vendorapi.ContentItem{
				ItemID: id, At: at, SessionRef: cid, Role: role, Text: text, Truncated: cut,
			})
			continue
		}
		action, known := eventKinds[kind]
		detail := map[string]string{}
		switch {
		case kind == messageKind:
			action = "message"
		case !known:
			action = ActionOther
		}
		if len(source) <= vendorapi.MaxIDLen && tokenSafe(source) {
			detail["source"] = source
		}
		if v := str(e.ToolCallID); v != "" {
			if len(v) > vendorapi.MaxAttrValue {
				return vendorapi.Page{}, drift(SurfaceEvents, "items[%d].tool_call_id is over-long", i)
			}
			detail["tool_call_id"] = v
		}
		target := str(e.ToolName)
		if len(target) > vendorapi.MaxTargetLen {
			return vendorapi.Page{}, drift(SurfaceEvents, "items[%d].tool_name is over-long", i)
		}
		out.Audit = append(out.Audit, vendorapi.AuditEvent{
			Namespace: EventNamespace, EventID: id, At: at, ActorIsAgent: source == "agent",
			AgentSessionID: cid, Action: action, Target: target, Detail: detail,
		})
	}
	return out, nil
}

// tokenSafe reports whether a short vendor enum value (a source) is safe to
// carry as a detail value: lower-case letters, digits and underscores.
func tokenSafe(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return s != ""
}

// canaryEvents reports an event kind outside the documented table (landed as
// other). The kind name itself is never carried.
func canaryEvents(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, e := range p.Audit {
		if e.Action == ActionOther {
			return []vendorapi.DriftSignal{{Path: "items[].kind", Kind: "unknown_enum"}}
		}
	}
	return nil
}

// eventsKnownPaths are the response paths of the corpus field ledger of
// "Search Events".
var eventsKnownPaths = []string{
	"items", "items[]", "items[].action", "items[].action_id", "items[].id", "items[].kind", "items[].llm_message",
	"items[].llm_message.content", "items[].llm_message.content[]", "items[].llm_message.content[].text",
	"items[].llm_message.content[].type", "items[].llm_message.role", "items[].observation", "items[].source",
	"items[].timestamp", "items[].tool_call_id", "items[].tool_name", "next_page_id",
}
