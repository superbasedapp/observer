package warp

import (
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Conversation surface.
const (
	SurfaceConversation vs.SurfaceID = "warp.agent_api.run_conversation"

	ConversationContract = "warp.agent_api.run_conversation/v1 " + contract
)

// Conversation vocabulary.
const (
	// EventNamespace keys the metadata-only events of a run's conversation.
	EventNamespace = "warp.conversation"
	// The event actions a conversation lands.
	ActionToolCall   = "tool_call"
	ActionToolResult = "tool_result"
	ActionEvent      = "event"
	// maxStepDepth bounds the nested delegated steps walked.
	maxStepDepth = 16
)

// roleContent maps a normalized message role to a content role; a tool or
// system message lands no content item (its blocks still land as events).
var roleContent = map[string]string{"user": "prompt", "assistant": "response"}

// RunConversation returns the driver of warp.agent_api.run_conversation.
//
// Contract (OpenAPI getRunConversation): GET
// /api/v1/agent/runs/{runId}/conversation, one document {conversation_id,
// steps[]} with nested steps, each holding ordered messages {message_ids,
// role, timestamp, content[]}; a block is text, action {id, category, name,
// input}, action_result {action_id, category, name, state, output} or event
// {name, data}. User and assistant text lands as content items (prompt,
// response) under the run id; an action lands as a tool_call event naming
// the public action and its category, an action_result as a tool_result
// event with its state, an event block as an event row with its name. Action
// input and output and event data are never decoded. A message with no
// timestamp takes its step's started_at; a message with neither is not
// landed.
func RunConversation() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceConversation,
		Build:           buildConversation,
		ParseResponse:   parseConversation,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassContent, vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: ConversationContract,
		KnownPaths:      conversationKnownPaths,
	}
}

func buildConversation(p vendorapi.Params, _ vendorapi.Window, _ string) (vendorapi.Request, error) {
	path, err := runPath(SurfaceConversation, p, "/conversation")
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path}, nil
}

type block struct {
	Type     *string `json:"type"`
	Text     *string `json:"text"`
	ID       *string `json:"id"`
	ActionID *string `json:"action_id"`
	Category *string `json:"category"`
	Name     *string `json:"name"`
	State    *string `json:"state"`
	// input, output and data are curated free-form objects; they have no
	// field here, so they are never decoded.
}

type message struct {
	MessageIDs *[]string `json:"message_ids"`
	Role       *string   `json:"role"`
	Timestamp  *string   `json:"timestamp"`
	Content    *[]block  `json:"content"`
}

type step struct {
	ID        *string    `json:"id"`
	StartedAt *string    `json:"started_at"`
	Messages  *[]message `json:"messages"`
	Steps     *[]step    `json:"steps"`
}

type conversationDoc struct {
	ConversationID *string `json:"conversation_id"`
	Steps          *[]step `json:"steps"`
}

// convWalk carries one parse.
type convWalk struct {
	run   string
	out   *vendorapi.Page
	items map[string]bool
	evs   map[string]bool
}

func parseConversation(r vendorapi.Response) (vendorapi.Page, error) {
	if err := status200(SurfaceConversation, r); err != nil {
		return vendorapi.Page{}, err
	}
	runID := r.Params[ParamRunID]
	if !idRE.MatchString(runID) {
		return vendorapi.Page{}, drift(SurfaceConversation, "the request named no run id")
	}
	var doc conversationDoc
	if err := decode(r.Body, &doc); err != nil {
		return vendorapi.Page{}, drift(SurfaceConversation, "body does not decode as the documented ConversationResponse")
	}
	if !idRE.MatchString(str(doc.ConversationID)) {
		return vendorapi.Page{}, drift(SurfaceConversation, "required field conversation_id is missing or not an id")
	}
	if doc.Steps == nil {
		return vendorapi.Page{}, drift(SurfaceConversation, "required field steps is missing")
	}
	// SourceRecords counts the record container, the root steps.
	out := vendorapi.Page{SourceRecords: len(*doc.Steps)}
	w := &convWalk{run: runID, out: &out, items: map[string]bool{}, evs: map[string]bool{}}
	for i, s := range *doc.Steps {
		if err := w.step("steps["+strconv.Itoa(i)+"]", s, 0); err != nil {
			return vendorapi.Page{}, err
		}
	}
	return out, nil
}

func (w *convWalk) step(at string, s step, depth int) error {
	if depth >= maxStepDepth {
		return drift(SurfaceConversation, "%s nests deeper than %d steps", at, maxStepDepth)
	}
	id := str(s.ID)
	if !idRE.MatchString(id) {
		return drift(SurfaceConversation, "%s.id is missing or not an id", at)
	}
	if s.Messages == nil || s.Steps == nil {
		return drift(SurfaceConversation, "%s is missing the required messages or steps", at)
	}
	var stepStart time.Time
	if s.StartedAt != nil {
		t, ok := rfc3339(s.StartedAt)
		if !ok {
			return drift(SurfaceConversation, "%s.started_at is not an RFC 3339 timestamp", at)
		}
		stepStart = t
	}
	for i, m := range *s.Messages {
		if err := w.message(at+".messages["+strconv.Itoa(i)+"]", id, i, m, stepStart); err != nil {
			return err
		}
	}
	for i, c := range *s.Steps {
		if err := w.step(at+".steps["+strconv.Itoa(i)+"]", c, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (w *convWalk) message(at, stepID string, idx int, m message, stepStart time.Time) error {
	role := str(m.Role)
	if role == "" {
		return drift(SurfaceConversation, "%s.role is missing", at)
	}
	if m.Content == nil {
		return drift(SurfaceConversation, "%s.content is missing", at)
	}
	ts := stepStart
	if m.Timestamp != nil {
		t, ok := rfc3339(m.Timestamp)
		if !ok {
			return drift(SurfaceConversation, "%s.timestamp is not an RFC 3339 timestamp", at)
		}
		ts = t
	}
	itemID := "step:" + stepID + ":" + strconv.Itoa(idx)
	if m.MessageIDs != nil && len(*m.MessageIDs) > 0 && idRE.MatchString((*m.MessageIDs)[0]) {
		itemID = (*m.MessageIDs)[0]
	}
	if ts.IsZero() {
		return nil // no time anywhere: not landed (inventing one would be fabrication)
	}
	var text []string
	for j, b := range *m.Content {
		kind := str(b.Type)
		switch kind {
		case "text":
			if b.Text == nil {
				return drift(SurfaceConversation, "%s.content[%d] is a text block without text", at, j)
			}
			text = append(text, *b.Text)
		case "action":
			if !idRE.MatchString(str(b.ID)) || !tokenRE.MatchString(str(b.Name)) {
				return drift(SurfaceConversation, "%s.content[%d] is an action without an id or a name", at, j)
			}
			if err := w.event(str(b.ID), ts, ActionToolCall, str(b.Name), true, map[string]string{"category": token(b.Category)}); err != nil {
				return err
			}
		case "action_result":
			if !idRE.MatchString(str(b.ActionID)) || !tokenRE.MatchString(str(b.Name)) {
				return drift(SurfaceConversation, "%s.content[%d] is an action result without an action id or a name", at, j)
			}
			if err := w.event("result:"+str(b.ActionID), ts, ActionToolResult, str(b.Name), false,
				map[string]string{"category": token(b.Category), "state": token(b.State), "action_id": str(b.ActionID)}); err != nil {
				return err
			}
		case "event":
			if !tokenRE.MatchString(str(b.Name)) {
				return drift(SurfaceConversation, "%s.content[%d] is an event without a name", at, j)
			}
			if err := w.event("event:"+itemID+":"+strconv.Itoa(j), ts, ActionEvent, str(b.Name), true, nil); err != nil {
				return err
			}
		default:
			return drift(SurfaceConversation, "%s.content[%d] has an undocumented block type", at, j)
		}
	}
	cr, ok := roleContent[role]
	if !ok || len(text) == 0 {
		return nil
	}
	if w.items[itemID] {
		return drift(SurfaceConversation, "%s repeats message %s", at, itemID)
	}
	w.items[itemID] = true
	t, cut := capText(strings.Join(text, "\n\n"), vendorapi.MaxContentBytes)
	w.out.Content = append(w.out.Content, vendorapi.ContentItem{
		ItemID: itemID, At: ts, SessionRef: w.run, Role: cr, Text: t, Truncated: cut,
	})
	return nil
}

func (w *convWalk) event(id string, at time.Time, action, target string, agent bool, detail map[string]string) error {
	if len(id) > vendorapi.MaxIDLen {
		return drift(SurfaceConversation, "an event id is over-long")
	}
	if w.evs[id] {
		return drift(SurfaceConversation, "event %s repeats", id)
	}
	w.evs[id] = true
	for k, v := range detail {
		if v == "" {
			delete(detail, k)
		}
	}
	w.out.Audit = append(w.out.Audit, vendorapi.AuditEvent{
		Namespace: EventNamespace, EventID: id, At: at, ActorIsAgent: agent, AgentSessionID: w.run,
		Action: action, Target: target, Detail: detail,
	})
	return nil
}

// token lowercases a bounded enum value ("" when absent or malformed).
func token(s *string) string {
	v := str(s)
	if !tokenRE.MatchString(v) {
		return ""
	}
	return strings.ToLower(v)
}
