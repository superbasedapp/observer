package qoder

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Cloud Agents session event history (lane CA-V2). Content is never
// decoded: a message lands as a metadata-only event (its kind and time), a
// tool call as its tool name, a tool result as its success flag. No credit
// figure is landed from events: the live check of 2026-11-02 showed credits
// only as the session's cumulative total (session.usage, the Session's usage)
// and rounded per-request figures (span.model_request_end model_usage), both
// of which repeat the total the sessions surface lands, and no
// session.status_idle usage at all.
const (
	SurfaceCloudEvents vs.SurfaceID = "qoder.ca.session_events"

	CloudEventsContract = "qoder.ca.session_events/v1 qca-sdk 54e7a314 (2026-10-29)"

	// CloudEventNamespace keys the metadata-only event rows.
	CloudEventNamespace = "qoder.cloud_event"

	// The event actions (AuditEvent.Action).
	ActionUserMessage      = "user_message"
	ActionAgentMessage     = "agent_message"
	ActionToolCall         = "tool_call"
	ActionToolResult       = "tool_result"
	ActionTurnEnd          = "turn_end"
	ActionStatusRunning    = "status_running"
	ActionStatusTerminated = "status_terminated"
	ActionSessionError     = "session_error"
	ActionContextCompacted = "context_compacted"
	ActionModelRequest     = "model_request"
	ActionUsageSnapshot    = "usage_snapshot"
	ActionCloudOther       = "other"

	// DetailToolUseID names the tool call a result answers.
	DetailToolUseID = "tool_use_id"
	// DetailIsError is "true" for a failed tool result.
	DetailIsError = "is_error"
	// DetailStopReason is a turn end's stop_reason.type.
	DetailStopReason = "stop_reason"
	// DetailMCPServer names an MCP tool call's server.
	DetailMCPServer = "mcp_server"
)

// cloudEventRule maps one event type to its action.
type cloudEventRule struct {
	action string
}

// cloudEventRules is the event type table (qca-sdk SessionEvent types, plus
// the thread, span-start and thinking types the live check of 2026-11-02
// showed in every turn).
var cloudEventRules = map[string]cloudEventRule{
	"user.message":                     {action: ActionUserMessage},
	"agent.message":                    {action: ActionAgentMessage},
	"agent.tool_use":                   {action: ActionToolCall},
	"agent.mcp_tool_use":               {action: ActionToolCall},
	"agent.custom_tool_use":            {action: ActionToolCall},
	"agent.tool_result":                {action: ActionToolResult},
	"agent.mcp_tool_result":            {action: ActionToolResult},
	"user.tool_result":                 {action: ActionToolResult},
	"user.custom_tool_result":          {action: ActionToolResult},
	"session.status_idle":              {action: ActionTurnEnd},
	"session.status_running":           {action: ActionStatusRunning},
	"session.status_terminated":        {action: ActionStatusTerminated},
	"session.error":                    {action: ActionSessionError},
	"agent.thread_context_compacted":   {action: ActionContextCompacted},
	"span.model_request_start":         {action: "model_request_start"},
	"span.model_request_end":           {action: ActionModelRequest},
	"agent.thinking":                   {action: "agent_thinking"},
	"session.usage":                    {action: ActionUsageSnapshot},
	"user.interrupt":                   {action: "user_interrupt"},
	"user.define_outcome":              {action: "define_outcome"},
	"agent.artifact_delivered":         {action: "artifact_delivered"},
	"session.thread_status_running":    {action: "thread_running"},
	"session.thread_status_idle":       {action: "thread_idle"},
	"session.thread_status_terminated": {action: "thread_terminated"},
	"session.deleted":                  {action: "session_deleted"},
}

// CloudEvents returns the driver of qoder.ca.session_events.
//
// Contract (qca-sdk Managed sessions.events.list, "GET
// /sessions/{session_id}/events"): query limit (at most 100), order,
// page, after_id, before_id, created_at[gt|gte|lt|lte], types[]; response
// {data: [SessionEvent], has_more, next_page} (page style PageCursor).
// Events are read oldest first; a window, when one is passed, is a
// created_at[gte] / created_at[lt] window. Each event lands as one
// metadata-only audit row (namespace qoder.cloud_event) timed by
// processed_at: a tool call carries its tool name as the target, a tool
// result its tool_use_id and is_error, a turn end its stop reason. No usage
// row is landed: every credit figure an event carries repeats the session's
// cumulative total (see the package note above). Message content, thinking,
// tool input and output, error messages and artifact names are never
// decoded. An event type outside the table lands as other and trips the
// canary; an event without processed_at is counted and not landed.
func CloudEvents() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCloudEvents,
		Build:           buildCloudEvents,
		ParseResponse:   parseCloudEvents,
		Canary:          canaryCloudEvents,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: CloudEventsContract,
		Tool:            CloudTool,
		KnownPaths:      cloudEventsKnownPaths,
	}
}

func buildCloudEvents(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	id, err := cloudIDPath(SurfaceCloudEvents, p, ParamSessionID)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q := map[string][]string{}
	if err := cloudWindow(SurfaceCloudEvents, q, w); err != nil {
		return vendorapi.Request{}, err
	}
	if err := cloudPageQuery(SurfaceCloudEvents, q, "asc", cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: CloudPathPrefix + "/sessions/" + id + "/events", Query: q}, nil
}

// cloudEvent is the closed DTO of one SessionEvent: content, input, result
// text, error bodies, file names, usage and every other free-text member are
// deliberately absent.
type cloudEvent struct {
	ID            *string `json:"id"`
	Type          *string `json:"type"`
	ProcessedAt   *string `json:"processed_at"`
	Name          *string `json:"name"`
	MCPServerName *string `json:"mcp_server_name"`
	ToolUseID     *string `json:"tool_use_id"`
	MCPToolUseID  *string `json:"mcp_tool_use_id"`
	CustomToolUse *string `json:"custom_tool_use_id"`
	IsError       *bool   `json:"is_error"`
	StopReason    *struct {
		Type *string `json:"type"`
	} `json:"stop_reason"`
}

func parseCloudEvents(r vendorapi.Response) (vendorapi.Page, error) {
	var doc cloudPage[cloudEvent]
	next, err := cloudEnvelope(SurfaceCloudEvents, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	d := driftOf(SurfaceCloudEvents)
	sid := r.Params[ParamSessionID]
	if !cloudIDRE.MatchString(sid) {
		return vendorapi.Page{}, d("the request's %s parameter is not a session id", ParamSessionID)
	}
	out := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, e := range *doc.Data {
		id := str(e.ID)
		if !cloudIDRE.MatchString(id) {
			return vendorapi.Page{}, d("data[%d].id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, d("data[%d] repeats an event", i)
		}
		seen[id] = true
		typ := str(e.Type)
		if typ == "" || len(typ) > 64 {
			return vendorapi.Page{}, d("data[%d].type is missing", i)
		}
		at, ok := cloudTime(e.ProcessedAt)
		if !ok {
			if e.ProcessedAt != nil && *e.ProcessedAt != "" {
				return vendorapi.Page{}, d("data[%d].processed_at is not an ISO timestamp", i)
			}
			continue // no time: counted, never given an invented one
		}
		rule, known := cloudEventRules[typ]
		if !known {
			rule = cloudEventRule{action: ActionCloudOther}
		}
		ev := vendorapi.AuditEvent{
			Namespace: CloudEventNamespace, EventID: id, At: at, AgentSessionID: sid, Action: rule.action,
			ActorIsAgent: len(typ) > 6 && typ[:6] == "agent.",
		}
		detail := map[string]string{}
		switch rule.action {
		case ActionToolCall:
			name := str(e.Name)
			if len(name) > vendorapi.MaxTargetLen {
				return vendorapi.Page{}, d("data[%d].name is over-long", i)
			}
			ev.Target = name
			if v := str(e.MCPServerName); v != "" && len(v) <= 128 {
				detail[DetailMCPServer] = v
			}
		case ActionToolResult:
			ref := firstSet(e.ToolUseID, e.MCPToolUseID, e.CustomToolUse)
			if ref != "" {
				if !cloudIDRE.MatchString(ref) {
					return vendorapi.Page{}, d("data[%d] names a tool use that is not an id", i)
				}
				detail[DetailToolUseID] = ref
			}
			if e.IsError != nil {
				detail[DetailIsError] = fmt.Sprint(*e.IsError)
			}
		case ActionTurnEnd:
			if e.StopReason != nil {
				if v := str(e.StopReason.Type); v != "" && cloudTokenRE.MatchString(v) {
					detail[DetailStopReason] = v
				}
			}
		}
		if len(detail) > 0 {
			ev.Detail = detail
		}
		out.Audit = append(out.Audit, ev)
	}
	return out, nil
}

func firstSet(v ...*string) string {
	for _, s := range v {
		if str(s) != "" {
			return *s
		}
	}
	return ""
}

// canaryCloudEvents reports an event type outside the documented table
// (landed as other). The type name itself is never carried.
func canaryCloudEvents(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, e := range p.Audit {
		if e.Action == ActionCloudOther {
			return []vendorapi.DriftSignal{{Path: "data[].type", Kind: "unknown_enum"}}
		}
	}
	return nil
}

// cloudEventsKnownPaths are the response paths of the corpus field ledger.
var cloudEventsKnownPaths = []string{
	"data", "data[]", "data[].agent_name", "data[].content", "data[].evaluated_permission", "data[].evaluation",
	"data[].id", "data[].input", "data[].is_error", "data[].mcp_server_name", "data[].model_credits",
	"data[].model_request_start_id", "data[].model_usage", "data[].model_usage.credits", "data[].name",
	"data[].processed_at", "data[].sandbox_runtime_credits", "data[].session_thread_id", "data[].stop_reason",
	"data[].stop_reason.type", "data[].tool_use_id", "data[].total_credits", "data[].type", "data[].usage",
	"data[].usage.credits", "first_id", "has_more", "last_id", "next_page",
}
