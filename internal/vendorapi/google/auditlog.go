package google

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceCodeAssistAudit is the catalog id of the surface.
const SurfaceCodeAssistAudit vs.SurfaceID = "google.codeassist.audit_logs"

// Vocabulary.
const (
	CodeAssistAuditContract = "google.codeassist.audit_logs/v1 Logging v2 entries.list + cloudaicompanion audit logging (2026-10-08)"

	// Service is the audited service ("cloudaicompanion API audit logging").
	Service = "cloudaicompanion.googleapis.com"
	// AuditNamespace is the vendor audit namespace of these entries.
	AuditNamespace = "google.cloud_audit"
	// ParamProject is the connection parameter naming the Google Cloud
	// project whose logs are read.
	ParamProject = "project_id"
	// Tool is the registry tool the entries are attributed to: the Gemini
	// CLI on a Gemini Code Assist license calls the cloudaicompanion API like
	// the IDE plugins do, so attribution only resolves the actor.
	Tool = "gemini-cli"
	// PageSize is the entries.list maximum.
	PageSize = vendorapi.MaxCloudLogPageSize
	// MaxWindow caps one run; Data Access logs are kept 30 days by default.
	MaxWindow   = 31 * day
	MaxLookback = 30 * day
	day         = 24 * time.Hour

	auditLogType = "type.googleapis.com/google.cloud.audit.AuditLog"
)

var saAuth = vendorapi.AuthContract{Kind: vs.AuthCloudIAM, Scheme: vendorapi.SchemeGoogleServiceAccount}

// methodActions is the closed method table of "cloudaicompanion API audit
// logging" (every audited method, 22 rows): the full method name and the
// audit action token it lands as. Anything else lands as "other" with a
// canary.
var methodActions = map[string]string{
	"google.cloud.cloudaicompanion.v1.CodeGenerationService.CompleteCode": "code_generation.complete_code",
	"google.cloud.cloudaicompanion.v1.CodeGenerationService.GenerateCode": "code_generation.generate_code",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.CreateCodeRepositoryIndex": "code_repository_index." +
		"create_code_repository_index",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.DeleteCodeRepositoryIndex": "code_repository_index." +
		"delete_code_repository_index",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.GetCodeRepositoryIndex": "code_repository_index." +
		"get_code_repository_index",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.ListCodeRepositoryIndexes": "code_repository_index." +
		"list_code_repository_indexes",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.UpdateCodeRepositoryIndex": "code_repository_index." +
		"update_code_repository_index",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.CreateRepositoryGroup": "code_repository_index." +
		"create_repository_group",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.DeleteRepositoryGroup": "code_repository_index." +
		"delete_repository_group",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.GetRepositoryGroup": "code_repository_index." +
		"get_repository_group",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.ListRepositoryGroups": "code_repository_index." +
		"list_repository_groups",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.UpdateRepositoryGroup": "code_repository_index." +
		"update_repository_group",
	"google.cloud.cloudaicompanion.v1.CodeRepositoryIndexManagementService.UseRepositoryGroup": "code_repository_index." +
		"use_repository_group",
	"google.cloud.cloudaicompanion.v1.EntitlementService.CheckStatus":     "entitlement.check_status",
	"google.cloud.cloudaicompanion.v1.MessageService.EnumerateMessages":   "message.enumerate_messages",
	"google.cloud.cloudaicompanion.v1.TaskCompletionService.CompleteTask": "task_completion.complete_task",
	"google.cloud.cloudaicompanion.v1.TextGenerationService.GenerateText": "text_generation.generate_text",
	"google.cloud.cloudaicompanion.v1.TopicService.CreateTopic":           "topic.create_topic",
	"google.cloud.cloudaicompanion.v1.TopicService.DeleteTopic":           "topic.delete_topic",
	"google.cloud.cloudaicompanion.v1.TopicService.FindReadableTopics":    "topic.find_readable_topics",
	"google.cloud.cloudaicompanion.v1.TopicService.GetTopic":              "topic.get_topic",
	"google.cloud.cloudaicompanion.v1.TopicService.UpdateTopic":           "topic.update_topic",
}

// MethodAction returns the action token of a documented method ("other" for
// any method outside the closed table).
func MethodAction(method string) string {
	if a := methodActions[method]; a != "" {
		return a
	}
	return "other"
}

// CodeAssistAudit returns the driver of google.codeassist.audit_logs.
//
// Contract (Cloud Logging API v2 entries.list, discovery document; LogEntry;
// AuditLog; "cloudaicompanion API audit logging"): POST /v2/entries:list on
// logging.googleapis.com with {resourceNames: ["projects/<id>"], filter,
// orderBy: "timestamp asc", pageSize (at most 1000), pageToken}; response
// {entries: [LogEntry], nextPageToken}, both members omitted when empty
// (proto3 JSON). The filter selects the project's Admin Activity and Data
// Access audit logs of cloudaicompanion.googleapis.com in the window. Each
// entry lands as one audit event: the method (closed table) as the action,
// authenticationInfo.principalEmail as the actor, the resource name as the
// target, the log type, the status code and the monitored resource type as
// detail. requestMetadata (caller IP, user agent), request, response,
// metadata and labels are never decoded (closed DTO; may_return_secret).
func CodeAssistAudit() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCodeAssistAudit,
		Build:           buildAudit,
		ParseResponse:   parseAudit,
		Canary:          canaryAudit,
		Auth:            saAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAudit, vs.ClassUsage},
		ClosedDTO:       true,
		ContractVersion: CodeAssistAuditContract,
		Tool:            Tool,
		MaxWindow:       MaxWindow,
		MaxLookback:     MaxLookback,
		KnownPaths: []string{
			"entries", "entries[]", "entries[].insertId", "entries[].logName", "entries[].protoPayload",
			"entries[].protoPayload.@type", "entries[].protoPayload.authenticationInfo",
			"entries[].protoPayload.authenticationInfo.principalEmail", "entries[].protoPayload.methodName",
			"entries[].protoPayload.resourceName", "entries[].protoPayload.serviceName", "entries[].protoPayload.status",
			"entries[].protoPayload.status.code", "entries[].receiveTimestamp", "entries[].resource",
			"entries[].resource.type", "entries[].severity", "entries[].timestamp", "nextPageToken",
		},
	}
}

func buildAudit(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceCodeAssistAudit
	project := p[ParamProject]
	if !vendorapi.ValidGCPProject(project) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is not a Google Cloud project id", s, ParamProject)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > MaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, MaxWindow)
	}
	if cursor != "" && !vendorapi.ValidOpaqueToken(cursor) {
		return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque page token", s)
	}
	body := vendorapi.CloudAuditLogQuery{
		Project: project, Service: Service, From: w.From.UTC(), To: w.To.UTC(), PageSize: PageSize, PageToken: cursor,
	}
	if _, err := body.Filter(); err != nil {
		return vendorapi.Request{}, fmt.Errorf("%s: %w", s, err)
	}
	return vendorapi.Request{Method: "POST", Path: "/v2/entries:list", Body: body}, nil
}

// number is a JSON number kept as its literal text.
type number string

// UnmarshalJSON accepts a bare JSON number only.
func (n *number) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("google: %.16q is not a JSON number", b)
	}
	*n = number(b)
	return nil
}

// entry is the closed DTO of one LogEntry with an AuditLog payload.
type entry struct {
	InsertID  *string `json:"insertId"`
	LogName   *string `json:"logName"`
	Timestamp *string `json:"timestamp"`
	Resource  *struct {
		Type *string `json:"type"`
	} `json:"resource"`
	ProtoPayload *struct {
		Type               *string `json:"@type"`
		ServiceName        *string `json:"serviceName"`
		MethodName         *string `json:"methodName"`
		ResourceName       *string `json:"resourceName"`
		AuthenticationInfo *struct {
			PrincipalEmail *string `json:"principalEmail"`
		} `json:"authenticationInfo"`
		Status *struct {
			Code *number `json:"code"`
		} `json:"status"`
	} `json:"protoPayload"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceCodeAssistAudit, format, a...)
}

// logType maps the project's two audit log names to their type; any other
// log name is outside the query and is drift.
func logType(project, name string) (string, bool) {
	prefix := "projects/" + project + "/logs/cloudaudit.googleapis.com%2F"
	switch name {
	case prefix + "activity":
		return "activity", true
	case prefix + "data_access":
		return "data_access", true
	}
	return "", false
}

// topLevel is the closed member set of ListLogEntriesResponse. Both members
// are omitted when empty (proto3 JSON), so a renamed container is caught only
// by refusing any other top-level member.
var topLevel = map[string]bool{"entries": true, "nextPageToken": true}

func parseAudit(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &top); err != nil || top == nil {
		return vendorapi.Page{}, drift("body is not the documented object")
	}
	for k := range top {
		if !topLevel[k] {
			return vendorapi.Page{}, drift("undocumented top-level member")
		}
	}
	var doc struct {
		Entries       []entry `json:"entries"`
		NextPageToken *string `json:"nextPageToken"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented response")
	}
	page := vendorapi.Page{}
	if doc.NextPageToken != nil && *doc.NextPageToken != "" {
		if !vendorapi.ValidOpaqueToken(*doc.NextPageToken) {
			return vendorapi.Page{}, drift("nextPageToken is not an opaque token")
		}
		if r.Cursor != "" && *doc.NextPageToken == r.Cursor {
			return vendorapi.Page{}, drift("nextPageToken repeats the token the page was asked with")
		}
		page.NextCursor = *doc.NextPageToken
	}
	project := r.Params[ParamProject]
	seen := map[string]bool{}
	for i, e := range doc.Entries {
		ev, err := auditEvent(project, i, e)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if seen[ev.EventID] {
			return vendorapi.Page{}, drift("entries[%d] repeats an entry", i)
		}
		seen[ev.EventID] = true
		page.Audit = append(page.Audit, ev)
	}
	return page, nil
}

func auditEvent(project string, i int, e entry) (vendorapi.AuditEvent, error) {
	id := vendorapi.TrimStr(e.InsertID)
	if id == "" {
		return vendorapi.AuditEvent{}, drift("entries[%d].insertId is missing", i)
	}
	ts := vendorapi.TrimStr(e.Timestamp)
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return vendorapi.AuditEvent{}, drift("entries[%d].timestamp is not RFC 3339", i)
	}
	lt, ok := logType(project, vendorapi.TrimStr(e.LogName))
	if !ok {
		return vendorapi.AuditEvent{}, drift("entries[%d].logName is not one of the queried audit logs", i)
	}
	pp := e.ProtoPayload
	if pp == nil || vendorapi.TrimStr(pp.Type) != auditLogType {
		return vendorapi.AuditEvent{}, drift("entries[%d].protoPayload is not an AuditLog", i)
	}
	if vendorapi.TrimStr(pp.ServiceName) != Service {
		return vendorapi.AuditEvent{}, drift("entries[%d].protoPayload.serviceName is not the queried service", i)
	}
	method := vendorapi.TrimStr(pp.MethodName)
	if method == "" {
		return vendorapi.AuditEvent{}, drift("entries[%d].protoPayload.methodName is missing", i)
	}
	// insertId is unique per log and timestamp, so the event id joins them.
	ev := vendorapi.AuditEvent{
		Namespace: AuditNamespace, EventID: lt + "/" + at.UTC().Format(time.RFC3339Nano) + "/" + id, At: at.UTC(),
		Action: MethodAction(method), Target: vendorapi.TrimStr(pp.ResourceName),
		Detail: map[string]string{"log_type": lt, "service_name": Service},
	}
	if pp.AuthenticationInfo != nil {
		if em := vendorapi.TrimStr(pp.AuthenticationInfo.PrincipalEmail); em != "" {
			ev.ActorKind, ev.ActorIdentity = "email", em
			ev.ActorIsAgent = strings.HasSuffix(em, ".gserviceaccount.com")
		}
	}
	if pp.Status != nil && pp.Status.Code != nil {
		ev.Detail["status_code"] = string(*pp.Status.Code)
	}
	if e.Resource != nil {
		if rt := vendorapi.TrimStr(e.Resource.Type); rt != "" {
			ev.Detail["resource_type"] = rt
		}
	}
	return ev, nil
}

// canaryAudit flags a method outside the documented table (landed as
// "other").
func canaryAudit(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, e := range p.Audit {
		if e.Namespace == AuditNamespace && e.Action == "other" {
			return []vendorapi.DriftSignal{{Path: "entries[].protoPayload.methodName", Kind: "unknown_enum"}}
		}
	}
	return nil
}
