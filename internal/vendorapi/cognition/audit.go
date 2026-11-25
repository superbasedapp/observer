package cognition

import (
	"fmt"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceAuditLogs is the catalog id of the surface.
const SurfaceAuditLogs vs.SurfaceID = "cognition.devin_v3.audit_logs"

// Audit vocabulary.
const (
	AuditContract = "cognition.devin_v3.audit_logs/v1 v3-openapi 3.0.0 (2026-10-08)"

	// AuditNamespace is the vendor audit namespace of the enterprise log.
	AuditNamespace = "cognition.audit"
	// AuditMaxWindow caps one run. The reference states no range limit.
	AuditMaxWindow = 31 * day
	// ActorServiceUser is the actor kind of an event a service user caused.
	ActorServiceUser = "service_user_id"
)

// AuditLogs returns the driver of cognition.devin_v3.audit_logs.
//
// Contract (v3 OpenAPI, "List Enterprise Audit Logs"): GET
// /v3/enterprise/audit-logs with order (asc here, so a window reads
// oldest first), time_after and time_before (Unix seconds), first and
// after; response PaginatedResponse[AuditLogResponse] {items: [{audit_log_id,
// action, created_at, org_id, user_id, user_email, service_user_id,
// service_user_name, data}], has_next_page, end_cursor}. data is an open
// object whose members the reference does not document: the driver is
// closed-DTO and never decodes it (the row is may_return_secret).
func AuditLogs() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceAuditLogs,
		Build:           buildAudit,
		ParseResponse:   parseAudit,
		Canary:          canaryAudit,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: AuditContract,
		Tool:            Tool,
		MaxWindow:       AuditMaxWindow,
		KnownPaths:      auditKnownPaths,
	}
}

func buildAudit(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceAuditLogs)
	}
	if w.To.Sub(w.From) > AuditMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", SurfaceAuditLogs, AuditMaxWindow)
	}
	q := map[string][]string{
		"order":       {"asc"},
		"time_after":  {strconv.FormatInt(w.From.UTC().Unix(), 10)},
		"time_before": {strconv.FormatInt(w.To.UTC().Unix(), 10)},
	}
	if err := pageQuery(SurfaceAuditLogs, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v3/enterprise/audit-logs", Query: q}, nil
}

// auditEntry is the closed DTO of one event: data is deliberately absent.
type auditEntry struct {
	ID              *string `json:"audit_log_id"`
	Action          *string `json:"action"`
	CreatedAt       *num    `json:"created_at"`
	OrgID           *string `json:"org_id"`
	UserID          *string `json:"user_id"`
	UserEmail       *string `json:"user_email"`
	ServiceUserID   *string `json:"service_user_id"`
	ServiceUserName *string `json:"service_user_name"`
}

func parseAudit(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceAuditLogs
	var doc paginated[auditEntry]
	next, err := envelope(s, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next}
	seen := map[string]bool{}
	for i, e := range *doc.Items {
		id := vendorapi.Str(e.ID)
		if id == "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].audit_log_id is missing", i)
		}
		if seen[id] {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d] repeats an event", i)
		}
		seen[id] = true
		at, ok := unixSeconds(e.CreatedAt)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].created_at is not a Unix time", i)
		}
		if e.Action == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "items[%d].action is missing", i)
		}
		action := *e.Action
		if !auditActions[action] {
			action = "other"
		}
		ev := vendorapi.AuditEvent{Namespace: AuditNamespace, EventID: id, At: at, Action: action, Detail: map[string]string{}}
		switch {
		case vendorapi.Str(e.UserEmail) != "":
			ev.ActorKind, ev.ActorIdentity = "email", vendorapi.Str(e.UserEmail)
		case vendorapi.Str(e.ServiceUserID) != "":
			ev.ActorKind, ev.ActorIdentity, ev.ActorIsAgent = ActorServiceUser, vendorapi.Str(e.ServiceUserID), true
		}
		if v := vendorapi.Str(e.OrgID); v != "" {
			ev.Detail["org_id"] = v
		}
		if v := vendorapi.Str(e.UserID); v != "" {
			ev.Detail["user_id"] = v
		}
		if v := vendorapi.Str(e.ServiceUserID); v != "" {
			ev.Detail["service_user_id"] = v
		}
		if v := vendorapi.Str(e.ServiceUserName); v != "" {
			ev.Detail["service_user_name"] = v
		}
		page.Audit = append(page.Audit, ev)
	}
	return page, nil
}

// canaryAudit flags an action outside the documented enum (it landed as
// "other").
func canaryAudit(p vendorapi.Page) []vendorapi.DriftSignal {
	if auditActions["other"] {
		return nil // "other" would be a documented action, not a fold
	}
	for _, e := range p.Audit {
		if e.Namespace == AuditNamespace && e.Action == "other" {
			return []vendorapi.DriftSignal{{Path: "items[].action", Kind: "unknown_enum"}}
		}
	}
	return nil
}

// auditKnownPaths are the documented response paths (the corpus field ledger
// of the audit log).
var auditKnownPaths = []string{
	"end_cursor", "has_next_page", "items", "items[]", "items[].action", "items[].audit_log_id", "items[].created_at",
	"items[].data", "items[].org_id", "items[].service_user_id", "items[].service_user_name", "items[].user_email",
	"items[].user_id",
}
