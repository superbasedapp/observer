package cursor

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Audit log paging and window limits (Cursor Admin API, "Get Audit Logs":
// page and pageSize <= 500 in the query; a request window of at most 30
// days, 7 by default).
const (
	AuditPageSize  = 500
	AuditMaxWindow = 30 * 24 * time.Hour
)

// AuditLogs returns the driver of cursor.admin.audit_logs.
//
// Contract: GET /teams/audit-logs with startTime and endTime (epoch
// milliseconds), page and pageSize; response {"events": [...],
// "pagination": {"page", "hasNextPage", ...}}. Each event has event_id,
// timestamp (RFC 3339), user_email, event_type, application_type,
// ip_address and an event_data object whose members depend on the event
// type. The driver reads a closed set of event_data members (auditDetailKeys)
// and nothing else, so the surface may be classified may_return_secret and
// still run (plan 4.5 R-E-06: a closed-DTO driver).
func AuditLogs() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceAuditLogs,
		Build:           buildAudit,
		ParseResponse:   parseAudit,
		Canary:          canaryAudit,
		Auth:            basicAuth,
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
		return vendorapi.Request{}, fmt.Errorf("cursor.admin.audit_logs: a non-empty window is required")
	}
	if w.To.Sub(w.From) > AuditMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("cursor.admin.audit_logs: the window exceeds the documented 30-day maximum")
	}
	q := map[string][]string{
		"startTime": {epochMillis(w.From)},
		"endTime":   {epochMillis(w.To)},
		"pageSize":  {strconv.Itoa(AuditPageSize)},
	}
	if cursor != "" {
		if n, err := strconv.Atoi(cursor); err != nil || n < 2 || strconv.Itoa(n) != cursor {
			return vendorapi.Request{}, fmt.Errorf("cursor.admin.audit_logs: cursor must be a page number")
		}
		q["page"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/teams/audit-logs", Query: q}, nil
}

type auditDoc struct {
	Events     *[]auditEvent `json:"events"`
	Pagination *struct {
		Page        *json.Number `json:"page"`
		HasNextPage *bool        `json:"hasNextPage"`
	} `json:"pagination"`
}

type auditEvent struct {
	EventID         *string                    `json:"event_id"`
	Timestamp       *string                    `json:"timestamp"`
	UserEmail       *string                    `json:"user_email"`
	EventType       *string                    `json:"event_type"`
	ApplicationType *string                    `json:"application_type"`
	IPAddress       *string                    `json:"ip_address"`
	EventData       map[string]json.RawMessage `json:"event_data"`
}

// auditDetailKeys is the closed set of event_data members the driver reads
// (the documented members of the reference examples). Every other member is
// never decoded.
var auditDetailKeys = []string{
	"success", "login_type", "user_email", "role", "source", "team_id", "invited_by_email",
	"invited_by_user_id", "invite_id",
}

var actionRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// scalar renders a JSON scalar (string, number, boolean) as a string; an
// object, array or null is not a scalar and is skipped.
func scalar(raw json.RawMessage) (string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	switch x := v.(type) {
	case string:
		return x, true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	}
	return "", false
}

func parseAudit(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "status %d is not the documented 200", r.Status)
	}
	var doc auditDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "body does not decode as the documented object")
	}
	if doc.Events == nil || doc.Pagination == nil || doc.Pagination.Page == nil || doc.Pagination.HasNextPage == nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "required field events, pagination.page or pagination.hasNextPage is missing")
	}
	current, err := doc.Pagination.Page.Int64()
	if err != nil || current < 1 {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "pagination.page is not a page number")
	}
	page := vendorapi.Page{}
	if *doc.Pagination.HasNextPage {
		page.NextCursor = strconv.FormatInt(current+1, 10)
	}
	seen := map[string]bool{}
	for i, e := range *doc.Events {
		if e.EventID == nil || *e.EventID == "" || e.Timestamp == nil || e.EventType == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "events[%d] misses event_id, timestamp or event_type", i)
		}
		at, err := time.Parse(time.RFC3339Nano, *e.Timestamp)
		if err != nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "events[%d].timestamp is not RFC 3339", i)
		}
		if seen[*e.EventID] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "events[%d] repeats an event id", i)
		}
		seen[*e.EventID] = true
		action := strings.ToLower(strings.TrimSpace(*e.EventType))
		if !actionRE.MatchString(action) {
			action = "other"
		}
		ev := vendorapi.AuditEvent{Namespace: AuditNamespace, EventID: *e.EventID, At: at.UTC(), Action: action, Detail: map[string]string{}}
		if e.UserEmail != nil && *e.UserEmail != "" {
			ev.ActorKind, ev.ActorIdentity = "email", vendorapi.FoldEmail(*e.UserEmail)
		}
		if e.ApplicationType != nil && *e.ApplicationType != "" {
			ev.Detail["application_type"] = *e.ApplicationType
		}
		if e.IPAddress != nil && *e.IPAddress != "" {
			ev.Detail["ip_address"] = *e.IPAddress
		}
		for _, k := range auditDetailKeys {
			raw, ok := e.EventData[k]
			if !ok {
				continue
			}
			if v, ok := scalar(raw); ok && v != "" {
				ev.Detail[k] = v
			}
		}
		if t, ok := ev.Detail["user_email"]; ok {
			ev.Target = strings.ToLower(t)
		}
		page.Audit = append(page.Audit, ev)
	}
	return page, nil
}

// canaryAudit reports drift that does not fail the page: an event type
// outside the action vocabulary (landed as "other", plan 12A.5).
func canaryAudit(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, e := range p.Audit {
		if e.Action == "other" {
			return []vendorapi.DriftSignal{{Path: "events[].event_type", Kind: "unknown_enum"}}
		}
	}
	return nil
}

// auditKnownPaths are the documented response paths (the corpus field ledger
// of "Get Audit Logs").
var auditKnownPaths = []string{
	"events", "events[]", "events[].application_type", "events[].event_data", "events[].event_data.invite_id",
	"events[].event_data.invited_by_email", "events[].event_data.invited_by_user_id", "events[].event_data.login_type",
	"events[].event_data.role", "events[].event_data.source", "events[].event_data.success",
	"events[].event_data.team_id", "events[].event_data.user_email", "events[].event_id", "events[].event_type",
	"events[].ip_address", "events[].timestamp", "events[].user_email", "pagination", "pagination.hasNextPage",
	"pagination.hasPreviousPage", "pagination.page", "pagination.pageSize", "pagination.totalCount",
	"pagination.totalPages", "params", "params.endDate", "params.startDate", "params.teamId",
}
