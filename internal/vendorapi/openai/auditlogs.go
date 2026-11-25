package openai

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

// SurfaceAuditLogs is the catalog id of the surface.
const SurfaceAuditLogs vs.SurfaceID = "openai.platform.audit_logs"

// Audit log vocabulary.
const (
	AuditContract = "openai.platform.audit_logs/v1 openai-python admin types (2026-10-07)"
	// AuditNamespace is the vendor audit namespace of the Platform audit log.
	AuditNamespace = "openai.audit"
)

// AuditLogs returns the driver of openai.platform.audit_logs.
//
// Contract (openai-python AuditLogListParams and AuditLogListResponse): GET
// /v1/organization/audit_logs with effective_at[gte] and effective_at[lt]
// (Unix seconds), limit (1 to 100) and after (the last id of the previous
// page); response {"object": "list", "data": [...], "first_id", "last_id",
// "has_more"}. Each event has id, type, effective_at, an optional actor
// (type session with user {id, email} and ip_address, or type api_key with
// id, type and a user or service_account), an optional project {id, name}
// and a detail object keyed by the event type. The driver reads the detail
// object's id only (the target), never its data, and no other member: a
// closed DTO, so the surface may stay classified may_return_secret.
func AuditLogs() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceAuditLogs,
		Build:           buildAudit,
		ParseResponse:   parseAudit,
		Canary:          canaryAudit,
		Auth:            adminAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: AuditContract,
		Tool:            Tool,
		KnownPaths:      auditKnownPaths,
	}
}

func buildAudit(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceAuditLogs)
	}
	q, err := listQuery(SurfaceAuditLogs, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q["effective_at[gte]"] = []string{strconv.FormatInt(w.From.UTC().Unix(), 10)}
	q["effective_at[lt]"] = []string{strconv.FormatInt(w.To.UTC().Unix(), 10)}
	return vendorapi.Request{Method: "GET", Path: "/v1/organization/audit_logs", Query: q}, nil
}

type auditUser struct {
	ID    *string `json:"id"`
	Email *string `json:"email"`
}

type auditActor struct {
	Type    *string `json:"type"`
	Session *struct {
		User      *auditUser `json:"user"`
		IPAddress *string    `json:"ip_address"`
	} `json:"session"`
	APIKey *struct {
		ID             *string    `json:"id"`
		Type           *string    `json:"type"`
		User           *auditUser `json:"user"`
		ServiceAccount *struct {
			ID *string `json:"id"`
		} `json:"service_account"`
	} `json:"api_key"`
}

// auditEvent is the closed DTO of one event. Detail is the raw member keyed
// by the event type; only its id is ever decoded.
type auditEvent struct {
	ID          *string      `json:"id"`
	Type        *string      `json:"type"`
	EffectiveAt *json.Number `json:"effective_at"`
	Actor       *auditActor  `json:"actor"`
	Project     *struct {
		ID *string `json:"id"`
	} `json:"project"`
}

var actionRE = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// actorIdentity is the actor table, walked top down: a user's e-mail first,
// then the user id, then a service account, then the key's tracking id.
func actorIdentity(a *auditActor) (string, string) {
	if a == nil {
		return "", ""
	}
	var u *auditUser
	if a.Session != nil {
		u = a.Session.User
	} else if a.APIKey != nil {
		u = a.APIKey.User
	}
	switch {
	case u != nil && vendorapi.Str(u.Email) != "":
		return "email", vendorapi.FoldEmail(vendorapi.Str(u.Email))
	case u != nil && vendorapi.Str(u.ID) != "":
		return "user_id", vendorapi.Str(u.ID)
	case a.APIKey != nil && a.APIKey.ServiceAccount != nil && vendorapi.Str(a.APIKey.ServiceAccount.ID) != "":
		return "service_account_id", vendorapi.Str(a.APIKey.ServiceAccount.ID)
	case a.APIKey != nil && vendorapi.Str(a.APIKey.ID) != "":
		return "key_tracking_id", vendorapi.Str(a.APIKey.ID)
	}
	return "", ""
}

// auditDetail is the flat detail an event keeps (the sanitizer's
// openai.audit allowlist row is the same list).
func auditDetail(e auditEvent) map[string]string {
	d := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			d[k] = v
		}
	}
	if a := e.Actor; a != nil {
		set("actor_type", vendorapi.Str(a.Type))
		if a.Session != nil {
			set("ip_address", vendorapi.Str(a.Session.IPAddress))
		}
		if a.APIKey != nil {
			set("key_type", vendorapi.Str(a.APIKey.Type))
			set("key_tracking_id", vendorapi.Str(a.APIKey.ID))
			if a.APIKey.ServiceAccount != nil {
				set("service_account_id", vendorapi.Str(a.APIKey.ServiceAccount.ID))
			}
		}
	}
	if e.Project != nil {
		set("project_id", vendorapi.Str(e.Project.ID))
	}
	return d
}

// target reads the id of the event's per-type detail object, if any.
func target(raw map[string]json.RawMessage, typ string) string {
	b, ok := raw[typ]
	if !ok {
		return ""
	}
	var d struct {
		ID *string `json:"id"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return ""
	}
	return vendorapi.Str(d.ID)
}

func parseAudit(r vendorapi.Response) (vendorapi.Page, error) {
	var doc listDoc[json.RawMessage]
	next, err := listEnvelope(SurfaceAuditLogs, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next}
	seen := map[string]bool{}
	for i, raw := range *doc.Data {
		var e auditEvent
		var members map[string]json.RawMessage
		if vendorapi.DecodeNumbers(raw, &e) != nil || json.Unmarshal(raw, &members) != nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "data[%d] is not an audit log object", i)
		}
		if e.ID == nil || *e.ID == "" || e.Type == nil || e.EffectiveAt == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "data[%d] misses id, type or effective_at", i)
		}
		secs, err := e.EffectiveAt.Int64()
		if err != nil || secs < 0 {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "data[%d].effective_at is not Unix seconds", i)
		}
		if seen[*e.ID] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceAuditLogs, "data[%d] repeats an event id", i)
		}
		seen[*e.ID] = true
		action := strings.ToLower(strings.TrimSpace(*e.Type))
		if !actionRE.MatchString(action) {
			action = "other"
		}
		kind, id := actorIdentity(e.Actor)
		page.Audit = append(page.Audit, vendorapi.AuditEvent{
			Namespace: AuditNamespace, EventID: *e.ID, At: time.Unix(secs, 0).UTC(), Action: action,
			ActorKind: kind, ActorIdentity: id, Target: target(members, *e.Type), Detail: auditDetail(e),
		})
	}
	return page, nil
}

// canaryAudit reports an event type outside the action vocabulary (landed
// as "other", plan 12A.5).
func canaryAudit(p vendorapi.Page) []vendorapi.DriftSignal {
	for _, e := range p.Audit {
		if e.Action == "other" {
			return []vendorapi.DriftSignal{{Path: "data[].type", Kind: "unknown_enum"}}
		}
	}
	return nil
}

// auditKnownPaths are the documented response paths (the corpus field
// ledgers; a detail member's dotted name is escaped).
var auditKnownPaths = []string{
	"data", "data[]", "data[].actor", "data[].actor.api_key", "data[].actor.api_key.id",
	"data[].actor.api_key.service_account", "data[].actor.api_key.service_account.id", "data[].actor.api_key.type",
	"data[].actor.session", "data[].actor.session.ip_address", "data[].actor.session.user",
	"data[].actor.session.user.email", "data[].actor.session.user.id", "data[].actor.type",
	`data[].api_key\.created`, `data[].api_key\.created.data`, `data[].api_key\.created.data.scopes`,
	`data[].api_key\.created.data.scopes[]`, `data[].api_key\.created.id`, "data[].effective_at", "data[].id",
	`data[].login\.succeeded`, "data[].project", "data[].project.id", "data[].project.name",
	`data[].project\.created`, `data[].project\.created.data`, `data[].project\.created.data.name`,
	`data[].project\.created.data.title`, `data[].project\.created.id`, "data[].type", "first_id", "has_more",
	"last_id", "object",
}
