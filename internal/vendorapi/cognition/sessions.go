package cognition

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The Devin v3 organization session surfaces (lane CA-A4, cloud agents arc;
// plan docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, connector devin). They are consumed by the node connector
// (lane CA-B2) with the developer's own PAT or service-user key through the
// node's egress package. Since lane CA-C3 org_sessions also has an org
// driver-table entry: the org runner lands its snapshots and ACU rows, and
// internal/orgserver/cloudproj projects the sessions to members
// (session_messages stays node-only). Each Build is a GET on api.devin.ai;
// nothing here sends a request.
const (
	SurfaceOrgSessions     vs.SurfaceID = "cognition.devin_v3.org_sessions"
	SurfaceSessionMessages vs.SurfaceID = "cognition.devin_v3.session_messages"

	OrgSessionsContract     = "cognition.devin_v3.org_sessions/v1 devin-api v3 reference 2026-10-31"
	SessionMessagesContract = "cognition.devin_v3.session_messages/v1 devin-api v3 reference 2026-10-31"

	// SessionClass is the snapshot class of one Devin session; its subject
	// is the session id (kept as sessions.id, CA-D2).
	SessionClass = "cognition.devin_session"
	// SessionUsageNamespace and SessionUsageJoinKind key a session's ACU
	// usage row: one row per session, re-landed with a higher revision
	// (updated_at) as the session consumes more.
	SessionUsageNamespace = "cognition.session"
	SessionUsageJoinKind  = "session_id"

	// ParamOrgID names the organization a request reads.
	ParamOrgID = "org_id"
	// ParamSessionID names the session whose messages a request reads.
	ParamSessionID = "devin_id"
)

var (
	// orgIDRE and sessionIDRE bound a path parameter before it enters a
	// request path.
	orgIDRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	sessionIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// eventIDRE bounds a message event id.
	eventIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,256}$`)
)

// messageRoles maps a message source to a content role. A source outside the
// table is reported by the canary and not landed.
var messageRoles = map[string]string{
	"user":  "prompt",
	"devin": "response",
}

// maxBodyText caps a free-text snapshot value (a title) below
// vendorapi.MaxAttrValue.
const maxBodyText = 256

// OrgSessions returns the driver of cognition.devin_v3.org_sessions.
//
// Contract (Devin API v3, "List Organization Sessions", reference source
// DV03): GET /v3/organizations/{org_id}/sessions with first (at most 200),
// after (the previous end_cursor) and, for an incremental run, updated_after
// and updated_before (Unix seconds) from the window; response
// PaginatedResponse {items, has_next_page, end_cursor}. Each session lands as
// one snapshot of class cognition.devin_session (status, title, origin,
// creator, repository pull requests, parent and child ids, timestamps, the
// Teams-only on_demand_usage in USD) and, when acus_consumed is reported, one
// usage row charged in ACUs keyed by the session id with updated_at as its
// revision (charged in UnitACU, never summed with USD or tokens, CA-D11). An
// absent ACU figure lands no row, never a zero.
func OrgSessions() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceOrgSessions,
		Build:           buildOrgSessions,
		ParseResponse:   parseOrgSessions,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassSessions, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: OrgSessionsContract,
		Tool:            Tool,
		KnownPaths:      orgSessionsKnownPaths,
	}
}

// SessionMessages returns the driver of cognition.devin_v3.session_messages.
//
// Contract (Devin API v3, "List Organization Session Messages", DV06): GET
// /v3/organizations/{org_id}/sessions/{devin_id}/messages with first and
// after; response PaginatedResponse of chronological messages {event_id,
// source (user or devin), message, user_id, username, created_at}. Each
// message lands as one content item (a prompt for user, a response for
// devin) keyed by event_id, grouped by the session id. A content surface:
// the org sanitizer drops it without a content consent, and the node
// connector lands it only under its own content setting.
func SessionMessages() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceSessionMessages,
		Build:           buildSessionMessages,
		ParseResponse:   parseSessionMessages,
		Canary:          canaryMessages,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassContent},
		ClosedDTO:       true,
		ContractVersion: SessionMessagesContract,
		Tool:            Tool,
		KnownPaths:      sessionMessagesKnownPaths,
	}
}

func orgPath(surface vs.SurfaceID, p vendorapi.Params) (string, error) {
	org := p[ParamOrgID]
	if !orgIDRE.MatchString(org) {
		return "", fmt.Errorf("%s: parameter %s must be a Devin organization id", surface, ParamOrgID)
	}
	return "/v3/organizations/" + url.PathEscape(org) + "/sessions", nil
}

func buildOrgSessions(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	path, err := orgPath(SurfaceOrgSessions, p)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q := map[string][]string{}
	switch {
	case w.From.IsZero() && w.To.IsZero():
	case w.From.IsZero() || !w.To.After(w.From):
		return vendorapi.Request{}, fmt.Errorf("%s: a window needs both bounds, From before To", SurfaceOrgSessions)
	default:
		q["updated_after"] = []string{strconv.FormatInt(w.From.UTC().Unix(), 10)}
		q["updated_before"] = []string{strconv.FormatInt(w.To.UTC().Unix(), 10)}
	}
	if err := pageQuery(SurfaceOrgSessions, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path, Query: q}, nil
}

func buildSessionMessages(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	path, err := orgPath(SurfaceSessionMessages, p)
	if err != nil {
		return vendorapi.Request{}, err
	}
	sid := p[ParamSessionID]
	if !sessionIDRE.MatchString(sid) {
		return vendorapi.Request{}, fmt.Errorf("%s: parameter %s must be a Devin session id", SurfaceSessionMessages, ParamSessionID)
	}
	q := map[string][]string{}
	if err := pageQuery(SurfaceSessionMessages, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: path + "/" + url.PathEscape(sid) + "/messages", Query: q}, nil
}

// sessionEntry is the closed DTO of one session record.
type sessionEntry struct {
	SessionID *string `json:"session_id"`
	URL       *string `json:"url"`
	Status    *string `json:"status"`
	// StatusDetail refines Status (live-verified 2026-11-01: "running" with
	// "waiting_for_user" is a session awaiting its next instruction). Not in
	// the corpus ledger, so the shape digest wildcards its name.
	StatusDetail    *string   `json:"status_detail"`
	Title           *string   `json:"title"`
	Origin          *string   `json:"origin"`
	OrgID           *string   `json:"org_id"`
	UserID          *string   `json:"user_id"`
	ServiceUserID   *string   `json:"service_user_id"`
	CreatedAt       *num      `json:"created_at"`
	UpdatedAt       *num      `json:"updated_at"`
	ACUsConsumed    *num      `json:"acus_consumed"`
	OnDemandUsage   *num      `json:"on_demand_usage"`
	ParentSessionID *string   `json:"parent_session_id"`
	ChildSessionIDs *[]string `json:"child_session_ids"`
	PlaybookID      *string   `json:"playbook_id"`
	AutomationID    *string   `json:"automation_id"`
	PullRequests    *[]struct {
		PRURL   *string `json:"pr_url"`
		PRState *string `json:"pr_state"`
	} `json:"pull_requests"`
}

// capBody cuts free text at a rune boundary within maxBodyText bytes.
func capBody(s string) string {
	if len(s) <= maxBodyText {
		return s
	}
	cut := maxBodyText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// putID sets an optional id-shaped body value, refusing an over-long one.
func putID(body map[string]string, key string, v *string) bool {
	s := str(v)
	if s == "" {
		return true
	}
	if len(s) > vendorapi.MaxIDLen {
		return false
	}
	body[key] = s
	return true
}

func parseOrgSessions(r vendorapi.Response) (vendorapi.Page, error) {
	var doc paginated[sessionEntry]
	next, err := envelope(SurfaceOrgSessions, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Items)}
	seen := map[string]bool{}
	for i, s := range *doc.Items {
		id := str(s.SessionID)
		if !sessionIDRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].session_id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d] repeats a session", i)
		}
		seen[id] = true
		status := str(s.Status)
		if status == "" || len(status) > 64 {
			return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].status is missing", i)
		}
		created, ok := unixSeconds(s.CreatedAt)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].created_at is not Unix seconds", i)
		}
		at := created
		body := map[string]string{"status": status, "created_at": created.Format(time.RFC3339)}
		if s.UpdatedAt != nil {
			u, ok := unixSeconds(s.UpdatedAt)
			if !ok {
				return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].updated_at is not Unix seconds", i)
			}
			at = u
			body["updated_at"] = u.Format(time.RFC3339)
		}
		if v := capBody(str(s.Title)); v != "" {
			body["title"] = v
		}
		if v := str(s.URL); v != "" && len(v) <= vendorapi.MaxAttrValue {
			body["url"] = v
		}
		for _, f := range []struct {
			key string
			v   *string
		}{
			{"origin", s.Origin},
			{"status_detail", s.StatusDetail},
			{"org_id", s.OrgID},
			{"user_id", s.UserID},
			{"service_user_id", s.ServiceUserID},
			{"parent_session_id", s.ParentSessionID},
			{"playbook_id", s.PlaybookID},
			{"automation_id", s.AutomationID},
		} {
			if !putID(body, f.key, f.v) {
				return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].%s is over-long", i, f.key)
			}
		}
		if s.ChildSessionIDs != nil {
			body["child_session_count"] = strconv.Itoa(len(*s.ChildSessionIDs))
		}
		if s.PullRequests != nil {
			prs := *s.PullRequests
			body["pull_request_count"] = strconv.Itoa(len(prs))
			if len(prs) > 0 {
				if v := str(prs[0].PRURL); v != "" && len(v) <= vendorapi.MaxAttrValue {
					body["pr_url"] = v
				}
				if !putID(body, "pr_state", prs[0].PRState) {
					return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].pull_requests[0].pr_state is over-long", i)
				}
			}
		}
		if s.OnDemandUsage != nil {
			usd, ok := vendorapi.DecimalMicros(string(*s.OnDemandUsage), 0)
			if !ok || usd < 0 {
				return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].on_demand_usage is not a non-negative amount", i)
			}
			body["on_demand_usage_usd"] = string(*s.OnDemandUsage)
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: SessionClass, Subject: id, Body: body})
		if s.ACUsConsumed == nil {
			continue
		}
		acus, ok := acuMicros(s.ACUsConsumed)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceOrgSessions, "items[%d].acus_consumed is not a non-negative number", i)
		}
		u := vendorapi.UsageRow{
			JoinKind: SessionUsageJoinKind, JoinNamespace: SessionUsageNamespace, JoinValue: id,
			At: at, SessionRef: id, ChargedUnit: UnitACU, ChargedMicros: acus, Revision: at.Unix(),
		}
		switch {
		case str(s.UserID) != "":
			u.IdentityKind, u.Identity = "user_id", *s.UserID
		case str(s.ServiceUserID) != "":
			u.IdentityKind, u.Identity = ActorServiceUser, *s.ServiceUserID
		case str(s.OrgID) != "":
			u.IdentityKind, u.Identity = ParamOrgID, *s.OrgID
		default:
			u.IdentityKind, u.Identity = ParamOrgID, r.Params[ParamOrgID]
		}
		page.Usage = append(page.Usage, u)
	}
	return page, nil
}

// messageEntry is the closed DTO of one session message.
type messageEntry struct {
	EventID   *string `json:"event_id"`
	Source    *string `json:"source"`
	Message   *string `json:"message"`
	UserID    *string `json:"user_id"`
	Username  *string `json:"username"`
	CreatedAt *num    `json:"created_at"`
}

// cutContent cuts text at a rune boundary within vendorapi.MaxContentBytes.
func cutContent(s string) (string, bool) {
	if len(s) <= vendorapi.MaxContentBytes {
		return s, false
	}
	cut := vendorapi.MaxContentBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

func parseSessionMessages(r vendorapi.Response) (vendorapi.Page, error) {
	var doc paginated[messageEntry]
	next, err := envelope(SurfaceSessionMessages, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	sid := r.Params[ParamSessionID]
	if !sessionIDRE.MatchString(sid) {
		return vendorapi.Page{}, drift(SurfaceSessionMessages, "the request's %s parameter is not a session id", ParamSessionID)
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Items)}
	seen := map[string]bool{}
	for i, m := range *doc.Items {
		id := str(m.EventID)
		if !eventIDRE.MatchString(id) {
			return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d].event_id is missing or not an id", i)
		}
		if seen[id] {
			return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d] repeats an event", i)
		}
		seen[id] = true
		if m.Source == nil || m.Message == nil {
			return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d] misses source or message", i)
		}
		at, ok := unixSeconds(m.CreatedAt)
		if !ok {
			return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d].created_at is not Unix seconds", i)
		}
		role, known := messageRoles[*m.Source]
		if !known {
			continue
		}
		if !utf8.ValidString(*m.Message) {
			return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d].message is not valid UTF-8", i)
		}
		text, cut := cutContent(*m.Message)
		c := vendorapi.ContentItem{ItemID: id, At: at, SessionRef: sid, Role: role, Text: text, Truncated: cut}
		if role == "prompt" && str(m.UserID) != "" {
			if len(*m.UserID) > vendorapi.MaxIDLen {
				return vendorapi.Page{}, drift(SurfaceSessionMessages, "items[%d].user_id is over-long", i)
			}
			c.IdentityKind, c.Identity = "user_id", *m.UserID
		}
		page.Content = append(page.Content, c)
	}
	return page, nil
}

// canaryMessages reports a message whose source is outside the documented
// user/devin pair (it was not landed). The source value itself is never
// carried.
func canaryMessages(p vendorapi.Page) []vendorapi.DriftSignal {
	if p.SourceRecords > len(p.Content) {
		return []vendorapi.DriftSignal{{Path: "items[].source", Kind: "unknown_enum"}}
	}
	return nil
}

// orgSessionsKnownPaths are the response paths of the corpus field ledger of
// "List Organization Sessions".
var orgSessionsKnownPaths = []string{
	"end_cursor", "has_next_page", "items", "items[]", "items[].acus_consumed", "items[].automation_id",
	"items[].child_session_ids", "items[].child_session_ids[]", "items[].created_at", "items[].on_demand_usage", "items[].org_id", "items[].origin",
	"items[].parent_session_id", "items[].playbook_id", "items[].pull_requests", "items[].pull_requests[]",
	"items[].pull_requests[].pr_state", "items[].pull_requests[].pr_url", "items[].service_user_id",
	"items[].session_id", "items[].status", "items[].tags", "items[].tags[]", "items[].title", "items[].updated_at", "items[].url",
	"items[].user_id",
}

// sessionMessagesKnownPaths are the response paths of the corpus field ledger
// of "List Organization Session Messages".
var sessionMessagesKnownPaths = []string{
	"end_cursor", "has_next_page", "items", "items[]", "items[].created_at", "items[].event_id", "items[].message",
	"items[].source", "items[].user_id", "items[].username",
}
