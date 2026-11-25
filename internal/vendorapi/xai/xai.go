package xai

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The two xAI Management API surfaces this lane builds.
const (
	SurfaceAuditEvents    vs.SurfaceID = "xai.mgmt.audit_events"
	SurfaceSpendingLimits vs.SurfaceID = "xai.mgmt.spending_limits"
)

// Shared vocabulary.
const (
	// Tool is the registry tool the xAI team surfaces report on.
	Tool = "grok"
	// ParamTeam is the connection parameter naming the xAI team (the
	// {teamId} path segment of every Management API read).
	ParamTeam = "team_id"

	Contract = "xai.mgmt/v1 management-api reference (2026-10-08)"

	// AuditNamespace keys the team audit events.
	AuditNamespace = "xai.audit"
	// AuditAction is the one action every event lands under: the reference
	// gives an event a free-form English description and no action type, so
	// the driver never invents one from the text.
	AuditAction = "team_event"
	// ActorUser is the actor kind of an event whose user has no email (the
	// reference says the email "may not always" be populated).
	ActorUser = "xai_user"
	// AuditPageSize bounds a page (the reference documents pageSize without a
	// maximum; 100 keeps one page small).
	AuditPageSize = 100
	// AuditMaxWindow caps one run.
	AuditMaxWindow = 31 * 24 * time.Hour

	// SpendingLimitType is the team's postpaid monthly spending limit.
	SpendingLimitType vs.ResourceType = "Limit/xai.spending_limit/v1"
	// NamespaceSpendingLimit keys it by team.
	NamespaceSpendingLimit = "xai.spending_limit"
	// UnitUSDCents is the documented unit of every limit value.
	UnitUSDCents = "usd_cents"
)

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// teamRE bounds the team id before it becomes a path segment (the reference
// example is a UUID).
var teamRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// tokenRE bounds an opaque page token before it is sent back.
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)

func team(s vs.SurfaceID, p vendorapi.Params) (string, error) {
	t := p[ParamTeam]
	if !teamRE.MatchString(t) {
		return "", fmt.Errorf("%s: connection parameter %s is missing or not a team id", s, ParamTeam)
	}
	return t, nil
}

// AuditEvents returns the driver of xai.mgmt.audit_events.
//
// Contract (Management API reference, "Audit Logs"): GET
// /audit/teams/{teamId}/events with pageSize, pageToken, eventTimeFrom and
// eventTimeTo (ISO 8601) and orderBy TIME_ASCENDING; response {events:
// [{eventTime, eventId, description, user: {userId, email, givenName,
// familyName, profileImage, profileImageUrl}}], nextPageToken}. The token is
// present while more events exist. The description is free English text: it
// travels only as a detail value the sanitizer bounds (24 words, typed
// secrets redacted), and the user's names and profile image are never read.
func AuditEvents() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceAuditEvents,
		Build:           buildAudit,
		ParseResponse:   parseAudit,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAudit},
		ClosedDTO:       true,
		ContractVersion: Contract,
		Tool:            Tool,
		MaxWindow:       AuditMaxWindow,
		KnownPaths: []string{
			"events", "events[]", "events[].description", "events[].eventId", "events[].eventTime", "events[].user",
			"events[].user.email", "events[].user.familyName", "events[].user.givenName", "events[].user.userId",
			"nextPageToken",
		},
	}
}

func buildAudit(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceAuditEvents
	t, err := team(s, p)
	if err != nil {
		return vendorapi.Request{}, err
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > AuditMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, AuditMaxWindow)
	}
	q := map[string][]string{
		"pageSize":      {strconv.Itoa(AuditPageSize)},
		"orderBy":       {"TIME_ASCENDING"},
		"eventTimeFrom": {w.From.UTC().Format(time.RFC3339)},
		"eventTimeTo":   {w.To.UTC().Format(time.RFC3339)},
	}
	if cursor != "" {
		if !tokenRE.MatchString(cursor) {
			return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque page token", s)
		}
		q["pageToken"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/audit/teams/" + t + "/events", Query: q}, nil
}

type auditDoc struct {
	Events *[]struct {
		EventTime   *string `json:"eventTime"`
		EventID     *string `json:"eventId"`
		Description *string `json:"description"`
		User        *struct {
			UserID *string `json:"userId"`
			Email  *string `json:"email"`
		} `json:"user"`
	} `json:"events"`
	NextPageToken *string `json:"nextPageToken"`
}

func parseAudit(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceAuditEvents
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc auditDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented response")
	}
	if doc.Events == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field events is missing")
	}
	page := vendorapi.Page{}
	if tok := vendorapi.Str(doc.NextPageToken); tok != "" {
		if !tokenRE.MatchString(tok) {
			return vendorapi.Page{}, vendorapi.Drift(s, "nextPageToken is not an opaque token")
		}
		if r.Cursor != "" && tok == r.Cursor {
			return vendorapi.Page{}, vendorapi.Drift(s, "nextPageToken repeats the token the page was asked with")
		}
		page.NextCursor = tok
	}
	seen := map[string]bool{}
	for i, e := range *doc.Events {
		id := vendorapi.Str(e.EventID)
		if id == "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "events[%d].eventId is missing", i)
		}
		if seen[id] {
			return vendorapi.Page{}, vendorapi.Drift(s, "events[%d] repeats an event", i)
		}
		seen[id] = true
		at, err := time.Parse(time.RFC3339Nano, vendorapi.Str(e.EventTime))
		if err != nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "events[%d].eventTime is not RFC 3339", i)
		}
		ev := vendorapi.AuditEvent{Namespace: AuditNamespace, EventID: id, At: at.UTC(), Action: AuditAction, Detail: map[string]string{}}
		if u := e.User; u != nil {
			switch {
			case strings.TrimSpace(vendorapi.Str(u.Email)) != "":
				ev.ActorKind, ev.ActorIdentity = "email", strings.TrimSpace(vendorapi.Str(u.Email))
			case vendorapi.Str(u.UserID) != "":
				ev.ActorKind, ev.ActorIdentity = ActorUser, vendorapi.Str(u.UserID)
			}
			if v := vendorapi.Str(u.UserID); v != "" {
				ev.Detail["user_id"] = v
			}
		}
		if d := strings.TrimSpace(vendorapi.Str(e.Description)); d != "" {
			ev.Detail["description"] = d
		}
		page.Audit = append(page.Audit, ev)
	}
	return page, nil
}

// SpendingLimits returns the driver of xai.mgmt.spending_limits.
//
// Contract (Management API reference, "Billing Management"): GET
// /v1/billing/teams/{team_id}/postpaid/spending-limits, not paged; response
// {spendingLimits: {hardSlOverride, hardSlAuto, effectiveHardSl, softSl,
// effectiveSl}}, each optional and each {val: string} in USD cents. The team's
// one postpaid monthly limit lands as one Limit resource keyed by the team
// id; a member the vendor omits is absent, never zero. Read only: the soft
// limit POST is not built and nothing here feeds a budget.
func SpendingLimits() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:               SurfaceSpendingLimits,
		Build:                 buildLimits,
		ParseResponse:         parseLimits,
		Auth:                  bearerAuth,
		ContentTypes:          []string{"application/json"},
		Supplies:              []vs.DataClass{vs.ClassLimits},
		AuthoritativeSnapshot: true,
		ContractVersion:       Contract,
		KnownPaths: []string{
			"spendingLimits", "spendingLimits.effectiveHardSl", "spendingLimits.effectiveHardSl.val",
			"spendingLimits.effectiveSl", "spendingLimits.effectiveSl.val", "spendingLimits.hardSlAuto",
			"spendingLimits.hardSlAuto.val", "spendingLimits.softSl", "spendingLimits.softSl.val",
		},
	}
}

func buildLimits(p vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceSpendingLimits
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", s)
	}
	t, err := team(s, p)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/billing/teams/" + t + "/postpaid/spending-limits"}, nil
}

type cents struct {
	Val *string `json:"val"`
}

type limitsDoc struct {
	SpendingLimits *struct {
		HardOverride  *cents `json:"hardSlOverride"`
		HardAuto      *cents `json:"hardSlAuto"`
		EffectiveHard *cents `json:"effectiveHardSl"`
		Soft          *cents `json:"softSl"`
		Effective     *cents `json:"effectiveSl"`
	} `json:"spendingLimits"`
}

var centsRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

func parseLimits(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceSpendingLimits
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc limitsDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented response")
	}
	if doc.SpendingLimits == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field spendingLimits is missing")
	}
	t, err := team(s, r.Params)
	if err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "the response has no team to key the limit by")
	}
	sl := doc.SpendingLimits
	attrs := map[string]string{"unit": UnitUSDCents, "period": "monthly", "billing": "postpaid"}
	for _, c := range []struct {
		name string
		v    *cents
	}{
		{"hard_override_cents", sl.HardOverride},
		{"hard_auto_cents", sl.HardAuto},
		{"effective_hard_cents", sl.EffectiveHard},
		{"soft_cents", sl.Soft},
		{"effective_cents", sl.Effective},
	} {
		if c.v == nil {
			continue
		}
		if c.v.Val == nil || !centsRE.MatchString(*c.v.Val) {
			return vendorapi.Page{}, vendorapi.Drift(s, "spendingLimits %s is not a whole number of cents", c.name)
		}
		attrs[c.name] = *c.v.Val
	}
	return vendorapi.Page{
		SourceRecords: 1,
		Snapshot: &vendorapi.SnapshotManifest{
			Scope:          []vendorapi.ScopeKey{{Namespace: NamespaceSpendingLimit, Kind: vs.KindLimit}},
			SelectorDigest: "team", PageSet: "team_postpaid_spending_limits", ContractVersion: Contract,
		},
		Resources: []vendorapi.ResourceObservation{{
			Type: SpendingLimitType, ID: vs.ExternalID{Namespace: NamespaceSpendingLimit, Value: t}, Attrs: attrs,
		}},
	}, nil
}
