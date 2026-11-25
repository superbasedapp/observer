package factory

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsers is the catalog id of the per-user analytics surface.
const SurfaceUsers vs.SurfaceID = "factory.analytics.users"

// Per-user analytics vocabulary.
const (
	UsersContract = "factory.analytics.users/v1 analytics-api (2026-10-08)"

	// UsersPageSize is the documented maximum of limit (1 to 100).
	UsersPageSize = 100
	// UsersDomain is the coverage domain of the per-user report.
	UsersDomain = "factory.organization"
	// UnitCount counts events (tool calls, sessions, commits, messages).
	UnitCount = "count"
)

// Users returns the driver of factory.analytics.users.
//
// Contract (Factory Analytics API, "Per-user metrics"): GET
// /api/v1/analytics/users with startDate and endDate (YYYY-MM-DD, UTC, both
// required; the request ends at yesterday because today is a documented
// 400), limit (1 to 100) and cursor (a user id, from meta.next_cursor);
// response {"data": [{user_id, user_email|null, date, tool_calls,
// billable_tokens, ...}], "meta": {org_id, start_date, end_date, has_more,
// next_cursor}}. Each row lands as per-user facts for one UTC day: Standard
// Credits in credits and the documented event counts in count. The primary
// model, its tier, the autonomy ratio, the delegation level and the language
// list are descriptive and are not landed (a most-used model is not a usage
// split, so it never becomes a model dimension).
func Users() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUsers,
		Build:           buildUsers,
		ParseResponse:   parseUsers,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost, vs.ClassAdoption, vs.ClassCommits, vs.ClassSessions},
		ClosedDTO:       true,
		ContractVersion: UsersContract,
		Tool:            Tool,
		MaxWindow:       TokensMaxWindow,
		MaxLookback:     TokensMaxLookback,
		KnownPaths:      usersKnownPaths,
	}
}

// cursorRE bounds an opaque cursor before it is sent back.
var cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)

func buildUsers(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q, err := dayRange(SurfaceUsers, w)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q["limit"] = []string{strconv.Itoa(UsersPageSize)}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return vendorapi.Request{}, fmt.Errorf("%s: cursor is not an opaque user id", SurfaceUsers)
		}
		q["cursor"] = []string{cursor}
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/analytics/users", Query: q}, nil
}

// dayRange is the shared analytics date range: the last complete UTC day is
// the one before the window end's day, and the first day re-reads the day
// before the window so a late day is restated.
func dayRange(s vs.SurfaceID, w vendorapi.Window) (map[string][]string, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return nil, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > TokensMaxWindow {
		return nil, fmt.Errorf("%s: window longer than %s", s, TokensMaxWindow)
	}
	end := w.To.UTC().Truncate(day).Add(-day)
	start := w.From.UTC().Truncate(day).Add(-day)
	if start.After(end) {
		start = end
	}
	return map[string][]string{"startDate": {start.Format(dateLayout)}, "endDate": {end.Format(dateLayout)}}, nil
}

type usersDoc struct {
	Data *[]userRow `json:"data"`
	Meta *struct {
		HasMore    *bool   `json:"has_more"`
		NextCursor *string `json:"next_cursor"`
	} `json:"meta"`
}

type userRow struct {
	UserID            *string `json:"user_id"`
	UserEmail         *string `json:"user_email"`
	Date              *string `json:"date"`
	Billable          *num    `json:"billable_tokens"`
	ToolCalls         *num    `json:"tool_calls"`
	FilesCreated      *num    `json:"files_created"`
	FilesEdited       *num    `json:"files_edited"`
	GitCommits        *num    `json:"git_commits"`
	GitPRsCreated     *num    `json:"git_prs_created"`
	MCPCalls          *num    `json:"mcp_calls"`
	SkillCalls        *num    `json:"skill_calls"`
	SlashCommands     *num    `json:"slash_commands"`
	Hooks             *num    `json:"hooks"`
	Sessions          *num    `json:"sessions"`
	Messages          *num    `json:"messages"`
	UserMessages      *num    `json:"user_messages"`
	AssistantMessages *num    `json:"assistant_messages"`
}

// userMetric is one row of the per-user metric table: the documented field,
// its unit and its reader. Standard Credits are required (the reference's
// central figure); a count the vendor omits is absent, never zero.
type userMetric struct {
	metric, unit string
	required     bool
	get          func(userRow) *num
}

var userMetrics = []userMetric{
	{MetricStandardCredits, UnitCredits, true, func(r userRow) *num { return r.Billable }},
	{"tool_calls", UnitCount, false, func(r userRow) *num { return r.ToolCalls }},
	{"files_created", UnitCount, false, func(r userRow) *num { return r.FilesCreated }},
	{"files_edited", UnitCount, false, func(r userRow) *num { return r.FilesEdited }},
	{"git_commits", UnitCount, false, func(r userRow) *num { return r.GitCommits }},
	{"git_prs_created", UnitCount, false, func(r userRow) *num { return r.GitPRsCreated }},
	{"mcp_calls", UnitCount, false, func(r userRow) *num { return r.MCPCalls }},
	{"skill_calls", UnitCount, false, func(r userRow) *num { return r.SkillCalls }},
	{"slash_commands", UnitCount, false, func(r userRow) *num { return r.SlashCommands }},
	{"hooks", UnitCount, false, func(r userRow) *num { return r.Hooks }},
	{"sessions", UnitCount, false, func(r userRow) *num { return r.Sessions }},
	{"messages", UnitCount, false, func(r userRow) *num { return r.Messages }},
	{"user_messages", UnitCount, false, func(r userRow) *num { return r.UserMessages }},
	{"assistant_messages", UnitCount, false, func(r userRow) *num { return r.AssistantMessages }},
}

func parseUsers(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceUsers
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc usersDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented envelope")
	}
	if doc.Data == nil || doc.Meta == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field data or meta is missing")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Data)}
	if doc.Meta.HasMore != nil && *doc.Meta.HasMore {
		if doc.Meta.NextCursor == nil || !cursorRE.MatchString(*doc.Meta.NextCursor) {
			return vendorapi.Page{}, vendorapi.Drift(s, "meta.has_more is true without a usable next_cursor")
		}
		if r.Cursor != "" && *doc.Meta.NextCursor == r.Cursor {
			return vendorapi.Page{}, vendorapi.Drift(s, "meta.next_cursor repeats the cursor the page was asked with")
		}
		page.NextCursor = *doc.Meta.NextCursor
	}
	seen := map[string]bool{}
	for i, row := range *doc.Data {
		if row.UserID == nil || strings.TrimSpace(*row.UserID) == "" || row.Date == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] misses user_id or date", i)
		}
		d, err := time.Parse(dateLayout, *row.Date)
		if err != nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].date is not YYYY-MM-DD", i)
		}
		key := *row.UserID + "|" + *row.Date
		if seen[key] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] repeats a user and day", i)
		}
		seen[key] = true
		// The documented user_email resolves to a member through the seam's
		// identity resolution; a null email keeps the vendor user id, held.
		kind, id := "user_id", strings.TrimSpace(*row.UserID)
		if e := strings.TrimSpace(vendorapi.Str(row.UserEmail)); e != "" {
			kind, id = "email", e
		}
		for _, m := range userMetrics {
			n := m.get(row)
			if n == nil {
				if m.required {
					return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] misses %s", i, m.metric)
				}
				continue
			}
			v, ok := vendorapi.DecimalMicros(string(*n), 0)
			if !ok || v < 0 {
				return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].%s is not a non-negative number", i, m.metric)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: d, IntervalEnd: d.Add(day), SourceTZ: "UTC", CoverageDomain: UsersDomain,
				IdentityKind: kind, Identity: id, Metric: m.metric, Unit: m.unit, ValueMicros: v,
			})
		}
	}
	return page, nil
}

// usersKnownPaths are the documented response paths (the corpus field ledger
// of /users).
var usersKnownPaths = []string{
	"data", "data[]", "data[].assistant_messages", "data[].autonomy_ratio", "data[].billable_tokens", "data[].date",
	"data[].delegation_level", "data[].files_created", "data[].files_edited", "data[].git_commits",
	"data[].git_prs_created", "data[].hooks", "data[].languages", "data[].mcp_calls", "data[].messages",
	"data[].primary_model", "data[].primary_model_tier", "data[].sessions", "data[].skill_calls",
	"data[].slash_commands", "data[].tool_calls", "data[].user_email", "data[].user_id", "data[].user_messages",
	"meta", "meta.end_date", "meta.has_more", "meta.next_cursor", "meta.org_id", "meta.start_date",
}
