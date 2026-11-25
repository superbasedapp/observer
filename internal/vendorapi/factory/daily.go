package factory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The organization-wide daily analytics reads of lane ENTAPI-L16C (T-710):
// /activity, /productivity and /tools, each requested WITHOUT group_by (the
// documented ungrouped shape: one row per UTC day with nested breakdowns).
// The grouped shapes are not requested, so no group row's grain is guessed.
const (
	SurfaceActivity     vs.SurfaceID = "factory.analytics.activity"
	SurfaceProductivity vs.SurfaceID = "factory.analytics.productivity"
	SurfaceTools        vs.SurfaceID = "factory.analytics.tools"

	ActivityContract     = "factory.analytics.activity/v1 analytics-api ungrouped (2026-10-08)"
	ProductivityContract = "factory.analytics.productivity/v1 analytics-api (2026-10-08)"
	ToolsContract        = "factory.analytics.tools/v1 analytics-api ungrouped (2026-10-08)"

	// UnitUsers counts distinct users (never summed across days or clients).
	UnitUsers = "users"
	// DailyDomain is the coverage domain of the organization-wide daily reads.
	DailyDomain = "factory.organization"
)

// dailyMetric is one row of a daily metric table: the documented field, the
// fact metric and unit. Every documented scalar of the table is required on
// a row (the reference lists them on every row); a quoted, negative or
// fractional-exponent value is schema drift.
type dailyMetric struct {
	field, metric, unit string
}

// breakdown is one documented nested array landed per element: the array
// field, the element's key and value members and the fact metric and unit. The
// key travels as the fact's Feature dimension; a breakdown fact is never added
// to its total (the total row carries an empty Feature).
type breakdown struct {
	array, key, value, metric, unit string
}

// dailySpec is the closed description of one daily read: the path, the
// scalar metrics, the breakdown arrays, an optional per-client object of
// distinct-user counts and the documented paths the fixtures ledger.
type dailySpec struct {
	surface    vs.SurfaceID
	path       string
	contract   string
	supplies   []vs.DataClass
	scalars    []dailyMetric
	breakdowns []breakdown
	// byClient is the object member mapping a client type to its distinct
	// users (activity only).
	byClient string
	closed   bool
	known    []string
}

// featureRE bounds a breakdown key (a tool name or a client type) before it
// becomes a fact dimension.
var featureRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,63}$`)

var activitySpec = dailySpec{
	surface: SurfaceActivity, path: "/api/v1/analytics/activity", contract: ActivityContract,
	supplies: []vs.DataClass{vs.ClassAdoption, vs.ClassSessions},
	scalars: []dailyMetric{
		{"daily_active_users", "daily_active_users", UnitUsers},
		{"sessions", "sessions", UnitCount},
		{"messages", "messages", UnitCount},
		{"user_messages", "user_messages", UnitCount},
	},
	byClient: "daily_active_users_by_client",
	known: []string{
		"data", "data[]", "data[].daily_active_users", "data[].daily_active_users_by_client",
		"data[].daily_active_users_by_client.non-interactive-cli", "data[].daily_active_users_by_client.terminal-ui",
		"data[].daily_active_users_by_client.web", "data[].date", "data[].messages", "data[].monthly_active_users",
		"data[].sessions", "data[].user_messages", "data[].weekly_active_users", "meta", "meta.end_date",
		"meta.org_id", "meta.start_date",
	},
}

var productivitySpec = dailySpec{
	surface: SurfaceProductivity, path: "/api/v1/analytics/productivity", contract: ProductivityContract,
	supplies: []vs.DataClass{vs.ClassCommits, vs.ClassLOC},
	scalars: []dailyMetric{
		{"files_created", "files_created", UnitCount},
		{"files_edited", "files_edited", UnitCount},
		{"git_commits", "git_commits", UnitCount},
		{"git_prs_created", "git_prs_created", UnitCount},
	},
	known: []string{
		"data", "data[]", "data[].by_extension", "data[].by_extension[]", "data[].by_extension[].count",
		"data[].by_extension[].extension", "data[].by_language", "data[].by_language[]", "data[].by_language[].count",
		"data[].by_language[].language", "data[].date", "data[].files_created", "data[].files_edited",
		"data[].git_commits", "data[].git_prs_created", "meta", "meta.end_date", "meta.org_id", "meta.start_date",
	},
}

var toolsSpec = dailySpec{
	surface: SurfaceTools, path: "/api/v1/analytics/tools", contract: ToolsContract,
	supplies: []vs.DataClass{vs.ClassAdoption},
	scalars: []dailyMetric{
		{"tool_calls", "tool_calls", UnitCount},
		{"skills_invocations", "skills_invocations", UnitCount},
		{"slash_commands_invocations", "slash_commands_invocations", UnitCount},
		{"hooks_invocations", "hooks_invocations", UnitCount},
		{"mcp_users_with_mcp", "mcp_users", UnitUsers},
		{"web_users", "web_users", UnitUsers},
	},
	breakdowns: []breakdown{{array: "by_tool", key: "tool", value: "invocations", metric: "tool_calls", unit: UnitCount}},
	// hooks_by_event carries the configured hook command (free text that may
	// hold a credential): the DTO has no member for it, so it is never decoded.
	closed: true,
	known: []string{
		"data", "data[]", "data[].autonomy_ratio_avg", "data[].autonomy_ratio_p50", "data[].autonomy_ratio_p90",
		"data[].by_tool", "data[].by_tool[]", "data[].by_tool[].invocations", "data[].by_tool[].tool", "data[].date",
		"data[].hooks_by_event", "data[].hooks_by_event[]", "data[].hooks_by_event[].command",
		"data[].hooks_by_event[].count", "data[].hooks_by_event[].event", "data[].hooks_by_event[].matcher",
		"data[].hooks_invocations", "data[].mcp_by_server", "data[].mcp_by_server[]",
		"data[].mcp_by_server[].invocations", "data[].mcp_by_server[].server", "data[].mcp_users_with_mcp",
		"data[].skills_by_name", "data[].skills_by_name[]", "data[].skills_by_name[].count",
		"data[].skills_by_name[].name", "data[].skills_invocations", "data[].slash_commands_by_name",
		"data[].slash_commands_by_name[]", "data[].slash_commands_by_name[].count",
		"data[].slash_commands_by_name[].name", "data[].slash_commands_invocations",
		"data[].tool_autonomy_level_ratio", "data[].tool_autonomy_level_ratio.auto_high",
		"data[].tool_autonomy_level_ratio.auto_low", "data[].tool_autonomy_level_ratio.auto_medium",
		"data[].tool_autonomy_level_ratio.manual", "data[].tool_calls", "data[].tool_calls_per_session_avg",
		"data[].user_turns_per_session_avg", "data[].web_users", "meta", "meta.end_date", "meta.org_id",
		"meta.start_date",
	},
}

// Activity returns the driver of factory.analytics.activity.
//
// Contract (Factory Analytics API, "User activity"): GET
// /api/v1/analytics/activity with startDate and endDate (YYYY-MM-DD, UTC,
// ending yesterday; today is a documented 400), no group_by; each row {date,
// daily_active_users, weekly_active_users, monthly_active_users,
// daily_active_users_by_client: {client: users}, sessions, messages,
// user_messages}. Lands per UTC day: daily active users (unit users), sessions,
// messages and user messages (count), and daily active users per client type
// (Feature = the client). Weekly and monthly active users are trailing-window
// distinct counts whose interval is not the row's day, so they are not landed.
func Activity() vendorapi.Driver { return dailyDriver(activitySpec) }

// Productivity returns the driver of factory.analytics.productivity.
//
// Contract (Factory Analytics API, "Productivity"): GET
// /api/v1/analytics/productivity with startDate and endDate; each row {date,
// files_created, files_edited, by_extension, by_language, git_commits,
// git_prs_created}. Lands the four counts per UTC day; the per-extension and
// per-language breakdowns are not landed (one documented total is enough for
// the LOC and Commits supplies; the breakdowns overlap each other).
func Productivity() vendorapi.Driver { return dailyDriver(productivitySpec) }

// Tools returns the driver of factory.analytics.tools.
//
// Contract (Factory Analytics API, "Tool usage"): GET /api/v1/analytics/tools
// with startDate and endDate, no group_by. Lands per UTC day: tool calls,
// skill, slash command and hook invocations (count), MCP and web users
// (users), and tool calls per built-in tool name (Feature). The averages,
// percentiles and autonomy ratios are derived values and are not landed; MCP
// server, skill and slash command names are organization-authored and are not
// landed; the hook breakdown (which names the configured command) is never
// decoded, so the surface is may_return_secret and runs closed-DTO.
func Tools() vendorapi.Driver { return dailyDriver(toolsSpec) }

func dailyDriver(s dailySpec) vendorapi.Driver {
	return vendorapi.Driver{
		Surface: s.surface,
		Build: func(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
			return buildDaily(s, w, cursor)
		},
		ParseResponse:   func(r vendorapi.Response) (vendorapi.Page, error) { return parseDaily(s, r) },
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        s.supplies,
		ClosedDTO:       s.closed,
		ContractVersion: s.contract,
		Tool:            Tool,
		MaxWindow:       TokensMaxWindow,
		MaxLookback:     TokensMaxLookback,
		KnownPaths:      s.known,
	}
}

func buildDaily(s dailySpec, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", s.surface)
	}
	q, err := dayRange(s.surface, w)
	if err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: s.path, Query: q}, nil
}

// dailyRow is the closed DTO of one daily row: the date, every scalar the
// tables name, the by_tool breakdown and the per-client object. Nothing else
// is decoded (hooks_by_event, the other name breakdowns and the ratios have no
// member here).
type dailyRow struct {
	Date    *string         `json:"date"`
	Scalars map[string]*num `json:"-"`
	ByTool  *[]struct {
		Tool        *string `json:"tool"`
		Invocations *num    `json:"invocations"`
	} `json:"by_tool"`
	ByClient map[string]*num `json:"-"`
}

// decodeDailyRow reads the members of one row the spec names: each scalar
// and the per-client object decoded on its own, so a member the spec does not
// name is never decoded at all.
func decodeDailyRow(s dailySpec, raw map[string]json.RawMessage) (dailyRow, error) {
	var row dailyRow
	if v, ok := raw["date"]; ok {
		if err := json.Unmarshal(v, &row.Date); err != nil {
			return row, err
		}
	}
	row.Scalars = map[string]*num{}
	for _, m := range s.scalars {
		v, ok := raw[m.field]
		if !ok || string(v) == "null" {
			continue
		}
		var n num
		if err := json.Unmarshal(v, &n); err != nil {
			return row, err
		}
		row.Scalars[m.field] = &n
	}
	for _, b := range s.breakdowns {
		if v, ok := raw[b.array]; ok && b.array == "by_tool" {
			if err := json.Unmarshal(v, &row.ByTool); err != nil {
				return row, err
			}
		}
	}
	if s.byClient != "" {
		if v, ok := raw[s.byClient]; ok && string(v) != "null" {
			if err := json.Unmarshal(v, &row.ByClient); err != nil {
				return row, err
			}
		}
	}
	return row, nil
}

func parseDaily(s dailySpec, r vendorapi.Response) (vendorapi.Page, error) {
	drift := func(format string, a ...any) error {
		return vendorapi.Drift(s.surface, format, a...)
	}
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc struct {
		Data *[]map[string]json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode as the documented envelope")
	}
	if doc.Data == nil {
		return vendorapi.Page{}, drift("required field data is missing")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, raw := range *doc.Data {
		if raw == nil {
			return vendorapi.Page{}, drift("data[%d] is not an object", i)
		}
		row, err := decodeDailyRow(s, raw)
		if err != nil {
			return vendorapi.Page{}, drift("data[%d] has a member of the wrong type", i)
		}
		if _, grouped := raw["group_key"]; grouped {
			return vendorapi.Page{}, drift("data[%d] is a grouped row (group_by is never sent)", i)
		}
		if row.Date == nil {
			return vendorapi.Page{}, drift("data[%d].date is missing", i)
		}
		d, err := time.Parse(dateLayout, *row.Date)
		if err != nil {
			return vendorapi.Page{}, drift("data[%d].date is not YYYY-MM-DD", i)
		}
		if seen[*row.Date] {
			return vendorapi.Page{}, drift("data[%d] repeats a day", i)
		}
		seen[*row.Date] = true
		fact := func(metric, unit, feature string, n *num, what string) error {
			v, ok := vendorapi.DecimalMicros(string(*n), 0)
			if !ok || v < 0 {
				return drift("data[%d].%s is not a non-negative number", i, what)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: d, IntervalEnd: d.Add(day), SourceTZ: "UTC", CoverageDomain: DailyDomain,
				Feature: feature, Metric: metric, Unit: unit, ValueMicros: v,
			})
			return nil
		}
		for _, m := range s.scalars {
			n := row.Scalars[m.field]
			if n == nil {
				return vendorapi.Page{}, drift("data[%d] misses %s", i, m.field)
			}
			if err := fact(m.metric, m.unit, "", n, m.field); err != nil {
				return vendorapi.Page{}, err
			}
		}
		for _, b := range s.breakdowns {
			if b.array != "by_tool" || row.ByTool == nil {
				continue
			}
			keys := map[string]bool{}
			for k, e := range *row.ByTool {
				if e.Tool == nil || !featureRE.MatchString(*e.Tool) || e.Invocations == nil {
					return vendorapi.Page{}, drift("data[%d].%s[%d] is not a %s and a %s", i, b.array, k, b.key, b.value)
				}
				if keys[*e.Tool] {
					return vendorapi.Page{}, drift("data[%d].%s repeats %q", i, b.array, *e.Tool)
				}
				keys[*e.Tool] = true
				if err := fact(b.metric, b.unit, *e.Tool, e.Invocations, b.array); err != nil {
					return vendorapi.Page{}, err
				}
			}
		}
		clients := make([]string, 0, len(row.ByClient))
		for client := range row.ByClient {
			clients = append(clients, client)
		}
		sort.Strings(clients)
		for _, client := range clients {
			n := row.ByClient[client]
			if !featureRE.MatchString(client) || n == nil {
				return vendorapi.Page{}, drift("data[%d].%s has a member that is not a client and a count", i, s.byClient)
			}
			if err := fact("daily_active_users", UnitUsers, client, n, s.byClient); err != nil {
				return vendorapi.Page{}, err
			}
		}
	}
	return page, nil
}
