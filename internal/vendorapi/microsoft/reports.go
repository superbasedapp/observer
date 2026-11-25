package microsoft

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Surface ids and vocabulary of the Microsoft 365 Copilot report drivers.
const (
	SurfaceUsageUserDetail  vs.SurfaceID = "microsoft.m365.reports_usage_user_detail"
	SurfaceUserCountSummary vs.SurfaceID = "microsoft.m365.reports_user_count_summary"
	SurfaceUserCountTrend   vs.SurfaceID = "microsoft.m365.reports_user_count_trend"

	// Tool is the coverage target these reports describe: Microsoft 365
	// Copilot (a vendor product target with no registry row).
	Tool = "m365-copilot"
	// UserActivityClass is the snapshot class of one user's last-activity
	// dates.
	UserActivityClass = "microsoft.copilot_user_activity"
	// CoverageDomain is the population the counts describe: the tenant's
	// users licensed for Microsoft 365 Copilot (unlicensed Copilot Chat is
	// not in these reports, per the reference).
	CoverageDomain = "microsoft.m365.copilot_licensed"

	UsageUserDetailContract  = "microsoft.m365.reports_usage_user_detail/v1 graph v1.0 json 2026-10-08"
	UserCountSummaryContract = "microsoft.m365.reports_user_count_summary/v1 graph v1.0 json 2026-10-08"
	UserCountTrendContract   = "microsoft.m365.reports_user_count_trend/v1 graph v1.0 json 2026-10-08"

	// MaxLookback is the longest documented report period (D180).
	MaxLookback = 180 * 24 * time.Hour

	reportsPrefix = "/v1.0/copilot/reports/"
	day           = 24 * time.Hour
)

// clientCredentials is the auth contract of every Graph report: the
// OAuth client-credentials grant through the egress seam's token step.
var clientCredentials = vendorapi.AuthContract{
	Kind: vs.AuthOAuthClientCredentials, Scheme: vendorapi.SchemeOAuthClientCredentials,
}

// periodFor picks the shortest documented report period (version v2, the
// default: D7, D28, D90, D180) that covers the run's window.
func periodFor(w vendorapi.Window) string {
	span := w.To.Sub(w.From)
	switch {
	case span <= 7*day:
		return "D7"
	case span <= 28*day:
		return "D28"
	case span <= 90*day:
		return "D90"
	}
	return "D180"
}

// functionPath renders the OData function call path of a report.
func functionPath(function, period string) string {
	return reportsPrefix + function + "(period='" + period + "')"
}

// allowedNextQuery is the closed set of query members a next link may carry.
var allowedNextQuery = map[string]bool{"$format": true, "$skiptoken": true, "$skip": true, "$top": true}

// build returns the Build of a report: the first request asks the function
// for the window's period in JSON; a cursor is the path and query of the
// @odata.nextLink the previous page answered, which Parse already bound to
// the request's origin and path.
func build(surface vs.SurfaceID, function string) func(vendorapi.Params, vendorapi.Window, string) (vendorapi.Request, error) {
	return func(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
		if cursor == "" {
			if w.From.IsZero() || !w.To.After(w.From) {
				return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", surface)
			}
			return vendorapi.Request{
				Method: "GET", Path: functionPath(function, periodFor(w)),
				Query: map[string][]string{"$format": {"application/json"}},
			}, nil
		}
		path, raw, ok := strings.Cut(cursor, "?")
		if !ok || !strings.HasPrefix(path, reportsPrefix+function+"(") {
			return vendorapi.Request{}, fmt.Errorf("%s: the cursor is not this report's next link", surface)
		}
		q, err := url.ParseQuery(raw)
		if err != nil {
			return vendorapi.Request{}, fmt.Errorf("%s: the next link query does not parse", surface)
		}
		for k := range q {
			if !allowedNextQuery[k] {
				return vendorapi.Request{}, fmt.Errorf("%s: the next link carries an undocumented query member", surface)
			}
		}
		if q.Get("$skiptoken") == "" && q.Get("$skip") == "" {
			return vendorapi.Request{}, fmt.Errorf("%s: the next link carries no $skiptoken or $skip", surface)
		}
		return vendorapi.Request{Method: "GET", Path: path, Query: q}, nil
	}
}

var defaultPorts = map[string]string{"https": "443", "http": "80"}

// origin canonicalises scheme://host:port with the default port explicit.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// nextCursor validates an @odata.nextLink: an absolute URL with no userinfo
// or fragment, on the origin the request was sent to and on the same report
// path. Anything else is a paging-contract change (schema drift), never a
// request the runner follows.
func nextCursor(surface vs.SurfaceID, r vendorapi.Response, link *string) (string, error) {
	if link == nil {
		return "", nil
	}
	u, err := url.Parse(*link)
	if err != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
		return "", vendorapi.Drift(surface, "@odata.nextLink is not an absolute URL")
	}
	want, err := url.Parse(r.Origin)
	if err != nil || origin(u) != origin(want) {
		return "", vendorapi.Drift(surface, "@odata.nextLink points at another origin")
	}
	if u.Path != r.Path {
		return "", vendorapi.Drift(surface, "@odata.nextLink points at another path")
	}
	return u.Path + "?" + u.RawQuery, nil
}

// isoDate parses a documented yyyy-mm-dd date.
func isoDate(s string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02", s)
	return t.UTC(), err == nil
}

// ---- getMicrosoft365CopilotUsageUserDetail ----

// UsageUserDetail returns the driver of
// microsoft.m365.reports_usage_user_detail.
//
// Contract (copilotReportRoot: getMicrosoft365CopilotUsageUserDetail, JSON
// representation): {"value": [{reportRefreshDate, userPrincipalName,
// displayName, lastActivityDate, copilotChatLastActivityDate,
// microsoftTeamsCopilotLastActivityDate, wordCopilotLastActivityDate,
// excelCopilotLastActivityDate, powerPointCopilotLastActivityDate,
// outlookCopilotLastActivityDate, oneNoteCopilotLastActivityDate,
// loopCopilotLastActivityDate, copilotActivityUserDetailsByPeriod:
// [{reportPeriod}]}], "@odata.nextLink"}. Each user lands as one snapshot of
// class microsoft.copilot_user_activity keyed by the lower-cased user
// principal name (a concealed tenant answers a hash there, which then names
// no member); the display name never lands. An empty date means no activity
// in the period and is omitted. A snapshot is stored only when it changed.
func UsageUserDetail() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUsageUserDetail,
		Build:           build(SurfaceUsageUserDetail, "getMicrosoft365CopilotUsageUserDetail"),
		ParseResponse:   parseUserDetail,
		Auth:            clientCredentials,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAdoption},
		ClosedDTO:       true,
		ContractVersion: UsageUserDetailContract,
		Tool:            Tool,
		MaxLookback:     MaxLookback,
		KnownPaths:      userDetailKnownPaths,
	}
}

type userDetailDoc struct {
	Value    *[]userDetail `json:"value"`
	NextLink *string       `json:"@odata.nextLink"`
}

type userDetail struct {
	ReportRefreshDate *string `json:"reportRefreshDate"`
	UserPrincipalName *string `json:"userPrincipalName"`
	LastActivityDate  *string `json:"lastActivityDate"`
	CopilotChat       *string `json:"copilotChatLastActivityDate"`
	Teams             *string `json:"microsoftTeamsCopilotLastActivityDate"`
	Word              *string `json:"wordCopilotLastActivityDate"`
	Excel             *string `json:"excelCopilotLastActivityDate"`
	PowerPoint        *string `json:"powerPointCopilotLastActivityDate"`
	Outlook           *string `json:"outlookCopilotLastActivityDate"`
	OneNote           *string `json:"oneNoteCopilotLastActivityDate"`
	Loop              *string `json:"loopCopilotLastActivityDate"`
	ByPeriod          *[]struct {
		ReportPeriod *json.Number `json:"reportPeriod"`
	} `json:"copilotActivityUserDetailsByPeriod"`
}

func parseUserDetail(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "status %d is not the documented 200", r.Status)
	}
	var doc userDetailDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "body does not decode as the documented object")
	}
	if doc.Value == nil {
		return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "required field value is missing")
	}
	next, err := nextCursor(SurfaceUsageUserDetail, r, doc.NextLink)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next}
	seen := map[string]bool{}
	for i, u := range *doc.Value {
		upn := vendorapi.FoldEmail(strOf(u.UserPrincipalName))
		if upn == "" || u.ReportRefreshDate == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "value[%d] misses userPrincipalName or reportRefreshDate", i)
		}
		if _, ok := isoDate(*u.ReportRefreshDate); !ok {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "value[%d].reportRefreshDate is not a date", i)
		}
		if seen[upn] {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "value[%d] repeats a user", i)
		}
		seen[upn] = true
		body := map[string]string{"report_refresh_date": *u.ReportRefreshDate}
		for _, f := range []struct {
			key string
			v   *string
		}{
			{"last_activity_date", u.LastActivityDate},
			{"copilot_chat_last_activity_date", u.CopilotChat},
			{"teams_last_activity_date", u.Teams},
			{"word_last_activity_date", u.Word},
			{"excel_last_activity_date", u.Excel},
			{"powerpoint_last_activity_date", u.PowerPoint},
			{"outlook_last_activity_date", u.Outlook},
			{"onenote_last_activity_date", u.OneNote},
			{"loop_last_activity_date", u.Loop},
		} {
			if f.v == nil || *f.v == "" {
				continue
			}
			if _, ok := isoDate(*f.v); !ok {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "value[%d] %s is not a date", i, f.key)
			}
			body[f.key] = *f.v
		}
		if u.ByPeriod != nil && len(*u.ByPeriod) > 0 && (*u.ByPeriod)[0].ReportPeriod != nil {
			n, err := (*u.ByPeriod)[0].ReportPeriod.Int64()
			if err != nil || n <= 0 {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageUserDetail, "value[%d] reportPeriod is not a day count", i)
			}
			body["report_period"] = fmt.Sprint(n)
		}
		page.Snapshots = append(page.Snapshots, vendorapi.VendorSnapshot{Class: UserActivityClass, Subject: upn, Body: body})
	}
	return page, nil
}

func strOf(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// userDetailKnownPaths are the documented response paths (the corpus field
// ledgers of getMicrosoft365CopilotUsageUserDetail).
var userDetailKnownPaths = []string{
	`@odata\.nextLink`, "value", "value[]", "value[].copilotActivityUserDetailsByPeriod",
	"value[].copilotActivityUserDetailsByPeriod[]", "value[].copilotActivityUserDetailsByPeriod[].reportPeriod",
	"value[].copilotChatLastActivityDate", "value[].displayName", "value[].excelCopilotLastActivityDate",
	"value[].lastActivityDate", "value[].loopCopilotLastActivityDate", "value[].microsoftTeamsCopilotLastActivityDate",
	"value[].oneNoteCopilotLastActivityDate", "value[].outlookCopilotLastActivityDate",
	"value[].powerPointCopilotLastActivityDate", "value[].reportRefreshDate", "value[].userPrincipalName",
	"value[].wordCopilotLastActivityDate",
}

// ---- user counts (summary and trend) ----

// app maps one documented per-app JSON prefix to a fact feature.
type app struct{ prefix, feature string }

// apps is the closed per-app table of the user-count reports' JSON
// representation (the version 1 members; version 2 additions are not in the
// documented JSON example and are not read).
var apps = []app{
	{"anyApp", "any_app"},
	{"microsoftTeams", "teams"},
	{"word", "word"},
	{"powerPoint", "powerpoint"},
	{"outlook", "outlook"},
	{"excel", "excel"},
	{"oneNote", "onenote"},
	{"loop", "loop"},
	{"copilotChat", "copilot_chat"},
}

// countFacts turns one adoption object's per-app enabled and active user
// counts into org facts over [start, end).
func countFacts(surface vs.SurfaceID, where string, obj map[string]json.RawMessage, start, end time.Time) ([]vendorapi.FactRow, error) {
	var out []vendorapi.FactRow
	for _, a := range apps {
		for _, m := range []struct{ suffix, metric string }{{"EnabledUsers", "enabled_users"}, {"ActiveUsers", "active_users"}} {
			raw, ok := obj[a.prefix+m.suffix]
			if !ok || string(raw) == "null" {
				continue
			}
			if len(raw) > 0 && raw[0] == '"' {
				return nil, vendorapi.Drift(surface, "%s.%s is a quoted number", where, a.prefix+m.suffix)
			}
			var n json.Number
			if err := vendorapi.DecodeNumbers(raw, &n); err != nil {
				return nil, vendorapi.Drift(surface, "%s.%s is not a number", where, a.prefix+m.suffix)
			}
			v, err := n.Int64()
			if err != nil || v < 0 {
				return nil, vendorapi.Drift(surface, "%s.%s is not a whole non-negative number", where, a.prefix+m.suffix)
			}
			mv, ok := vendorapi.CountMicros(v)
			if !ok {
				return nil, vendorapi.Drift(surface, "%s.%s overflows", where, a.prefix+m.suffix)
			}
			out = append(out, vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: CoverageDomain,
				Feature: a.feature, Metric: m.metric, Unit: "users", ValueMicros: mv,
			})
		}
	}
	return out, nil
}

// whole reads a required positive whole number member.
func whole(obj map[string]json.RawMessage, key string) (int64, bool) {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 || raw[0] == '"' {
		return 0, false
	}
	var n json.Number
	if err := vendorapi.DecodeNumbers(raw, &n); err != nil {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil && v > 0
}

// dateMember reads a required date member.
func dateMember(obj map[string]json.RawMessage, key string) (time.Time, bool) {
	raw, ok := obj[key]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return time.Time{}, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, false
	}
	return isoDate(s)
}

type countDoc struct {
	Value    *[]map[string]json.RawMessage `json:"value"`
	NextLink *string                       `json:"@odata.nextLink"`
}

func objects(raw json.RawMessage) ([]map[string]json.RawMessage, bool) {
	var out []map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	return out, vendorapi.DecodeNumbers(raw, &out) == nil
}

// UserCountSummary returns the driver of
// microsoft.m365.reports_user_count_summary.
//
// Contract (getMicrosoft365CopilotUserCountSummary, JSON representation):
// {"value": [{reportRefreshDate, adoptionByProduct: [{reportPeriod,
// anyAppEnabledUsers, anyAppActiveUsers, microsoftTeamsEnabledUsers, ...,
// copilotChatActiveUsers}]}]}. Each per-app count lands as one org fact
// (feature the app, metric enabled_users or active_users, unit users) over
// the report period ending with the refresh date (the period's alignment to
// the refresh date is Inferred). Provisional: a later run restates it.
func UserCountSummary() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUserCountSummary,
		Build:           build(SurfaceUserCountSummary, "getMicrosoft365CopilotUserCountSummary"),
		ParseResponse:   parseSummary,
		Auth:            clientCredentials,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAdoption},
		ClosedDTO:       true,
		ContractVersion: UserCountSummaryContract,
		Tool:            Tool,
		MaxLookback:     MaxLookback,
		KnownPaths:      summaryKnownPaths,
	}
}

func parseSummary(r vendorapi.Response) (vendorapi.Page, error) {
	const s = SurfaceUserCountSummary
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc countDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented object")
	}
	if doc.Value == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field value is missing")
	}
	next, err := nextCursor(s, r, doc.NextLink)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Value)}
	for i, v := range *doc.Value {
		refresh, ok := dateMember(v, "reportRefreshDate")
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].reportRefreshDate is missing or not a date", i)
		}
		products, ok := objects(v["adoptionByProduct"])
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByProduct is missing or not an array", i)
		}
		end := refresh.Add(day)
		periods := map[int64]bool{}
		for j, p := range products {
			n, ok := whole(p, "reportPeriod")
			if !ok || n > 366 {
				return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByProduct[%d].reportPeriod is not a day count", i, j)
			}
			if periods[n] {
				return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByProduct[%d] repeats a report period", i, j)
			}
			periods[n] = true
			facts, err := countFacts(s, fmt.Sprintf("value[%d].adoptionByProduct[%d]", i, j), p, end.Add(-time.Duration(n)*day), end)
			if err != nil {
				return vendorapi.Page{}, err
			}
			page.Facts = append(page.Facts, facts...)
		}
	}
	return page, nil
}

// summaryKnownPaths are the documented response paths.
var summaryKnownPaths = []string{
	"value", "value[]", "value[].adoptionByProduct", "value[].adoptionByProduct[]",
	"value[].adoptionByProduct[].anyAppActiveUsers", "value[].adoptionByProduct[].anyAppEnabledUsers",
	"value[].adoptionByProduct[].copilotChatActiveUsers", "value[].adoptionByProduct[].copilotChatEnabledUsers",
	"value[].adoptionByProduct[].excelActiveUsers", "value[].adoptionByProduct[].excelEnabledUsers",
	"value[].adoptionByProduct[].loopActiveUsers", "value[].adoptionByProduct[].loopEnabledUsers",
	"value[].adoptionByProduct[].microsoftTeamsActiveUsers", "value[].adoptionByProduct[].microsoftTeamsEnabledUsers",
	"value[].adoptionByProduct[].oneNoteActiveUsers", "value[].adoptionByProduct[].oneNoteEnabledUsers",
	"value[].adoptionByProduct[].outlookActiveUsers", "value[].adoptionByProduct[].outlookEnabledUsers",
	"value[].adoptionByProduct[].powerPointActiveUsers", "value[].adoptionByProduct[].powerPointEnabledUsers",
	"value[].adoptionByProduct[].reportPeriod", "value[].adoptionByProduct[].wordActiveUsers",
	"value[].adoptionByProduct[].wordEnabledUsers", "value[].reportRefreshDate",
}

// UserCountTrend returns the driver of
// microsoft.m365.reports_user_count_trend.
//
// Contract (getMicrosoft365CopilotUserCountTrend, JSON representation):
// {"value": [{reportRefreshDate, reportPeriod, adoptionByDate: [{reportDate,
// anyAppEnabledUsers, ..., copilotChatActiveUsers}]}]}. Each per-app count
// of a report date lands as one org fact over that UTC day. Provisional: a
// later run restates a day.
func UserCountTrend() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUserCountTrend,
		Build:           build(SurfaceUserCountTrend, "getMicrosoft365CopilotUserCountTrend"),
		ParseResponse:   parseTrend,
		Auth:            clientCredentials,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAdoption},
		ClosedDTO:       true,
		ContractVersion: UserCountTrendContract,
		Tool:            Tool,
		MaxLookback:     MaxLookback,
		KnownPaths:      trendKnownPaths,
	}
}

func parseTrend(r vendorapi.Response) (vendorapi.Page, error) {
	const s = SurfaceUserCountTrend
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc countDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented object")
	}
	if doc.Value == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field value is missing")
	}
	next, err := nextCursor(s, r, doc.NextLink)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Value)}
	days := map[time.Time]bool{}
	for i, v := range *doc.Value {
		if _, ok := dateMember(v, "reportRefreshDate"); !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].reportRefreshDate is missing or not a date", i)
		}
		if _, ok := whole(v, "reportPeriod"); !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].reportPeriod is not a day count", i)
		}
		dates, ok := objects(v["adoptionByDate"])
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByDate is missing or not an array", i)
		}
		for j, d := range dates {
			at, ok := dateMember(d, "reportDate")
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByDate[%d].reportDate is missing or not a date", i, j)
			}
			if days[at] {
				return vendorapi.Page{}, vendorapi.Drift(s, "value[%d].adoptionByDate[%d] repeats a report date", i, j)
			}
			days[at] = true
			facts, err := countFacts(s, fmt.Sprintf("value[%d].adoptionByDate[%d]", i, j), d, at, at.Add(day))
			if err != nil {
				return vendorapi.Page{}, err
			}
			page.Facts = append(page.Facts, facts...)
		}
	}
	return page, nil
}

// trendKnownPaths are the documented response paths.
var trendKnownPaths = []string{
	"value", "value[]", "value[].adoptionByDate", "value[].adoptionByDate[]",
	"value[].adoptionByDate[].anyAppActiveUsers", "value[].adoptionByDate[].anyAppEnabledUsers",
	"value[].adoptionByDate[].copilotChatActiveUsers", "value[].adoptionByDate[].copilotChatEnabledUsers",
	"value[].adoptionByDate[].excelActiveUsers", "value[].adoptionByDate[].excelEnabledUsers",
	"value[].adoptionByDate[].loopActiveUsers", "value[].adoptionByDate[].loopEnabledUsers",
	"value[].adoptionByDate[].microsoftTeamsActiveUsers", "value[].adoptionByDate[].microsoftTeamsEnabledUsers",
	"value[].adoptionByDate[].oneNoteActiveUsers", "value[].adoptionByDate[].oneNoteEnabledUsers",
	"value[].adoptionByDate[].outlookActiveUsers", "value[].adoptionByDate[].outlookEnabledUsers",
	"value[].adoptionByDate[].powerPointActiveUsers", "value[].adoptionByDate[].powerPointEnabledUsers",
	"value[].adoptionByDate[].reportDate", "value[].adoptionByDate[].wordActiveUsers",
	"value[].adoptionByDate[].wordEnabledUsers", "value[].reportPeriod", "value[].reportRefreshDate",
}
