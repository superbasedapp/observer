package kilo

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceTable is the catalog id of the aggregated usage table.
const SurfaceTable vs.SurfaceID = "kilo.analytics.table"

// Usage table vocabulary (lane ENTAPI-L16D, T-713).
const (
	TableContract = "kilo.analytics.table/v1 openapi usageAnalytics.getTable day by user and model org-wide (2026-10-08)"

	// TableLimit is the documented maximum of limit. The table has no cursor,
	// so an answer of exactly TableLimit rows may be cut: it is refused as
	// incomplete rather than landed short.
	TableLimit = 10000
	// TableWindow caps one run: whole UTC days, a week keeps one answer far
	// under the row cap for a large organization.
	TableWindow = 7 * day
	// TableDomain is the coverage domain of the per-member grain.
	TableDomain = "kilo.organization.member"
)

// tableInput is the closed input of usageAnalytics.getTable: the window,
// daily buckets, the vendor's own cost source, the organization-wide view of
// one organization, grouped by user and model, at the documented maximum
// limit. No filter, exclusion or other dimension is ever sent (project and
// feature values can be customer-named).
type tableInput struct {
	StartDate      string   `json:"startDate"`
	EndDate        string   `json:"endDate"`
	Granularity    string   `json:"granularity"`
	CostSource     string   `json:"costSource"`
	OrganizationID string   `json:"organizationId"`
	PersonalScope  string   `json:"personalScope"`
	ViewAs         string   `json:"viewAs"`
	GroupBy        []string `json:"groupBy"`
	Limit          int      `json:"limit"`
}

func (tableInput) procedure() string { return "usageAnalytics.getTable" }

// tableDims is the closed groupBy list; the answer's dimensions map must
// carry exactly these keys.
var tableDims = []string{"user", "model"}

// tableMetric is one landed column of a table row: the documented field, the
// fact metric and unit, and whether it is microdollars (else a whole count).
type tableMetric struct {
	field, metric, unit string
	get                 func(*tableRow) *number
	microdollars        bool
}

var tableMetrics = []tableMetric{
	{"requestCount", "requests", "count", func(r *tableRow) *number { return r.RequestCount }, false},
	{"inputTokens", "input_tokens", "tokens", func(r *tableRow) *number { return r.InputTokens }, false},
	{"outputTokens", "output_tokens", "tokens", func(r *tableRow) *number { return r.OutputTokens }, false},
	{"cacheWriteTokens", "cache_write_tokens", "tokens", func(r *tableRow) *number { return r.CacheWriteTokens }, false},
	{"cacheHitTokens", "cache_read_tokens", "tokens", func(r *tableRow) *number { return r.CacheHitTokens }, false},
	{"errorCount", "errors", "count", func(r *tableRow) *number { return r.ErrorCount }, false},
	// costMicrodollars: the field name states the unit (millionths of a US
	// dollar), so one microdollar is one micro-unit of usd.
	{"costMicrodollars", "cost", "usd", func(r *tableRow) *number { return r.CostMicrodollars }, true},
}

// Table returns the driver of kilo.analytics.table.
//
// Contract (OpenAPI usageAnalytics_getTable): GET
// /api/trpc/usageAnalytics.getTable?input=<JSON> with startDate and endDate
// (RFC 3339, Z), granularity day, costSource cost, organizationId,
// personalScope personal-only, viewAs org-wide, groupBy ["user","model"] and
// limit 10000; answer {result: {data: {rows: [{datetime, dimensions,
// costMicrodollars, requestCount, inputTokens, outputTokens,
// cacheWriteTokens, cacheHitTokens, errorCount}], effectiveGranularity}}}
// (additionalProperties false). Each row lands one fact per column for the
// reserved Kilo gateway attribution, per UTC day, under the Kilo user id
// (kind user_id: held until an admin links it, the member list carries the
// same id with the e-mail), with the model as ModelRaw. The value of the
// "user" and "model" dimension keys is Inferred (the schema types the map,
// not its keys). A row count equal to the limit, an effective granularity
// other than day, a dimension set other than the asked one, a repeated key
// or a fractional count is schema drift. Spend from this table is vendor
// reported: display only, never spend or a budget (VCONN-SPEND-1).
func Table() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceTable,
		Build:           buildTable,
		ParseResponse:   parseTable,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: TableContract,
		Tool:            Tool,
		MaxWindow:       TableWindow,
		KnownPaths: []string{
			"result", "result.data", "result.data.effectiveGranularity", "result.data.rows", "result.data.rows[]",
			"result.data.rows[].cacheHitTokens", "result.data.rows[].cacheWriteTokens",
			"result.data.rows[].costMicrodollars", "result.data.rows[].datetime", "result.data.rows[].dimensions",
			"result.data.rows[].dimensions.model", "result.data.rows[].dimensions.user",
			"result.data.rows[].errorCount", "result.data.rows[].inputTokens", "result.data.rows[].outputTokens",
			"result.data.rows[].requestCount",
		},
	}
}

func buildTable(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceTable
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the table is not paged", s)
	}
	o := p[ParamOrganization]
	if !uuidRE.MatchString(o) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not an organization UUID", s, ParamOrganization)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > TableWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, TableWindow)
	}
	start := w.From.UTC().Truncate(day)
	return encodeTRPC(tableInput{
		StartDate: start.Format(time.RFC3339), EndDate: w.To.UTC().Format(time.RFC3339), Granularity: "day",
		CostSource: "cost", OrganizationID: o, PersonalScope: "personal-only", ViewAs: "org-wide",
		GroupBy: append([]string(nil), tableDims...), Limit: TableLimit,
	})
}

// tableRow is the closed DTO of one table row.
type tableRow struct {
	Datetime         *string           `json:"datetime"`
	Dimensions       map[string]string `json:"dimensions"`
	CostMicrodollars *number           `json:"costMicrodollars"`
	RequestCount     *number           `json:"requestCount"`
	InputTokens      *number           `json:"inputTokens"`
	OutputTokens     *number           `json:"outputTokens"`
	CacheWriteTokens *number           `json:"cacheWriteTokens"`
	CacheHitTokens   *number           `json:"cacheHitTokens"`
	ErrorCount       *number           `json:"errorCount"`
}

type tableData struct {
	Rows                 *[]tableRow `json:"rows"`
	EffectiveGranularity *string     `json:"effectiveGranularity"`
}

func parseTable(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceTable
	raw, err := unwrapTRPC(s, r)
	if err != nil {
		return vendorapi.Page{}, err
	}
	var d tableData
	if err := decodeData(s, raw, &d); err != nil {
		return vendorapi.Page{}, err
	}
	if d.Rows == nil || d.EffectiveGranularity == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field rows or effectiveGranularity is missing")
	}
	if *d.EffectiveGranularity != "day" {
		return vendorapi.Page{}, vendorapi.Drift(s, "effectiveGranularity %q is not the requested day", *d.EffectiveGranularity)
	}
	if len(*d.Rows) >= TableLimit {
		return vendorapi.Page{}, vendorapi.Drift(s, "%d rows reach the limit: the unpaged answer may be cut", len(*d.Rows))
	}
	page := vendorapi.Page{}
	seen := map[string]bool{}
	for i := range *d.Rows {
		row := &(*d.Rows)[i]
		if row.Datetime == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d] misses datetime", i)
		}
		start, ok := bucketDay(*row.Datetime)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d].datetime is not a UTC day", i)
		}
		if len(row.Dimensions) != len(tableDims) {
			return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d].dimensions is not the asked user and model", i)
		}
		user := strings.TrimSpace(row.Dimensions["user"])
		model := strings.TrimSpace(row.Dimensions["model"])
		if user == "" || model == "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d].dimensions misses user or model", i)
		}
		key := fmt.Sprintf("%d|%s|%s", start.Unix(), user, model)
		if seen[key] {
			return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d] repeats a day, user and model", i)
		}
		seen[key] = true
		for _, m := range tableMetrics {
			n := m.get(row)
			var v int64
			if m.microdollars {
				// A microdollar is one micro-unit of usd: exponent 6 reads
				// the value as millionths (a fraction rounds to the nearest).
				v, ok = vendorapi.DecimalMicros(numText(n), 6)
				ok = ok && v >= 0
			} else {
				v, ok = whole(n)
			}
			if n == nil || !ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "rows[%d].%s is not a non-negative number", i, m.field)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: start.Add(day), SourceTZ: "UTC", CoverageDomain: TableDomain,
				IdentityKind: "user_id", Identity: user, ModelRaw: model, Metric: m.metric, Unit: m.unit, ValueMicros: v,
			})
		}
	}
	// The vendor record container is the one result.data object (as for
	// the series); its rows become several facts each.
	page.SourceRecords = 1
	return page, nil
}

func numText(n *number) string {
	if n == nil {
		return ""
	}
	return string(*n)
}
