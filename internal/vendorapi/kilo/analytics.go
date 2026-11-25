package kilo

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceTimeseries is the catalog id of the usage time series.
const SurfaceTimeseries vs.SurfaceID = "kilo.analytics.timeseries"

// Usage analytics vocabulary.
const (
	TimeseriesContract = "kilo.analytics.timeseries/v1 openapi usageAnalytics.getTimeseries tokens day org-wide (2026-10-08)"

	// ParamOrganization is the connection parameter naming the Kilo
	// organization (the organizationId input, a UUID).
	ParamOrganization = "organization_id"
	// MaxWindow caps one run (the reference states no range limit).
	MaxWindow = 31 * day
	day       = 24 * time.Hour

	// MetricTokens is the documented "tokens" metric: input plus output
	// tokens of the bucket (a count, never money).
	MetricTokens = "total_tokens"
	// Domain is the coverage domain of the organization-wide view.
	Domain = "kilo.organization"
)

// Tool is the reserved gateway attribution of Kilo Gateway usage: the
// analytics count every request the organization sent through the Kilo
// Gateway, from the Kilo extension, the Kilo CLI or any other client, so they
// are never attributed to one registry tool (vendorapi/gateway.go).
var Tool = vendorapi.GatewayTool("kilo")

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// timeseriesInput is the closed input of usageAnalytics.getTimeseries: the
// window, a fixed daily granularity, the vendor's own cost source, the
// organization-wide view of one organization and the fixed "tokens" metric.
// No filter, exclusion or split is ever sent.
type timeseriesInput struct {
	StartDate      string `json:"startDate"`
	EndDate        string `json:"endDate"`
	Granularity    string `json:"granularity"`
	CostSource     string `json:"costSource"`
	OrganizationID string `json:"organizationId"`
	PersonalScope  string `json:"personalScope"`
	ViewAs         string `json:"viewAs"`
	Metric         string `json:"metric"`
}

func (timeseriesInput) procedure() string { return "usageAnalytics.getTimeseries" }

// Timeseries returns the driver of kilo.analytics.timeseries.
//
// Contract (OpenAPI usageAnalytics_getTimeseries): GET
// /api/trpc/usageAnalytics.getTimeseries?input=<JSON> with startDate and
// endDate (RFC 3339, Z), granularity day, costSource cost, organizationId,
// personalScope personal-only (its documented default), viewAs org-wide and
// metric tokens; answer {result: {data: {timeseries: [{datetime, value,
// label?}], effectiveGranularity}}}. Each bucket lands one org-level
// total_tokens fact for the reserved gateway attribution. The bucket's
// datetime format is not stated (Inferred: RFC 3339 or a bare date at UTC
// midnight); an effective granularity other than day, a label (a split the
// driver never asked for), a fractional or negative value or a repeated
// bucket is schema drift. The cost metric is not landed: its unit (dollars or
// micro-dollars) is not documented for the series.
func Timeseries() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceTimeseries,
		Build:           buildTimeseries,
		ParseResponse:   parseTimeseries,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage},
		ClosedDTO:       true,
		ContractVersion: TimeseriesContract,
		Tool:            Tool,
		MaxWindow:       MaxWindow,
		KnownPaths: []string{
			"result", "result.data", "result.data.effectiveGranularity", "result.data.timeseries",
			"result.data.timeseries[]", "result.data.timeseries[].datetime", "result.data.timeseries[].value",
		},
	}
}

func buildTimeseries(p vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceTimeseries
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the series is not paged", s)
	}
	o := p[ParamOrganization]
	if !uuidRE.MatchString(o) {
		return vendorapi.Request{}, fmt.Errorf("%s: connection parameter %s is missing or not an organization UUID", s, ParamOrganization)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > MaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, MaxWindow)
	}
	// Whole UTC days: the bucket containing the window start is re-read in
	// full so a restatement replaces it.
	start := w.From.UTC().Truncate(day)
	return encodeTRPC(timeseriesInput{
		StartDate: start.Format(time.RFC3339), EndDate: w.To.UTC().Format(time.RFC3339), Granularity: "day",
		CostSource: "cost", OrganizationID: o, PersonalScope: "personal-only", ViewAs: "org-wide", Metric: "tokens",
	})
}

// bucket is the closed DTO of one series point.
type bucket struct {
	Datetime *string `json:"datetime"`
	Value    *number `json:"value"`
	Label    *string `json:"label"`
}

type timeseriesData struct {
	Timeseries           *[]bucket `json:"timeseries"`
	EffectiveGranularity *string   `json:"effectiveGranularity"`
}

// number is a bare JSON number kept as its literal text; a quoted value is a
// type change and fails the page.
type number string

// UnmarshalJSON accepts a bare JSON number only.
func (n *number) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("kilo: %.16q is not a JSON number", b)
	}
	*n = number(b)
	return nil
}

// whole reads a non-negative integer count (a JSON number with no fraction
// or exponent).
func whole(n *number) (int64, bool) {
	if n == nil || strings.ContainsAny(string(*n), ".eE+-") {
		return 0, false
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil {
		return 0, false
	}
	return vendorapi.CountMicros(v)
}

// bucketDay reads a bucket's datetime as a UTC day start.
func bucketDay(s string) (time.Time, bool) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	t = t.UTC()
	return t, t.Equal(t.Truncate(day))
}

func parseTimeseries(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceTimeseries
	raw, err := unwrapTRPC(s, r)
	if err != nil {
		return vendorapi.Page{}, err
	}
	var d timeseriesData
	if err := decodeData(s, raw, &d); err != nil {
		return vendorapi.Page{}, err
	}
	if d.Timeseries == nil || d.EffectiveGranularity == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field timeseries or effectiveGranularity is missing")
	}
	if *d.EffectiveGranularity != "day" {
		return vendorapi.Page{}, vendorapi.Drift(s, "effectiveGranularity %q is not the requested day", *d.EffectiveGranularity)
	}
	page := vendorapi.Page{SourceRecords: 1}
	seen := map[int64]bool{}
	for i, b := range *d.Timeseries {
		if b.Datetime == nil || b.Value == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "timeseries[%d] misses datetime or value", i)
		}
		if b.Label != nil && *b.Label != "" {
			return vendorapi.Page{}, vendorapi.Drift(s, "timeseries[%d] carries a label (a split that was never asked for)", i)
		}
		start, ok := bucketDay(*b.Datetime)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "timeseries[%d].datetime is not a UTC day", i)
		}
		if seen[start.Unix()] {
			return vendorapi.Page{}, vendorapi.Drift(s, "timeseries[%d] repeats a day", i)
		}
		seen[start.Unix()] = true
		v, ok := whole(b.Value)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "timeseries[%d].value is not a non-negative whole count", i)
		}
		page.Facts = append(page.Facts, vendorapi.FactRow{
			IntervalStart: start, IntervalEnd: start.Add(day), SourceTZ: "UTC", CoverageDomain: Domain,
			Metric: MetricTokens, Unit: "tokens", ValueMicros: v,
		})
	}
	return page, nil
}
