package factory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceTokens is the catalog id of the surface.
const SurfaceTokens vs.SurfaceID = "factory.analytics.tokens"

// Tokens vocabulary.
const (
	TokensContract = "factory.analytics.tokens/v1 analytics-api (2026-10-08)"

	// Tool is the registry tool the Factory surfaces report on.
	Tool = "droid"
	// TokensMaxWindow caps one run. The reference states no range limit for
	// /tokens (90 days is documented only for /cost/me/query).
	TokensMaxWindow = 31 * day
	// TokensMaxLookback is how far back the reference serves data ("Available
	// from January 14, 2026"); the runner default of 90 days is inside it.
	TokensMaxLookback = 90 * day
	day               = 24 * time.Hour

	// MetricStandardCredits is billable_tokens: Factory Standard Credits, a
	// billing unit computed from tokens with cache discounts (documented), not
	// a token count.
	MetricStandardCredits = "standard_credits"
	// UnitCredits is the Factory Standard Credit.
	UnitCredits = "credits"
	// TokensDomain is the coverage domain of the organization-wide report.
	TokensDomain = "factory.organization"
)

var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// Tokens returns the driver of factory.analytics.tokens.
//
// Contract (Factory Analytics API, "Factory Standard Credits usage"): GET
// /api/v1/analytics/tokens with startDate and endDate (YYYY-MM-DD, UTC, both
// required) and group_by=model; response {"data": [...], "meta": {org_id,
// start_date, end_date}}, each row {date, group_key, billable_tokens,
// input_tokens, output_tokens, cache_read_tokens|null,
// cache_write_tokens|null}. Data is available through yesterday (UTC):
// asking for today is a 400, so the request ends at yesterday. Manager or
// Owner role.
func Tokens() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceTokens,
		Build:           buildTokens,
		ParseResponse:   parseTokens,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost},
		ContractVersion: TokensContract,
		Tool:            Tool,
		MaxWindow:       TokensMaxWindow,
		MaxLookback:     TokensMaxLookback,
		KnownPaths:      tokensKnownPaths,
	}
}

const dateLayout = "2006-01-02"

func buildTokens(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceTokens)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceTokens)
	}
	if w.To.Sub(w.From) > TokensMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", SurfaceTokens, TokensMaxWindow)
	}
	// The last complete UTC day is the one before the window end's day; the
	// first day re-reads the previous one so a late day is restated.
	end := w.To.UTC().Truncate(day).Add(-day)
	start := w.From.UTC().Truncate(day).Add(-day)
	if start.After(end) {
		start = end
	}
	q := map[string][]string{
		"startDate": {start.Format(dateLayout)},
		"endDate":   {end.Format(dateLayout)},
		"group_by":  {"model"},
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/analytics/tokens", Query: q}, nil
}

type tokensDoc struct {
	Data *[]tokensRow `json:"data"`
}

type tokensRow struct {
	Date       *string `json:"date"`
	GroupKey   *string `json:"group_key"`
	Billable   *num    `json:"billable_tokens"`
	Input      *num    `json:"input_tokens"`
	Output     *num    `json:"output_tokens"`
	CacheRead  *num    `json:"cache_read_tokens"`
	CacheWrite *num    `json:"cache_write_tokens"`
}

// num is a JSON number kept as its literal text. Unlike json.Number it
// refuses a quoted value: a count the vendor starts sending as a string is a
// type change, so the page fails as schema drift (plan 12A.5). A JSON null
// leaves a *num nil (a not-reported cache count).
type num string

// UnmarshalJSON accepts a bare JSON number only.
func (n *num) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("factory: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// tokensMetric is one row of the metric table: the fact metric and unit,
// whether the documented row requires it (the cache counts are "always
// present; null when not reported", and null never lands as zero), and its
// reader.
type tokensMetric struct {
	metric, unit string
	required     bool
	get          func(tokensRow) *num
}

var tokensMetrics = []tokensMetric{
	{MetricStandardCredits, UnitCredits, true, func(r tokensRow) *num { return r.Billable }},
	{"input_tokens", "tokens", true, func(r tokensRow) *num { return r.Input }},
	{"output_tokens", "tokens", true, func(r tokensRow) *num { return r.Output }},
	{"cache_read_tokens", "tokens", false, func(r tokensRow) *num { return r.CacheRead }},
	{"cache_write_tokens", "tokens", false, func(r tokensRow) *num { return r.CacheWrite }},
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceTokens, format, a...)
}

func parseTokens(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not the documented 200", r.Status)
	}
	var doc tokensDoc
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
	for i, row := range *doc.Data {
		if row.Date == nil {
			return vendorapi.Page{}, drift("data[%d].date is missing", i)
		}
		d, err := time.Parse(dateLayout, *row.Date)
		if err != nil {
			return vendorapi.Page{}, drift("data[%d].date is not YYYY-MM-DD", i)
		}
		if row.GroupKey == nil || *row.GroupKey == "" {
			return vendorapi.Page{}, drift("data[%d].group_key is missing (the request groups by model)", i)
		}
		key := *row.Date + "|" + *row.GroupKey
		if seen[key] {
			return vendorapi.Page{}, drift("data[%d] repeats a day and model", i)
		}
		seen[key] = true
		for _, m := range tokensMetrics {
			n := m.get(row)
			if n == nil {
				if m.required {
					return vendorapi.Page{}, drift("data[%d] misses %s", i, m.metric)
				}
				continue
			}
			v, ok := vendorapi.DecimalMicros(string(*n), 0)
			if !ok || v < 0 {
				return vendorapi.Page{}, drift("data[%d].%s is not a non-negative number", i, m.metric)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: d, IntervalEnd: d.Add(day), SourceTZ: "UTC", CoverageDomain: TokensDomain,
				ModelRaw: *row.GroupKey, Metric: m.metric, Unit: m.unit, ValueMicros: v,
			})
		}
	}
	return page, nil
}

// tokensKnownPaths are the documented response paths (the corpus field
// ledger of /tokens).
var tokensKnownPaths = []string{
	"data", "data[]", "data[].billable_tokens", "data[].cache_read_tokens", "data[].cache_write_tokens",
	"data[].date", "data[].group_key", "data[].input_tokens", "data[].output_tokens", "meta", "meta.end_date",
	"meta.org_id", "meta.start_date",
}
