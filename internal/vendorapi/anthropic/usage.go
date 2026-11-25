package anthropic

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsageMessages is the catalog id of the surface.
const SurfaceUsageMessages vs.SurfaceID = "anthropic.console.usage_messages"

// Usage report vocabulary.
const (
	UsageContract = "anthropic.console.usage_messages/v1 admin-api 2023-06-01 (2026-10-07)"

	// ReportBucketLimit is the documented maximum of daily buckets per page
	// (usage report 1d: default 7, maximum 31; cost report: 31).
	ReportBucketLimit = 31
	// ReportMaxWindow keeps one run's daily buckets (widened by settleLag
	// and rounded to whole days) inside one documented page.
	ReportMaxWindow = 28 * day
)

// UsageMessages returns the driver of anthropic.console.usage_messages.
//
// Contract (Usage and Cost API guide and the generated Admin API reference):
// GET /v1/organizations/usage_report/messages with starting_at and ending_at
// (RFC 3339), bucket_width=1d, group_by[]=model, limit and page; response
// {"data": [{"starting_at", "ending_at", "results": [...]}], "has_more",
// "next_page"}. Each result carries uncached_input_tokens,
// cache_read_input_tokens, cache_creation.ephemeral_5m_input_tokens and
// ephemeral_1h_input_tokens, output_tokens and server_tool_use
// web_search_requests. Results are grouped by model only, so one bucket has
// at most one result per model; a repeat is schema drift.
func UsageMessages() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUsageMessages,
		Build:           buildUsage,
		ParseResponse:   parseUsage,
		Auth:            adminAuth,
		Headers:         headers(),
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage},
		ContractVersion: UsageContract,
		Tool:            Tool,
		MaxWindow:       ReportMaxWindow,
		KnownPaths:      usageKnownPaths,
	}
}

func buildUsage(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	start, end, err := bucketWindow(SurfaceUsageMessages, w)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q := map[string][]string{
		"starting_at":  {start.Format(time.RFC3339)},
		"ending_at":    {end.Format(time.RFC3339)},
		"bucket_width": {"1d"},
		"group_by[]":   {"model"},
		"limit":        {strconv.Itoa(ReportBucketLimit)},
	}
	if err := pageQuery(SurfaceUsageMessages, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/usage_report/messages", Query: q}, nil
}

type usageBucket struct {
	StartingAt *string        `json:"starting_at"`
	EndingAt   *string        `json:"ending_at"`
	Results    *[]usageResult `json:"results"`
}

type usageResult struct {
	Model         *string      `json:"model"`
	Uncached      *json.Number `json:"uncached_input_tokens"`
	CacheRead     *json.Number `json:"cache_read_input_tokens"`
	Output        *json.Number `json:"output_tokens"`
	CacheCreation *struct {
		OneHour  *json.Number `json:"ephemeral_1h_input_tokens"`
		FiveMins *json.Number `json:"ephemeral_5m_input_tokens"`
	} `json:"cache_creation"`
	ServerToolUse *struct {
		WebSearch *json.Number `json:"web_search_requests"`
	} `json:"server_tool_use"`
}

// usageMetric is one row of the usage metric table: a metric name, its unit,
// whether the documented result requires it, and where it is read from.
type usageMetric struct {
	metric, unit string
	required     bool
	get          func(usageResult) *json.Number
}

var usageMetrics = []usageMetric{
	{"input_tokens_uncached", "tokens", true, func(r usageResult) *json.Number { return r.Uncached }},
	{"input_tokens_cache_read", "tokens", true, func(r usageResult) *json.Number { return r.CacheRead }},
	{"input_tokens_cache_write_5m", "tokens", true, func(r usageResult) *json.Number {
		if r.CacheCreation == nil {
			return nil
		}
		return r.CacheCreation.FiveMins
	}},
	{"input_tokens_cache_write_1h", "tokens", true, func(r usageResult) *json.Number {
		if r.CacheCreation == nil {
			return nil
		}
		return r.CacheCreation.OneHour
	}},
	{"output_tokens", "tokens", true, func(r usageResult) *json.Number { return r.Output }},
	{"web_search_requests", "requests", false, func(r usageResult) *json.Number {
		if r.ServerToolUse == nil {
			return nil
		}
		return r.ServerToolUse.WebSearch
	}},
}

func parseUsage(r vendorapi.Response) (vendorapi.Page, error) {
	var doc reportDoc[usageBucket]
	next, err := envelope(SurfaceUsageMessages, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	for i, b := range *doc.Data {
		start, end, err := bucketInterval(SurfaceUsageMessages, i, b.StartingAt, b.EndingAt)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if b.Results == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageMessages, "data[%d].results is missing", i)
		}
		seen := map[string]bool{}
		for j, res := range *b.Results {
			model := vendorapi.Str(res.Model)
			if seen[model] {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageMessages, "data[%d].results[%d] repeats a model group", i, j)
			}
			seen[model] = true
			for _, m := range usageMetrics {
				n := m.get(res)
				if n == nil {
					if m.required {
						return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageMessages, "data[%d].results[%d] misses %s", i, j, m.metric)
					}
					continue
				}
				v, ok := count(n)
				if !ok {
					return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageMessages, "data[%d].results[%d] %s is not a token count", i, j, m.metric)
				}
				page.Facts = append(page.Facts, vendorapi.FactRow{
					IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: "anthropic.console.api",
					ModelRaw: model, Metric: m.metric, Unit: m.unit, ValueMicros: v,
				})
			}
		}
	}
	return page, nil
}

// usageKnownPaths are the documented response paths (the corpus field ledger
// of the usage report).
var usageKnownPaths = []string{
	"data", "data[]", "data[].ending_at", "data[].results", "data[].results[]", "data[].results[].account_id",
	"data[].results[].api_key_id", "data[].results[].cache_creation",
	"data[].results[].cache_creation.ephemeral_1h_input_tokens",
	"data[].results[].cache_creation.ephemeral_5m_input_tokens", "data[].results[].cache_read_input_tokens",
	"data[].results[].context_window", "data[].results[].inference_geo", "data[].results[].model",
	"data[].results[].output_tokens", "data[].results[].server_tool_use",
	"data[].results[].server_tool_use.web_search_requests", "data[].results[].service_account_id",
	"data[].results[].service_tier", "data[].results[].uncached_input_tokens", "data[].results[].workspace_id",
	"data[].starting_at", "has_more", "next_page",
}
