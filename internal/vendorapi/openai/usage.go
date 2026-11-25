package openai

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceUsageCompletions is the catalog id of the surface.
const SurfaceUsageCompletions vs.SurfaceID = "openai.platform.usage_completions"

// Usage vocabulary.
const (
	UsageContract = "openai.platform.usage_completions/v1 openai-python admin types (2026-10-07)"
)

// UsageCompletions returns the driver of openai.platform.usage_completions.
//
// Contract (openai-python UsageCompletionsParams and UsageCompletionsResponse):
// GET /v1/organization/usage/completions with start_time (Unix seconds,
// inclusive, required), end_time (exclusive), bucket_width=1d, limit (at most
// 31 for 1d), group_by[]=model and page; response {"object": "page", "data":
// [{"object": "bucket", "start_time", "end_time", "results": [...]}],
// "has_more", "next_page"}. A result requires input_tokens, output_tokens and
// num_model_requests; the cached, uncached, cache-write and audio counts are
// optional and land only when present. Grouped by model only, a bucket has
// at most one result per model; a repeat is schema drift.
func UsageCompletions() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceUsageCompletions,
		Build:           buildUsage,
		ParseResponse:   parseUsage,
		Auth:            adminAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage},
		LegacyPoller:    LegacyOrgKey,
		ClosedDTO:       true,
		ContractVersion: UsageContract,
		Tool:            Tool,
		MaxWindow:       ReportMaxWindow,
		KnownPaths:      usageKnownPaths,
	}
}

func buildUsage(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q, err := reportQuery(SurfaceUsageCompletions, w, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q["group_by[]"] = []string{"model"}
	return vendorapi.Request{Method: "GET", Path: "/v1/organization/usage/completions", Query: q}, nil
}

// usageResult is the closed DTO of one completions result.
type usageResult struct {
	Model            *string      `json:"model"`
	Input            *json.Number `json:"input_tokens"`
	Output           *json.Number `json:"output_tokens"`
	Requests         *json.Number `json:"num_model_requests"`
	InputCached      *json.Number `json:"input_cached_tokens"`
	InputUncached    *json.Number `json:"input_uncached_tokens"`
	InputCacheWrite  *json.Number `json:"input_cache_write_tokens"`
	InputCacheWrite2 *json.Number `json:"input_cache_write_12h_tokens"`
	InputAudio       *json.Number `json:"input_audio_tokens"`
	OutputAudio      *json.Number `json:"output_audio_tokens"`
}

type usageMetric struct {
	metric, unit string
	required     bool
	get          func(usageResult) *json.Number
}

// usageMetrics is the metric table of one result, walked in order.
var usageMetrics = []usageMetric{
	{"input_tokens", "tokens", true, func(r usageResult) *json.Number { return r.Input }},
	{"output_tokens", "tokens", true, func(r usageResult) *json.Number { return r.Output }},
	{"model_requests", "requests", true, func(r usageResult) *json.Number { return r.Requests }},
	{"input_tokens_cached", "tokens", false, func(r usageResult) *json.Number { return r.InputCached }},
	{"input_tokens_uncached", "tokens", false, func(r usageResult) *json.Number { return r.InputUncached }},
	{"input_tokens_cache_write_30m", "tokens", false, func(r usageResult) *json.Number { return r.InputCacheWrite }},
	{"input_tokens_cache_write_12h", "tokens", false, func(r usageResult) *json.Number { return r.InputCacheWrite2 }},
	{"input_audio_tokens", "tokens", false, func(r usageResult) *json.Number { return r.InputAudio }},
	{"output_audio_tokens", "tokens", false, func(r usageResult) *json.Number { return r.OutputAudio }},
}

func parseUsage(r vendorapi.Response) (vendorapi.Page, error) {
	var doc bucketPage[usageResult]
	next, err := envelope(SurfaceUsageCompletions, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	for i, b := range *doc.Data {
		start, end, err := bucketInterval(SurfaceUsageCompletions, i, b)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if b.Results == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageCompletions, "data[%d].results is missing", i)
		}
		seen := map[string]bool{}
		for j, res := range *b.Results {
			model := vendorapi.Str(res.Model)
			if seen[model] {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageCompletions, "data[%d].results[%d] repeats a model group", i, j)
			}
			seen[model] = true
			for _, m := range usageMetrics {
				n := m.get(res)
				if n == nil {
					if m.required {
						return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageCompletions, "data[%d].results[%d] misses %s", i, j, m.metric)
					}
					continue
				}
				v, ok := count(n)
				if !ok {
					return vendorapi.Page{}, vendorapi.Drift(SurfaceUsageCompletions, "data[%d].results[%d] %s is not a count", i, j, m.metric)
				}
				page.Facts = append(page.Facts, vendorapi.FactRow{
					IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: "openai.platform.api",
					ModelRaw: model, Metric: m.metric, Unit: m.unit, ValueMicros: v,
				})
			}
		}
	}
	return page, nil
}

// usageKnownPaths are the documented response paths (the corpus field ledgers).
var usageKnownPaths = []string{
	"data", "data[]", "data[].end_time", "data[].object", "data[].results", "data[].results[]",
	"data[].results[].api_key_id", "data[].results[].batch", "data[].results[].input_audio_tokens",
	"data[].results[].input_cache_write_tokens", "data[].results[].input_cached_tokens",
	"data[].results[].input_tokens", "data[].results[].input_uncached_tokens", "data[].results[].model",
	"data[].results[].num_model_requests", "data[].results[].object", "data[].results[].output_audio_tokens",
	"data[].results[].output_tokens", "data[].results[].project_id", "data[].results[].service_tier",
	"data[].results[].user_id", "data[].start_time", "has_more", "next_page", "object",
}
