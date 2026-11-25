package openrouter

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceActivity is the catalog id of the activity report.
const SurfaceActivity vs.SurfaceID = "openrouter.mgmt.activity"

// Activity vocabulary.
const (
	ActivityContract = "openrouter.mgmt.activity/v1 openapi getUserActivity (2026-10-08)"

	// Domain is the coverage domain of the account-wide activity report.
	Domain = "openrouter.account"
	// Lookback is the documented window: the last 30 completed UTC days.
	Lookback = 30 * 24 * time.Hour
)

// Tool is the reserved gateway attribution of OpenRouter activity: never a
// registry tool (vendorapi/gateway.go).
var Tool = vendorapi.GatewayTool("openrouter")

// Activity returns the driver of openrouter.mgmt.activity.
//
// Contract (OpenAPI getUserActivity): GET /api/v1/activity with no filter
// returns the last 30 completed UTC days, aggregated across workspaces, one
// row per (date, model, endpoint): {data: [{date YYYY-MM-DD, model,
// model_permaslug, endpoint_id, provider_name, usage (USD, OpenRouter credits
// spent), byok_usage_inference (USD), requests, prompt_tokens,
// completion_tokens, reasoning_tokens, cached_tokens}]}. The report is one
// unpaged document; every run restates the whole 30 days (the fact key keeps
// the restatement idempotent). The date, api_key_hash, user_id, group_by and
// workspace_id filters are never sent.
//
// Each row lands org-level facts (no member: the default report is not per
// user) for the reserved gateway attribution, keyed by the model slug
// (ModelRaw) and the endpoint id (Feature): cost and byok_cost in usd,
// requests, and the four token counts. cached_tokens can exceed prompt_tokens
// (documented), so the two are never subtracted or added.
func Activity() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceActivity,
		Build:           buildActivity,
		ParseResponse:   parseActivity,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: ActivityContract,
		Tool:            Tool,
		MaxLookback:     Lookback,
		KnownPaths: []string{
			"data", "data[]", "data[].byok_usage_inference", "data[].cached_tokens", "data[].completion_tokens",
			"data[].date", "data[].endpoint_id", "data[].model", "data[].model_permaslug", "data[].prompt_tokens",
			"data[].provider_name", "data[].reasoning_tokens", "data[].requests", "data[].usage",
		},
	}
}

func buildActivity(_ vendorapi.Params, _ vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, vendorapi.Drift(SurfaceActivity, "the report is not paged")
	}
	return vendorapi.Request{Method: "GET", Path: "/api/v1/activity"}, nil
}

type activityDoc struct {
	Data *[]struct {
		Date       *string  `json:"date"`
		Model      *string  `json:"model"`
		Permaslug  *string  `json:"model_permaslug"`
		EndpointID *string  `json:"endpoint_id"`
		Provider   *string  `json:"provider_name"`
		Usage      *decimal `json:"usage"`
		BYOKUsage  *decimal `json:"byok_usage_inference"`
		Requests   *count   `json:"requests"`
		Prompt     *count   `json:"prompt_tokens"`
		Completion *count   `json:"completion_tokens"`
		Reasoning  *count   `json:"reasoning_tokens"`
		CachedRead *count   `json:"cached_tokens"`
	} `json:"data"`
}

// decimal is a bare JSON number kept as its literal text; a quoted value is a
// type change and fails the page (plan 12A.5).
type decimal string

// UnmarshalJSON accepts a bare JSON number only.
func (d *decimal) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("openrouter: %.16q is not a JSON number", b)
	}
	*d = decimal(b)
	return nil
}

// dollars converts a documented USD double to micro-dollars; a negative,
// exponent-form or unrepresentable value is refused.
func dollars(n *decimal) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, ok := vendorapi.DecimalMicros(string(*n), 0)
	return v, ok && v >= 0
}

func counted(c *count) (int64, bool) {
	if c == nil {
		return 0, false
	}
	return vendorapi.CountMicros(int64(*c))
}

func parseActivity(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceActivity
	var doc activityDoc
	if err := decode(r, s, &doc); err != nil {
		return vendorapi.Page{}, err
	}
	if doc.Data == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field data is missing")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.Data)}
	seen := map[string]bool{}
	for i, row := range *doc.Data {
		model, endpoint := vendorapi.TrimStr(row.Model), vendorapi.TrimStr(row.EndpointID)
		if row.Date == nil || model == "" || endpoint == "" || row.Permaslug == nil || row.Provider == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] misses date, model, model_permaslug, endpoint_id or provider_name", i)
		}
		day, err := time.Parse("2006-01-02", *row.Date)
		if err != nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].date is not YYYY-MM-DD", i)
		}
		key := *row.Date + "|" + model + "|" + endpoint
		if seen[key] {
			return vendorapi.Page{}, vendorapi.Drift(s, "data[%d] repeats a date, model and endpoint", i)
		}
		seen[key] = true
		type metric struct {
			name, unit string
			v          int64
			ok         bool
		}
		cost, okc := dollars(row.Usage)
		byok, okb := dollars(row.BYOKUsage)
		req, okr := counted(row.Requests)
		pt, okp := counted(row.Prompt)
		ct, okt := counted(row.Completion)
		rt, okrt := counted(row.Reasoning)
		cr, okcr := counted(row.CachedRead)
		for _, m := range []metric{
			{"cost", "usd", cost, okc},
			{"byok_cost", "usd", byok, okb},
			{"requests", "requests", req, okr},
			{"input_tokens", "tokens", pt, okp},
			{"output_tokens", "tokens", ct, okt},
			{"reasoning_tokens", "tokens", rt, okrt},
			{"cache_read_tokens", "tokens", cr, okcr},
		} {
			if !m.ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "data[%d].%s is missing, negative or not a documented number", i, m.name)
			}
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: day, IntervalEnd: day.Add(24 * time.Hour), SourceTZ: "UTC", CoverageDomain: Domain,
				ModelRaw: model, Feature: strings.ToLower(endpoint), Metric: m.name, Unit: m.unit, ValueMicros: m.v,
			})
		}
	}
	return page, nil
}
