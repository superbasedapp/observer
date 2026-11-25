package poolside

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceLiteLLM is the catalog id of the customer-deployed LiteLLM gateway
// in front of Poolside model inference.
const SurfaceLiteLLM vs.SurfaceID = "poolside.gateway.litellm"

// LiteLLM daily activity vocabulary.
const (
	LiteLLMContract = "poolside.gateway.litellm/v1 litellm /user/daily/activity SpendAnalyticsPaginatedResponse (2026-10-08)"

	// Domain is the coverage domain of one gateway's daily spend table.
	Domain = "litellm.gateway"
	// LiteLLMWindow caps one run: the request asks for one page of at most
	// PageSize daily spend rows, and a window that needs more is refused, so
	// a run covers one UTC day (two dates when the window crosses midnight).
	LiteLLMWindow = 24 * time.Hour
	// PageSize is the documented page size maximum (le=1000).
	PageSize = 1000
)

// Tool is the reserved gateway attribution of LiteLLM activity: never a
// registry tool (vendorapi/gateway.go). Poolside's client, a script or any
// other OpenAI-compatible client may have sent the traffic.
var Tool = vendorapi.GatewayTool("litellm")

// bearerAuth is LiteLLM's documented key contract: a master key or a virtual
// key as "Authorization: Bearer <key>". The global view needs an admin role
// (proxy_admin, or the read-only proxy_admin_viewer the catalog recommends).
var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// LiteLLM returns the driver of poolside.gateway.litellm.
//
// Contract (LiteLLM proxy, "Daily Spend Breakdown API", and the endpoint's
// source, get_user_daily_activity): GET /user/daily/activity with start_date
// and end_date (YYYY-MM-DD, required), page and page_size (1..1000). With an
// admin key and no user_id the answer is the gateway-wide view. The body is
// SpendAnalyticsPaginatedResponse: results, one per date, each with the day's
// metrics and a breakdown by model (breakdown.models[<model>].metrics), and a
// metadata object with page, total_pages and has_more. The user_id, api_key,
// model, timezone and include_current_utc_day parameters are never sent, so
// dates are UTC.
//
// Paging is over the gateway's underlying daily spend rows, NOT over dates:
// one date's model totals can be split across two pages. So the driver asks
// for exactly one page of the documented maximum size and refuses an answer
// that says more pages exist (has_more, or total_pages above one) as schema
// drift: landing a partial day as if it were whole would understate it.
//
// Each (date, model) lands org-level facts (no member: the gateway-wide view
// is not per user) under the reserved gateway attribution, keyed by the model
// (ModelRaw): cost in usd (the documented float, converted to micro-dollars),
// input_tokens, output_tokens and requests (in the documented example), and
// cache_read_tokens, cache_write_tokens, successful_requests and
// failed_requests when the response carries them (the source model's
// defaults; absent is not landed, never zero). Requests the gateway logged
// without a model are in the day totals only and are not landed. The api_keys
// breakdown (hashed keys with their alias, team, user and email), the
// providers, model groups, MCP servers, endpoints and entities are never
// decoded.
func LiteLLM() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceLiteLLM,
		Build:           buildLiteLLM,
		ParseResponse:   parseLiteLLM,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassUsage, vs.ClassCost},
		ClosedDTO:       true,
		ContractVersion: LiteLLMContract,
		Tool:            Tool,
		MaxWindow:       LiteLLMWindow,
		KnownPaths:      litellmKnownPaths,
	}
}

// litellmKnownPaths are the documented member paths of the fixture ledger,
// for the two model keys the fixture names.
var litellmKnownPaths = func() []string {
	p := []string{
		"metadata", "metadata.has_more", "metadata.page", "metadata.total_api_requests",
		"metadata.total_completion_tokens", "metadata.total_pages", "metadata.total_prompt_tokens",
		"metadata.total_spend", "results", "results[]", "results[].breakdown", "results[].breakdown.models",
		"results[].date", "results[].metrics", "results[].metrics.api_requests",
		"results[].metrics.completion_tokens", "results[].metrics.prompt_tokens", "results[].metrics.spend",
		"results[].metrics.total_tokens",
	}
	for _, m := range []string{"laguna", "laguna-xs"} {
		base := "results[].breakdown.models." + m
		p = append(p, base, base+".metrics")
		for _, f := range []string{
			"api_requests", "cache_creation_input_tokens", "cache_read_input_tokens", "completion_tokens",
			"failed_requests", "prompt_tokens", "spend", "successful_requests", "total_tokens",
		} {
			p = append(p, base+".metrics."+f)
		}
	}
	sort.Strings(p)
	return p
}()

const dateLayout = "2006-01-02"

func buildLiteLLM(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceLiteLLM
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: one page per run; a cursor is never followed", s)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > LiteLLMWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, LiteLLMWindow)
	}
	start := w.From.UTC().Format(dateLayout)
	end := w.To.Add(-time.Nanosecond).UTC().Format(dateLayout)
	q := map[string][]string{
		"start_date": {start}, "end_date": {end},
		"page": {"1"}, "page_size": {strconv.Itoa(PageSize)},
	}
	return vendorapi.Request{Method: "GET", Path: "/user/daily/activity", Query: q}, nil
}

// number is a bare JSON number kept as its literal text; a quoted value is a
// type change and fails the page (plan 12A.5).
type number string

// UnmarshalJSON accepts a bare JSON number only.
func (n *number) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("poolside: %.16q is not a JSON number", b)
	}
	*n = number(b)
	return nil
}

// counted converts a whole, non-negative count to micro-units; a fraction,
// an exponent or a negative value is refused.
func counted(n *number) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return vendorapi.CountMicros(v)
}

// dollars converts the documented float spend to micro-dollars; negative is
// refused.
func dollars(n *number) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, ok := vendorapi.FloatMicros(string(*n))
	return v, ok && v >= 0
}

// spendMetrics is the closed subset of the source model SpendMetrics the
// driver reads.
type spendMetrics struct {
	Spend      *number `json:"spend"`
	Prompt     *number `json:"prompt_tokens"`
	Completion *number `json:"completion_tokens"`
	CacheRead  *number `json:"cache_read_input_tokens"`
	CacheWrite *number `json:"cache_creation_input_tokens"`
	Requests   *number `json:"api_requests"`
	Successful *number `json:"successful_requests"`
	Failed     *number `json:"failed_requests"`
}

type dailyDoc struct {
	Results *[]struct {
		Date      *string `json:"date"`
		Breakdown *struct {
			Models *map[string]struct {
				Metrics *spendMetrics `json:"metrics"`
			} `json:"models"`
		} `json:"breakdown"`
	} `json:"results"`
	Metadata *struct {
		Page       *number `json:"page"`
		TotalPages *number `json:"total_pages"`
		HasMore    *bool   `json:"has_more"`
	} `json:"metadata"`
}

func drift(format string, a ...any) error {
	return vendorapi.Drift(SurfaceLiteLLM, format, a...)
}

func parseLiteLLM(r vendorapi.Response) (vendorapi.Page, error) {
	if r.Status != 200 {
		return vendorapi.Page{}, drift("status %d is not 200", r.Status)
	}
	var doc dailyDoc
	if err := json.NewDecoder(bytes.NewReader(r.Body)).Decode(&doc); err != nil {
		return vendorapi.Page{}, drift("body does not decode: a member has an undocumented type")
	}
	if doc.Results == nil || doc.Metadata == nil || doc.Metadata.HasMore == nil || doc.Metadata.Page == nil || doc.Metadata.TotalPages == nil {
		return vendorapi.Page{}, drift("required results, metadata.page, metadata.total_pages or metadata.has_more is missing")
	}
	page, okp := counted(doc.Metadata.Page)
	pages, okt := counted(doc.Metadata.TotalPages)
	if !okp || !okt || page != 1_000_000 {
		return vendorapi.Page{}, drift("metadata.page is not 1 or total_pages is not a count")
	}
	if *doc.Metadata.HasMore || pages > 1_000_000 {
		return vendorapi.Page{}, drift("the window holds more than %d daily spend rows: a split day would land partial, so the page is refused", PageSize)
	}
	out := vendorapi.Page{SourceRecords: len(*doc.Results)}
	seen := map[string]bool{}
	for i, res := range *doc.Results {
		if res.Date == nil || res.Breakdown == nil || res.Breakdown.Models == nil {
			return vendorapi.Page{}, drift("results[%d] misses date, breakdown or breakdown.models", i)
		}
		day, err := time.Parse(dateLayout, *res.Date)
		if err != nil {
			return vendorapi.Page{}, drift("results[%d].date is not YYYY-MM-DD", i)
		}
		if seen[*res.Date] {
			return vendorapi.Page{}, drift("results[%d] repeats a date", i)
		}
		seen[*res.Date] = true
		models := make([]string, 0, len(*res.Breakdown.Models))
		for m := range *res.Breakdown.Models {
			models = append(models, m)
		}
		sort.Strings(models)
		for _, model := range models {
			if model == "" || len(model) > 256 {
				return vendorapi.Page{}, drift("results[%d] names an empty or oversized model key", i)
			}
			mm := (*res.Breakdown.Models)[model].Metrics
			if mm == nil {
				return vendorapi.Page{}, drift("results[%d].breakdown.models[%q] misses metrics", i, model)
			}
			type metric struct {
				name, unit string
				n          *number
				conv       func(*number) (int64, bool)
				required   bool
			}
			for _, m := range []metric{
				{"cost", "usd", mm.Spend, dollars, true},
				{"input_tokens", "tokens", mm.Prompt, counted, true},
				{"output_tokens", "tokens", mm.Completion, counted, true},
				{"requests", "requests", mm.Requests, counted, true},
				{"cache_read_tokens", "tokens", mm.CacheRead, counted, false},
				{"cache_write_tokens", "tokens", mm.CacheWrite, counted, false},
				{"successful_requests", "requests", mm.Successful, counted, false},
				{"failed_requests", "requests", mm.Failed, counted, false},
			} {
				if m.n == nil && !m.required {
					continue
				}
				v, ok := m.conv(m.n)
				if !ok {
					return vendorapi.Page{}, drift("results[%d].breakdown.models[%q].metrics.%s is missing, negative or not a documented number", i, model, m.name)
				}
				out.Facts = append(out.Facts, vendorapi.FactRow{
					IntervalStart: day, IntervalEnd: day.Add(24 * time.Hour), SourceTZ: "UTC", CoverageDomain: Domain,
					ModelRaw: model, Metric: m.name, Unit: m.unit, ValueMicros: v,
				})
			}
		}
	}
	return out, nil
}
