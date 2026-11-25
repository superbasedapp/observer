package anthropic

import (
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceCostReport is the catalog id of the surface.
const SurfaceCostReport vs.SurfaceID = "anthropic.console.cost_report"

// Cost report vocabulary.
const (
	CostContract = "anthropic.console.cost_report/v1 admin-api 2023-06-01 (2026-10-07)"
)

// CostReport returns the driver of anthropic.console.cost_report.
//
// Contract (Usage and Cost API guide: "All costs in USD, reported as decimal
// strings in lowest units (cents)", daily buckets only): GET
// /v1/organizations/cost_report with starting_at, ending_at, group_by[]=description,
// limit and page; each result carries amount (a decimal string in cents),
// currency, cost_type, token_type, model, service_tier, context_window and
// inference_geo. The fact dimension is the parsed line (cost type, token
// type, tier, context window, geography) and the model; a repeat inside one
// bucket is schema drift. A currency other than USD is a unit change and
// fails the page. Priority Tier costs are not in this report (the guide).
func CostReport() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCostReport,
		Build:           buildCost,
		ParseResponse:   parseCost,
		Auth:            adminAuth,
		Headers:         headers(),
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		ContractVersion: CostContract,
		Tool:            Tool,
		MaxWindow:       ReportMaxWindow,
		KnownPaths:      costKnownPaths,
	}
}

func buildCost(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	start, end, err := bucketWindow(SurfaceCostReport, w)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q := map[string][]string{
		"starting_at": {start.Format(time.RFC3339)},
		"ending_at":   {end.Format(time.RFC3339)},
		"group_by[]":  {"description"},
		"limit":       {strconv.Itoa(ReportBucketLimit)},
	}
	if err := pageQuery(SurfaceCostReport, q, cursor); err != nil {
		return vendorapi.Request{}, err
	}
	return vendorapi.Request{Method: "GET", Path: "/v1/organizations/cost_report", Query: q}, nil
}

type costBucket struct {
	StartingAt *string       `json:"starting_at"`
	EndingAt   *string       `json:"ending_at"`
	Results    *[]costResult `json:"results"`
}

type costResult struct {
	Amount        *string `json:"amount"`
	Currency      *string `json:"currency"`
	CostType      *string `json:"cost_type"`
	TokenType     *string `json:"token_type"`
	Model         *string `json:"model"`
	ServiceTier   *string `json:"service_tier"`
	ContextWindow *string `json:"context_window"`
	InferenceGeo  *string `json:"inference_geo"`
}

// costLine is the fact's feature dimension: the parsed line fields joined in
// a fixed order, empty fields kept as empty so positions never shift.
func costLine(r costResult) string {
	return strings.Join([]string{vendorapi.Str(r.CostType), vendorapi.Str(r.TokenType), vendorapi.Str(r.ServiceTier), vendorapi.Str(r.ContextWindow), vendorapi.Str(r.InferenceGeo)}, "|")
}

func parseCost(r vendorapi.Response) (vendorapi.Page, error) {
	var doc reportDoc[costBucket]
	next, err := envelope(SurfaceCostReport, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	for i, b := range *doc.Data {
		start, end, err := bucketInterval(SurfaceCostReport, i, b.StartingAt, b.EndingAt)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if b.Results == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceCostReport, "data[%d].results is missing", i)
		}
		seen := map[string]bool{}
		for j, res := range *b.Results {
			if res.Amount == nil || res.Currency == nil {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCostReport, "data[%d].results[%d] misses amount or currency", i, j)
			}
			if !strings.EqualFold(*res.Currency, "USD") {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCostReport, "data[%d].results[%d] currency is not USD", i, j)
			}
			micros, ok := vendorapi.DecimalMicros(*res.Amount, 2)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCostReport, "data[%d].results[%d] amount is not a decimal in cents", i, j)
			}
			model, line := vendorapi.Str(res.Model), costLine(res)
			if seen[model+"\x00"+line] {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCostReport, "data[%d].results[%d] repeats a cost line", i, j)
			}
			seen[model+"\x00"+line] = true
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: "anthropic.console.api",
				ModelRaw: model, Feature: line, Metric: "cost", Unit: "usd", ValueMicros: micros,
			})
		}
	}
	return page, nil
}

// costKnownPaths are the documented response paths (the corpus field ledger
// of the cost report).
var costKnownPaths = []string{
	"data", "data[]", "data[].ending_at", "data[].results", "data[].results[]", "data[].results[].amount",
	"data[].results[].context_window", "data[].results[].cost_type", "data[].results[].currency",
	"data[].results[].description", "data[].results[].inference_geo", "data[].results[].model",
	"data[].results[].service_tier", "data[].results[].token_type", "data[].results[].workspace_id",
	"data[].starting_at", "has_more", "next_page",
}
