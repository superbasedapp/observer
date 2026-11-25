package openai

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceCosts is the catalog id of the surface.
const SurfaceCosts vs.SurfaceID = "openai.platform.costs"

// Costs vocabulary.
const (
	CostsContract = "openai.platform.costs/v1 openai-python admin types (2026-10-07)"
)

// Costs returns the driver of openai.platform.costs.
//
// Contract (openai-python UsageCostsParams and the costs response): GET
// /v1/organization/costs with start_time, end_time, bucket_width=1d (the only
// width), group_by[]=line_item, limit (1 to 180; the driver asks 31) and
// page; each result carries amount {value (a number of dollars), currency}
// and the line_item it is grouped by. The fact feature is the line item; a
// repeat inside one bucket is schema drift. A currency other than USD is a
// unit change and fails the page.
func Costs() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceCosts,
		Build:           buildCosts,
		ParseResponse:   parseCosts,
		Auth:            adminAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		LegacyPoller:    LegacyOrgKey,
		ClosedDTO:       true,
		ContractVersion: CostsContract,
		Tool:            Tool,
		MaxWindow:       ReportMaxWindow,
		KnownPaths:      costsKnownPaths,
	}
}

func buildCosts(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	q, err := reportQuery(SurfaceCosts, w, cursor)
	if err != nil {
		return vendorapi.Request{}, err
	}
	q["group_by[]"] = []string{"line_item"}
	return vendorapi.Request{Method: "GET", Path: "/v1/organization/costs", Query: q}, nil
}

// costResult is the closed DTO of one costs result.
type costResult struct {
	Amount *struct {
		Value    *json.Number `json:"value"`
		Currency *string      `json:"currency"`
	} `json:"amount"`
	LineItem *string `json:"line_item"`
}

func parseCosts(r vendorapi.Response) (vendorapi.Page, error) {
	var doc bucketPage[costResult]
	next, err := envelope(SurfaceCosts, r, &doc)
	if err != nil {
		return vendorapi.Page{}, err
	}
	page := vendorapi.Page{NextCursor: next, SourceRecords: len(*doc.Data)}
	for i, b := range *doc.Data {
		start, end, err := bucketInterval(SurfaceCosts, i, b)
		if err != nil {
			return vendorapi.Page{}, err
		}
		if b.Results == nil {
			return vendorapi.Page{}, vendorapi.Drift(SurfaceCosts, "data[%d].results is missing", i)
		}
		seen := map[string]bool{}
		for j, res := range *b.Results {
			if res.Amount == nil || res.Amount.Value == nil || res.Amount.Currency == nil {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCosts, "data[%d].results[%d] misses amount.value or amount.currency", i, j)
			}
			if !strings.EqualFold(*res.Amount.Currency, "usd") {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCosts, "data[%d].results[%d] currency is not USD", i, j)
			}
			micros, ok := vendorapi.DecimalMicros(res.Amount.Value.String(), 0)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCosts, "data[%d].results[%d] amount.value is not a decimal", i, j)
			}
			line := vendorapi.Str(res.LineItem)
			if seen[line] {
				return vendorapi.Page{}, vendorapi.Drift(SurfaceCosts, "data[%d].results[%d] repeats a line item", i, j)
			}
			seen[line] = true
			page.Facts = append(page.Facts, vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: "openai.platform.api",
				Feature: line, Metric: "cost", Unit: "usd", ValueMicros: micros,
			})
		}
	}
	return page, nil
}

// costsKnownPaths are the documented response paths (the corpus field ledgers).
var costsKnownPaths = []string{
	"data", "data[]", "data[].end_time", "data[].object", "data[].results", "data[].results[]",
	"data[].results[].amount", "data[].results[].amount.currency", "data[].results[].amount.value",
	"data[].results[].line_item", "data[].results[].object", "data[].results[].project_id", "data[].start_time",
	"has_more", "next_page", "object",
}
