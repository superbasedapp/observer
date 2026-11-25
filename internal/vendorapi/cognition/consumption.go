package cognition

import (
	"fmt"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceConsumptionDaily is the catalog id of the surface.
const SurfaceConsumptionDaily vs.SurfaceID = "cognition.devin_v3.consumption_daily"

// Consumption vocabulary.
const (
	ConsumptionContract = "cognition.devin_v3.consumption_daily/v1 v3-openapi 3.0.0 (2026-10-08)"

	// BillingDayOffset is the documented day boundary of Devin consumption:
	// midnight PST, 08:00 UTC.
	BillingDayOffset = 8 * time.Hour
	// ConsumptionMaxWindow caps one run. The reference states no range limit;
	// a month of days keeps one response small.
	ConsumptionMaxWindow = 31 * day
	// consumptionSettle re-reads the previous billing day on every run, so a
	// day read while still open is restated once it closes.
	consumptionSettle = day

	// MetricACUs is the per-product ACU fact (Feature names the product);
	// MetricACUsTotal is the day's total. The product facts sum to the total
	// (documented), so they are never added to it.
	MetricACUs      = "acus"
	MetricACUsTotal = "acus_total"
	// UnitACU is Devin's billing unit, the Agent Compute Unit. Never converted
	// to money here.
	UnitACU = "acu"
	// ConsumptionDomain is the coverage domain of the enterprise-wide report.
	ConsumptionDomain = "cognition.enterprise"
	// BillingTZ names the billing day's zone.
	BillingTZ = "UTC-08:00"
)

// ConsumptionDaily returns the driver of cognition.devin_v3.consumption_daily.
//
// Contract (v3 OpenAPI, "Get Enterprise Daily Consumption"): GET
// /v3/enterprise/consumption/daily with time_after and time_before (Unix
// seconds, both optional), no paging; response ConsumptionResponse
// {total_acus, consumption_by_date: [{date, acus, acus_by_product: {devin,
// cascade, terminal, review|null, automation|null}}]}. Enterprise plan only
// (403 otherwise); permission ViewAccountConsumption.
func ConsumptionDaily() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceConsumptionDaily,
		Build:           buildConsumption,
		ParseResponse:   parseConsumption,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassCost},
		ContractVersion: ConsumptionContract,
		Tool:            Tool,
		MaxWindow:       ConsumptionMaxWindow,
		KnownPaths:      consumptionKnownPaths,
	}
}

// billingDayStart returns the start of the billing day holding t.
func billingDayStart(t time.Time) time.Time {
	return t.UTC().Add(-BillingDayOffset).Truncate(day).Add(BillingDayOffset)
}

func buildConsumption(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", SurfaceConsumptionDaily)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", SurfaceConsumptionDaily)
	}
	if w.To.Sub(w.From) > ConsumptionMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", SurfaceConsumptionDaily, ConsumptionMaxWindow)
	}
	start := billingDayStart(w.From.Add(-consumptionSettle))
	q := map[string][]string{
		"time_after":  {strconv.FormatInt(start.Unix(), 10)},
		"time_before": {strconv.FormatInt(w.To.UTC().Unix(), 10)},
	}
	return vendorapi.Request{Method: "GET", Path: "/v3/enterprise/consumption/daily", Query: q}, nil
}

type consumptionDoc struct {
	TotalACUs *num              `json:"total_acus"`
	ByDate    *[]consumptionDay `json:"consumption_by_date"`
}

type consumptionDay struct {
	Date      *num `json:"date"`
	ACUs      *num `json:"acus"`
	ByProduct *struct {
		Devin      *num `json:"devin"`
		Cascade    *num `json:"cascade"`
		Terminal   *num `json:"terminal"`
		Review     *num `json:"review"`
		Automation *num `json:"automation"`
	} `json:"acus_by_product"`
}

// product is one row of the product table: the documented bucket, whether
// the schema requires it (review and automation are nullable: null means the
// breakdown is not available, never zero), and its reader.
type product struct {
	name     string
	required bool
	get      func(consumptionDay) *num
}

var products = []product{
	{"devin", true, func(d consumptionDay) *num { return d.ByProduct.Devin }},
	{"cascade", true, func(d consumptionDay) *num { return d.ByProduct.Cascade }},
	{"terminal", true, func(d consumptionDay) *num { return d.ByProduct.Terminal }},
	{"review", false, func(d consumptionDay) *num { return d.ByProduct.Review }},
	{"automation", false, func(d consumptionDay) *num { return d.ByProduct.Automation }},
}

func parseConsumption(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceConsumptionDaily
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var doc consumptionDoc
	if err := vendorapi.DecodeNumbers(r.Body, &doc); err != nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body does not decode as the documented ConsumptionResponse")
	}
	if doc.ByDate == nil || doc.TotalACUs == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "required field consumption_by_date or total_acus is missing")
	}
	if _, ok := acuMicros(doc.TotalACUs); !ok {
		return vendorapi.Page{}, vendorapi.Drift(s, "total_acus is not a non-negative amount")
	}
	page := vendorapi.Page{SourceRecords: len(*doc.ByDate)}
	seen := map[int64]bool{}
	for i, d := range *doc.ByDate {
		start, ok := unixSeconds(d.Date)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d].date is not a Unix time", i)
		}
		if seen[start.Unix()] {
			return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d] repeats a day", i)
		}
		seen[start.Unix()] = true
		total, ok := acuMicros(d.ACUs)
		if !ok {
			return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d].acus is not a non-negative amount", i)
		}
		if d.ByProduct == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d].acus_by_product is missing", i)
		}
		fact := func(metric, feature string, v int64) vendorapi.FactRow {
			return vendorapi.FactRow{
				IntervalStart: start, IntervalEnd: start.Add(day), SourceTZ: BillingTZ, CoverageDomain: ConsumptionDomain,
				Feature: feature, Metric: metric, Unit: UnitACU, ValueMicros: v,
			}
		}
		page.Facts = append(page.Facts, fact(MetricACUsTotal, "", total))
		for _, p := range products {
			n := p.get(d)
			if n == nil {
				if p.required {
					return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d].acus_by_product.%s is missing", i, p.name)
				}
				continue
			}
			v, ok := acuMicros(n)
			if !ok {
				return vendorapi.Page{}, vendorapi.Drift(s, "consumption_by_date[%d].acus_by_product.%s is not a non-negative amount", i, p.name)
			}
			page.Facts = append(page.Facts, fact(MetricACUs, p.name, v))
		}
	}
	return page, nil
}

// consumptionKnownPaths are the documented response paths (the corpus field
// ledger of the consumption report).
var consumptionKnownPaths = []string{
	"consumption_by_date", "consumption_by_date[]", "consumption_by_date[].acus",
	"consumption_by_date[].acus_by_product", "consumption_by_date[].acus_by_product.automation",
	"consumption_by_date[].acus_by_product.cascade", "consumption_by_date[].acus_by_product.devin",
	"consumption_by_date[].acus_by_product.review", "consumption_by_date[].acus_by_product.terminal",
	"consumption_by_date[].date", "total_acus",
}
