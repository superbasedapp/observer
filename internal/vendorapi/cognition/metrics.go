package cognition

import (
	"fmt"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// SurfaceMetricsActive is the catalog id of the active-user metrics surface.
const SurfaceMetricsActive vs.SurfaceID = "cognition.devin_v3.metrics_active"

// Active-user metrics vocabulary.
const (
	MetricsContract = "cognition.devin_v3.metrics_active/v1 dau v3-openapi 3.0.0 (2026-10-08)"

	// MetricDailyActiveUsers is the count of users active on one UTC day: at
	// least min_sessions sessions or min_searches searches (both left at
	// their documented default, 1). A distinct-user count, so days are never
	// summed into a longer period.
	MetricDailyActiveUsers = "daily_active_users"
	// UnitUsers counts distinct users.
	UnitUsers = "users"
	// MetricsMaxWindow caps one run. The reference states no range limit.
	MetricsMaxWindow = 31 * day
)

// MetricsActive returns the driver of cognition.devin_v3.metrics_active (the
// daily active users read; the weekly, monthly and custom-range reads of the
// same row are not built).
//
// Contract (v3 OpenAPI, "Get daily active users"): GET
// /v3/enterprise/metrics/dau with time_after and time_before (integers, both
// required); response ActiveUserMetricsListResponse, an array of
// {start_time, end_time, active_users} in ascending order with no
// overlapping periods, one entry per UTC day.
func MetricsActive() vendorapi.Driver {
	return vendorapi.Driver{
		Surface:         SurfaceMetricsActive,
		Build:           buildMetricsActive,
		ParseResponse:   parseMetricsActive,
		Auth:            bearerAuth,
		ContentTypes:    []string{"application/json"},
		Supplies:        []vs.DataClass{vs.ClassAdoption},
		ContractVersion: MetricsContract,
		Tool:            Tool,
		MaxWindow:       MetricsMaxWindow,
		KnownPaths:      []string{"[]", "[].active_users", "[].end_time", "[].start_time"},
	}
}

func buildMetricsActive(_ vendorapi.Params, w vendorapi.Window, cursor string) (vendorapi.Request, error) {
	s := SurfaceMetricsActive
	if cursor != "" {
		return vendorapi.Request{}, fmt.Errorf("%s: the surface is not paged", s)
	}
	if w.From.IsZero() || !w.To.After(w.From) {
		return vendorapi.Request{}, fmt.Errorf("%s: a non-empty window is required", s)
	}
	if w.To.Sub(w.From) > MetricsMaxWindow {
		return vendorapi.Request{}, fmt.Errorf("%s: window longer than %s", s, MetricsMaxWindow)
	}
	// Start at the UTC day before the window so a day read while open is
	// restated once it closes.
	start := w.From.UTC().Truncate(day).Add(-day)
	q := map[string][]string{
		"time_after":  {strconv.FormatInt(start.Unix(), 10)},
		"time_before": {strconv.FormatInt(w.To.UTC().Unix(), 10)},
	}
	return vendorapi.Request{Method: "GET", Path: "/v3/enterprise/metrics/dau", Query: q}, nil
}

type activeUsers struct {
	Start  *num `json:"start_time"`
	End    *num `json:"end_time"`
	Active *num `json:"active_users"`
}

func parseMetricsActive(r vendorapi.Response) (vendorapi.Page, error) {
	s := SurfaceMetricsActive
	if r.Status != 200 {
		return vendorapi.Page{}, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var rows []activeUsers
	if err := vendorapi.DecodeNumbers(r.Body, &rows); err != nil || rows == nil {
		return vendorapi.Page{}, vendorapi.Drift(s, "body is not the documented array of active-user entries")
	}
	page := vendorapi.Page{}
	var prevEnd int64 = -1
	for i, e := range rows {
		start, ok1 := unixSeconds(e.Start)
		end, ok2 := unixSeconds(e.End)
		if !ok1 || !ok2 || !end.After(start) || end.Sub(start) > day {
			return vendorapi.Page{}, vendorapi.Drift(s, "[%d] is not a period of at most one day in Unix seconds", i)
		}
		if start.Unix() < prevEnd {
			return vendorapi.Page{}, vendorapi.Drift(s, "[%d] overlaps or precedes the previous period", i)
		}
		prevEnd = end.Unix()
		if e.Active == nil {
			return vendorapi.Page{}, vendorapi.Drift(s, "[%d].active_users is missing", i)
		}
		n, err := strconv.ParseInt(string(*e.Active), 10, 64)
		if err != nil || n < 0 {
			return vendorapi.Page{}, vendorapi.Drift(s, "[%d].active_users is not a non-negative integer", i)
		}
		page.Facts = append(page.Facts, vendorapi.FactRow{
			IntervalStart: start, IntervalEnd: end, SourceTZ: "UTC", CoverageDomain: ConsumptionDomain,
			Metric: MetricDailyActiveUsers, Unit: UnitUsers, ValueMicros: n * 1_000_000,
		})
	}
	return page, nil
}
