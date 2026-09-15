// Package community is the pure, compiled-in registry of the fixed, versioned
// community metrics and cohorts (divergence remediation plan §3 "W5"; operator
// ruling R3). It is the Go half of the forbidden-metric rule: a metric that is
// not in this registry is un-contributable and un-readable, table-driven, with
// no free-form slicing. It MUST stay in lockstep with the SQL seed in
// migration 0022 (community_metrics) — a store-side test
// (TestMetricRegistryMatchesSeed) pins the two against each other so drift fails
// loudly.
//
// The package is PURE: no database/sql, no net/http, no fsnotify (pinned by
// imports_test.go). Band edges are data-INDEPENDENT constants (a quantile edge
// would shift with one contributor and leak a cohort-minus-one signal), and the
// floor/k thresholds mirror the DB — the DB HARD-floors them at 30/5 regardless,
// so this registry can only ever request EQUAL-OR-STRICTER privacy, never weaker.
package community

import (
	"fmt"
	"sort"
	"time"
)

// Metric is one fixed, versioned community metric definition.
type Metric struct {
	// ID is the stable metric identifier (matches community_metrics.metric_id).
	ID string
	// Version is the metric definition version. A change to edges/floor/k ships
	// as a NEW version so historical windows keep their original banding.
	Version int
	// BandEdges are the ascending, data-independent width_bucket thresholds:
	// width_bucket(value, edges) yields band 0 (below the first edge) .. N
	// (at/above the last edge), i.e. len(edges)+1 fixed bands.
	BandEdges []float64
	// MinCohort is the displayed-cohort floor (the DB hard-floors at 30).
	MinCohort int
	// KMin is the cell-suppression threshold (the DB hard-floors at 5).
	KMin int
	// MinValue / MaxValue are this metric's own value DOMAIN — distinct from
	// cloudcontract.MaxContributionValue, which is a data-independent absolute
	// sanity ceiling shared by every metric. A percentage metric's domain is
	// [0,100]; the shared ceiling (1e9) would happily pass 101. Enforced by the
	// intake handler AFTER the registry lookup, BEFORE any grant mutation (Sol
	// F12): a value outside [MinValue,MaxValue] is a 400, not a stored outlier.
	MinValue float64
	MaxValue float64
	// Label + Unit + Description drive the portal Community page's metric
	// definitions panel (R3: "metric definitions" shown).
	Label       string
	Unit        string
	Description string
}

// Cohort is one fixed, versioned cohort definition (no arbitrary slicing).
type Cohort struct {
	Key         string
	Label       string
	Description string
}

// metrics is the canonical registry, keyed logically by (ID, Version). Keep in
// lockstep with migration 0022's community_metrics seed.
var metrics = []Metric{
	{
		ID:          "sessions_per_active_day",
		Version:     1,
		BandEdges:   []float64{1, 2, 3, 5, 8, 13},
		MinCohort:   30,
		KMin:        5,
		MinValue:    0,
		MaxValue:    1000,
		Label:       "Sessions per active day",
		Unit:        "sessions/day",
		Description: "Coding sessions started on days you were active, as a private cohort distribution.",
	},
	{
		ID:          "verification_coverage_pct",
		Version:     1,
		BandEdges:   []float64{10, 25, 50, 75, 90},
		MinCohort:   30,
		KMin:        5,
		MinValue:    0,
		MaxValue:    100,
		Label:       "Verification coverage",
		Unit:        "%",
		Description: "Share of sessions with a verification signal (tests/build/lint), as a private cohort distribution.",
	},
}

// cohorts is the fixed cohort vocabulary. Phase 1 ships the single global cohort;
// finer cohorts (e.g. by primary language) are added here as versioned entries,
// never derived from a free-form request argument.
var cohorts = []Cohort{
	{Key: "global", Label: "All developers", Description: "Every developer who opted into community benchmarking."},
}

// Metrics returns a copy of the registry in a stable order (by ID, then version).
func Metrics() []Metric {
	out := make([]Metric, len(metrics))
	copy(out, metrics)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// Cohorts returns a copy of the cohort vocabulary in key order.
func Cohorts() []Cohort {
	out := make([]Cohort, len(cohorts))
	copy(out, cohorts)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// LookupMetric returns the registered metric for (id, version), or false if it
// is not registered (the forbidden-metric guard).
func LookupMetric(id string, version int) (Metric, bool) {
	for _, m := range metrics {
		if m.ID == id && m.Version == version {
			return m, true
		}
	}
	return Metric{}, false
}

// ValidCohort reports whether key is a registered cohort.
func ValidCohort(key string) bool {
	for _, c := range cohorts {
		if c.Key == key {
			return true
		}
	}
	return false
}

// MaterializationTargets enumerates every (cohort, metric, version) pair the
// band-materialization job should compute for a finalized window. It is the
// cross product of the registered cohorts and metrics — a fixed, closed set, so
// materialization can never be steered to an arbitrary slice.
type Target struct {
	CohortKey     string
	MetricID      string
	MetricVersion int
}

// MaterializationTargets returns the fixed cross product of cohorts × metrics.
func MaterializationTargets() []Target {
	var out []Target
	for _, c := range Cohorts() {
		for _, m := range Metrics() {
			out = append(out, Target{CohortKey: c.Key, MetricID: m.ID, MetricVersion: m.Version})
		}
	}
	return out
}

// RecentFinalizedWindows returns the n most recent FULLY-ELAPSED UTC-month
// window ids ("YYYY-MM"), newest first, relative to now. The current month is
// never included (it is not finalized — the aggregation would return nothing for
// it anyway). n<=0 yields nil. This is the set the materialization job recomputes
// each pass; keeping it small (e.g. 2-3) is enough to catch late contributions
// that landed just before a window finalized.
func RecentFinalizedWindows(now time.Time, n int) []string {
	if n <= 0 {
		return nil
	}
	// Start from the first day of the current UTC month, then step back a month
	// at a time — each of those months is fully elapsed.
	u := now.UTC()
	cur := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		w := cur.AddDate(0, -i, 0)
		out = append(out, fmt.Sprintf("%04d-%02d", w.Year(), int(w.Month())))
	}
	return out
}

// IsWindowFinalized reports whether the UTC-month window ("YYYY-MM") is fully
// elapsed as of now (its month has ended). A finalized window is FROZEN: the
// upload path must refuse to write or change a contribution in it, so its
// aggregate can never be perturbed by a later value change (repeated-window
// differencing defense). A malformed window_id is treated as not-finalized
// (the caller rejects it upstream). Judged in UTC only, matching the SQL
// aggregation's finalization gate.
func IsWindowFinalized(now time.Time, windowID string) bool {
	if len(windowID) != 7 || windowID[4] != '-' {
		return false
	}
	var y, mo int
	if _, err := fmt.Sscanf(windowID, "%04d-%02d", &y, &mo); err != nil {
		return false
	}
	if mo < 1 || mo > 12 {
		return false
	}
	// The instant the window's month ENDS = the first day of the next month, UTC.
	end := time.Date(y, time.Month(mo), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return !now.UTC().Before(end)
}

// InDomain reports whether value lies within metric m's own [MinValue,MaxValue]
// domain (Sol F12). This is a NARROWER, metric-specific check than
// cloudcontract.CommunityContribution.Validate's shared MaxContributionValue
// ceiling — that check already rejected non-finite/negative/absurd values; this
// one rejects an in-range-looking-but-nonsensical value for THIS metric (e.g.
// verification_coverage_pct=101).
func (m Metric) InDomain(value float64) bool {
	return value >= m.MinValue && value <= m.MaxValue
}

// CurrentWindow returns the server's current UTC-month window id ("YYYY-MM") as
// of now — the ONLY window a contribution may be written into (Sol F10: an
// authenticated device must not be able to pre-seed a future window that later
// becomes eligible for materialization, nor resurrect a past one).
func CurrentWindow(now time.Time) string {
	u := now.UTC()
	return fmt.Sprintf("%04d-%02d", u.Year(), int(u.Month()))
}

// IsCurrentWindow reports whether windowID names exactly the server's current
// UTC-month window as of now. Malformed input is never current. This is
// STRICTER than !IsWindowFinalized(now, windowID): that predicate accepts any
// window whose month has not yet elapsed, including one far in the future;
// IsCurrentWindow accepts only the single in-progress month, matching the SQL
// trigger's equivalent tightening in migration 0027.
func IsCurrentWindow(now time.Time, windowID string) bool {
	if len(windowID) != 7 || windowID[4] != '-' {
		return false
	}
	var y, mo int
	if _, err := fmt.Sscanf(windowID, "%04d-%02d", &y, &mo); err != nil {
		return false
	}
	if mo < 1 || mo > 12 {
		return false
	}
	return windowID == CurrentWindow(now)
}

// Band computes which width_bucket band a value falls in for metric m — the same
// data-independent banding the DB applies (bucket 0 below the first edge .. N
// at/above the last). Used by the own-percentile surface to place a developer's
// own value against the materialized cohort bands, WITHOUT any cross-tenant read.
func (m Metric) Band(value float64) int {
	b := 0
	for _, edge := range m.BandEdges {
		if value >= edge {
			b++
		} else {
			break
		}
	}
	return b
}
