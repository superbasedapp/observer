package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// community.go serves the W5 own-percentile READ surface (divergence remediation
// plan §3 "W5"; ruling R3): a developer sees the PRIVATE, delayed, floored,
// k-suppressed band distribution for a cohort (from the materialized snapshot the
// front-door role is allowed to read) plus WHERE THEY SIT in it (their own value,
// RLS-scoped, banded locally). The front-door process holds SELECT on
// community_band_snapshots but NOT EXECUTE on the cross-tenant aggregation, so
// this handler can never compute a live cross-tenant read — it only reads the
// worker's delayed materialization.
//
// The contribution UPLOAD path (POST, consent-gated) and the node value
// computation are the remaining W5 follow-ons; this is the read half.

// communityBandView is one band cell in the response.
type communityBandView struct {
	Band  int   `json:"band"`
	Count int64 `json:"count"`
}

// communityOwnView is the caller's own placement, present only if they contributed.
type communityOwnView struct {
	Contributed bool     `json:"contributed"`
	Value       *float64 `json:"value,omitempty"`
	Band        *int     `json:"band,omitempty"`
}

// communityPercentileView is the GET response.
type communityPercentileView struct {
	CohortKey     string              `json:"cohort_key"`
	MetricID      string              `json:"metric_id"`
	MetricVersion int                 `json:"metric_version"`
	MetricLabel   string              `json:"metric_label"`
	MetricUnit    string              `json:"metric_unit"`
	WindowID      string              `json:"window_id"`
	CohortSize    int64               `json:"cohort_size"`
	BandEdges     []float64           `json:"band_edges"`
	Bands         []communityBandView `json:"bands"`
	Own           communityOwnView    `json:"own"`
}

// handleCommunityPercentile is GET /v1/community/percentile (device PoP).
func (s *Server) handleCommunityPercentile(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	s.serveCommunityPercentile(w, r, p.AccountID)
}

// handlePortalCommunity is GET /portal/api/community (portal session).
func (s *Server) handlePortalCommunity(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	s.serveCommunityPercentile(w, r, p.AccountID)
}

// serveCommunityPercentile is the shared core: validate the fixed registry
// arguments, read the materialized bands (front-door SELECT) and the caller's own
// value (RLS-scoped), and place the caller. All arguments are validated against
// the compiled-in registry — an unregistered metric or an unknown cohort is a
// 400 (the forbidden-metric guard), never a free-form query.
func (s *Server) serveCommunityPercentile(w http.ResponseWriter, r *http.Request, accountID string) {
	q := r.URL.Query()
	cohort := q.Get("cohort")
	if cohort == "" {
		cohort = "global"
	}
	metricID := q.Get("metric")
	version := 1
	if v := q.Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid_version", "version must be a positive integer")
			return
		}
		version = n
	}
	if !community.ValidCohort(cohort) {
		writeErr(w, http.StatusBadRequest, "unknown_cohort", "cohort is not a registered community cohort")
		return
	}
	metric, ok := community.LookupMetric(metricID, version)
	if !ok {
		writeErr(w, http.StatusBadRequest, "unknown_metric", "metric is not a registered community metric at this version")
		return
	}
	// Default to the most recent finalized window when none is named.
	window := q.Get("window")
	if window == "" {
		recent := community.RecentFinalizedWindows(s.now(), 1)
		if len(recent) == 0 {
			writeErr(w, http.StatusInternalServerError, "internal", "no finalized window")
			return
		}
		window = recent[0]
	}

	cells, err := s.store.ReadCommunityBands(r.Context(), cohort, metric.ID, metric.Version, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read community bands")
		return
	}
	view := communityPercentileView{
		CohortKey:     cohort,
		MetricID:      metric.ID,
		MetricVersion: metric.Version,
		MetricLabel:   metric.Label,
		MetricUnit:    metric.Unit,
		WindowID:      window,
		BandEdges:     metric.BandEdges,
		Bands:         []communityBandView{},
	}
	for _, c := range cells {
		view.CohortSize = c.CohortSize // identical on every cell
		view.Bands = append(view.Bands, communityBandView{Band: c.Band, Count: c.BandCount})
	}

	// The caller's own placement (RLS-scoped read of their own value). Present
	// only if they contributed; the band is computed locally against the fixed
	// edges (no cross-tenant read).
	own, oerr := s.store.AccountContribution(r.Context(), accountID, cohort, metric.ID, metric.Version, window)
	switch {
	case oerr == nil:
		b := metric.Band(own)
		v := own
		view.Own = communityOwnView{Contributed: true, Value: &v, Band: &b}
	case errors.Is(oerr, store.ErrNotFound):
		view.Own = communityOwnView{Contributed: false}
	default:
		// A read failure of the caller's own value degrades to "not contributed"
		// rather than failing the whole page (the bands are the primary content).
		s.log.Warn("cloudserver/api: community own value", "err", oerr)
		view.Own = communityOwnView{Contributed: false}
	}

	writeJSON(w, http.StatusOK, view)
}

// communityMetricsView lists the registered metric + cohort definitions for the
// portal Community page's "metric definitions" panel (R3). Pure registry data.
func (s *Server) handlePortalCommunityMetrics(w http.ResponseWriter, r *http.Request) {
	_ = r
	type metricDef struct {
		ID          string    `json:"id"`
		Version     int       `json:"version"`
		Label       string    `json:"label"`
		Unit        string    `json:"unit"`
		Description string    `json:"description"`
		BandEdges   []float64 `json:"band_edges"`
	}
	type cohortDef struct {
		Key         string `json:"key"`
		Label       string `json:"label"`
		Description string `json:"description"`
	}
	var metricsOut []metricDef
	for _, m := range community.Metrics() {
		metricsOut = append(metricsOut, metricDef{m.ID, m.Version, m.Label, m.Unit, m.Description, m.BandEdges})
	}
	var cohortsOut []cohortDef
	for _, c := range community.Cohorts() {
		cohortsOut = append(cohortsOut, cohortDef{c.Key, c.Label, c.Description})
	}
	writeJSON(w, http.StatusOK, map[string]any{"metrics": metricsOut, "cohorts": cohortsOut})
}
