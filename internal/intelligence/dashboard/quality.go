package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
	"github.com/marmutapp/superbased-observer/internal/codequalitysvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// quality.go serves the Projects page's Quality tab (docs/projects-page.md
// "Quality metrics"):
//
//	GET /api/project/{id}/quality   View   current measurement + daily trend
//
// The current figures are measured on the request through
// internal/codequalitysvc (coverage report files read under a cap, the
// codeintel index read through the store); nothing is written. The trend is
// the stored daily points the daemon loop records, inside the page window.

// qualityConfig resolves the service tunables from the live config file
// when the server has one (a toggle in Settings shows on the next load),
// else from the boot-time options.
func (s *Server) qualityConfig() codequalitysvc.Config {
	if s.opts.ConfigPath != "" {
		if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
			return codequalitysvc.ConfigFrom(cfg)
		}
	}
	return codequalitysvc.Config{Enabled: s.opts.Projects.QualityMetrics, ActiveProjectDays: s.opts.Projects.ActiveProjectDays}
}

// qualityResponse is GET /api/project/{id}/quality's body. Every list is
// [] (never null); a metric that is not measured carries no numbers.
type qualityResponse struct {
	ProjectID   int64              `json:"project_id"`
	Enabled     bool               `json:"enabled"`
	MeasuredAt  time.Time          `json:"measured_at"`
	Coverage    qualityCoverage    `json:"coverage"`
	Duplication qualityDuplication `json:"duplication"`
	Complexity  qualityComplexity  `json:"complexity"`
	History     []qualityDay       `json:"history"`
	Trend       qualityTrend       `json:"trend"`
	WindowDays  int                `json:"window_days"`
}

type qualityState struct {
	State  codequality.State `json:"state"`
	Reason string            `json:"reason"`
}

type qualityLocation struct {
	Path   string             `json:"path"`
	Format codequality.Format `json:"format"`
	Writer string             `json:"writer"`
}

type qualityCoverage struct {
	qualityState
	Lines        int                         `json:"lines"`
	Covered      int                         `json:"covered"`
	Percent      *float64                    `json:"percent,omitempty"`
	NewestReport *time.Time                  `json:"newest_report_at,omitempty"`
	OldestReport *time.Time                  `json:"oldest_report_at,omitempty"`
	Reports      []codequality.ReportSummary `json:"reports"`
	Problems     []codequality.Problem       `json:"problems"`
	LeastCovered []codequality.FileLine      `json:"least_covered"`
	Locations    []qualityLocation           `json:"locations"`
}

type qualityDuplication struct {
	qualityState
	EligibleSymbols int                      `json:"eligible_symbols"`
	ClonedSymbols   int                      `json:"cloned_symbols"`
	EligibleLines   int                      `json:"eligible_lines"`
	ClonedLines     int                      `json:"cloned_lines"`
	Groups          int                      `json:"groups"`
	SymbolShare     *float64                 `json:"symbol_share,omitempty"`
	LineShare       *float64                 `json:"line_share,omitempty"`
	TopGroups       []codequality.CloneGroup `json:"top_groups"`
	SkippedBuckets  int                      `json:"skipped_buckets"`
	IndexedFiles    int                      `json:"indexed_files"`
	LastIndexedAt   *time.Time               `json:"last_indexed_at,omitempty"`
	Stale           bool                     `json:"stale"`
	Truncated       bool                     `json:"truncated"`
	Method          qualityDupMethod         `json:"method"`
}

// qualityDupMethod states the roll-up's thresholds on the wire so the page
// can say exactly what "near-clone" means.
type qualityDupMethod struct {
	MinLines       int      `json:"min_lines"`
	MinSharedBands int      `json:"min_shared_bands"`
	TotalBands     int      `json:"total_bands"`
	Kinds          []string `json:"kinds"`
}

type qualityComplexity struct {
	qualityState
	Functions int `json:"functions"`
	// Over counts functions above Method.Threshold; OverShare and Mean are
	// absent unless measured.
	Over           int                           `json:"over"`
	OverShare      *float64                      `json:"over_share,omitempty"`
	Mean           *float64                      `json:"mean,omitempty"`
	P50            int                           `json:"p50"`
	P90            int                           `json:"p90"`
	Max            int                           `json:"max"`
	PerLanguage    []codequality.LangComplexity  `json:"per_language"`
	Top            []codequality.ComplexFunction `json:"top"`
	CountedFiles   int                           `json:"counted_files"`
	PendingFiles   int                           `json:"pending_files"`
	UncountedFiles int                           `json:"uncounted_files"`
	UncountedLangs []string                      `json:"uncounted_langs"`
	IndexedFiles   int                           `json:"indexed_files"`
	LastIndexedAt  *time.Time                    `json:"last_indexed_at,omitempty"`
	Stale          bool                          `json:"stale"`
	Truncated      bool                          `json:"truncated"`
	Method         qualityCxMethod               `json:"method"`
}

// qualityCxMethod states the roll-up's rules on the wire so the page can
// say exactly what is counted.
type qualityCxMethod struct {
	Threshold int      `json:"threshold"`
	Kinds     []string `json:"kinds"`
}

type qualityDay struct {
	Day             string            `json:"day"`
	MeasuredAt      time.Time         `json:"measured_at"`
	CoverageState   codequality.State `json:"coverage_state"`
	CoveragePercent *float64          `json:"coverage_percent,omitempty"`
	CoverageLines   int               `json:"coverage_lines"`
	DupState        codequality.State `json:"dup_state"`
	DupLineShare    *float64          `json:"dup_line_share,omitempty"`
	DupClonedLines  int               `json:"dup_cloned_lines"`
	DupGroups       int               `json:"dup_groups"`
	// ComplexityState is "" for a day recorded before complexity was.
	ComplexityState     codequality.State `json:"complexity_state"`
	ComplexityOverShare *float64          `json:"complexity_over_share,omitempty"`
	ComplexityFunctions int               `json:"complexity_functions"`
	ComplexityP90       int               `json:"complexity_p90"`
	ComplexityMax       int               `json:"complexity_max"`
}

type qualityTrend struct {
	Coverage    codequality.Change `json:"coverage"`
	Duplication codequality.Change `json:"duplication"`
	// Complexity is the movement of the share of functions over the
	// threshold.
	Complexity codequality.Change `json:"complexity"`
}

// handleProjectQuality serves GET /api/project/{id}/quality.
func (s *Server) handleProjectQuality(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, days := projectDetailWindow(r)
	resp, err := composeProjectQuality(ctx, codequalitysvc.New(st, s.qualityConfig()), st, projectID, since, until)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp.WindowDays = days
	writeJSON(w, resp)
}

// composeProjectQuality measures projectID now and loads its daily points
// in [since, until).
func composeProjectQuality(ctx context.Context, svc *codequalitysvc.Service, st *store.Store, projectID int64, since, until time.Time) (qualityResponse, error) {
	m, err := svc.Measure(ctx, projectID)
	if err != nil {
		return qualityResponse{}, err
	}
	points, err := st.LoadProjectQualityHistory(ctx, projectID, since)
	if err != nil {
		return qualityResponse{}, err
	}
	untilDay := codequality.Day(until)
	var inWindow []codequality.DayPoint
	for _, p := range points {
		if until.IsZero() || p.Day <= untilDay {
			inWindow = append(inWindow, p)
		}
	}
	resp := qualityResponse{
		ProjectID: projectID, Enabled: svc.Enabled(), MeasuredAt: m.MeasuredAt,
		Coverage:    coverageWire(m.Coverage),
		Duplication: duplicationWire(m.Duplication),
		Complexity:  complexityWire(m.Complexity),
		History:     []qualityDay{},
		Trend: qualityTrend{
			Coverage: codequality.CoverageChange(inWindow), Duplication: codequality.DuplicationChange(inWindow),
			Complexity: codequality.ComplexityChange(inWindow),
		},
	}
	for _, p := range inWindow {
		resp.History = append(resp.History, qualityDay{
			Day: p.Day, MeasuredAt: p.MeasuredAt,
			CoverageState: p.CoverageState, CoveragePercent: p.CoveragePercent(), CoverageLines: p.CoverageLines,
			DupState: p.DupState, DupLineShare: p.DupLineShare(), DupClonedLines: p.DupClonedLines, DupGroups: p.DupGroups,
			ComplexityState: p.ComplexityState, ComplexityOverShare: p.ComplexityOverShare(),
			ComplexityFunctions: p.ComplexityFunctions, ComplexityP90: p.ComplexityP90, ComplexityMax: p.ComplexityMax,
		})
	}
	return resp, nil
}

func qualityOptTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func coverageWire(c codequality.CoverageResult) qualityCoverage {
	out := qualityCoverage{
		qualityState: qualityState{State: c.State, Reason: c.Reason},
		Lines:        c.Lines, Covered: c.Covered, Percent: c.Percent,
		Reports: qualityNonNil(c.Reports), Problems: qualityNonNil(c.Problems), LeastCovered: qualityNonNil(c.LeastCovered),
	}
	if c.State == codequality.StateMeasured {
		out.NewestReport, out.OldestReport = qualityOptTime(c.NewestReport), qualityOptTime(c.OldestReport)
	}
	for _, l := range codequality.ReportLocations {
		out.Locations = append(out.Locations, qualityLocation{Path: l.RelPath, Format: l.Format, Writer: l.Writer})
	}
	return out
}

func duplicationWire(d codequality.DuplicationResult) qualityDuplication {
	return qualityDuplication{
		qualityState:    qualityState{State: d.State, Reason: d.Reason},
		EligibleSymbols: d.EligibleSymbols, ClonedSymbols: d.ClonedSymbols,
		EligibleLines: d.EligibleLines, ClonedLines: d.ClonedLines, Groups: d.Groups,
		SymbolShare: d.SymbolShare, LineShare: d.LineShare, TopGroups: qualityNonNil(d.TopGroups),
		SkippedBuckets: d.SkippedBuckets, IndexedFiles: d.Index.IndexedFiles,
		LastIndexedAt: qualityOptTime(d.Index.LastIndexedAt), Stale: d.Stale, Truncated: d.Index.Truncated,
		Method: qualityDupMethod{
			MinLines: codequality.MinSymbolLines, MinSharedBands: codequality.MinSharedBands,
			TotalBands: codequality.TotalBands, Kinds: codequality.EligibleKinds,
		},
	}
}

func complexityWire(c codequality.ComplexityResult) qualityComplexity {
	return qualityComplexity{
		qualityState: qualityState{State: c.State, Reason: c.Reason},
		Functions:    c.Functions, Over: c.Over, OverShare: c.OverShare, Mean: c.Mean,
		P50: c.P50, P90: c.P90, Max: c.Max,
		PerLanguage: qualityNonNil(c.PerLanguage), Top: qualityNonNil(c.Top),
		CountedFiles: c.CountedFiles, PendingFiles: c.PendingFiles,
		UncountedFiles: c.UncountedFiles, UncountedLangs: qualityNonNil(c.UncountedLangs),
		IndexedFiles: c.Index.IndexedFiles, LastIndexedAt: qualityOptTime(c.Index.LastIndexedAt),
		Stale: c.Stale, Truncated: c.Index.Truncated,
		Method: qualityCxMethod{Threshold: codequality.ComplexityThreshold, Kinds: codequality.EligibleKinds},
	}
}

// qualityNonNil returns s, or an empty slice for nil, so the wire never says null.
func qualityNonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
