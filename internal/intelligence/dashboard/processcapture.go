package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The read side of the process capture budget
// (docs/plans/process-capture-budget-plan-2026-11-04.md §9.3,
// docs/process-observability.md §11.3):
//
//   - GET /api/session/<id>/processes/summary — the small, ETagged document
//     the System tab polls: the capture counters, the budget, the service
//     roots, the top rollups and the findings count;
//   - the window parameters of GET /api/session/<id>/processes (from, to,
//     limit, since), parsed here and served by handleSessionProcesses;
//   - GET /api/process/capture/estimate — the Settings page's data-volume
//     card: a replay of recent stored runs through the draft capture limits.

// summaryRollupLimit is how many rollup groups the summary lists (plan §9.3).
const summaryRollupLimit = 200

// summaryServiceLimit bounds the service roots one summary lists.
const summaryServiceLimit = 200

// captureHistoryTTL is how long the estimate endpoint reuses its loaded
// history: the Settings card asks on every debounced edit, and the replay
// basis (up to 200,000 stored runs) barely moves in a minute.
const captureHistoryTTL = 60 * time.Second

// summaryCorrelateTimeout bounds the background correlation passes the
// summary starts.
const summaryCorrelateTimeout = 2 * time.Minute

// ProcessSummaryResponse is GET /api/session/<id>/processes/summary
// (web/src/lib/types.ts ProcessSummaryResponse). The counters are the
// session's process_capture_stats row; Legacy is true when the session has
// none (its rows predate the capture budget), and then Observed and Kept are
// the session's plain row count so the panel still has numbers.
type ProcessSummaryResponse struct {
	Observed        int64                   `json:"observed"`
	Kept            int64                   `json:"kept"`
	Folded          int64                   `json:"folded"`
	RolledUp        int64                   `json:"rolled_up"`
	ServiceKept     int64                   `json:"service_kept"`
	ServiceRolledUp int64                   `json:"service_rolled_up"`
	Dropped         int64                   `json:"dropped"`
	Budget          ProcessSummaryBudget    `json:"budget"`
	Services        []ProcessSummaryService `json:"services"`
	Rollups         []ProcessSummaryRollup  `json:"rollups"`
	// Findings is the number of §14 findings over the session's rows.
	Findings int  `json:"findings"`
	Legacy   bool `json:"legacy"`
}

// ProcessSummaryBudget is the capture budget in force (the saved
// [observer.process.capture.budget]) and whether this session hit it.
type ProcessSummaryBudget struct {
	PerToolCall int  `json:"per_tool_call"`
	PerSession  int  `json:"per_session"`
	PerMinute   int  `json:"per_minute"`
	Hit         bool `json:"hit"`
}

// ProcessSummaryService is one service root of the session
// (web/src/lib/types.ts ProcessSummaryService).
type ProcessSummaryService struct {
	RootKey      string `json:"root_key"`
	Exe          string `json:"exe"`
	ArgvPreview  string `json:"argv_preview,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
	ActionID     *int64 `json:"action_id,omitempty"`
	TurnIndex    *int   `json:"turn_index,omitempty"`
	MessageID    string `json:"message_id,omitempty"`
	Kept         int64  `json:"kept"`
	RolledUp     int64  `json:"rolled_up"`
	CPUSumMs     int64  `json:"cpu_sum_ms"`
	PeakRSSBytes int64  `json:"peak_rss_bytes"`
}

// ProcessSummaryRollup is one rollup group summed across buckets
// (web/src/lib/types.ts ProcessSummaryRollup).
type ProcessSummaryRollup struct {
	GroupKind          string `json:"group_kind"`
	ExeBasename        string `json:"exe_basename,omitempty"`
	ExampleArgvPreview string `json:"example_argv_preview,omitempty"`
	ParentProcessKey   string `json:"parent_process_key,omitempty"`
	ServiceRootKey     string `json:"service_root_key,omitempty"`
	ActionID           *int64 `json:"action_id,omitempty"`
	Count              int64  `json:"count"`
	FailedCount        int64  `json:"failed_count"`
	DurationSumMs      int64  `json:"duration_sum_ms"`
	DurationMaxMs      int64  `json:"duration_max_ms"`
	CPUSumMs           int64  `json:"cpu_sum_ms"`
	PeakRSSBytes       int64  `json:"peak_rss_bytes"`
	FirstSeen          string `json:"first_seen,omitempty"`
	LastSeen           string `json:"last_seen,omitempty"`
}

// processCaptureState is the Server's one owner of the capture read side's
// in-memory caches: the findings count per session (keyed by the session's
// row mark, exact because a finding is a pure function of a run's immutable
// exec facts) and the estimate endpoint's loaded history.
type processCaptureState struct {
	mu       sync.Mutex
	findings map[string]findingsCount

	historyMu sync.Mutex
	historyAt time.Time
	history   []proccapture.RunFacts
}

// findingsCount is one cached findings count and the row mark it holds for.
type findingsCount struct {
	rows, maxID int64
	n           int
}

// findingsCacheMax bounds the findings cache; past it the cache starts over.
const findingsCacheMax = 256

// sessionFindingsCount returns the session's findings count. An unchanged
// session is served from the cache; a session that only gained new rows (a
// live one, on every poll) adds the findings of the rows above the cached
// highest id; anything else (rows attached late by correlation, or deleted)
// recounts the whole session.
func (s *Server) sessionFindingsCount(ctx context.Context, st *store.Store, sessionID string, rows, maxID int64) int {
	c := &s.procCapture
	c.mu.Lock()
	v, ok := c.findings[sessionID]
	c.mu.Unlock()
	if ok && v.rows == rows && v.maxID == maxID {
		return v.n
	}
	n := -1
	if ok && rows > v.rows && maxID > v.maxID {
		added, read, err := st.ProcessFindingsForSessionAfter(ctx, sessionID, v.maxID)
		if err == nil && v.rows+int64(read) == rows {
			n = v.n + len(added)
		}
	}
	if n < 0 {
		findings, err := st.ProcessFindingsForSession(ctx, sessionID)
		if err != nil {
			return 0
		}
		n = len(findings)
	}
	c.mu.Lock()
	if c.findings == nil || len(c.findings) >= findingsCacheMax {
		c.findings = map[string]findingsCount{}
	}
	c.findings[sessionID] = findingsCount{rows: rows, maxID: maxID, n: n}
	c.mu.Unlock()
	return n
}

// captureHistory returns the replay basis for the estimate endpoint
// (store.LoadCaptureHistory defaults: the last 7 days, at most 200,000
// rows), reloaded at most once per captureHistoryTTL. Concurrent callers wait
// for one load rather than each scanning the table.
func (s *Server) captureHistory(ctx context.Context) ([]proccapture.RunFacts, error) {
	c := &s.procCapture
	c.historyMu.Lock()
	defer c.historyMu.Unlock()
	now := s.now()
	if c.history != nil && now.Sub(c.historyAt) < captureHistoryTTL {
		return c.history, nil
	}
	h, err := store.New(s.db()).LoadCaptureHistory(ctx, time.Time{}, 0)
	if err != nil {
		return nil, err
	}
	if h == nil {
		h = []proccapture.RunFacts{}
	}
	c.history, c.historyAt = h, now
	return h, nil
}

// handleSessionProcessSummary serves GET /api/session/<id>/processes/summary.
// Every read is an aggregate or an index range (store/processwindow.go,
// store/processrollups.go), so a 92k-row session answers in milliseconds. The
// ETag hashes the body together with a change mark of the session's rows (row
// count, highest id, and the latest sighting, exits and action links of the
// newest window), so it moves whenever the windowed tree would read
// differently; an If-None-Match hit answers 304 with no body.
func (s *Server) handleSessionProcessSummary(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	exists, err := st.SessionExists(ctx, sessionID)
	if err != nil {
		writeErr(w, fmt.Errorf("session lookup: %w", err))
		return
	}
	if !exists {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	// The same debounced correlation passes the tree runs. The summary is what
	// the panel polls, so they run in the background instead of on this
	// request (seconds on a session with ~100k rows): a link they make moves
	// the ETag, and the next poll and the tree re-read pick it up.
	if s.shouldCorrelate(sessionID) {
		go func() {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), summaryCorrelateTimeout)
			defer cancel()
			_, _ = st.CorrelateCrossOS(cctx, sessionID)
			_, _ = st.CorrelateProcessActions(cctx, sessionID)
			_, _ = st.DeriveProcessRunsFromActions(cctx, sessionID)
		}()
	}

	resp, mark, err := s.buildProcessSummary(ctx, st, sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	body, err := json.Marshal(resp)
	if err != nil {
		writeErr(w, fmt.Errorf("encode summary: %w", err))
		return
	}
	sum := sha256.New()
	sum.Write(body)
	sum.Write([]byte{0})
	sum.Write([]byte(mark))
	etag := `"` + hex.EncodeToString(sum.Sum(nil))[:32] + `"`

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(body, '\n'))
}

// buildProcessSummary assembles the summary and the row change mark the ETag
// folds in.
func (s *Server) buildProcessSummary(ctx context.Context, st *store.Store, sessionID string) (ProcessSummaryResponse, string, error) {
	rows, maxID, err := st.ProcessSessionRowMark(ctx, sessionID)
	if err != nil {
		return ProcessSummaryResponse{}, "", err
	}
	recent, err := st.ProcessSessionRecentMark(ctx, sessionID, store.ProcessWindowDefaultLimit)
	if err != nil {
		return ProcessSummaryResponse{}, "", err
	}
	mark := fmt.Sprintf("%d|%d|%s|%d|%d", rows, maxID, recent.LastSeen, recent.Exited, recent.Linked)

	stats, ok, err := st.ProcessCaptureStatsForSession(ctx, sessionID)
	if err != nil {
		return ProcessSummaryResponse{}, "", err
	}
	cfg, _ := loadConfigForDashboard(s.opts.ConfigPath)
	budget := cfg.Observer.Process.Capture.Budget
	resp := ProcessSummaryResponse{
		Observed:        stats.Observed,
		Kept:            stats.Kept,
		Folded:          stats.Folded,
		RolledUp:        stats.RolledUp,
		ServiceKept:     stats.ServiceKept,
		ServiceRolledUp: stats.ServiceRolledUp,
		Dropped:         stats.Dropped,
		Budget: ProcessSummaryBudget{
			PerToolCall: budget.PerToolCall,
			PerSession:  budget.PerSession,
			PerMinute:   budget.PerMinute,
			Hit:         stats.BudgetHits > 0,
		},
		Services: []ProcessSummaryService{},
		Rollups:  []ProcessSummaryRollup{},
		Legacy:   !ok,
	}
	if !ok {
		resp.Observed, resp.Kept = rows, rows
	}

	roots, err := st.ProcessServiceRootsForSession(ctx, sessionID, summaryServiceLimit)
	if err != nil {
		return ProcessSummaryResponse{}, "", err
	}
	for _, sr := range roots {
		resp.Services = append(resp.Services, ProcessSummaryService{
			RootKey:      sr.RootKey,
			Exe:          sr.Exe,
			ArgvPreview:  sr.ArgvPreview,
			StartedAt:    startedAtISO(sr.StartedAt),
			LastSeen:     startedAtISO(sr.LastSeen),
			ActionID:     sr.ActionID,
			TurnIndex:    sr.TurnIndex,
			MessageID:    sr.MessageID,
			Kept:         sr.Kept,
			RolledUp:     sr.RolledUp,
			CPUSumMs:     sr.CPUSumMs,
			PeakRSSBytes: sr.PeakRSSBytes,
		})
	}
	rollups, err := st.ProcessRollupsForSession(ctx, sessionID, summaryRollupLimit)
	if err != nil {
		return ProcessSummaryResponse{}, "", err
	}
	for _, ru := range rollups {
		resp.Rollups = append(resp.Rollups, ProcessSummaryRollup{
			GroupKind:          ru.GroupKind,
			ExeBasename:        ru.ExeBasename,
			ExampleArgvPreview: ru.ExampleArgvPreview,
			ParentProcessKey:   ru.ParentProcessKey,
			ServiceRootKey:     ru.ServiceRootKey,
			ActionID:           ru.ActionID,
			Count:              ru.Count,
			FailedCount:        ru.FailedCount,
			DurationSumMs:      ru.DurationSumMs,
			DurationMaxMs:      ru.DurationMaxMs,
			CPUSumMs:           ru.CPUSumMs,
			PeakRSSBytes:       ru.PeakRSSBytes,
			FirstSeen:          startedAtISO(ru.FirstSeen),
			LastSeen:           startedAtISO(ru.LastSeen),
		})
	}
	resp.Findings = s.sessionFindingsCount(ctx, st, sessionID, rows, maxID)
	return resp, mark, nil
}

// etagMatches reports whether an If-None-Match header names etag (a list,
// "*", or a weak spelling of the same opaque value).
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}

// parseProcessWindow reads the window parameters of
// GET /api/session/<id>/processes: from, to and since as RFC3339 instants
// (fractional seconds accepted; compared at one-second resolution), limit as
// an integer (default 2000, capped at 10000).
func parseProcessWindow(q url.Values) (store.ProcessRunWindow, error) {
	var w store.ProcessRunWindow
	parseTime := func(name string, dst *time.Time) error {
		v := strings.TrimSpace(q.Get(name))
		if v == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fmt.Errorf("invalid %s %q: want RFC3339", name, v)
		}
		*dst = t.UTC()
		return nil
	}
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"from", &w.From}, {"to", &w.To}, {"since", &w.Since}} {
		if err := parseTime(p.name, p.dst); err != nil {
			return store.ProcessRunWindow{}, err
		}
	}
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return store.ProcessRunWindow{}, fmt.Errorf("invalid limit %q: want a non-negative integer", v)
		}
		w.Limit = n
	}
	return w.Normalized(), nil
}

// windowArchivedRuns applies a window to an in-memory row set (the cold
// archive fallback, which has no SQL to push the window into), with the same
// semantics as store.ProcessRunsWindowForSession: bounds at one-second
// resolution, To inclusive of its second, the newest Limit rows, oldest
// first, Truncated when older rows were left out.
func windowArchivedRuns(runs []store.ProcessRunRow, w store.ProcessRunWindow) ([]store.ProcessRunRow, bool) {
	w = w.Normalized()
	floor := func(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
	var in []store.ProcessRunRow
	older := false
	for _, r := range runs {
		started := r.StartedAt.UTC()
		switch {
		case !w.From.IsZero() && started.Before(floor(w.From)):
			if w.Since.IsZero() {
				older = true
			}
			continue
		case !w.To.IsZero() && !started.Before(floor(w.To).Add(time.Second)):
			continue
		case !w.Since.IsZero() && r.LastSeenAt.UTC().Before(floor(w.Since)):
			continue
		}
		in = append(in, r)
	}
	sort.SliceStable(in, func(i, j int) bool {
		if !in[i].StartedAt.Equal(in[j].StartedAt) {
			return in[i].StartedAt.Before(in[j].StartedAt)
		}
		return in[i].PID < in[j].PID
	})
	if len(in) > w.Limit {
		return in[len(in)-w.Limit:], true
	}
	return in, older
}

// handleProcessCaptureEstimate serves GET /api/process/capture/estimate. The
// query parameters are the plan §9.1 keys, dotted and bare
// (proccapture.ConfigKeys: budget.per_tool_call=150, fold.enabled=false,
// services.extra_basenames=a.exe,b.exe); current is the saved
// [observer.process.capture] block (restart-bound, so it is what the daemon
// runs with once restarted), proposed is current with the query applied. An
// unknown key or a bad value is a 400. The replay basis is cached for
// captureHistoryTTL.
func (s *Server) handleProcessCaptureEstimate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	current := cfg.Observer.Process.Capture.CaptureConfig()
	proposed := current
	proposed.ExtraServiceBasenames = slices.Clone(current.ExtraServiceBasenames)
	proposed.ExtraFoldBasenames = slices.Clone(current.ExtraFoldBasenames)
	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vals := q[k]
		if err := proposed.Set(k, vals[len(vals)-1]); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error(), "key": k})
			return
		}
	}
	history, err := s.captureHistory(r.Context())
	if err != nil {
		writeErr(w, fmt.Errorf("load capture history: %w", err))
		return
	}
	writeJSON(w, proccapture.Estimate(history, current, proposed))
}
