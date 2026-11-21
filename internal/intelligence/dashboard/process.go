package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// SessionProcessResponse is the /api/session/<id>/processes payload — the
// session process tree captured by Process Observability
// (docs/process-observability.md §13.1). Drives the session-detail Processes
// drawer; the React component lives in the (external) webapp source and
// consumes this shape.
type SessionProcessResponse struct {
	SessionID string `json:"session_id"`
	Total     int    `json:"total"`
	// NetworkTotal is the count of network_connect events attributed to the
	// session. Body details are intentionally not embedded here; callers fetch
	// /api/session/<id>/network and /api/process/network/<event_id> on demand.
	NetworkTotal int           `json:"network_total"`
	Roots        []ProcessNode `json:"roots"`
	// Findings are the §14 observe-only side-effect flags for this session's
	// processes (privileged exec, exec-from-tmp), derived from the envelope.
	Findings []store.ProcessFindingRow `json:"findings"`
	// Diagnostics explains the empty/partial-data cases the UI cannot infer
	// from row counts alone: opt-in config gates, proxy-only network rows, and
	// restart-bound settings. It is node-local config/status metadata only.
	Diagnostics ProcessDiagnostics `json:"diagnostics"`
	// Total (above) is the session's full row count; Roots holds only the
	// window (process capture budget plan §9.3). Truncated reports that the
	// session has rows older than the window's oldest that it left out (the
	// client's "Load earlier" pages them with ?to=); Window describes what
	// was returned.
	Truncated bool               `json:"truncated"`
	Window    *ProcessWindowInfo `json:"window,omitempty"`
}

// ProcessWindowInfo is the window a /processes response covers. From / To
// are RFC3339 UTC (whole seconds); Limit is the effective row cap and
// Returned the rows in the response.
type ProcessWindowInfo struct {
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Limit    int    `json:"limit"`
	Returned int    `json:"returned"`
}

// ProcessDiagnostics is the session-process drawer's operator guidance model.
// It intentionally reports only config gates and row counts, never prompt/tool
// content. The frontend turns the settings URLs into direct remediation links.
type ProcessDiagnostics struct {
	ProcessEnabled              bool     `json:"process_enabled"`
	ProcessBackend              string   `json:"process_backend,omitempty"`
	ProcessNetworkEnabled       bool     `json:"process_network_enabled"`
	ProcessNetworkCaptureBodies string   `json:"process_network_capture_bodies,omitempty"`
	ProcessNetworkBodyCapture   bool     `json:"process_network_body_capture"`
	ConfigWritable              bool     `json:"config_writable"`
	RestartRequired             bool     `json:"restart_required"`
	ProcessRows                 int      `json:"process_rows"`
	NetworkEvents               int      `json:"network_events"`
	ProxyOnlyNetworkEvents      int      `json:"proxy_only_network_events"`
	ReasonCodes                 []string `json:"reason_codes"`
	ProcessSettingsURL          string   `json:"process_settings_url"`
	ProxySettingsURL            string   `json:"proxy_settings_url"`
	BackfillSettingsURL         string   `json:"backfill_settings_url"`
	RestartSettingsURL          string   `json:"restart_settings_url"`
}

// ProcessNode is one process in the tree, with its children nested.
type ProcessNode struct {
	ProcessKey  string `json:"process_key"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	Exe         string `json:"exe"`
	ArgvPreview string `json:"argv_preview,omitempty"`
	CWD         string `json:"cwd,omitempty"`
	Source      string `json:"attribution_source"`
	Confidence  string `json:"attribution_confidence"`
	Exited      bool   `json:"exited"`
	ExitCode    int    `json:"exit_code"`
	ExitSignal  int    `json:"exit_signal,omitempty"`
	DurationMs  int64  `json:"duration_ms"`
	// StartedAt is the wall-clock instant the process was first observed
	// (process_runs.started_at, RFC3339 UTC). The drawer shows the actual
	// capture time alongside the elapsed/duration figures. Empty (zero)
	// when unknown.
	StartedAt string `json:"started_at,omitempty"`
	// LastSeenAt is the last instant the capture saw the process alive
	// (process_runs.last_seen_at, RFC3339 UTC). The Call stack view uses it
	// to draw an honest "exit not seen" bar for a process that was never
	// marked exited but has not been seen for a while (a missed exit: the
	// daemon stopped, or a poll gap), instead of a bar that runs to now.
	// Empty when unknown.
	LastSeenAt string `json:"last_seen_at,omitempty"`
	IsBoundary bool   `json:"is_boundary,omitempty"`
	ActionID   *int64 `json:"action_id,omitempty"`
	TurnIndex  *int   `json:"turn_index,omitempty"`
	// Command is the run_command target that spawned this subtree (§9.2.4),
	// empty when the process wasn't correlated to an action.
	Command string `json:"command,omitempty"`
	// MessageID is the assistant message that issued the spawning command
	// (actions.message_id, e.g. an Anthropic "msg_…" id) — the message→OS-side-
	// effect join (§9.2.4 / D8). Empty when the process wasn't correlated to an
	// action (e.g. session-infrastructure processes, or a short-lived command the
	// poll backend missed).
	MessageID string `json:"message_id,omitempty"`
	// Security / isolation posture (P4) — present only when captured.
	SeccompMode     string `json:"seccomp_mode,omitempty"`
	CapabilitiesEff string `json:"capabilities_eff,omitempty"`
	AppArmorLabel   string `json:"apparmor_label,omitempty"`
	SELinuxLabel    string `json:"selinux_label,omitempty"`
	ContainerID     string `json:"container_id,omitempty"`

	// Resource metrics (migration 045) — present only when captured (Windows
	// poll capturer today). CPUMs is cumulative user+system; WorkingSetBytes is
	// current RSS, PeakRSSBytes the lifetime peak; Read/WriteBytes cumulative
	// disk I/O. MetricSamples is the sparkline ring buffer. There is no
	// top-level cumulative network total here (unlike CPU/RSS/disk) — per-
	// sample NetRxBytes/NetTxBytes/NetMeasured live inside MetricSamples
	// (Linux eBPF backend only; Windows still needs ETW, deferred); the
	// differentiated, availability-gated network series is what
	// /api/session/<id>/metrics (handleSessionMetrics) derives from it.
	CPUMs           int64                    `json:"cpu_ms,omitempty"`
	WorkingSetBytes int64                    `json:"working_set_bytes,omitempty"`
	PeakRSSBytes    int64                    `json:"peak_rss_bytes,omitempty"`
	ReadBytes       int64                    `json:"read_bytes,omitempty"`
	WriteBytes      int64                    `json:"write_bytes,omitempty"`
	ThreadCount     int32                    `json:"thread_count,omitempty"`
	HandleCount     int32                    `json:"handle_count,omitempty"`
	MetricSamples   []procmodel.MetricSample `json:"metric_samples,omitempty"`
	NetworkCount    int                      `json:"network_count,omitempty"`

	Children []ProcessNode `json:"children"`
}

// correlateMinInterval debounces the per-session correlation passes run from
// handleSessionProcesses (see Server.lastCorrelate). The Processes drawer polls
// that endpoint every few seconds while open; re-running the cross-OS + action-
// link WRITE passes on every poll scaled with the unattributed-row backlog and
// slowed the UI. ~30s freshness is plenty (a newly ingested action/session links
// on the next eligible poll) and keeps the writes off the hot poll path.
const correlateMinInterval = 30 * time.Second

// shouldCorrelate reports whether enough time has passed since the last
// correlation pass for this session to run another, recording "now" when it
// returns true. Concurrency-safe — the drawer may have several polls in flight.
func (s *Server) shouldCorrelate(sessionID string) bool {
	s.correlateMu.Lock()
	defer s.correlateMu.Unlock()
	now := s.now()
	if last, ok := s.lastCorrelate[sessionID]; ok && now.Sub(last) < correlateMinInterval {
		return false
	}
	s.lastCorrelate[sessionID] = now
	return true
}

// handleSessionProcesses serves /api/session/<id>/processes. It refreshes the
// §9.2.4 action links lazily (so a process shows the command that spawned it
// even if the action was ingested after the process event), then returns the
// attributed process tree. Empty result is a valid empty tree, not an error.
func (s *Server) handleSessionProcesses(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())

	// Correlation refresh — debounced per session (the drawer polls this every
	// few seconds; these are WRITE passes). Cross-OS first (§5.5: attribute the
	// Windows bridge subtree to this session), then the §9.2.4 action links on
	// the now-attributed rows. The read below is always served fresh, so a poll
	// that skips correlation still returns current data.
	if s.shouldCorrelate(sessionID) {
		_, _ = st.CorrelateCrossOS(ctx, sessionID)
		_, _ = st.CorrelateProcessActions(ctx, sessionID)
		// Materialize action-derived command rows for the commands the OS
		// poll backend missed (sub-interval, born-and-died-between-ticks) —
		// AFTER the OS-link pass so a captured process always wins and a
		// derived row is only synthesized where no real process exists
		// (docs/process-observability.md §9.2.4).
		_, _ = st.DeriveProcessRunsFromActions(ctx, sessionID)
	}

	// The window (process capture budget plan §9.3): the newest `limit` rows
	// by default (2000, capped at 10000), or the rows in from/to, or only the
	// rows seen since `since`. Never the whole history: a busy session holds
	// tens of thousands of rows and their metric rings.
	win, err := parseProcessWindow(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	total, _, err := st.ProcessSessionRowMark(ctx, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("count process runs: %v", err), http.StatusInternalServerError)
		return
	}
	var runs []store.ProcessRunRow
	var truncated bool
	var findings []store.ProcessFindingRow
	if total > 0 {
		res, err := st.ProcessRunsWindowForSession(ctx, sessionID, win)
		if err != nil {
			http.Error(w, fmt.Sprintf("load process runs: %v", err), http.StatusInternalServerError)
			return
		}
		runs, truncated = res.Rows, res.Truncated
		// Observe-only side-effect flags for the drawer (§13.1 / §14), over
		// the same window. Best-effort - a findings error never blocks the
		// tree.
		findings, _ = st.ProcessFindingsForSessionWindow(ctx, sessionID, win)
	} else {
		// Cold-storage fallback (corpus archival P3.5). Only on a hot MISS: a
		// session with live rows is answered entirely from the hot database,
		// and an archived one is answered from the archive file for this one
		// request, with no write-back. The window applies the same way.
		archived := s.archivedProcessRuns(ctx, sessionID)
		total = int64(len(archived))
		runs, truncated = windowArchivedRuns(archived, win)
	}
	cmds, err := st.ActionCommandsForSession(ctx, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load action commands: %v", err), http.StatusInternalServerError)
		return
	}
	msgIDs, err := st.ActionMessageIDsForSession(ctx, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load action message ids: %v", err), http.StatusInternalServerError)
		return
	}
	// Default to an empty slice so the JSON shape stays `"findings": []`.
	if findings == nil {
		findings = []store.ProcessFindingRow{}
	}
	networkEvents, _ := st.NetworkEventsForSession(ctx, sessionID, 500)
	networkCounts := map[string]int{}
	proxyOnlyNetworkEvents := 0
	for _, ev := range networkEvents {
		if ev.ProcessKey != "" {
			networkCounts[ev.ProcessKey]++
		}
		if strings.HasPrefix(ev.ProcessKey, "proxy:") {
			proxyOnlyNetworkEvents++
		}
	}
	cfg, _ := loadConfigForDashboard(s.opts.ConfigPath)

	writeJSON(w, SessionProcessResponse{
		SessionID:    sessionID,
		Total:        int(total),
		NetworkTotal: len(networkEvents),
		Roots:        buildProcessTree(runs, cmds, msgIDs, networkCounts),
		Findings:     findings,
		Diagnostics:  buildProcessDiagnostics(cfg, s.opts.ConfigPath != "", int(total), len(networkEvents), proxyOnlyNetworkEvents),
		Truncated:    truncated,
		Window:       processWindowInfo(win, runs),
	})
}

// processWindowInfo describes the window a tree response covers: the
// requested bounds, or (for an open bound) the start of the oldest / newest
// row returned, plus the effective limit and the rows returned.
func processWindowInfo(w store.ProcessRunWindow, runs []store.ProcessRunRow) *ProcessWindowInfo {
	info := &ProcessWindowInfo{Limit: w.Limit, Returned: len(runs)}
	if !w.From.IsZero() {
		info.From = w.From.UTC().Format(time.RFC3339)
	} else if len(runs) > 0 {
		info.From = startedAtISO(runs[0].StartedAt)
	}
	if !w.To.IsZero() {
		info.To = w.To.UTC().Format(time.RFC3339)
	} else if len(runs) > 0 {
		info.To = startedAtISO(runs[len(runs)-1].StartedAt)
	}
	return info
}

func buildProcessDiagnostics(cfg config.Config, configWritable bool, processRows, networkEvents, proxyOnlyNetworkEvents int) ProcessDiagnostics {
	captureBodies := cfg.Observer.Process.Network.CaptureBodies
	bodyCapture := captureBodies == "proxied" || captureBodies == "available"
	reasons := []string{}
	if !cfg.Observer.Process.Enabled {
		reasons = append(reasons, "process_disabled")
	}
	if cfg.Observer.Process.Backend == "off" {
		reasons = append(reasons, "process_backend_off")
	}
	if !cfg.Observer.Process.Network.Enabled {
		reasons = append(reasons, "process_network_disabled")
	}
	if cfg.Observer.Process.Network.Enabled && !bodyCapture {
		reasons = append(reasons, "network_body_capture_disabled")
	}
	if processRows == 0 && networkEvents == 0 {
		reasons = append(reasons, "no_session_process_or_network_rows")
	}
	if processRows == 0 && networkEvents > 0 {
		reasons = append(reasons, "proxy_only_network_events")
	}
	if processRows == 0 && cfg.Observer.Process.Enabled {
		reasons = append(reasons, "no_live_process_rows")
	}
	return ProcessDiagnostics{
		ProcessEnabled:              cfg.Observer.Process.Enabled,
		ProcessBackend:              cfg.Observer.Process.Backend,
		ProcessNetworkEnabled:       cfg.Observer.Process.Network.Enabled,
		ProcessNetworkCaptureBodies: captureBodies,
		ProcessNetworkBodyCapture:   bodyCapture,
		ConfigWritable:              configWritable,
		RestartRequired:             true,
		ProcessRows:                 processRows,
		NetworkEvents:               networkEvents,
		ProxyOnlyNetworkEvents:      proxyOnlyNetworkEvents,
		ReasonCodes:                 reasons,
		ProcessSettingsURL:          "/settings?section=process",
		ProxySettingsURL:            "/settings?section=proxy",
		BackfillSettingsURL:         "/settings?section=backfill",
		RestartSettingsURL:          "/settings?section=health",
	}
}

// --- Session resource metrics (GET /api/session/<id>/metrics) --------------
//
// The per-process ring buffer on process_runs.metric_samples_json is the raw
// substrate (procmodel.MetricSample). It is NOT directly plottable:
//
//   - cpu_ms / rb / wb are CUMULATIVE MONOTONIC counters — plotted raw they
//     are a straight ramp, never a "CPU %" or a "B/s". They must be
//     DIFFERENTIATED.
//   - ws (working set / RSS) is INSTANTANEOUS — it must be SUMMED across live
//     processes and never differentiated.
//   - Sample timestamps are per-process and UNALIGNED across the tree, so any
//     subtree aggregate requires bucketing onto a common grid first.
//
// This endpoint does that work server-side and returns a plottable series, so
// the UI never re-derives rates from counters.

// SessionMetricsResponse is the /api/session/<id>/metrics payload: the
// subtree-aggregated, differentiated resource series for a session, plus the
// metadata a client needs to render it honestly (bucket size, actual window
// covered, contributing process counts, whether the in-memory ring truncated
// the window, and which series are actually measured on this host).
type SessionMetricsResponse struct {
	SessionID string `json:"session_id"`
	// BucketMs is the width of one point. Either the caller's ?bucket= or, by
	// default, derived from the OBSERVED sampling cadence — never a hardcoded
	// constant, so a change to the capture interval flows through.
	BucketMs int64 `json:"bucket_ms"`
	// SampleIntervalMs is the observed median gap between consecutive samples
	// (0 when not derivable). It is what BucketMs is derived from.
	SampleIntervalMs int64 `json:"sample_interval_ms"`
	// From/To bound the window actually covered by data (RFC3339 UTC): From is
	// the first bucket's start, To the last bucket's end. Empty when no points.
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	WindowMs int64  `json:"window_ms"`
	// Points is always non-nil. Buckets inside the window with no coverage are
	// still emitted, with null metric values, so a sampling gap renders as a
	// GAP rather than silently compressing the time base.
	Points []SessionMetricPoint `json:"points"`
	// Processes counts every attributed process run; SampledProcesses those
	// carrying at least one metric sample; RateProcesses those carrying at
	// least two (the only ones from which a rate is derivable at all).
	Processes        int `json:"processes"`
	SampledProcesses int `json:"sampled_processes"`
	RateProcesses    int `json:"rate_processes"`
	// WindowTruncated reports that at least one process's ring had already
	// evicted older samples (its first retained sample is materially later
	// than the process start), i.e. the window shown is SHORTER than the
	// process's life. The ring is in-memory in the Attributor and resets when
	// the daemon restarts.
	WindowTruncated bool `json:"window_truncated"`
	// CPUScale names the CPU unit: "per_core_sum" means cpu_pct is the sum of
	// per-process (Δcpu_ms / Δwall_ms × 100), i.e. percent of ONE core. A
	// multi-threaded process legitimately exceeds 100; the ceiling is
	// cpu_cores × 100. Values are NOT clamped — clamping would hide sampling
	// skew. CPUCores is the daemon host's core count, for labelling only.
	CPUScale string `json:"cpu_scale"`
	CPUCores int    `json:"cpu_cores"`
	// Series says which of the series are actually measured. A false flag
	// means "not measured", NOT "measured as zero" — clients must omit that
	// chart rather than draw a flat zero line.
	Series MetricSeriesAvailability `json:"series"`
	// ProcessEnabled mirrors [observer.process].enabled so an empty payload
	// can explain itself without a second request.
	ProcessEnabled bool `json:"process_enabled"`
	// Reason is a machine-readable code for an EMPTY series (see
	// metricsReasonRules); empty string when points were returned.
	Reason string `json:"reason,omitempty"`
}

// SessionMetricPoint is one bucket of the aggregated series. Every rate field
// is a pointer: nil means "no coverage in this bucket" (a real gap), which is
// materially different from 0 ("covered, and idle"). The network fields are
// omitted entirely on hosts where the counters were never measured (no eBPF
// socket accounting attached), so an unmeasured host is absent rather than
// zero.
type SessionMetricPoint struct {
	// T is the bucket START, RFC3339 UTC.
	T string `json:"t"`
	// CPUPct is percent of one core, summed across the subtree (see CPUScale).
	CPUPct *float64 `json:"cpu_pct"`
	// RSSBytes is the instantaneous working set SUMMED across the processes
	// observed in this bucket. Never differentiated.
	RSSBytes *int64 `json:"rss_bytes"`
	// ReadBps/WriteBps/DiskBps are differentiated disk counters in bytes/sec;
	// DiskBps is read+write (what the compact chart plots, with the split in
	// its tooltip).
	ReadBps  *float64 `json:"read_bps"`
	WriteBps *float64 `json:"write_bps"`
	DiskBps  *float64 `json:"disk_bps"`
	// NetRxBps/NetTxBps are differentiated per-process network counters in
	// bytes/sec, sourced from eBPF socket accounting and therefore TCP
	// PAYLOAD bytes only — a QUIC/UDP-heavy workload legitimately reads near
	// zero. There is no combined field: the client sums the covered halves
	// itself. Absent (omitted) when unmeasured, which is NOT zero traffic.
	NetRxBps *float64 `json:"net_rx_bps,omitempty"`
	NetTxBps *float64 `json:"net_tx_bps,omitempty"`
	// Procs is how many processes contributed any data to this bucket.
	Procs int `json:"procs"`
}

// MetricSeriesAvailability reports, per series, whether the underlying counter
// was actually measured anywhere in the window. Adding a series here is
// additive: an older client ignores the new key.
type MetricSeriesAvailability struct {
	CPU     bool `json:"cpu"`
	RSS     bool `json:"rss"`
	Disk    bool `json:"disk"`
	Network bool `json:"network"`
}

// metricKind discriminates how a sampled field is reduced onto the bucket
// grid. This is the ONE place the counter-vs-gauge distinction lives.
type metricKind int

const (
	// metricCounter is cumulative and monotonic: it is DIFFERENTIATED
	// (Δvalue ÷ Δwall) and a decrease is treated as a counter reset.
	metricCounter metricKind = iota
	// metricGauge is instantaneous: it is SUMMED across processes and never
	// differentiated.
	metricGauge
)

// metricSpec is one row of the metric table (CLAUDE.md rule 5: decision logic
// is a data table walked top-down, not a nested conditional). The bucketing,
// differentiation, reset handling and availability reporting are all generic
// over this table — adding a series is ONE row plus its read function.
type metricSpec struct {
	// ID keys the accumulators; it is internal, not wire-visible.
	ID   string
	Kind metricKind
	// Read extracts the raw value from a sample. ok=false means "this host /
	// capture backend does not measure it", which propagates to
	// MetricSeriesAvailability as false so the client omits the chart instead
	// of drawing a misleading flat zero.
	Read func(procmodel.MetricSample) (int64, bool)
	// Scale converts the per-millisecond rate into the reported unit:
	// 100 → percent of one core (ms of CPU per ms of wall), 1000 → per second.
	// Ignored for gauges.
	Scale float64
}

const (
	metricIDCPU   = "cpu"
	metricIDRead  = "read"
	metricIDWrite = "write"
	metricIDNetRx = "net_rx"
	metricIDNetTx = "net_tx"
	metricIDRSS   = "rss"
)

// metricSpecs is the table. Order is irrelevant (every row is independent);
// only the ID/Kind/Read/Scale tuple matters.
var metricSpecs = []metricSpec{
	{ID: metricIDCPU, Kind: metricCounter, Scale: 100, Read: func(s procmodel.MetricSample) (int64, bool) { return s.CPUMs, true }},
	{ID: metricIDRead, Kind: metricCounter, Scale: 1000, Read: func(s procmodel.MetricSample) (int64, bool) { return s.ReadBytes, true }},
	{ID: metricIDWrite, Kind: metricCounter, Scale: 1000, Read: func(s procmodel.MetricSample) (int64, bool) { return s.WriteBytes, true }},
	{ID: metricIDNetRx, Kind: metricCounter, Scale: 1000, Read: sampleNetworkRx},
	{ID: metricIDNetTx, Kind: metricCounter, Scale: 1000, Read: sampleNetworkTx},
	{ID: metricIDRSS, Kind: metricGauge, Read: func(s procmodel.MetricSample) (int64, bool) { return s.WorkingSet, true }},
}

// sampleNetworkRx reads a per-process cumulative received-bytes counter off a
// metric sample, gated on NetMeasured: procmodel.MetricSample.NetRxBytes is
// only meaningful when NetMeasured is true (live eBPF socket accounting
// attached), so an unmeasured sample reports ok=false — never an inferred
// zero — exactly like every other Read in metricSpecs. That keeps the general
// machinery honest for network too: measurableCounters only flips
// MetricSeriesAvailability.Network on once some process somewhere shows a
// real, measured, nonzero byte count, and a client sees an absent network
// chart rather than a flat zero line for a host that never measured it.
//
// Mixed availability within one process's ring (e.g. probes attach partway
// through a long-lived process, or a daemon restart re-attaches them) is
// handled entirely by the existing PER-PAIR gate in accumulateCounters: a
// consecutive sample pair needs BOTH pv/cv to read ok before it is
// differentiated. A pair straddling a measured→unmeasured (or vice versa)
// transition therefore contributes no rate for that interval — same as an
// unmeasured-host pair — so the series has an honest gap across the
// transition instead of a diluted or fabricated rate; pairs fully inside the
// measured span still differentiate normally. No extra handling was needed
// here: the counter-vs-gauge table was already built to make per-sample
// availability changes safe.
func sampleNetworkRx(s procmodel.MetricSample) (int64, bool) { return s.NetRxBytes, s.NetMeasured }

// sampleNetworkTx is the transmitted-bytes counterpart of sampleNetworkRx.
func sampleNetworkTx(s procmodel.MetricSample) (int64, bool) { return s.NetTxBytes, s.NetMeasured }

// procMetricSeries is one process's sample ring plus the lifecycle facts the
// aggregator needs. It is a plain value — the aggregation below touches no
// SQL, no HTTP and no clock, so it is unit-testable on its own.
type procMetricSeries struct {
	Key       string
	StartedAt time.Time
	Exited    bool
	Samples   []procmodel.MetricSample
}

const (
	// metricsMaxPoints caps the returned series length; the bucket is widened
	// until the window fits.
	metricsMaxPoints = 120
	// metricsTargetPoints is the point count aimed for when no sampling
	// cadence can be observed.
	metricsTargetPoints = 40
	// metricsMinBucket / metricsMaxBucket clamp both the caller's ?bucket= and
	// the derived default.
	metricsMinBucket = time.Second
	metricsMaxBucket = time.Hour
	// metricsMaxPairSpanBuckets bounds how far apart two consecutive samples
	// may be and still yield a rate. Beyond it the pair is a SAMPLING GAP: we
	// cannot know when within a long silence the CPU/disk was consumed, so
	// smearing the delta evenly would invent a plateau. Dropped ⇒ a gap.
	metricsMaxPairSpanBuckets = 8
)

// metricsAggregate is the pure aggregation result, lifted out of the HTTP
// response so it can be asserted directly in tests.
type metricsAggregate struct {
	Points           []SessionMetricPoint
	BucketMs         int64
	SampleIntervalMs int64
	From             time.Time
	To               time.Time
	SampledProcesses int
	RateProcesses    int
	WindowTruncated  bool
	Series           MetricSeriesAvailability
}

// counterAcc accumulates one metric's differentiated contribution to one
// bucket. Rate is already per-millisecond and already summed across
// processes — each process contributes its OWN Δvalue ÷ its OWN covered wall
// time, so a process with partial coverage in a bucket is not diluted by the
// bucket's full width.
type counterAcc struct {
	rate     float64
	measured bool
}

// bucketAcc is one bucket of the common grid.
type bucketAcc struct {
	counters map[string]*counterAcc
	gauges   map[string]int64
	gaugeSet map[string]bool
	procs    map[string]struct{}
}

func newBucketAcc() *bucketAcc {
	return &bucketAcc{
		counters: map[string]*counterAcc{},
		gauges:   map[string]int64{},
		gaugeSet: map[string]bool{},
		procs:    map[string]struct{}{},
	}
}

// aggregateProcessMetrics is the pure core: it buckets every process's ring
// onto a common grid, differentiates the cumulative counters, sums the
// instantaneous gauges, and reports which series were measured at all.
//
// bucket <= 0 selects the bucket from the observed sampling cadence.
//
// Differentiation traps handled here, all of them by construction:
//   - A process with a SINGLE sample yields no pair, hence no rate. It still
//     contributes its instantaneous RSS.
//   - A process that STARTS mid-window has no prior sample for its first
//     reading, so that reading is a baseline only — never a Δ against an
//     implicit zero (which would spike the first bucket by the process's
//     entire lifetime CPU).
//   - A process that EXITS mid-window simply stops contributing after its last
//     sample: no phantom trailing zeros, no negative delta, and the subtree
//     total falls because the process genuinely stopped consuming.
//   - A COUNTER RESET (Δ < 0, e.g. a recycled pid or a capture restart) drops
//     that pair for that metric only — the other metrics of the same pair
//     still count.
//   - A pair spanning more than metricsMaxPairSpanBuckets is a sampling gap
//     and is dropped rather than smeared.
func aggregateProcessMetrics(series []procMetricSeries, bucket time.Duration) metricsAggregate {
	return aggregateWithFacts(series, factsOf(series), bucket)
}

// aggregateWithFacts is aggregateProcessMetrics with the whole-session facts
// supplied separately. f must describe EVERY series of the session; series
// may omit any series whose samples all fall before the grid floor (see
// metricsGrid), because such a series contributes nothing to any bucket. That
// is what lets the handler hand over only the unsettled tail of a long
// session (loadSessionMetricSeries) and still produce the identical result.
func aggregateWithFacts(series []procMetricSeries, f metricsFacts, bucket time.Duration) metricsAggregate {
	out := metricsAggregate{Points: []SessionMetricPoint{}}
	sampleInterval := f.sampleInterval()
	out.SampleIntervalMs = sampleInterval.Milliseconds()
	out.SampledProcesses = f.sampled
	out.RateProcesses = f.rated
	out.WindowTruncated = f.truncated(sampleInterval)

	bucket, floorIdx, ok := metricsGrid(f, bucket)
	out.BucketMs = bucket.Milliseconds()
	if !ok {
		return out
	}

	grid := map[int64]*bucketAcc{}
	// at returns the accumulator for a bucket, or nil for a bucket below the
	// floor (callers skip it).
	at := func(idx int64) *bucketAcc {
		if idx < floorIdx {
			return nil
		}
		b, okb := grid[idx]
		if !okb {
			b = newBucketAcc()
			grid[idx] = b
		}
		return b
	}

	for _, s := range series {
		accumulateSeries(s, bucket, floorIdx, f.measurable, at)
	}
	if len(grid) == 0 {
		return out
	}

	minIdx, maxIdx := gridBounds(grid)
	// Anchor the reported window to the first bucket with RATE coverage when
	// any exists. A session's tree is dominated by short-lived, single-sample
	// commands (measured live: 455 sampled processes, only 33 with the two
	// samples a rate needs), and their lone readings stretch the grid across
	// the whole session — which would render the CPU/disk lines as a mostly
	// empty strip with a live sliver at the end. Buckets before the first rate
	// are gauge-only observations of processes that have since exited; dropping
	// them narrows the window to the continuously-observed span, and From/To
	// report that span, so nothing is claimed about what came before. With no
	// rate coverage at all (every process sampled once) the full gauge span is
	// kept — that is then genuinely all there is.
	if rateIdx, okRate := firstRateBucket(grid, minIdx, maxIdx); okRate {
		minIdx = rateIdx
	}
	for idx := minIdx; idx <= maxIdx; idx++ {
		out.Points = append(out.Points, pointFor(idx, bucket, grid[idx], &out.Series))
	}
	out.From = bucketStart(minIdx, bucket)
	out.To = bucketStart(maxIdx, bucket).Add(bucket)
	return out
}

// accumulateSeries folds one process's samples into the shared grid: the
// counter pairs differentiated and overlap-weighted, the gauges carried
// forward across the buckets the process was observed in.
func accumulateSeries(s procMetricSeries, bucket time.Duration, floorIdx int64, measurable map[string]bool, at func(int64) *bucketAcc) {
	if len(s.Samples) == 0 {
		return
	}
	accumulateCounters(s, bucket, measurable, at)
	accumulateGauges(s, bucket, floorIdx, at)
}

// metricsFacts are the whole-session facts the series depends on beyond the
// grid itself: the sample-interval gaps the default bucket is derived from,
// the contributing process counts, which counters are measurable, the ring
// truncation evidence and the sample bounds. Every field is a merge-able
// summary (a count, an OR, a max, a min/max, a sorted multiset), so the facts
// of a session are the merge of the facts of any partition of its series:
// the handler keeps the facts of the settled rows and merges in the tail's.
// A value is treated as immutable once built (merge returns a new one), so a
// cached value can be shared across concurrent requests.
type metricsFacts struct {
	// gaps holds every positive gap between consecutive samples of one
	// process, sorted ascending.
	gaps []time.Duration
	// sampled / rated count the series with at least one / two samples.
	sampled, rated int
	// measurable reports which cumulative counters actually carry data: a
	// counter that reads ZERO in every sample of every process is treated as
	// NOT MEASURED rather than as "measured, and idle".
	//
	// This is deliberate. A capture backend that does not populate a counter
	// leaves it at zero, and from the sample alone that is indistinguishable
	// from a process that genuinely did no I/O. Reporting it as measured would
	// put a flat zero line on screen — which reads as a confident "no disk
	// traffic" when the honest answer is "this host does not measure it". The
	// cost is that a genuinely, perfectly idle counter is reported unmeasured;
	// that under-claims rather than over-claims, which is the right direction.
	measurable map[string]bool
	// maxLead is the largest gap between a process's start and its oldest
	// RETAINED sample (hasLead: at least one such gap was measurable). See
	// truncated.
	maxLead time.Duration
	hasLead bool
	// first / last bound every non-zero sample timestamp (hasBounds: any).
	first, last time.Time
	hasBounds   bool
}

// factsOf computes the facts of a set of series.
func factsOf(series []procMetricSeries) metricsFacts {
	f := metricsFacts{measurable: map[string]bool{}}
	for _, s := range series {
		if len(s.Samples) > 0 {
			f.sampled++
		}
		if len(s.Samples) > 1 {
			f.rated++
		}
		for i := 1; i < len(s.Samples); i++ {
			if d := s.Samples[i].T.Sub(s.Samples[i-1].T); d > 0 {
				f.gaps = append(f.gaps, d)
			}
		}
		for _, sm := range s.Samples {
			if sm.T.IsZero() {
				continue
			}
			if !f.hasBounds || sm.T.Before(f.first) {
				f.first = sm.T
			}
			if !f.hasBounds || sm.T.After(f.last) {
				f.last = sm.T
			}
			f.hasBounds = true
		}
		if len(s.Samples) > 0 && !s.StartedAt.IsZero() && !s.Samples[0].T.IsZero() {
			if lead := s.Samples[0].T.Sub(s.StartedAt); !f.hasLead || lead > f.maxLead {
				f.maxLead, f.hasLead = lead, true
			}
		}
		for _, m := range metricSpecs {
			if m.Kind == metricCounter && !f.measurable[m.ID] && anySampleNonZero(s.Samples, m.Read) {
				f.measurable[m.ID] = true
			}
		}
	}
	sort.Slice(f.gaps, func(i, j int) bool { return f.gaps[i] < f.gaps[j] })
	return f
}

// merge returns the facts of the union of the series f and g describe. It
// never mutates either operand.
func (f metricsFacts) merge(g metricsFacts) metricsFacts {
	out := metricsFacts{
		gaps:    mergeSortedDurations(f.gaps, g.gaps),
		sampled: f.sampled + g.sampled,
		rated:   f.rated + g.rated,
	}
	out.measurable = make(map[string]bool, len(f.measurable)+len(g.measurable))
	for id, ok := range f.measurable {
		out.measurable[id] = out.measurable[id] || ok
	}
	for id, ok := range g.measurable {
		out.measurable[id] = out.measurable[id] || ok
	}
	out.maxLead, out.hasLead = f.maxLead, f.hasLead
	if g.hasLead && (!out.hasLead || g.maxLead > out.maxLead) {
		out.maxLead, out.hasLead = g.maxLead, true
	}
	out.first, out.last, out.hasBounds = f.first, f.last, f.hasBounds
	if g.hasBounds {
		if !out.hasBounds || g.first.Before(out.first) {
			out.first = g.first
		}
		if !out.hasBounds || g.last.After(out.last) {
			out.last = g.last
		}
		out.hasBounds = true
	}
	return out
}

// mergeSortedDurations merges two ascending slices into a new ascending one
// (or returns an operand unchanged when the other is empty; operands are
// never written).
func mergeSortedDurations(a, b []time.Duration) []time.Duration {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	out := make([]time.Duration, 0, len(a)+len(b))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if b[j] < a[i] {
			out = append(out, b[j])
			j++
			continue
		}
		out = append(out, a[i])
		i++
	}
	out = append(out, a[i:]...)
	return append(out, b[j:]...)
}

// sampleInterval is the observed median gap between consecutive samples
// across every process (0 when none). It is the ONLY source for the default
// bucket width — nothing here hardcodes the capture cadence, so raising the
// sampling frequency automatically tightens the buckets.
func (f metricsFacts) sampleInterval() time.Duration {
	if len(f.gaps) == 0 {
		return 0
	}
	return f.gaps[len(f.gaps)/2]
}

// truncated reports that at least one process's ring has already evicted
// samples: its oldest RETAINED sample starts materially after the process
// did, so the window shown is shorter than the process's life. The tolerance
// is derived from the observed cadence — the ring capacity constant is
// deliberately not referenced here. Because the tolerance is one value for
// the whole session, "any process exceeds it" is "the largest lead exceeds
// it", which is why the facts keep only the max.
func (f metricsFacts) truncated(sampleInterval time.Duration) bool {
	if !f.hasLead {
		return false
	}
	slack := 2 * sampleInterval
	if slack < 5*time.Second {
		slack = 5 * time.Second
	}
	return f.maxLead > slack
}

// metricsGrid resolves the bucket width and the grid floor (the lowest bucket
// index the series is accumulated into) from the whole-session facts. The
// floor keeps the grid at the most recent metricsMaxPoints buckets: the
// derived bucket already fits the window, but an explicit ?bucket= is honored
// as asked, so this is what keeps a fine bucket over a long session bounded:
// the newest slice of the window is returned and From reports it honestly.
// ok=false when there is no sample at all (the bucket is then just the
// clamped request).
func metricsGrid(f metricsFacts, bucket time.Duration) (time.Duration, int64, bool) {
	if !f.hasBounds {
		return clampBucket(bucket), 0, false
	}
	bucket = chooseBucket(bucket, f.sampleInterval(), f.last.Sub(f.first))
	floorIdx := bucketIndex(f.first, bucket)
	if lastIdx := bucketIndex(f.last, bucket); lastIdx-floorIdx+1 > metricsMaxPoints {
		floorIdx = lastIdx - metricsMaxPoints + 1
	}
	return bucket, floorIdx, true
}

// localAcc is one process's own Δ and covered wall time inside one bucket for
// one metric. The per-process denominator is the point: a process's bucket
// rate is ITS delta over ITS covered time, so partial coverage (a process that
// started or exited mid-bucket, or a bucket wider than the sample interval) is
// exact rather than diluted by the bucket's full width — and several pairs
// landing in the same bucket accumulate into ONE rate instead of summing into
// a multiple of it.
type localAcc struct {
	delta  float64
	wallMs float64
}

// accumulateCounters differentiates each consecutive sample PAIR and spreads
// the resulting delta over the buckets the pair overlaps, weighted by overlap
// time. Per-process bucket rates are then summed across the subtree.
func accumulateCounters(s procMetricSeries, bucket time.Duration, measurable map[string]bool, at func(int64) *bucketAcc) {
	maxSpan := time.Duration(metricsMaxPairSpanBuckets) * bucket
	local := map[int64]map[string]*localAcc{}
	touched := map[int64]bool{}
	for i := 1; i < len(s.Samples); i++ {
		prev, cur := s.Samples[i-1], s.Samples[i]
		span := cur.T.Sub(prev.T)
		// Non-advancing or backwards timestamps yield no rate; an over-long
		// span is a sampling gap (see metricsMaxPairSpanBuckets).
		if span <= 0 || span > maxSpan {
			continue
		}
		spanMs := float64(span) / float64(time.Millisecond)
		for _, m := range metricSpecs {
			if m.Kind != metricCounter || !measurable[m.ID] {
				continue
			}
			pv, pok := m.Read(prev)
			cv, cok := m.Read(cur)
			if !pok || !cok {
				continue // not measured on this host
			}
			delta := cv - pv
			if delta < 0 {
				continue // counter reset — drop this pair for this metric only
			}
			forEachBucketOverlap(prev.T, cur.T, bucket, func(idx int64, overlapMs float64) {
				if overlapMs <= 0 {
					return
				}
				byMetric, okm := local[idx]
				if !okm {
					byMetric = map[string]*localAcc{}
					local[idx] = byMetric
				}
				a, oka := byMetric[m.ID]
				if !oka {
					a = &localAcc{}
					byMetric[m.ID] = a
				}
				// The pair's rate is constant across its span, so the share of
				// the delta falling in this bucket is proportional to overlap.
				a.delta += float64(delta) * (overlapMs / spanMs)
				a.wallMs += overlapMs
				touched[idx] = true
			})
		}
	}
	for idx, byMetric := range local {
		b := at(idx)
		if b == nil {
			continue
		}
		for id, a := range byMetric {
			if a.wallMs <= 0 {
				continue
			}
			acc, okc := b.counters[id]
			if !okc {
				acc = &counterAcc{}
				b.counters[id] = acc
			}
			acc.rate += a.delta / a.wallMs
			acc.measured = true
		}
		if touched[idx] {
			b.procs[s.Key] = struct{}{}
		}
	}
}

// accumulateGauges sums each instantaneous gauge across processes. Within the
// span the process was actually observed (first→last sample) the most recent
// reading is carried forward, so an unaligned or slightly slower-sampling
// sibling does not punch a phantom dip in the subtree total. Nothing is
// carried past the last sample: beyond it the value is unknown, not zero.
func accumulateGauges(s procMetricSeries, bucket time.Duration, floorIdx int64, at func(int64) *bucketAcc) {
	firstIdx := bucketIndex(s.Samples[0].T, bucket)
	if firstIdx < floorIdx {
		firstIdx = floorIdx
	}
	lastIdx := bucketIndex(s.Samples[len(s.Samples)-1].T, bucket)
	for _, m := range metricSpecs {
		if m.Kind != metricGauge {
			continue
		}
		// A process whose gauge is zero for every sample is not measured on
		// this backend; counting it would drag a summed total down.
		if !anySampleNonZero(s.Samples, m.Read) {
			continue
		}
		si := 0
		for idx := firstIdx; idx <= lastIdx; idx++ {
			// Buckets are half-open [start, start+bucket): a sample landing
			// exactly on the boundary belongs to the NEXT bucket, so the
			// advance test is strictly Before(end).
			end := bucketStart(idx, bucket).Add(bucket)
			for si+1 < len(s.Samples) && s.Samples[si+1].T.Before(end) {
				si++
			}
			v, okv := m.Read(s.Samples[si])
			if !okv {
				continue
			}
			b := at(idx)
			if b == nil {
				continue
			}
			b.gauges[m.ID] += v
			b.gaugeSet[m.ID] = true
			b.procs[s.Key] = struct{}{}
		}
	}
}

func anySampleNonZero(samples []procmodel.MetricSample, read func(procmodel.MetricSample) (int64, bool)) bool {
	for _, s := range samples {
		if v, ok := read(s); ok && v != 0 {
			return true
		}
	}
	return false
}

// pointFor renders one grid bucket, updating the availability flags as it
// goes. A bucket with no coverage still yields a point (with nil values) so
// the time base stays honest and the gap renders as a gap.
func pointFor(idx int64, bucket time.Duration, b *bucketAcc, avail *MetricSeriesAvailability) SessionMetricPoint {
	p := SessionMetricPoint{T: bucketStart(idx, bucket).UTC().Format(time.RFC3339)}
	if b == nil {
		return p
	}
	p.Procs = len(b.procs)
	if v, ok := counterValue(b, metricIDCPU); ok {
		avail.CPU = true
		p.CPUPct = round2(v)
	}
	if b.gaugeSet[metricIDRSS] {
		avail.RSS = true
		v := b.gauges[metricIDRSS]
		p.RSSBytes = &v
	}
	rd, rok := counterValue(b, metricIDRead)
	wr, wok := counterValue(b, metricIDWrite)
	if rok || wok {
		avail.Disk = true
		if rok {
			p.ReadBps = round2(rd)
		}
		if wok {
			p.WriteBps = round2(wr)
		}
		p.DiskBps = round2(rd + wr)
	}
	rx, rxok := counterValue(b, metricIDNetRx)
	tx, txok := counterValue(b, metricIDNetTx)
	if rxok || txok {
		avail.Network = true
		if rxok {
			p.NetRxBps = round2(rx)
		}
		if txok {
			p.NetTxBps = round2(tx)
		}
	}
	return p
}

// counterValue returns a bucket's scaled rate for a metric id.
func counterValue(b *bucketAcc, id string) (float64, bool) {
	acc, ok := b.counters[id]
	if !ok || !acc.measured {
		return 0, false
	}
	for _, m := range metricSpecs {
		if m.ID == id {
			return acc.rate * m.Scale, true
		}
	}
	return 0, false
}

func round2(v float64) *float64 {
	r := math.Round(v*100) / 100
	return &r
}

// forEachBucketOverlap invokes fn once per bucket the half-open interval
// [t0, t1) touches, with the overlap in milliseconds. This is what makes
// UNALIGNED per-process timestamps aggregate correctly.
func forEachBucketOverlap(t0, t1 time.Time, bucket time.Duration, fn func(idx int64, overlapMs float64)) {
	if !t1.After(t0) {
		return
	}
	startIdx := bucketIndex(t0, bucket)
	endIdx := bucketIndex(t1.Add(-time.Nanosecond), bucket)
	for idx := startIdx; idx <= endIdx; idx++ {
		bs := bucketStart(idx, bucket)
		be := bs.Add(bucket)
		lo, hi := t0, t1
		if bs.After(lo) {
			lo = bs
		}
		if be.Before(hi) {
			hi = be
		}
		if !hi.After(lo) {
			continue
		}
		fn(idx, float64(hi.Sub(lo))/float64(time.Millisecond))
	}
}

// bucketIndex maps an instant onto the shared epoch-anchored grid. Anchoring
// to the epoch (rather than to the first sample) is what gives every process
// the SAME grid regardless of when it started sampling.
func bucketIndex(t time.Time, bucket time.Duration) int64 {
	if bucket <= 0 {
		bucket = metricsMinBucket
	}
	n := t.UnixNano()
	b := int64(bucket)
	if n < 0 {
		return -((-n + b - 1) / b)
	}
	return n / b
}

func bucketStart(idx int64, bucket time.Duration) time.Time {
	if bucket <= 0 {
		bucket = metricsMinBucket
	}
	return time.Unix(0, idx*int64(bucket)).UTC()
}

// firstRateBucket returns the lowest bucket index in [lo, hi] carrying any
// differentiated (counter) coverage, and whether one exists at all.
func firstRateBucket(grid map[int64]*bucketAcc, lo, hi int64) (int64, bool) {
	for idx := lo; idx <= hi; idx++ {
		b := grid[idx]
		if b == nil {
			continue
		}
		for _, acc := range b.counters {
			if acc.measured {
				return idx, true
			}
		}
	}
	return 0, false
}

func gridBounds(grid map[int64]*bucketAcc) (int64, int64) {
	first := true
	var lo, hi int64
	for idx := range grid {
		if first || idx < lo {
			lo = idx
		}
		if first || idx > hi {
			hi = idx
		}
		first = false
	}
	return lo, hi
}

// medianSampleInterval is the observed median gap between consecutive samples
// across every process (metricsFacts.sampleInterval over these series).
func medianSampleInterval(series []procMetricSeries) time.Duration {
	return factsOf(series).sampleInterval()
}

// chooseBucket resolves the bucket width:
//
//   - an explicit caller value wins (clamped);
//   - otherwise the OBSERVED sampling cadence, at full resolution. It is
//     deliberately NOT widened to fit a long session into the point cap: this
//     is a live panel, so temporal resolution matters more than total history,
//     and the cap instead trims the window to its most RECENT slice (see the
//     grid floor in aggregateProcessMetrics). A 4-hour session therefore shows
//     the last N minutes at capture resolution rather than the whole session
//     smeared into multi-minute buckets. Raising the capture frequency
//     tightens the buckets automatically — nothing here names an interval;
//   - with no cadence observable at all (every process sampled once) there is
//     no resolution to preserve, so the window is simply split into points.
func chooseBucket(explicit, sampleInterval, window time.Duration) time.Duration {
	if explicit > 0 {
		return clampBucket(explicit)
	}
	if sampleInterval > 0 {
		return clampBucket(sampleInterval)
	}
	b := clampBucket(window / metricsTargetPoints)
	for window > 0 && window/b > metricsMaxPoints && b < metricsMaxBucket {
		b *= 2
	}
	return clampBucket(b)
}

func clampBucket(b time.Duration) time.Duration {
	if b < metricsMinBucket {
		return metricsMinBucket
	}
	if b > metricsMaxBucket {
		return metricsMaxBucket
	}
	return b.Round(time.Second)
}

// metricsReasonInput is the (tiny) fact set the empty-series reason table is
// evaluated against.
type metricsReasonInput struct {
	ProcessEnabled   bool
	Processes        int
	SampledProcesses int
	RateProcesses    int
	Points           int
}

// metricsReasonRules is the ordered, table-driven explanation for an EMPTY
// series — first match wins. Being explicit about WHY there is nothing to plot
// is what stops the panel reading as "broken" when the honest answer is
// "capture is off" or "the first two samples haven't landed yet".
var metricsReasonRules = []struct {
	Code string
	When func(metricsReasonInput) bool
}{
	{"capture_disabled", func(in metricsReasonInput) bool { return !in.ProcessEnabled }},
	{"no_processes", func(in metricsReasonInput) bool { return in.Processes == 0 }},
	{"no_samples", func(in metricsReasonInput) bool { return in.SampledProcesses == 0 }},
	{"awaiting_second_sample", func(in metricsReasonInput) bool { return in.RateProcesses == 0 }},
	{"no_points", func(in metricsReasonInput) bool { return in.Points == 0 }},
}

// metricsReason walks metricsReasonRules top-down. A series with points needs
// no explanation.
func metricsReason(in metricsReasonInput) string {
	if in.Points > 0 {
		return ""
	}
	for _, r := range metricsReasonRules {
		if r.When(in) {
			return r.Code
		}
	}
	return ""
}

// metricSeriesFromRuns projects the metrics read's rows onto the pure
// aggregator's input, one series per row in the same order, defensively
// re-sorting each ring by timestamp (the ring is appended in order, but a
// rate derivation must never depend on that). The rows are ours (freshly
// decoded by the store), so the ring is sorted in place.
func metricSeriesFromRuns(runs []store.ProcessMetricRun) []procMetricSeries {
	out := make([]procMetricSeries, 0, len(runs))
	for _, r := range runs {
		samples := r.Samples
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].T.Before(samples[j].T) })
		out = append(out, procMetricSeries{
			Key:       r.ProcessKey,
			StartedAt: r.StartedAt,
			Exited:    r.Exited,
			Samples:   samples,
		})
	}
	return out
}

// --- Settled-facts cache for the metrics read -------------------------------
//
// A live session holds ~100k process rows, almost all of them processes that
// exited long ago. Reading and decoding every ring on each 5s poll made the
// endpoint scale with the whole session. Instead the facts of the SETTLED rows
// (not seen for a while: see settleAgeFor) are kept here, and each poll reads
// only the unsettled tail (store.ProcessMetricsForSession with the cached
// mark), merging the tail's facts in. The cache is a pure accelerator: a mark
// mismatch, a grid that reaches back into settled rows, or an evicted entry
// all fall back to a full read and yield the identical response.
//
// It is package state rather than a Server field only because the Server
// struct lives in dashboard.go; it is keyed by the *sql.DB, so two servers (or
// the demo DB swap) never share entries.

// metricsSettledKey identifies one session of one database.
type metricsSettledKey struct {
	db      *sql.DB
	session string
}

// metricsSettledEntry is one session's cached settled facts.
type metricsSettledEntry struct {
	// mark is the store's mark for the settled rows the facts cover.
	mark store.ProcessMetricsSettled
	// facts are the facts of exactly those rows.
	facts metricsFacts
	// settleAge is the age the next read settles rows at.
	settleAge time.Duration
}

const (
	// metricsSettledCacheMax bounds the cache; past it the cache starts over.
	metricsSettledCacheMax = 32
	// metricsMinSettleAge is the least time a row must have gone unseen,
	// relative to the session's newest sighting, before its facts are frozen.
	// The live window is a few minutes at the default bucket; settleAgeFor
	// raises the age when the grid reaches further back.
	metricsMinSettleAge = 10 * time.Minute
)

var metricsSettled struct {
	mu sync.Mutex
	m  map[metricsSettledKey]metricsSettledEntry
}

func metricsSettledGet(k metricsSettledKey) (metricsSettledEntry, bool) {
	metricsSettled.mu.Lock()
	defer metricsSettled.mu.Unlock()
	e, ok := metricsSettled.m[k]
	return e, ok
}

func metricsSettledPut(k metricsSettledKey, e metricsSettledEntry) {
	metricsSettled.mu.Lock()
	defer metricsSettled.mu.Unlock()
	if metricsSettled.m == nil || len(metricsSettled.m) >= metricsSettledCacheMax {
		metricsSettled.m = map[metricsSettledKey]metricsSettledEntry{}
	}
	metricsSettled.m[k] = e
}

// settleAgeFor is how long a row must go unseen before it settles, for a grid
// resolved from f and the request's bucket: the span from the grid floor to
// the newest sample, plus the longest pair span a rate can bridge and a
// minute of slack, and never less than metricsMinSettleAge. A row settled at
// that age has (clock skew aside) no sample inside the grid, so the tail read
// alone covers every bucket; the exact check is settledBelowGrid.
func settleAgeFor(f metricsFacts, bucket time.Duration) time.Duration {
	b, floorIdx, ok := metricsGrid(f, bucket)
	if !ok {
		return metricsMinSettleAge
	}
	age := f.last.Sub(bucketStart(floorIdx, b)) + time.Duration(metricsMaxPairSpanBuckets)*b + time.Minute
	if age < metricsMinSettleAge {
		return metricsMinSettleAge
	}
	return age
}

// settledBelowGrid reports that every sample of the settled rows lies before
// the floor of the grid the whole-session facts resolve to, i.e. leaving the
// settled series out of the accumulation changes no bucket.
func settledBelowGrid(settled, whole metricsFacts, bucket time.Duration) bool {
	if !settled.hasBounds {
		return true
	}
	b, floorIdx, ok := metricsGrid(whole, bucket)
	return ok && settled.last.Before(bucketStart(floorIdx, b))
}

// settledSeries returns the series of the runs the read flagged Settled
// (series[i] is runs[i]).
func settledSeries(runs []store.ProcessMetricRun, series []procMetricSeries) []procMetricSeries {
	var out []procMetricSeries
	for i, r := range runs {
		if r.Settled {
			out = append(out, series[i])
		}
	}
	return out
}

// sessionMetricsInput is what the metrics handler aggregates: the series to
// accumulate, the whole-session facts, and the session's process row count.
type sessionMetricsInput struct {
	series []procMetricSeries
	facts  metricsFacts
	total  int64
	// tailOnly reports the series are only the unsettled tail (the cached
	// settled facts were used). Exposed for tests.
	tailOnly bool
}

// loadSessionMetricSeries reads a session's metric series through the one
// store seam, using and refreshing the settled-facts cache. The result
// aggregates (aggregateWithFacts) to exactly what aggregating every row of
// the session would.
func loadSessionMetricSeries(ctx context.Context, db *sql.DB, sessionID string, bucket time.Duration) (sessionMetricsInput, error) {
	st := store.New(db)
	key := metricsSettledKey{db: db, session: sessionID}
	prev, cached := metricsSettledGet(key)
	q := store.ProcessMetricsQuery{SettleAge: metricsMinSettleAge}
	if cached {
		mark := prev.mark
		q.Known = &mark
		q.SettleAge = prev.settleAge
	}
	res, err := st.ProcessMetricsForSession(ctx, sessionID, q)
	if err != nil {
		return sessionMetricsInput{}, err
	}
	if !res.Full {
		tail := metricSeriesFromRuns(res.Runs)
		whole := prev.facts.merge(factsOf(tail))
		if settledBelowGrid(prev.facts, whole, bucket) {
			metricsSettledPut(key, metricsSettledEntry{
				mark:      res.Settled,
				facts:     prev.facts.merge(factsOf(settledSeries(res.Runs, tail))),
				settleAge: settleAgeFor(whole, bucket),
			})
			return sessionMetricsInput{series: tail, facts: whole, total: res.Total, tailOnly: true}, nil
		}
		// The grid reaches back into settled rows (a wide ?bucket=): read the
		// whole session, settling at an age that clears this grid.
		res, err = st.ProcessMetricsForSession(ctx, sessionID, store.ProcessMetricsQuery{SettleAge: settleAgeFor(whole, bucket)})
		if err != nil {
			return sessionMetricsInput{}, err
		}
	}
	all := metricSeriesFromRuns(res.Runs)
	whole := factsOf(all)
	metricsSettledPut(key, metricsSettledEntry{
		mark:      res.Settled,
		facts:     factsOf(settledSeries(res.Runs, all)),
		settleAge: settleAgeFor(whole, bucket),
	})
	return sessionMetricsInput{series: all, facts: whole, total: res.Total}, nil
}

// handleSessionMetrics serves GET /api/session/<id>/metrics?bucket=<duration>.
//
// It is the plottable sibling of handleSessionProcesses: same substrate (the
// per-process metric_samples_json rings), but bucketed onto a common grid,
// differentiated, and aggregated across the WHOLE attributed subtree rather
// than one arbitrarily chosen process. Read-only — the correlation write
// passes stay on the /processes poll.
//
// Bounded: it reads only the metric columns of ring-bearing rows, and after
// the first poll of a session only the rows not yet settled (see
// loadSessionMetricSeries), so a long session's history is decoded once, not
// on every poll.
func (s *Server) handleSessionMetrics(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	var bucket time.Duration
	if v := r.URL.Query().Get("bucket"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid bucket %q: %v", v, err), http.StatusBadRequest)
			return
		}
		bucket = clampBucket(d)
	}
	in, err := loadSessionMetricSeries(r.Context(), s.db(), sessionID, bucket)
	if err != nil {
		http.Error(w, fmt.Sprintf("load process runs: %v", err), http.StatusInternalServerError)
		return
	}
	cfg, _ := loadConfigForDashboard(s.opts.ConfigPath)
	agg := aggregateWithFacts(in.series, in.facts, bucket)

	resp := SessionMetricsResponse{
		SessionID:        sessionID,
		BucketMs:         agg.BucketMs,
		SampleIntervalMs: agg.SampleIntervalMs,
		Points:           agg.Points,
		Processes:        int(in.total),
		SampledProcesses: agg.SampledProcesses,
		RateProcesses:    agg.RateProcesses,
		WindowTruncated:  agg.WindowTruncated,
		CPUScale:         "per_core_sum",
		CPUCores:         runtime.NumCPU(),
		Series:           agg.Series,
		ProcessEnabled:   cfg.Observer.Process.Enabled,
	}
	if !agg.From.IsZero() {
		resp.From = agg.From.Format(time.RFC3339)
		resp.To = agg.To.Format(time.RFC3339)
		resp.WindowMs = agg.To.Sub(agg.From).Milliseconds()
	}
	resp.Reason = metricsReason(metricsReasonInput{
		ProcessEnabled:   resp.ProcessEnabled,
		Processes:        resp.Processes,
		SampledProcesses: resp.SampledProcesses,
		RateProcesses:    resp.RateProcesses,
		Points:           len(resp.Points),
	})
	writeJSON(w, resp)
}

// SessionNetworkResponse is the lightweight event-list payload for
// /api/session/<id>/network. Bodies are omitted by design.
type SessionNetworkResponse struct {
	SessionID string                         `json:"session_id"`
	Total     int                            `json:"total"`
	Events    []store.ProcessNetworkEventRow `json:"events"`
}

func (s *Server) handleSessionNetwork(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	// ?summary=1: server-side proxied-vs-OS rollup with real COUNT/SUM over the
	// session's network events. The cockpit's "API traffic (proxied)" line
	// renders from this — it needs honest provenance (proxied calls only, not
	// git/curl/MCP OS connections) and byte totals, which the event LIST cannot
	// provide (it omits bodies and mixes both sources). No new §9.3 route: same
	// path, discriminated by the query param. See store.NetworkSummaryForSession
	// for the honest discriminator.
	if r.URL.Query().Get("summary") == "1" {
		sum, err := store.New(s.db()).NetworkSummaryForSession(r.Context(), sessionID)
		if err != nil {
			http.Error(w, fmt.Sprintf("load network summary: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, sum)
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	events, err := store.New(s.db()).NetworkEventsForSession(r.Context(), sessionID, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("load network events: %v", err), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []store.ProcessNetworkEventRow{}
	}
	writeJSON(w, SessionNetworkResponse{SessionID: sessionID, Total: len(events), Events: events})
}

func (s *Server) handleProcessNetworkDetail(w http.ResponseWriter, r *http.Request) {
	idText := strings.TrimPrefix(r.URL.Path, "/api/process/network/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid network event id", http.StatusBadRequest)
		return
	}
	row, err := store.New(s.db()).NetworkEventDetail(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "network event not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("load network event: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, row)
}

// ProcessFindingsResponse is the /api/process/findings payload — recent
// observe-only process findings (§14) for the Security/Observability tab,
// with per-rule and per-severity rollups. NODE-LOCAL; never leaves the box.
type ProcessFindingsResponse struct {
	WindowHours int                       `json:"window_hours"`
	Total       int                       `json:"total"`
	ByRule      map[string]int            `json:"by_rule"`
	BySeverity  map[string]int            `json:"by_severity"`
	Findings    []store.ProcessFindingRow `json:"findings"`
}

// handleProcessFindings serves GET /api/process/findings?hours=N — the recent
// cross-session process-finding rollup. Findings are derived on read from the
// process_runs envelope, so this reflects current data with no write path.
func (s *Server) handleProcessFindings(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hours = n
		}
	}
	findings, err := store.New(s.db()).RecentProcessFindings(r.Context(), time.Duration(hours)*time.Hour)
	if err != nil {
		http.Error(w, fmt.Sprintf("load process findings: %v", err), http.StatusInternalServerError)
		return
	}
	byRule := map[string]int{}
	bySeverity := map[string]int{}
	for _, f := range findings {
		byRule[f.RuleID]++
		bySeverity[f.Severity]++
	}
	if findings == nil {
		findings = []store.ProcessFindingRow{}
	}
	writeJSON(w, ProcessFindingsResponse{
		WindowHours: hours,
		Total:       len(findings),
		ByRule:      byRule,
		BySeverity:  bySeverity,
		Findings:    findings,
	})
}

// buildProcessTree assembles the nested ProcessNode forest from the flat
// run rows, ordering siblings by start time then pid. A run whose parent
// wasn't captured is promoted to a root so nothing is dropped. Always
// returns a non-nil slice so the JSON shape stays `"roots": []`.
func buildProcessTree(runs []store.ProcessRunRow, cmds, msgIDs map[int64]string, networkCounts map[string]int) []ProcessNode {
	roots := []ProcessNode{}
	if len(runs) == 0 {
		return roots
	}
	byKey := make(map[string]store.ProcessRunRow, len(runs))
	childrenOf := make(map[string][]string)
	for _, r := range runs {
		byKey[r.ProcessKey] = r
	}
	var rootKeys []string
	for _, r := range runs {
		if r.ParentProcessKey != "" {
			if _, ok := byKey[r.ParentProcessKey]; ok {
				childrenOf[r.ParentProcessKey] = append(childrenOf[r.ParentProcessKey], r.ProcessKey)
				continue
			}
		}
		rootKeys = append(rootKeys, r.ProcessKey)
	}

	less := func(a, b string) bool {
		ra, rb := byKey[a], byKey[b]
		if !ra.StartedAt.Equal(rb.StartedAt) {
			return ra.StartedAt.Before(rb.StartedAt)
		}
		return ra.PID < rb.PID
	}
	sort.SliceStable(rootKeys, func(i, j int) bool { return less(rootKeys[i], rootKeys[j]) })

	// Guard against a parent_process_key cycle (should never happen — keys
	// are append-only — but a malformed import must not infinite-loop).
	seen := make(map[string]bool, len(runs))
	var build func(key string) ProcessNode
	build = func(key string) ProcessNode {
		r := byKey[key]
		node := nodeFromRow(r, cmds, msgIDs, networkCounts)
		if seen[key] {
			return node
		}
		seen[key] = true
		ch := childrenOf[key]
		sort.SliceStable(ch, func(i, j int) bool { return less(ch[i], ch[j]) })
		for _, c := range ch {
			node.Children = append(node.Children, build(c))
		}
		return node
	}
	for _, rk := range rootKeys {
		roots = append(roots, build(rk))
	}
	return roots
}

// startedAtISO renders a process run's start instant as RFC3339 UTC for the
// drawer, or "" when the time is zero (unknown).
func startedAtISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nodeFromRow(r store.ProcessRunRow, cmds, msgIDs map[int64]string, networkCounts map[string]int) ProcessNode {
	n := ProcessNode{
		ProcessKey:      r.ProcessKey,
		PID:             r.PID,
		PPID:            r.PPID,
		Exe:             r.ExeBasename,
		ArgvPreview:     r.ArgvPreview,
		CWD:             r.CWD,
		Source:          r.AttributionSource,
		Confidence:      r.AttributionConfidence,
		Exited:          r.Exited,
		ExitCode:        r.ExitCode,
		ExitSignal:      r.ExitSignal,
		DurationMs:      r.DurationMs,
		StartedAt:       startedAtISO(r.StartedAt),
		LastSeenAt:      startedAtISO(r.LastSeenAt),
		IsBoundary:      r.IsBoundary,
		ActionID:        r.ActionID,
		TurnIndex:       r.TurnIndex,
		SeccompMode:     r.SeccompMode,
		CapabilitiesEff: r.CapabilitiesEff,
		AppArmorLabel:   r.AppArmorLabel,
		SELinuxLabel:    r.SELinuxLabel,
		ContainerID:     r.ContainerID,
		CPUMs:           r.CPUUserMs + r.CPUSystemMs,
		WorkingSetBytes: r.WorkingSetBytes,
		PeakRSSBytes:    r.MaxRSSBytes,
		ReadBytes:       r.ReadBytes,
		WriteBytes:      r.WriteBytes,
		ThreadCount:     r.ThreadCount,
		HandleCount:     r.HandleCount,
		MetricSamples:   r.MetricSamples,
		NetworkCount:    networkCounts[r.ProcessKey],
		Children:        []ProcessNode{},
	}
	if r.ActionID != nil {
		n.Command = cmds[*r.ActionID]
		n.MessageID = msgIDs[*r.ActionID]
	}
	return n
}
