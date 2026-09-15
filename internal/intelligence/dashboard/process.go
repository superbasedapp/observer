package dashboard

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/processobs"
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
	StartedAt  string `json:"started_at,omitempty"`
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
	CPUMs           int64                     `json:"cpu_ms,omitempty"`
	WorkingSetBytes int64                     `json:"working_set_bytes,omitempty"`
	PeakRSSBytes    int64                     `json:"peak_rss_bytes,omitempty"`
	ReadBytes       int64                     `json:"read_bytes,omitempty"`
	WriteBytes      int64                     `json:"write_bytes,omitempty"`
	ThreadCount     int32                     `json:"thread_count,omitempty"`
	HandleCount     int32                     `json:"handle_count,omitempty"`
	MetricSamples   []processobs.MetricSample `json:"metric_samples,omitempty"`
	NetworkCount    int                       `json:"network_count,omitempty"`

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

	runs, err := st.ProcessRunsForSession(ctx, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load process runs: %v", err), http.StatusInternalServerError)
		return
	}
	// Cold-storage fallback (corpus archival P3.5). Only on a hot MISS: a
	// session with live rows is answered entirely from the hot database, and
	// an archived one is answered from the archive file for this one request,
	// with no write-back. The endpoint's shape is unchanged either way.
	if len(runs) == 0 {
		runs = s.archivedProcessRuns(ctx, sessionID)
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
	// Observe-only side-effect flags for the drawer (§13.1 / §14). Best-effort
	// — a findings error never blocks the tree. Default to an empty slice so
	// the JSON shape stays `"findings": []`.
	findings, _ := st.ProcessFindingsForSession(ctx, sessionID)
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
		Total:        len(runs),
		NetworkTotal: len(networkEvents),
		Roots:        buildProcessTree(runs, cmds, msgIDs, networkCounts),
		Findings:     findings,
		Diagnostics:  buildProcessDiagnostics(cfg, s.opts.ConfigPath != "", len(runs), len(networkEvents), proxyOnlyNetworkEvents),
	})
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
// substrate (processobs.MetricSample). It is NOT directly plottable:
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
	Read func(processobs.MetricSample) (int64, bool)
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
	{ID: metricIDCPU, Kind: metricCounter, Scale: 100, Read: func(s processobs.MetricSample) (int64, bool) { return s.CPUMs, true }},
	{ID: metricIDRead, Kind: metricCounter, Scale: 1000, Read: func(s processobs.MetricSample) (int64, bool) { return s.ReadBytes, true }},
	{ID: metricIDWrite, Kind: metricCounter, Scale: 1000, Read: func(s processobs.MetricSample) (int64, bool) { return s.WriteBytes, true }},
	{ID: metricIDNetRx, Kind: metricCounter, Scale: 1000, Read: sampleNetworkRx},
	{ID: metricIDNetTx, Kind: metricCounter, Scale: 1000, Read: sampleNetworkTx},
	{ID: metricIDRSS, Kind: metricGauge, Read: func(s processobs.MetricSample) (int64, bool) { return s.WorkingSet, true }},
}

// sampleNetworkRx reads a per-process cumulative received-bytes counter off a
// metric sample, gated on NetMeasured: processobs.MetricSample.NetRxBytes is
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
func sampleNetworkRx(s processobs.MetricSample) (int64, bool) { return s.NetRxBytes, s.NetMeasured }

// sampleNetworkTx is the transmitted-bytes counterpart of sampleNetworkRx.
func sampleNetworkTx(s processobs.MetricSample) (int64, bool) { return s.NetTxBytes, s.NetMeasured }

// procMetricSeries is one process's sample ring plus the lifecycle facts the
// aggregator needs. It is a plain value — the aggregation below touches no
// SQL, no HTTP and no clock, so it is unit-testable on its own.
type procMetricSeries struct {
	Key       string
	StartedAt time.Time
	Exited    bool
	Samples   []processobs.MetricSample
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
	out := metricsAggregate{Points: []SessionMetricPoint{}}
	sampleInterval := medianSampleInterval(series)
	out.SampleIntervalMs = sampleInterval.Milliseconds()

	for _, s := range series {
		if len(s.Samples) > 0 {
			out.SampledProcesses++
		}
		if len(s.Samples) > 1 {
			out.RateProcesses++
		}
		if truncatedRing(s, sampleInterval) {
			out.WindowTruncated = true
		}
	}
	first, last, ok := sampleBounds(series)
	if !ok {
		out.BucketMs = clampBucket(bucket).Milliseconds()
		return out
	}
	bucket = chooseBucket(bucket, sampleInterval, last.Sub(first))
	out.BucketMs = bucket.Milliseconds()

	// Floor the grid at the most recent metricsMaxPoints buckets. The derived
	// bucket already fits the window, but an explicit ?bucket= is honored as
	// asked, so this is what keeps a fine bucket over a long session bounded:
	// the newest slice of the window is returned and From reports it honestly.
	floorIdx := bucketIndex(first, bucket)
	if lastIdx := bucketIndex(last, bucket); lastIdx-floorIdx+1 > metricsMaxPoints {
		floorIdx = lastIdx - metricsMaxPoints + 1
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

	measurable := measurableCounters(series)
	for _, s := range series {
		accumulateSeries(s, bucket, floorIdx, measurable, at)
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

// measurableCounters reports which cumulative counters actually carry data in
// this window: a counter that reads ZERO in every sample of every process is
// treated as NOT MEASURED rather than as "measured, and idle".
//
// This is deliberate. A capture backend that does not populate a counter
// leaves it at zero, and from the sample alone that is indistinguishable from
// a process that genuinely did no I/O. Reporting it as measured would put a
// flat zero line on screen — which reads as a confident "no disk traffic"
// when the honest answer is "this host does not measure it". The cost is that
// a genuinely, perfectly idle counter is reported unmeasured; that
// under-claims rather than over-claims, which is the right direction.
func measurableCounters(series []procMetricSeries) map[string]bool {
	out := map[string]bool{}
	for _, m := range metricSpecs {
		if m.Kind != metricCounter {
			continue
		}
		for _, s := range series {
			if anySampleNonZero(s.Samples, m.Read) {
				out[m.ID] = true
				break
			}
		}
	}
	return out
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

func anySampleNonZero(samples []processobs.MetricSample, read func(processobs.MetricSample) (int64, bool)) bool {
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

func sampleBounds(series []procMetricSeries) (time.Time, time.Time, bool) {
	var lo, hi time.Time
	found := false
	for _, s := range series {
		for _, sm := range s.Samples {
			if sm.T.IsZero() {
				continue
			}
			if !found || sm.T.Before(lo) {
				lo = sm.T
			}
			if !found || sm.T.After(hi) {
				hi = sm.T
			}
			found = true
		}
	}
	return lo, hi, found
}

// medianSampleInterval is the observed median gap between consecutive samples
// across every process. It is the ONLY source for the default bucket width —
// nothing here hardcodes the capture cadence, so raising the sampling
// frequency automatically tightens the buckets.
func medianSampleInterval(series []procMetricSeries) time.Duration {
	var gaps []time.Duration
	for _, s := range series {
		for i := 1; i < len(s.Samples); i++ {
			d := s.Samples[i].T.Sub(s.Samples[i-1].T)
			if d > 0 {
				gaps = append(gaps, d)
			}
		}
	}
	if len(gaps) == 0 {
		return 0
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return gaps[len(gaps)/2]
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

// truncatedRing reports that a process's ring has already evicted samples: its
// oldest RETAINED sample starts materially after the process did, so the
// window shown is shorter than the process's life. The tolerance is derived
// from the observed cadence — the ring capacity constant is deliberately not
// referenced here.
func truncatedRing(s procMetricSeries, sampleInterval time.Duration) bool {
	if len(s.Samples) == 0 || s.StartedAt.IsZero() || s.Samples[0].T.IsZero() {
		return false
	}
	slack := 2 * sampleInterval
	if slack < 5*time.Second {
		slack = 5 * time.Second
	}
	return s.Samples[0].T.Sub(s.StartedAt) > slack
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

// metricSeriesFromRuns projects store rows onto the pure aggregator's input,
// defensively re-sorting each ring by timestamp (the ring is appended in order,
// but a rate derivation must never depend on that).
func metricSeriesFromRuns(runs []store.ProcessRunRow) []procMetricSeries {
	out := make([]procMetricSeries, 0, len(runs))
	for _, r := range runs {
		if len(r.MetricSamples) == 0 {
			out = append(out, procMetricSeries{Key: r.ProcessKey, StartedAt: r.StartedAt, Exited: r.Exited})
			continue
		}
		samples := make([]processobs.MetricSample, len(r.MetricSamples))
		copy(samples, r.MetricSamples)
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

// handleSessionMetrics serves GET /api/session/<id>/metrics?bucket=<duration>.
//
// It is the plottable sibling of handleSessionProcesses: same substrate (the
// per-process metric_samples_json rings), but bucketed onto a common grid,
// differentiated, and aggregated across the WHOLE attributed subtree rather
// than one arbitrarily chosen process. Read-only — the correlation write
// passes stay on the /processes poll.
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
	runs, err := store.New(s.db()).ProcessRunsForSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load process runs: %v", err), http.StatusInternalServerError)
		return
	}
	cfg, _ := loadConfigForDashboard(s.opts.ConfigPath)
	agg := aggregateProcessMetrics(metricSeriesFromRuns(runs), bucket)

	resp := SessionMetricsResponse{
		SessionID:        sessionID,
		BucketMs:         agg.BucketMs,
		SampleIntervalMs: agg.SampleIntervalMs,
		Points:           agg.Points,
		Processes:        len(runs),
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
