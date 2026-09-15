package processobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

// EventType is the kind of an OS process event. The first three are the
// MVP taxonomy (spec §7.1); the rest are later high-signal events (§7.2),
// declared now so the vocabulary is stable and a forward-written backend
// round-trips.
type EventType string

const (
	EventFork EventType = "process_fork"
	EventExec EventType = "process_exec"
	EventExit EventType = "process_exit"

	// EventMetrics refreshes a LIVE process's resource counters (CPU / memory /
	// disk / threads / handles) without re-resolving attribution — emitted each
	// poll for the attributed AI subtree so the dashboard shows current usage
	// and a sparkline (docs/plans/process-obs-dashboard-enhancements-2026-06-17.md).
	EventMetrics EventType = "process_metrics"

	EventNetworkConnect    EventType = "network_connect"
	EventFileWrite         EventType = "file_write"
	EventFileOpenSensitive EventType = "file_open_sensitive"
	EventPrivilegeChange   EventType = "privilege_change"
	EventNamespaceChange   EventType = "namespace_change"
)

// AttributionSource records HOW a run was attributed to a session (spec
// §9.2). Stored as data, never branched on as control flow — it lets the
// dashboard/CLI show confidence honestly rather than hiding an assumption.
type AttributionSource string

const (
	AttrNone               AttributionSource = "none"                 // unattributed
	AttrBridge             AttributionSource = "bridge"               // §9.2.1 direct pidbridge hit (the AI-tool root pid)
	AttrInherited          AttributionSource = "inherited"            // §9.2.2 nearest attributed ancestor
	AttrAdapterPID         AttributionSource = "adapter_pid"          // §9.2.3 pid+start_time from an adapter session source
	AttrActionCorrelation  AttributionSource = "action_correlation"   // §9.2.4 action-derived command row: synthesized from the tool's run_command exec record (pid 0, message-linked, no OS metrics) — see derive.go
	AttrHeuristic          AttributionSource = "heuristic"            // §9.2.5 process-name/cwd signature (low confidence only)
	AttrCrossOSCorrelation AttributionSource = "cross_os_correlation" // §5.5 Windows root matched to a session by cwd/tool/time (deferred, medium)
	AttrEnvToken           AttributionSource = "env_token"            // §5.5 P-B6: a tree-inherited session-id env var resolves to an existing session (high, namespace-independent)
)

// Confidence is the qualitative trust in an attribution (spec §9.2). It
// travels with every run so consumers never present a guess as a fact.
type Confidence string

const (
	ConfNone   Confidence = "none"
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// RawEvent is the minimal fact a backend emits, before userspace
// enrichment. The kernel/event-source side keeps this tiny and versioned
// (spec §5.1); the Enricher fills the OS-specific remainder.
//
// Type discriminates which fields are meaningful: Fork uses PID/PPID/Start;
// Exec adds Exe/Argv/CWD/uids; Exit adds the exit + resource fields.
type RawEvent struct {
	Type      EventType
	Timestamp time.Time

	// Identity (all events).
	BootID         string
	PID            int
	PPID           int
	StartTimeTicks int64
	// HasStartTime is false when the backend could not read the process
	// start time. Per §9.3 such an event is counted for health but never
	// persisted as a fresh attributed run (no stable ProcessKey).
	HasStartTime bool

	// Exec fields.
	ExePath string
	Argv    []string
	CWD     string
	UID     int
	GID     int
	EUID    int
	EGID    int

	// SessionToken is an allowlisted, tree-inherited session-id env var value
	// the capturer recovered from the process environment (§5.5 P-B6 env-token
	// / EV). It is ONLY the value of a key in SessionTokenEnvKeys — never the
	// rest of the environment, which holds secrets and never leaves the
	// capturer. The Attributor resolves it to a session at HIGH confidence. It
	// round-trips through the bridge NDJSON codec unchanged (additive field).
	SessionToken string

	// Exit fields.
	ExitCode   int
	ExitSignal int

	// Resource accounting (spec §8 Resources). Best-effort, nullable
	// downstream. Captured at exec, refreshed each poll for the attributed
	// subtree (EventMetrics), and read once more best-effort at exit. CPU is
	// cumulative ms; MaxRSSBytes is the peak working set; WorkingSetBytes is the
	// current resident set; Read/WriteBytes + Read/WriteOps are cumulative disk
	// I/O; ThreadCount/HandleCount are the current compute footprint.
	HasMetrics      bool
	CPUUserMs       int64
	CPUSystemMs     int64
	MaxRSSBytes     int64
	WorkingSetBytes int64
	ReadBytes       int64
	WriteBytes      int64
	ReadOps         int64
	WriteOps        int64
	ThreadCount     int32
	HandleCount     int32

	// HasNetworkMetrics gates NetworkBytesIn/NetworkBytesOut on a metrics-
	// bearing event (exec / EventMetrics / exit). It is the "measured" bit that
	// keeps a genuine zero distinguishable from "never measured": only a
	// backend with live per-process socket accounting (today: the Linux eBPF
	// backend's fentry/fexit TCP probes, surfaced through
	// poll.Options.NetworkBytes) sets it. False everywhere else — including
	// every Windows-captured process, where per-process byte accounting needs
	// ETW and is not implemented. Never infer zero bytes from a false here.
	HasNetworkMetrics bool

	// Security / isolation posture (P4) — userspace-enriched at exec.
	// Compact identifiers only (spec §8 Security + Isolation groups). The
	// Attributor copies these onto the run; CgroupPath is hashed at that
	// boundary (the raw path is never stored).
	SeccompMode     string
	CapabilitiesEff string
	AppArmorLabel   string
	SELinuxLabel    string
	CgroupPath      string
	ContainerID     string
	PIDNamespace    string
	MountNamespace  string
	NetNamespace    string

	// Network fields (EventNetworkConnect). Metadata-only process backends fill
	// these when they observe outbound egress. Payload-bearing capture sources
	// (the Observer proxy path, browser instrumentation, future plaintext/TLS
	// backends) persist bodies through ProcessEvent.NetworkBody instead.
	NetworkProtocol string
	NetworkFamily   string
	RemoteAddr      string
	RemotePort      int
	RemoteHost      string
	LocalAddr       string
	LocalPort       int
	NetworkStatus   string
	NetworkBytesIn  int64
	NetworkBytesOut int64
}

// Attribution is the answer to "which AI session (and action) owns this
// process?" — populated by the Attributor.
type Attribution struct {
	SessionID  string
	Tool       string
	ProjectID  int64
	Source     AttributionSource
	Confidence Confidence

	// ActionID / TurnIndex are the §9.2.4 message/action refinement. nil
	// until the deferred run_command -> process_exec correlation pass
	// (P3) resolves them; a run attributed only to a session is valid.
	ActionID  *int64
	TurnIndex *int
}

// ProcessRun is the userspace-enriched envelope attached to one process,
// captured at exec and updated at exit (spec §8). It is the domain type
// the Sink consumes; the store translates it into its own SQL row at the
// boundary.
//
// P1 populates Identity, Attribution, Executable, Command, Working
// directory, User, and Runtime. The Security/Isolation/Resource/Env-posture
// groups are declared now (so the type and migration are stable) and filled
// from P4 onward — they are zero/empty until then.
type ProcessRun struct {
	// Identity (§8).
	ProcessKey       string
	BootID           string
	PID              int
	PPID             int
	StartTimeTicks   int64
	ParentProcessKey string

	Attribution Attribution

	// Executable.
	ExePath     string
	ExeBasename string
	ExeDevice   string
	ExeInode    string
	ExeHash     string

	// Command (scrubbed/capped — see scrub.go).
	CWD         string
	ArgvPreview string
	ArgvHash    string
	ArgvArgc    int

	// User.
	UID      int
	GID      int
	EUID     int
	EGID     int
	Username string

	// Isolation / Security (P4).
	CgroupHash      string
	ContainerID     string
	PIDNamespace    string
	MountNamespace  string
	NetNamespace    string
	SeccompMode     string
	AppArmorLabel   string
	SELinuxLabel    string
	CapabilitiesEff string

	// Environment posture (P4) — allowlisted presence/hashes only, never
	// full env. Serialized to env_posture_json at the store boundary.
	EnvPosture map[string]string

	// Runtime.
	StartedAt  time.Time
	LastSeenAt time.Time
	ExitedAt   time.Time // zero until exit observed
	Exited     bool
	ExitCode   int
	ExitSignal int
	DurationMs int64

	// Resources (best-effort). CPU cumulative ms; MaxRSSBytes peak working set;
	// WorkingSetBytes current RSS; Read/WriteBytes + Ops cumulative disk I/O;
	// Thread/HandleCount current compute footprint. Refreshed each poll for the
	// attributed subtree via EventMetrics; the store also folds the current
	// sample into a capped in-row sparkline ring buffer.
	CPUUserMs       int64
	CPUSystemMs     int64
	MaxRSSBytes     int64
	WorkingSetBytes int64
	ReadBytes       int64
	WriteBytes      int64
	ReadOps         int64
	WriteOps        int64
	ThreadCount     int32
	HandleCount     int32

	// MetricSamples is the live-chart ring buffer of recent resource readings.
	// Appended on exec + each EventMetrics refresh (≥ MetricPolicy.
	// SampleInterval apart), evicted past MetricPolicy.Window and capped at
	// MetricPolicy.MaxSamples (oldest dropped). The store serializes a
	// DOWNSAMPLED copy to the metric_samples_json column at the (much slower)
	// MetricPolicy.PersistInterval; the full-resolution ring is in-memory only
	// and resets if the daemon restarts.
	MetricSamples []MetricSample

	// lastMetricPersistAt is the ring's DB-write bookkeeping: the timestamp of
	// the last metrics refresh that was reported as ChangeUpdated (i.e. that
	// caused a row rewrite). Unexported — it is Attributor state that happens
	// to live per-run, never part of the persisted envelope.
	lastMetricPersistAt time.Time

	// IsBoundary marks init/systemd/WSL-relay processes (§9.2.6): they are
	// attribution boundaries and never propagate inheritance to children.
	IsBoundary bool
}

// ProcessEvent is one high-signal event emitted by the process/network
// observability stack after attribution. It maps to process_events, with
// optional network-body details in process_network_bodies.
type ProcessEvent struct {
	ID            int64
	ProcessRunID  int64
	ProcessKey    string
	Timestamp     time.Time
	Type          EventType
	Attribution   Attribution
	TargetKind    string
	Target        string
	TargetHash    string
	Severity      string
	FindingRuleID string
	Details       map[string]any
	NetworkBody   *NetworkBodyCapture
}

// NetworkBodyCapture carries capped request/response diagnostic payloads for a
// network event. Bodies are already scrubbed/capped by the capture source; the
// store writes them as node-local excerpts plus hashes/byte counts.
type NetworkBodyCapture struct {
	CaptureSource         string
	APITurnID             int64
	RequestID             string
	Method                string
	URL                   string
	Host                  string
	StatusCode            int
	DurationMs            int64
	RequestHeadersJSON    string
	ResponseHeadersJSON   string
	RequestBody           string
	RequestBodySHA256     string
	RequestBodyBytes      int
	RequestBodyTruncated  bool
	ResponseBody          string
	ResponseBodySHA256    string
	ResponseBodyBytes     int
	ResponseBodyTruncated bool
	ResponseContentType   string
	BodyUnavailableReason string
}

// EventSink persists process events. It is intentionally separate from Sink so
// lifecycle capture can stay process_run-only while network/file/privilege
// event backends opt in incrementally.
type EventSink interface {
	PersistProcessEvents(ctx context.Context, events []ProcessEvent) (int, error)
}

// MetricSample is one timestamped resource reading for the live-chart ring
// buffer (CPU cumulative ms, current working set, cumulative disk bytes,
// cumulative socket bytes).
//
// EVERY counter here except WorkingSet is CUMULATIVE — monotonically
// non-decreasing over the life of the process — so a consumer drawing rates
// must DIFFERENTIATE consecutive samples (Δvalue / ΔT) and treat a DECREASE as
// a counter reset (drop the interval rather than plotting a negative rate).
// WorkingSet is an instantaneous gauge and is plotted as-is.
//
// The JSON tags are the on-disk wire format of process_runs.metric_samples_json
// (a JSON ring — no migration is needed to add a field, and a ring written by
// an older build simply decodes with the new fields at their zero value).
// NetRx/NetTx/NetMeasured were added that way; never RENAME an existing tag.
type MetricSample struct {
	T          time.Time `json:"t"`
	CPUMs      int64     `json:"cpu_ms"`
	WorkingSet int64     `json:"ws"`
	ReadBytes  int64     `json:"rb"`
	WriteBytes int64     `json:"wb"`

	// NetRxBytes / NetTxBytes are CUMULATIVE per-process socket bytes received
	// / sent since the capture probes attached (NOT since process start — a
	// process that predates the daemon starts from 0 here). TCP ONLY: the
	// Linux eBPF backend counts tcp_sendmsg / tcp_cleanup_rbuf payload bytes,
	// so UDP (incl. QUIC / HTTP-3), unix-domain, and raw sockets are NOT
	// included, and neither are IP/TCP headers or retransmits. Meaningful only
	// when NetMeasured is true.
	NetRxBytes int64 `json:"net_rx,omitempty"`
	NetTxBytes int64 `json:"net_tx,omitempty"`

	// NetMeasured reports that per-process network accounting was LIVE for
	// this sample, so a zero in NetRx/NetTx is a real "no bytes moved" rather
	// than "not measured". False means UNMEASURED — the eBPF probes are not
	// attached (no CAP_BPF/CAP_PERFMON, unsupported kernel, feature off), the
	// process was captured on Windows (needs ETW, unimplemented), or the ring
	// predates this field. A chart MUST render an unmeasured series as absent,
	// never as a flat zero line.
	NetMeasured bool `json:"net_measured,omitempty"`
}

// MetricPolicy governs the live-chart ring buffer: how often a point is
// appended in memory, how long a window is retained, and — decoupled from
// both — how often the ring is written to the DB.
//
// The two cadences are deliberately independent (docs/process-observability.md
// §"Live metrics ring"). The ring is persisted inside process_runs.
// metric_samples_json, so EVERY persist rewrites the whole row: sampling at
// the poll rate while persisting at the poll rate would multiply write
// amplification by the sampling factor on a DB that is already multi-GB. So we
// sample often (fresh chart) and persist rarely (cheap), and downsample the
// persisted copy so the column size is independent of the sample rate.
type MetricPolicy struct {
	// SampleInterval throttles in-memory ring appends. A refresh arriving
	// sooner updates the newest point IN PLACE (values move, the point count
	// and its timestamp do not), so the buffer can never grow faster than
	// one point per interval no matter how fast the backend polls.
	// A sample can never be fresher than the backend poll that produced it —
	// setting this below [observer.process].poll_interval_ms does NOT make the
	// chart finer, it just makes every poll append instead of refresh.
	SampleInterval time.Duration
	// Window is the retained time span: on append, points older than
	// newest-Window are evicted. This is the bound the operator actually sees
	// ("the chart shows the last N minutes"), independent of sample rate.
	Window time.Duration
	// MaxSamples is the absolute in-memory cap (belt-and-braces against a
	// pathological Window/SampleInterval ratio). ≤ 0 = derived from
	// Window/SampleInterval only.
	MaxSamples int
	// PersistInterval throttles DB writes for metrics-only refreshes: a
	// refresh sooner than this updates memory but reports ChangeNone, so the
	// row is not rewritten. Lifecycle events (exec/exit) always persist, so a
	// finished process always lands with its final ring. ≤ 0 = persist every
	// refresh (the pre-decoupling behaviour; tests use it).
	PersistInterval time.Duration
	// PersistMaxSamples caps the number of points written to the DB. When the
	// in-memory ring is longer it is downsampled evenly, ALWAYS keeping the
	// oldest and — load-bearing for a live chart — the NEWEST point exactly.
	// ≤ 0 = persist the whole ring.
	PersistMaxSamples int
}

// Default live-chart ring constants. See docs/process-observability.md for the
// write-amplification arithmetic behind them.
const (
	// DefaultMetricSampleInterval matches the default process poll cadence
	// (2s), so every poll yields a fresh point instead of 7 of every 8 being
	// discarded by the old 15s throttle.
	DefaultMetricSampleInterval = 2 * time.Second
	// DefaultMetricWindow is the retained live window (5 min at 2s = 150
	// points), replacing the old fixed 60-point/15-min buffer.
	DefaultMetricWindow = 5 * time.Minute
	// DefaultMetricMaxSamples hard-caps the in-memory ring regardless of the
	// Window/SampleInterval ratio (300 points ≈ 24 KB/process worst case).
	DefaultMetricMaxSamples = 300
	// DefaultMetricPersistInterval is the DB write cadence for metrics-only
	// refreshes. At the 2s poll default this is 7.5× FEWER row rewrites than
	// the pre-decoupling behaviour (which persisted on every poll).
	DefaultMetricPersistInterval = 15 * time.Second
	// DefaultMetricPersistMaxSamples downsamples the persisted ring so the
	// JSON column stays the size it was before the sample rate went up.
	DefaultMetricPersistMaxSamples = 60
)

// DefaultMetricPolicy returns the shipped live-chart ring policy.
func DefaultMetricPolicy() MetricPolicy {
	return MetricPolicy{
		SampleInterval:    DefaultMetricSampleInterval,
		Window:            DefaultMetricWindow,
		MaxSamples:        DefaultMetricMaxSamples,
		PersistInterval:   DefaultMetricPersistInterval,
		PersistMaxSamples: DefaultMetricPersistMaxSamples,
	}
}

// withDefaults fills unset (≤ 0) fields from DefaultMetricPolicy, EXCEPT
// PersistInterval and PersistMaxSamples, whose ≤ 0 values are meaningful
// ("persist every refresh" / "persist the whole ring").
func (p MetricPolicy) withDefaults() MetricPolicy {
	d := DefaultMetricPolicy()
	if p.SampleInterval <= 0 {
		p.SampleInterval = d.SampleInterval
	}
	if p.Window <= 0 {
		p.Window = d.Window
	}
	return p
}

// ringCap is the effective in-memory point cap: the window's worth of samples
// (plus one, so a full window is representable), clamped by MaxSamples.
func (p MetricPolicy) ringCap() int {
	n := 1
	if p.SampleInterval > 0 && p.Window > 0 {
		n = int(p.Window/p.SampleInterval) + 1
	}
	if n < 1 {
		n = 1
	}
	if p.MaxSamples > 0 && n > p.MaxSamples {
		n = p.MaxSamples
	}
	return n
}

// NetworkAccounting is the shared, concurrency-safe status of per-process
// network byte accounting. The capture backend that owns the probes is the
// only writer; Health reads it so `observer doctor` / the dashboard can tell
// "measured zero bytes" from "not measured at all" — a flat zero line drawn
// for an unmeasured process is a lie, so the distinction is carried, never
// inferred.
//
// The zero value is valid and reports NetworkAccountingOff.
type NetworkAccounting struct {
	mu     sync.Mutex
	mode   string
	reason string
}

// Network-accounting modes (NetworkAccounting.Mode).
const (
	// NetworkAccountingOff — not requested (feature disabled by config).
	NetworkAccountingOff = "off"
	// NetworkAccountingUnavailable — requested but the probes could not
	// attach (no CAP_BPF/CAP_PERFMON, no BTF, kernel without fentry/fexit,
	// non-Linux). Capture degrades to lifecycle-only; bytes are UNMEASURED.
	NetworkAccountingUnavailable = "unavailable"
	// NetworkAccountingTCP — live, counting TCP payload bytes only.
	NetworkAccountingTCP = "tcp"
)

// networkAccountingModes is the CLOSED vocabulary of accounting modes this
// build understands. It is the one owner of that list (CLAUDE.md rule 4):
// every consumer that has to decide "is this a mode I recognise?" asks
// KnownNetworkAccountingMode rather than keeping its own copy.
var networkAccountingModes = []string{
	NetworkAccountingOff,
	NetworkAccountingUnavailable,
	NetworkAccountingTCP,
}

// KnownNetworkAccountingMode reports whether mode is one this build defines.
//
// It exists because a mode can arrive from OFF THIS MACHINE: the cross-OS
// capturer states its own accounting mode in its hello frame, over a socket
// that (under WSL's localhostForwarding) any process on the Windows host can
// dial. An unrecognised string must therefore never be adopted as-is — an
// arbitrary name would otherwise satisfy "not off, not unavailable, so it
// must be live" and let a remote assert a POSITIVE measurement claim under a
// mode nothing in this build has ever seen, and would land verbatim in a
// Prometheus label. Callers reject or normalise; nobody guesses.
//
// The empty string is NOT known: it means "the far side said nothing", which
// every consumer already handles as unknown rather than as a mode.
func KnownNetworkAccountingMode(mode string) bool {
	for _, m := range networkAccountingModes {
		if m == mode {
			return true
		}
	}
	return false
}

// NetworkAccountingModes returns the closed mode vocabulary, newly allocated
// so a caller cannot mutate the package's copy. Used by the metrics exporter,
// which emits one series per mode as an enum-style state set.
func NetworkAccountingModes() []string {
	return append([]string(nil), networkAccountingModes...)
}

// Set records the current mode and a human-readable reason (may be empty).
func (n *NetworkAccounting) Set(mode, reason string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.mode, n.reason = mode, reason
	n.mu.Unlock()
}

// Status returns the current mode and reason. A nil receiver reports "off".
func (n *NetworkAccounting) Status() (mode, reason string) {
	if n == nil {
		return NetworkAccountingOff, ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.mode == "" {
		return NetworkAccountingOff, ""
	}
	return n.mode, n.reason
}

// NetworkBytesFunc reports the CUMULATIVE socket bytes a pid has received and
// sent since accounting began. ok=false means accounting is not live at all
// (unmeasured); ok=true with (0,0) means the process is measured and has moved
// no bytes yet — the two are never conflated.
type NetworkBytesFunc func(pid int) (in, out int64, ok bool)

// Attributed reports whether the run carries a session attribution.
func (r *ProcessRun) Attributed() bool {
	return r.Attribution.SessionID != "" && r.Attribution.Source != AttrNone
}

// DropReason names why an event or run was discarded; it labels the
// dropped-event health counter (spec §15 metrics).
type DropReason string

const (
	DropNoStartTime    DropReason = "no_start_time"    // §9.3: unkeyable event
	DropUnattributed   DropReason = "unattributed"     // §9.2.7: no session and capture_unattributed=false
	DropQueueOverflow  DropReason = "queue_overflow"   // §15: newest-dropped under backpressure
	DropEnrichFailed   DropReason = "enrich_failed"    // enrichment returned an error
	DropExitBeforeExec DropReason = "exit_before_exec" // exit for a pid we never saw exec/fork for
	DropSelfExcluded   DropReason = "self_excluded"    // the observer daemon's own binary — never an AI-tool worker (Options.ExcludeOwnBasenames)
	// DropSinkError is a batch the run sink refused PERMANENTLY — a schema or
	// constraint failure that no later attempt can fix (see ClassifySinkError).
	// Retrying it would only delay the loss, so it is dropped at once and
	// counted here.
	DropSinkError DropReason = "sink_error"
	// DropSinkRetryExhausted is a run discarded because the RETAINED batch hit
	// Options.MaxRetainedRuns while the sink kept failing transiently. This is
	// the bounded-memory release valve: the retention cannot grow forever
	// against a sink that never recovers, so the OLDEST held rows are released
	// and counted here. Non-zero means capture was lost to a persistently
	// unavailable sink — a different fact from DropSinkError, and the one that
	// says "the DB was busy for longer than the retention could cover".
	DropSinkRetryExhausted DropReason = "sink_retry_exhausted"
	// DropSinkShutdown is a run still retained (or newly failed) when the
	// observer performed its FINAL flush. There is no next flush tick to retry
	// on, so these are a real loss and are counted rather than silently
	// discarded with the process.
	DropSinkShutdown DropReason = "sink_shutdown"
	// DropFlushBacklog is a run discarded on the DRAIN side because the
	// flusher goroutine fell far enough behind that the hand-off buffer AND
	// the drain's own backlog were both full (task 9g). It is the counterpart
	// of DropSinkRetryExhausted at the other end of the pipeline: retry
	// exhaustion means the sink kept refusing rows it had been offered, while
	// this means the sink was so slow that rows never got offered at all.
	//
	// It exists so the decoupling cannot buy speed with silence. The drain
	// never blocks on the flusher — that coupling is what made a 31 s flush a
	// 31 s capture blackout — but "never blocks" must not degrade into "quietly
	// forgets", so the overflow is bounded, oldest-first, and counted here.
	// Non-zero means the sink was persistently slower than capture; zero with a
	// non-zero FlushBacklogHits means the backlog absorbed the stall.
	DropFlushBacklog DropReason = "flush_backlog"
	// DropEventSinkError is the high-signal EVENT sink's failure counter. The
	// event sink has no retention: an event is a point-in-time fact whose
	// value decays, and it is emitted one at a time rather than batched.
	DropEventSinkError DropReason = "event_sink_error"
)

// SessionTokenEnvKeys is the allowlist of process-environment variable names
// that carry a tool's session id, inherited by the whole process subtree
// (§5.5 P-B6 env-token). The capturer extracts ONLY these keys' values from a
// process environment — the rest of the env (which holds secrets) is never
// read out, shipped, or stored. The Attributor resolves a recovered value to a
// session by direct equality against sessions.id, attributing at HIGH
// confidence (verified 2026-06-17: CLAUDE_CODE_SESSION_ID == sessions.id).
//
// Table-driven (CLAUDE.md rule 5): add a key here per tool that exposes a
// tree-inherited env var byte-equal to the session id observer stores. The
// per-adapter discovery matrix (P-B6.0) found Claude Code is the only such
// tool today — every other tool keeps its session id in a store DB, or (Kilo's
// KILO_RUN_ID) exposes an id on a different scheme than observer's.
var SessionTokenEnvKeys = []string{"CLAUDE_CODE_SESSION_ID"}

// ProcessKey derives the stable, PID-reuse-proof key for a process
// (spec §9.3): sha256(boot_id ":" pid ":" start_time_ticks). Callers must
// only build a key when the start time is known.
func ProcessKey(bootID string, pid int, startTimeTicks int64) string {
	h := sha256.Sum256([]byte(bootID + ":" + strconv.Itoa(pid) + ":" + strconv.FormatInt(startTimeTicks, 10)))
	return hex.EncodeToString(h[:])
}
