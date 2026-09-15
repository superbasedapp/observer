package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// Options configures a Renderer or Server.
type Options struct {
	// DB is the observer database. Required.
	DB *sql.DB
	// DBPath is surfaced via the db_path label on observer_db_size_bytes.
	DBPath string
	// CostEngine prices token summaries. Defaults to baked-in pricing.
	CostEngine *cost.Engine
	// CostWindowMinutes caps the cost rollup window. A short window keeps
	// each scrape bounded; Prometheus users get per-scrape deltas via
	// recording rules. Zero → 5 minutes.
	CostWindowMinutes int
	// Logger receives operational messages. Zero value → slog.Default().
	Logger *slog.Logger
	// Now overrides time.Now for tests.
	Now func() time.Time
}

// Render writes one scrape's worth of Prometheus text exposition to w. Any
// individual query failure is absorbed — we emit what we have and surface
// the failure as observer_metrics_scrape_ok = 0.
func Render(ctx context.Context, w io.Writer, opts Options) error {
	if opts.DB == nil {
		return errors.New("metrics.Render: DB is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CostEngine == nil {
		opts.CostEngine = cost.NewEngine(config.IntelligenceConfig{})
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	window := opts.CostWindowMinutes
	if window <= 0 {
		window = 5
	}

	start := opts.Now()
	out := &buf{}
	scrapeOK := true

	if err := writeSnapshotMetrics(ctx, out, opts); err != nil {
		opts.Logger.Warn("metrics.Render snapshot failed", "err", err)
		scrapeOK = false
	}
	if err := writeBridgeMetrics(ctx, out, opts); err != nil {
		opts.Logger.Warn("metrics.Render bridge count failed", "err", err)
		scrapeOK = false
	}
	if err := writeProcessMetrics(ctx, out, opts); err != nil {
		opts.Logger.Warn("metrics.Render process count failed", "err", err)
		scrapeOK = false
	}
	if err := writeCostMetrics(ctx, out, opts, window); err != nil {
		opts.Logger.Warn("metrics.Render cost failed", "err", err)
		scrapeOK = false
	}

	dur := opts.Now().Sub(start).Seconds()
	writeGauge(out, "observer_metrics_scrape_duration_seconds",
		"Duration of the most recent /metrics scrape, in seconds.", dur)
	ok := 1.0
	if !scrapeOK {
		ok = 0
	}
	writeGauge(out, "observer_metrics_scrape_ok",
		"1 if every query backing this scrape succeeded, 0 if any failed.", ok)

	if _, err := w.Write(out.buf); err != nil {
		return fmt.Errorf("metrics.Render write: %w", err)
	}
	return nil
}

// writeSnapshotMetrics emits gauges sourced from diag.Snapshot.
func writeSnapshotMetrics(ctx context.Context, out *buf, opts Options) error {
	snap, err := diag.Snapshot(ctx, opts.DB, opts.DBPath)
	if err != nil {
		return fmt.Errorf("diag.Snapshot: %w", err)
	}

	writeGaugeLabeled(out, "observer_db_size_bytes",
		"Size of the observer SQLite file on disk, in bytes.",
		[]labeled{{labels: [][2]string{{"path", snap.DBPath}}, value: float64(snap.DBSizeBytes)}})
	writeGauge(out, "observer_db_schema_version",
		"Applied schema migration version.", float64(snap.SchemaVersion))

	writeGauge(out, "observer_projects_total",
		"Total rows in the projects table.", float64(snap.Counts.Projects))
	writeGauge(out, "observer_sessions_total",
		"Total rows in the sessions table.", float64(snap.Counts.Sessions))
	writeGauge(out, "observer_actions_total",
		"Total rows in the actions table.", float64(snap.Counts.Actions))
	writeGauge(out, "observer_api_turns_total",
		"Total rows in the api_turns table (proxy-logged LLM turns).",
		float64(snap.Counts.APITurns))
	writeGauge(out, "observer_file_state_total",
		"Total rows in the file_state table (freshness snapshots).",
		float64(snap.Counts.FileState))
	writeGauge(out, "observer_failure_context_total",
		"Total rows in the failure_context table (lifetime).",
		float64(snap.Counts.FailureContext))
	writeGauge(out, "observer_action_excerpts_total",
		"Total rows in the FTS5 action_excerpts table.",
		float64(snap.Counts.ActionExcerpts))
	writeGauge(out, "observer_token_usage_rows_total",
		"Total rows in the token_usage table (JSONL-derived).",
		float64(snap.Counts.TokenUsageRows))
	writeGauge(out, "observer_failures_24h",
		"Rows in failure_context with timestamp within the last 24 hours.",
		float64(snap.RecentFailures24))

	if !snap.LastActionAt.IsZero() {
		writeGauge(out, "observer_last_action_timestamp_seconds",
			"Unix timestamp of the most recently ingested action, regardless of tool.",
			float64(snap.LastActionAt.Unix()))
	}

	if len(snap.PerToolLastSeen) > 0 {
		actions := make([]labeled, 0, len(snap.PerToolLastSeen))
		seen := make([]labeled, 0, len(snap.PerToolLastSeen))
		for _, t := range snap.PerToolLastSeen {
			actions = append(actions, labeled{
				labels: [][2]string{{"tool", t.Tool}},
				value:  float64(t.ActionCount),
			})
			if !t.LastSeenAt.IsZero() {
				seen = append(seen, labeled{
					labels: [][2]string{{"tool", t.Tool}},
					value:  float64(t.LastSeenAt.Unix()),
				})
			}
		}
		writeGaugeLabeled(out, "observer_tool_actions_total",
			"Actions observed per tool, lifetime.", actions)
		if len(seen) > 0 {
			writeGaugeLabeled(out, "observer_tool_last_seen_timestamp_seconds",
				"Unix timestamp of the most recently ingested action per tool.", seen)
		}
	}
	return nil
}

// writeBridgeMetrics emits the pid→session_id bridge row count.
func writeBridgeMetrics(ctx context.Context, out *buf, opts Options) error {
	var n int
	if err := opts.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM session_pid_bridge`).Scan(&n); err != nil {
		return fmt.Errorf("pidbridge count: %w", err)
	}
	writeGauge(out, "observer_pidbridge_entries",
		"Live entries in the session_pid_bridge table (populated by SessionStart hooks).",
		float64(n))
	return nil
}

// writeProcessMetrics emits the DB-derived process-observability gauges
// (docs/process-observability.md §15). These reflect persisted state and so
// work whether or not a backend is currently running. The table always
// exists (migration 044), so a disabled feature simply reports zeros.
//
// The LIVE runtime state (backend up, queue depth, network-accounting mode)
// comes from the daemon's in-memory processobs.Health. This exporter is its
// own process — `observer metrics`, not `observer start` — so it cannot read
// that memory; the daemon publishes it as a diag.ProcessHealth record beside
// the DB and writeProcessHealthMetrics below re-exports it.
func writeProcessMetrics(ctx context.Context, out *buf, opts Options) error {
	var total, attributed int
	if err := opts.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM process_runs`).Scan(&total); err != nil {
		return fmt.Errorf("process_runs count: %w", err)
	}
	if err := opts.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM process_runs WHERE session_id IS NOT NULL`).Scan(&attributed); err != nil {
		return fmt.Errorf("process_runs attributed count: %w", err)
	}
	writeGaugeLabeled(out, "observer_process_runs",
		"Persisted process_runs rows, split by whether they are attributed to a session.",
		[]labeled{
			{labels: [][2]string{{"attributed", "true"}}, value: float64(attributed)},
			{labels: [][2]string{{"attributed", "false"}}, value: float64(total - attributed)},
		})

	rows, err := opts.DB.QueryContext(ctx,
		`SELECT tool, COUNT(*) FROM process_runs WHERE tool IS NOT NULL GROUP BY tool ORDER BY tool`)
	if err != nil {
		return fmt.Errorf("process_runs by tool: %w", err)
	}
	defer rows.Close()
	var byTool []labeled
	for rows.Next() {
		var tool string
		var n int
		if err := rows.Scan(&tool, &n); err != nil {
			return fmt.Errorf("process_runs by tool scan: %w", err)
		}
		byTool = append(byTool, labeled{labels: [][2]string{{"tool", tool}}, value: float64(n)})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("process_runs by tool rows: %w", err)
	}
	if len(byTool) > 0 {
		writeGaugeLabeled(out, "observer_process_runs_by_tool",
			"Persisted, attributed process_runs rows per AI tool.", byTool)
	}
	writeProcessHealthMetrics(out, opts)
	return nil
}

// writeProcessHealthMetrics re-exports the running daemon's
// process-observability runtime health (diag.ProcessHealth) as gauges.
//
// Absence is meaningful and is expressed as absent metric families, not as
// zeros: no live record means no daemon has reported, and a fabricated
// `backend_up 0` would be indistinguishable from a daemon that is up with a
// dead backend. observer_process_health_age_seconds lets a scraper decide
// for itself whether the report is fresh — a wedged daemon keeps its record
// on disk, so the age is the honest signal, not the presence of the file.
//
// Read failures are silent for the same reason: "no daemon reporting" is the
// normal state for this optional, opt-in feature and must not fail the
// scrape.
func writeProcessHealthMetrics(out *buf, opts Options) {
	h, ok := diag.LatestProcessHealth(diag.ProcessHealthDir(opts.DBPath))
	if !ok {
		return
	}
	backend := h.Backend
	if backend == "" {
		backend = "unknown"
	}
	up := 0.0
	if h.BackendUp {
		up = 1
	}
	writeGaugeLabeled(out, "observer_process_backend_up",
		"1 if the process-observability capture backend reported itself up, 0 if down. Absent when no daemon has published health.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: up}})
	writeGaugeLabeled(out, "observer_process_queue_depth",
		"Depth of the process-observability event queue as last reported by the daemon.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.QueueDepth)}})
	writeGauge(out, "observer_process_health_timestamp_seconds",
		"Unix timestamp at which the daemon last published its process-observability health.",
		float64(h.WrittenAt.Unix()))
	writeGauge(out, "observer_process_health_age_seconds",
		"Age of the most recent process-observability health report, in seconds. Grows without bound if the daemon stops refreshing.",
		h.Age(opts.Now()).Seconds())

	// The capture-YIELD counters. They are the only scrape-side evidence that
	// distinguishes an idle box from a daemon discarding every batch, and
	// `reason` is a BOUNDED label (the processobs.DropReason vocabulary), so it
	// is safe as a series dimension unlike the free-form *_info reasons below.
	if drops := labeledCounts(h.Dropped, "reason"); len(drops) > 0 {
		writeGaugeLabeled(out, "observer_process_dropped",
			"Process runs/events the daemon discarded, by reason, cumulative since daemon start. `sink_retry_exhausted` is the loud one — capture that was buffered against a failing sink and then LOST when the retention overflowed; `flush_backlog` is its upstream twin — capture shed because the flusher fell so far behind that the rows were never offered to the sink at all. `sink_error` is a permanent sink failure; `unattributed` and `self_excluded` are ordinary policy drops, not faults. Absent when nothing has been dropped.",
			drops)
	}
	writeGaugeLabeled(out, "observer_process_sink_retained",
		"Process runs held back RIGHT NOW after a transient sink failure, waiting for the next flush. This is a gauge, not a counter, and a non-zero value is NOT loss — it is capture being buffered while the database is busy. Sustained non-zero is the early warning that precedes observer_process_dropped{reason=\"sink_retry_exhausted\"}.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.SinkRetained)}})
	writeGaugeLabeled(out, "observer_process_sink_flush_max_ms",
		"Longest single sink flush the daemon has observed, in milliseconds (a watermark, not a sample). Seconds-scale values mean the database was contended. This is NO LONGER a capture blackout — the flush runs on its own goroutine — so read it beside observer_process_flush_backlog_hits, which is what says the contention reached capture at all.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.SinkFlushMaxMs)}})
	writeGaugeLabeled(out, "observer_process_flush_backlog_hits",
		"Times the capture drain found the hand-off buffer to the flusher full, cumulative since daemon start. Non-zero alone is NOT loss — the drain holds the batch and retries, so this is capture being delayed by a slow sink. It becomes loss only alongside observer_process_dropped{reason=\"flush_backlog\"}.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.FlushBacklogHits)}})
	writeGaugeLabeled(out, "observer_process_handoff_depth_max",
		"High-water mark of the drain-to-flusher hand-off buffer, in BATCHES. A value pinned at the buffer's capacity beside a large observer_process_sink_flush_max_ms means the sink was the bottleneck for a sustained period.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.HandoffDepthMax)}})
	writeGaugeLabeled(out, "observer_process_queue_depth_max",
		"High-water mark of the process-observability event queue. Read beside observer_process_sink_flush_max_ms: a peak near the backend's channel capacity means the backend was blocked on send and stopped enumerating.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.QueueDepthMax)}})
	if attributed := labeledCounts(h.AttributedByTool, "tool"); len(attributed) > 0 {
		writeGaugeLabeled(out, "observer_process_attributed",
			"Process runs the daemon resolved to a session, by tool, cumulative since daemon start. The denominator the drop counters are read against.",
			attributed)
	}
	writeGaugeLabeled(out, "observer_process_unattributed",
		"Process runs the daemon could not resolve to any session, cumulative since daemon start. Normal in bulk on a shared box (every unrelated process); read it beside observer_process_attributed, not alone.",
		[]labeled{{labels: [][2]string{{"backend", backend}}, value: float64(h.Unattributed)}})

	// Enum-style state set: exactly one mode is 1. Emitting every mode
	// (rather than only the active one) means an alert can be written as
	// `observer_process_network_accounting{mode="unavailable"} == 1` without
	// needing an absence check, and a mode flip cannot leave a stale series
	// at 1.
	mode := h.NetworkAccountingMode
	if mode != "" && !processobs.KnownNetworkAccountingMode(mode) {
		// An unrecognised mode is bucketed, never emitted as itself. It is
		// reported (not folded into "off" — the point of this surface is to
		// not invent certainty) but the LABEL VALUE stays inside this build's
		// vocabulary: mode reaches the daemon partly from the cross-OS
		// capturer's hello frame, and a label whose values a remote picks is
		// a series Prometheus keeps forever, once per distinct string. The
		// unrecognised value itself is on the doctor line, which holds one
		// value at a time.
		mode = processNetworkModeUnrecognised
	}
	modes := make([]labeled, 0, len(processNetworkModes)+1)
	for _, m := range processNetworkModes {
		v := 0.0
		if m == mode {
			v = 1
		}
		modes = append(modes, labeled{labels: [][2]string{{"mode", m}}, value: v})
	}
	if mode == processNetworkModeUnrecognised {
		modes = append(modes, labeled{labels: [][2]string{{"mode", mode}}, value: 1})
	}
	writeGaugeLabeled(out, "observer_process_network_accounting",
		"Per-process network byte accounting state, one series per mode: off (not requested), unavailable (requested but not attached — bytes are UNMEASURED, not zero), tcp (live, TCP payload bytes only — UDP/QUIC is never counted), unrecognised (the daemon reported a mode this exporter does not define — see `observer doctor` for the value).",
		modes)

	// The reason is the actionable half of "unavailable" ("missing CAP_BPF/
	// CAP_PERFMON", "needs elevation", …) and is carried verbatim as a
	// label. Info-style: value is always 1. The mode label is the bucketed
	// one for the reason above; the reason itself is bounded in LENGTH at the
	// bridge boundary (a capturer's hello reason is clamped there), and is
	// accepted here as a documented trade: a post-authentication string whose
	// operator value is precisely its verbatim wording.
	writeGaugeLabeled(out, "observer_process_network_accounting_info",
		"Always 1. Carries the current per-process network accounting mode and the daemon's verbatim reason for a non-live mode.",
		[]labeled{{labels: [][2]string{
			{"mode", mode},
			{"reason", h.NetworkAccountingReason},
		}, value: 1}})

	writeProcessTransportMetrics(out, h)
}

// writeProcessTransportMetrics emits the cross-OS capturer link's connection
// gauges — the only surface on which "the elevated capturer never connected"
// and "the elevated capturer is being refused on a bad token" are visible.
//
// Absence is meaningful HERE TOO, and for a sharper reason than the health
// families above: most installs have no dial-in capture transport at all, so
// emitting `observer_process_transport_connections 0` for them would page on
// a feed they never configured. The whole family set is therefore skipped
// unless the daemon reported a configured transport — which also makes a
// record written by an older daemon (no such key) silently correct rather
// than a fabricated zero.
//
// The one thing that is NOT silence is a transport the operator asked for
// that never came up: that gets its own info-style series, because otherwise
// "requested and broken" scrapes identically to "never requested".
func writeProcessTransportMetrics(out *buf, h diag.ProcessHealth) {
	if h.TransportState == processobs.TransportStateUnavailable {
		// Info-style (value always 1), same shape as
		// observer_process_network_accounting_info: the free-form reason is a
		// label on an always-1 series, never a value.
		writeGaugeLabeled(out, "observer_process_transport_unavailable_info",
			"Always 1 when a cross-OS capture transport was REQUESTED but could not be created (bind conflict, unwritable token file, block left disabled), carrying the daemon's verbatim reason. Absent when no transport was requested and when one is running — a requested-and-broken transport must not scrape identically to an unconfigured one.",
			[]labeled{{labels: [][2]string{{"reason", h.TransportUnavailableReason}}, value: 1}})
		return
	}
	if !h.TransportConfigured() {
		return
	}
	addr := h.TransportAddr
	if addr == "" {
		addr = "unknown"
	}
	labels := [][2]string{{"addr", addr}}
	connected := 0.0
	if h.TransportConnected {
		connected = 1
	}
	writeGaugeLabeled(out, "observer_process_transport_connected",
		"1 if a cross-OS process capturer is connected to the daemon's accept listener right now, 0 if not. Absent when no such transport is configured.",
		[]labeled{{labels: labels, value: connected}})
	writeGaugeLabeled(out, "observer_process_transport_connections",
		"Capturers that connected AND authenticated over the daemon's accept listener, for the daemon's lifetime. 0 with 0 auth failures means no capturer has ever started.",
		[]labeled{{labels: labels, value: float64(h.TransportConnections)}})
	writeGaugeLabeled(out, "observer_process_transport_auth_failures",
		"Connections REFUSED at the daemon's capturer handshake, for ANY reason (wrong shared token, a protocol version this daemon does not speak, an unrelated local process probing the port). Non-zero with observer_process_transport_connections == 0 means something is dialling and nothing is getting through — the count names no cause; observer_process_transport_auth_failure_info carries the daemon's verbatim reason.",
		[]labeled{{labels: labels, value: float64(h.TransportAuthFailures)}})
	// The refusal's CLASS rides an info-style always-1 series as a label (the
	// observer_process_network_accounting_info pattern), never a gauge value.
	// Absent until a refusal is actually recorded: an empty series would read
	// as "refused for no reason".
	//
	// The class, not the daemon's verbatim reason. The reason quotes a
	// fragment supplied by whatever dialled the port — and this listener's
	// bind is reachable from every process on the Windows host under WSL
	// localhostForwarding — so a reason label lets any local process mint a
	// fresh label value per connection attempt, and Prometheus retains every
	// distinct series it has ever scraped. A length clamp does not help: it
	// bounds each string's SIZE, not the NUMBER of distinct strings. The
	// class comes from a closed vocabulary owned by this build and is
	// re-normalised here, so the label's value set is bounded no matter what
	// the health record on disk contains. The verbatim reason stays on
	// `observer doctor`'s transport line, which holds exactly one value.
	if h.TransportLastAuthError != "" {
		writeGaugeLabeled(out, "observer_process_transport_auth_failure_info",
			"Always 1. Classifies the most recent refused capturer handshake: token_mismatch (the shared secret did not match), protocol_version (the client speaks a wire version this daemon does not), malformed (not a capturer handshake at all — often an unrelated local process probing the port), transport (the socket died mid-handshake), unknown (a refusal recorded by a daemon predating this field). The daemon's VERBATIM reason is deliberately not a label — it quotes remote input, and one series per distinct string is unbounded cardinality; read `observer doctor` for it. Absent until a refusal is recorded.",
			[]labeled{{labels: append(append([][2]string{}, labels...),
				[2]string{"class", processobs.NormalizeTransportAuthClass(h.TransportLastAuthErrorClass)}), value: 1}})
	}

	// The capturer's OWN decoder health — the only evidence that the
	// fixed-offset payload layout it decodes by actually holds on that host.
	//
	// Gated on the presence flag, and the gate is the point: a capturer with
	// no running network decoder (every non-elevated run) reports nothing, and
	// emitting `observer_process_capturer_decode_dropped 0` for it would say
	// the layout assumptions were exercised and held when nothing was decoded
	// at all. Absent means "never reported"; a reported 0 is a REAL
	// measurement and is emitted as one, because "it stayed zero" is exactly
	// what an operator validating this feed needs to be able to alert on.
	if h.TransportCapturerDecodeReported {
		writeGaugeLabeled(out, "observer_process_capturer_decode_dropped",
			"Network data events the cross-OS capturer's decoder REFUSED as short or unexpectedly shaped, as of its most recent report. NON-ZERO IS THE LOUD ONE: the fixed-offset payload layout does not hold on that host, so the per-process byte totals are WRONG rather than merely missing. Absent when no capturer has ever reported its decode health (which is NOT the same as a reported zero).",
			[]labeled{{labels: labels, value: float64(h.TransportCapturerDropped)}})
		writeGaugeLabeled(out, "observer_process_capturer_decode_unsupported_version",
			"Network data events the cross-OS capturer's decoder refused because the OS stamped an event version its layout table does not describe. Broken out from the dropped count because the cause and the fix differ: the OS shipped a new template and this build's field offsets may no longer apply. Absent when no capturer has ever reported its decode health.",
			[]labeled{{labels: labels, value: float64(h.TransportCapturerUnsupportedVersion)}})
		// The POSITIVE half of the same report. The two counters above can
		// only say what was REFUSED, and the failure that matters most
		// refuses nothing: if the OS renumbers the Kernel-Network event ids,
		// every event lands in the ignored bucket and the capturer scrapes
		// clean while measuring zero bytes.
		//
		// A LARGE IGNORED COUNT IS NORMAL — do not alert on it alone; it
		// counts control-plane events, connect/disconnect/retransmit and UDP,
		// which outnumber data events on every healthy host. The alertable
		// fact is the conjunction, which is exported as its own 0/1 series
		// below rather than left for each operator to re-derive.
		writeGaugeLabeled(out, "observer_process_capturer_decode_decoded",
			"Network data events the cross-OS capturer's decoder ACCEPTED and counted bytes from, as of its most recent report. This is the only series that says the decoder measured anything: every per-process byte total comes from an accepted event, so a zero here means the byte totals are necessarily zero however clean the refusal counters look. Absent when no capturer has ever reported its decode health.",
			[]labeled{{labels: labels, value: float64(h.TransportCapturerDecoded)}})
		writeGaugeLabeled(out, "observer_process_capturer_decode_ignored",
			"Events the cross-OS capturer's decoder saw and classified as not-a-data-event (control-plane, TCP connect/disconnect/accept/retransmit, UDP). A LARGE VALUE IS NORMAL AND HEALTHY — this is not a fault counter and must not be alerted on by itself. It is exported because it is one half of the only conjunction that catches a renumbered provider; see observer_process_capturer_decode_nothing_classified. Absent when no capturer has ever reported its decode health.",
			[]labeled{{labels: labels, value: float64(h.TransportCapturerIgnored)}})
		nothingClassified := 0.0
		if h.CapturerDecodeNothingClassified() {
			nothingClassified = 1
		}
		writeGaugeLabeled(out, "observer_process_capturer_decode_nothing_classified",
			"1 when the capturer's decoder saw events, classified NONE of them as data, and refused none either — the renumbered-provider signature, in which every refusal-shaped check passes while the decoder measures nothing. It is exported as a derived series, not left to a PromQL conjunction, because the raw counters are individually unalarming and an operator cannot be expected to re-derive the one shape that matters. 1 is a SUSPICION, not a diagnosis: on a host moving TCP traffic it means the provider's event ids no longer match this build's layout table; on a genuinely idle host it means the feed has not yet proven it decodes anything. Absent when no capturer has ever reported its decode health.",
			[]labeled{{labels: labels, value: nothingClassified}})
		if !h.TransportCapturerDecodeAt.IsZero() {
			writeGaugeLabeled(out, "observer_process_capturer_decode_report_timestamp_seconds",
				"Unix timestamp at which the daemon RECEIVED the capturer's most recent decode-health report (stamped locally, never taken from the wire). Absent until one arrives; it is what makes the two counters above readable as current rather than as history.",
				[]labeled{{labels: labels, value: float64(h.TransportCapturerDecodeAt.Unix())}})
		}
	}

	// Never-happened is expressed as an absent series, not as epoch 0: a
	// capturer that has never connected must not read as "connected in 1970".
	if !h.TransportLastConnectAt.IsZero() {
		writeGaugeLabeled(out, "observer_process_transport_last_connect_timestamp_seconds",
			"Unix timestamp of the most recent successful capturer connection. Absent until one happens.",
			[]labeled{{labels: labels, value: float64(h.TransportLastConnectAt.Unix())}})
	}
	if !h.TransportLastDisconnectAt.IsZero() {
		writeGaugeLabeled(out, "observer_process_transport_last_disconnect_timestamp_seconds",
			"Unix timestamp of the most recent capturer disconnection. Absent until one happens; paired with the connect timestamp it makes a flapping capturer visible.",
			[]labeled{{labels: labels, value: float64(h.TransportLastDisconnectAt.Unix())}})
	}
}

// processNetworkModes is the set of accounting modes always emitted as a
// state set. It is READ FROM the processobs vocabulary rather than restated
// here, so this exporter cannot drift out of sync with the one owner of that
// list (CLAUDE.md rule 4).
var processNetworkModes = processobs.NetworkAccountingModes()

// processNetworkModeUnrecognised is the bucket every mode this build does not
// define lands in. It is not a processobs mode — it is this exporter's way of
// saying "the daemon named something I do not know" with ONE label value
// instead of one per distinct string.
const processNetworkModeUnrecognised = "unrecognised"

// writeCostMetrics emits cost / token / compression gauges rolled up over
// the last windowMinutes.
func writeCostMetrics(ctx context.Context, out *buf, opts Options, windowMinutes int) error {
	since := opts.Now().Add(-time.Duration(windowMinutes) * time.Minute)
	summary, err := opts.CostEngine.Summary(ctx, opts.DB, cost.Options{
		Since:   since,
		GroupBy: cost.GroupByModel,
		Source:  cost.SourceAuto,
		Now:     opts.Now,
	})
	if err != nil {
		return fmt.Errorf("cost.Summary: %w", err)
	}

	windowLabel := strconv.Itoa(windowMinutes) + "m"

	writeGaugeLabeled(out, "observer_cost_usd_window",
		"Total USD cost aggregated over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: summary.TotalCost}})
	writeGaugeLabeled(out, "observer_turns_window",
		"Total LLM turns aggregated over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(summary.TurnCount)}})

	if len(summary.Rows) > 0 {
		costs := make([]labeled, 0, len(summary.Rows))
		turns := make([]labeled, 0, len(summary.Rows))
		var tokens []labeled
		for _, r := range summary.Rows {
			modelLabels := [][2]string{
				{"model", r.Key},
				{"window", windowLabel},
			}
			costs = append(costs, labeled{labels: modelLabels, value: r.CostUSD})
			turns = append(turns, labeled{labels: modelLabels, value: float64(r.TurnCount)})
			for _, kv := range tokenKinds(r) {
				tokens = append(tokens, labeled{
					labels: [][2]string{
						{"model", r.Key},
						{"kind", kv.kind},
						{"window", windowLabel},
					},
					value: float64(kv.value),
				})
			}
		}
		writeGaugeLabeled(out, "observer_cost_usd",
			"USD cost per model over the scrape window.", costs)
		writeGaugeLabeled(out, "observer_turns_per_model",
			"LLM turns per model over the scrape window.", turns)
		writeGaugeLabeled(out, "observer_tokens",
			"Token counts per model and kind (input|output|cache_read|cache_creation) over the scrape window.",
			tokens)
	}

	c := summary.TotalCompression
	writeGaugeLabeled(out, "observer_compression_original_bytes",
		"Sum of pre-compression request body sizes over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.OriginalBytes)}})
	writeGaugeLabeled(out, "observer_compression_compressed_bytes",
		"Sum of post-compression request body sizes over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.CompressedBytes)}})
	writeGaugeLabeled(out, "observer_compression_saved_bytes",
		"Bytes saved by conversation compression over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.SavedBytes())}})
	writeGaugeLabeled(out, "observer_compression_compressed_count",
		"Tool-result bodies rewritten by per-type compression over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.CompressedCount)}})
	writeGaugeLabeled(out, "observer_compression_dropped_count",
		"Original messages replaced by markers over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.DroppedCount)}})
	writeGaugeLabeled(out, "observer_compression_marker_count",
		"Marker messages emitted by the compression pipeline over the scrape window.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.MarkerCount)}})
	writeGaugeLabeled(out, "observer_compression_turns",
		"Turns in the window that carried any compression metadata.",
		[]labeled{{labels: [][2]string{{"window", windowLabel}}, value: float64(c.Turns)}})
	return nil
}

type tokenKV struct {
	kind  string
	value int64
}

func tokenKinds(r cost.Row) []tokenKV {
	return []tokenKV{
		{"input", r.Tokens.Input},
		{"output", r.Tokens.Output},
		{"cache_read", r.Tokens.CacheRead},
		{"cache_creation", r.Tokens.CacheCreation},
	}
}

// labeled is one labeled sample.
type labeled struct {
	labels [][2]string
	value  float64
}

// buf is a thin bytes.Buffer replacement that avoids the extra import and
// tracks write errors cleanly. Methods always succeed (they write to a byte
// slice); the surrounding Render call decides how to surface failures.
type buf struct {
	buf []byte
}

func (b *buf) writeString(s string) { b.buf = append(b.buf, s...) }
func (b *buf) writeByte(c byte)     { b.buf = append(b.buf, c) }

// writeGauge emits HELP + TYPE + a single unlabeled sample.
// labeledCounts turns a counter map into one labeled sample per non-zero
// entry, under the given label name. Zero entries are skipped: a reason
// recorded as zero is a series that will never be interesting and only widens
// the cardinality. Nil/empty (or all-zero) yields nil, which writeGaugeLabeled
// renders as absence — the same absent-is-not-zero rule the transport
// counters follow.
func labeledCounts(m map[string]int64, label string) []labeled {
	out := make([]labeled, 0, len(m))
	for k, v := range m {
		if v == 0 || k == "" {
			continue
		}
		out = append(out, labeled{labels: [][2]string{{label, k}}, value: float64(v)})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func writeGauge(w *buf, name, help string, value float64) {
	writeHeader(w, name, help, "gauge")
	w.writeString(name)
	w.writeByte(' ')
	w.writeString(formatValue(value))
	w.writeByte('\n')
}

// writeGaugeLabeled emits HELP + TYPE + one sample per label set. Empty
// input is a no-op (absent metric families are valid in Prometheus).
func writeGaugeLabeled(w *buf, name, help string, samples []labeled) {
	if len(samples) == 0 {
		return
	}
	writeHeader(w, name, help, "gauge")
	// Deterministic order: sort by the formatted label string so tests are
	// stable regardless of map iteration.
	sort.SliceStable(samples, func(i, j int) bool {
		return formatLabels(samples[i].labels) < formatLabels(samples[j].labels)
	})
	for _, s := range samples {
		w.writeString(name)
		w.writeString(formatLabels(s.labels))
		w.writeByte(' ')
		w.writeString(formatValue(s.value))
		w.writeByte('\n')
	}
}

func writeHeader(w *buf, name, help, typeStr string) {
	w.writeString("# HELP ")
	w.writeString(name)
	w.writeByte(' ')
	w.writeString(escapeHelp(help))
	w.writeByte('\n')
	w.writeString("# TYPE ")
	w.writeString(name)
	w.writeByte(' ')
	w.writeString(typeStr)
	w.writeByte('\n')
}

// formatLabels renders `{k1="v1",k2="v2"}` with proper escaping. Returns
// an empty string when there are no labels.
func formatLabels(labels [][2]string) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, kv := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[0])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(kv[1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel makes s safe as a Prometheus label value.
//
// The text format defines exactly three escapes — `\\`, `\"`, `\n` — and
// nothing else. That is a smaller alphabet than "control characters", so the
// other control bytes need a decision rather than a pass-through:
//
//   - a raw CR inside a quoted label value is not escapable (there is no
//     `\r` escape; emitting one would be an UNDEFINED escape sequence that a
//     conforming parser rejects), and a raw CR/LF pair would end the sample
//     line early, splicing the tail of one label into what a scraper reads as
//     the next metric;
//   - invalid UTF-8 is not a legal label value at all.
//
// So the three defined escapes are applied, every OTHER C0 control and DEL is
// DROPPED, and invalid UTF-8 is replaced (ranging a string yields U+FFFD for
// each bad byte). Dropping loses a byte nobody can render anyway; it cannot
// forge exposition structure.
//
// This is BELT, not the braces. Today's callers are not known to be able to
// reach here with a control byte — the strings that quote remote input are
// built with %q at the error-construction site, which escapes them first, and
// the clamp on those strings bounds length, not bytes. That makes %q the
// ACTUAL protection and this function the backstop for the next caller that
// forgets one. Neither is a substitute for the other.
func escapeLabel(s string) string {
	if !needsLabelEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 || r == 0x7f:
			// No defined escape, and raw would corrupt the exposition.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// needsLabelEscape reports whether s must go through the escaping path. It is
// the fast path's gate, so it has to cover EVERY transform escapeLabel makes
// — including the ones that are not escapes (dropped control bytes, replaced
// invalid UTF-8). A gate narrower than the transform is how raw bytes slip
// past an escaper that would have handled them.
func needsLabelEscape(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '"' || c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// escapeHelp escapes `\` and newlines in HELP text (no `"` escape needed —
// HELP is terminated by end-of-line, not a quote).
//
// It deliberately does NOT carry escapeLabel's control-byte handling: every
// HELP string in this package is a compile-time literal written here, so
// there is no input path to defend. If a HELP string ever becomes dynamic,
// that changes and this must gain the same treatment.
func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatValue renders a float using Go's 'g' verb with full precision —
// Prometheus accepts decimal, exponential, and the three special tokens.
func formatValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Server wraps Render in an http.Handler for long-running scrapers.
type Server struct {
	opts Options
}

// New returns a Server. DB is required.
func New(opts Options) (*Server, error) {
	if opts.DB == nil {
		return nil, errors.New("metrics.New: DB is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CostEngine == nil {
		opts.CostEngine = cost.NewEngine(config.IntelligenceConfig{})
	}
	return &Server{opts: opts}, nil
}

// Handler returns an http.Handler that serves /metrics in Prometheus text
// format. Any other path 404s; GET is the only accepted method.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "observer metrics exporter\nGET /metrics\n")
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	if err := Render(r.Context(), w, s.opts); err != nil {
		s.opts.Logger.Error("metrics.Render failed", "err", err)
	}
}

// ListenAndServe runs the metrics server on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
