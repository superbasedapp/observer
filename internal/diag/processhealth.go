package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// ProcessHealth is the on-disk snapshot of a running daemon's
// process-observability runtime health (docs/process-observability.md §15).
//
// WHY A FILE. The daemon (`observer start`) owns the live
// processobs.Health in memory, but BOTH surfaces that must report it are
// separate OS processes:
//
//   - `observer doctor` is a one-shot CLI over DB + config, and
//   - `/metrics` is served by `observer metrics`, its own long-running
//     process — the daemon does not serve it.
//
// So neither can read the Observer's memory, and the alternatives are worse:
// deriving the state from process_runs.metric_samples_json rings would show
// only that bytes were unmeasured, never WHY, and could not tell "off" (the
// operator disabled it — do not nag) from "unavailable" (requested and
// failed — the loud case); scraping /metrics from doctor would only ask a
// second process that has the same blind spot. The daemon therefore
// publishes this small record next to the DB, on the same per-PID +
// liveness-filtered pattern as LockInfo, and doctor/metrics read it back and
// report it AS a report ("pid N said X, T ago") rather than as live truth.
//
// The zero value is meaningless — always read it via LiveProcessHealth or
// LatestProcessHealth, which drop records left behind by dead daemons.
type ProcessHealth struct {
	// PID is the daemon that wrote the record. Readers drop records whose
	// PID is no longer alive.
	PID int `json:"pid"`
	// WrittenAt is when the daemon sampled its health, in UTC. Readers use
	// it for the staleness classification (see ProcessHealthStaleAfter).
	WrittenAt time.Time `json:"written_at"`
	// Backend is processobs.HealthSnapshot.BackendName ("linux_ebpf+poll",
	// "poll", "etw", …).
	Backend string `json:"backend"`
	// BackendUp mirrors HealthSnapshot.BackendUp.
	BackendUp bool `json:"backend_up"`
	// QueueDepth mirrors HealthSnapshot.QueueDepth.
	QueueDepth int64 `json:"queue_depth"`
	// LastError mirrors HealthSnapshot.LastError (empty when clean).
	LastError string `json:"last_error,omitempty"`

	// Dropped mirrors HealthSnapshot.Dropped, keyed by the DropReason string
	// ("sink_error", "unattributed", "self_excluded", "no_start_time",
	// "sink_retry_exhausted", …). Counters, cumulative since daemon start.
	//
	// These are the ONLY outside-the-daemon evidence of why capture did not
	// land. Without them a daemon silently discarding whole batches on a busy
	// DB is indistinguishable from a quiet box where nothing spawned — which
	// is exactly the state the 2026-08-26 process-capture anomaly was stuck in
	// for a full boot (task 9c/9d). The keys are the domain's own vocabulary
	// carried as plain strings so this record stays a wire shape rather than a
	// leaked processobs type; an unknown key from a newer daemon must be
	// rendered, never dropped, so a reason added later is visible on an older
	// reader.
	Dropped map[string]int64 `json:"dropped,omitempty"`
	// Attributed / Unattributed mirror the runs the daemon resolved to a
	// session and the runs it could not. They are the DENOMINATOR the Dropped
	// counters are read against: "300 unattributed drops" means one thing
	// beside 4 attributed runs and another beside 40,000.
	Attributed   int64 `json:"attributed,omitempty"`
	Unattributed int64 `json:"unattributed,omitempty"`
	// AttributedByTool is Attributed broken out per tool, mirroring
	// HealthSnapshot.AttributedByTool. A tool absent here captured nothing.
	AttributedByTool map[string]int64 `json:"attributed_by_tool,omitempty"`
	// SinkRetained is a GAUGE (not a counter): runs held back right now after
	// a transient sink failure, waiting for the next flush. Non-zero means
	// writes are failing but capture is being BUFFERED rather than lost —
	// a different fact from any Dropped counter, and the early warning that
	// precedes "sink_retry_exhausted".
	SinkRetained int64 `json:"sink_retained,omitempty"`
	// SinkFlushMaxMs is the LONGEST single sink flush the daemon has observed,
	// and QueueDepthMax the high-water mark of its backend queue. Both are
	// WATERMARKS, so a stall that opened and closed between two 30 s health
	// publishes still shows — unlike QueueDepth, which is a sample.
	//
	// They used to measure a loss no drop counter could see: the flush ran on
	// the only goroutine draining the capture backend, so a long flush was a
	// window in which the backend was not read at all, and a snapshot-diff
	// backend that blocks on send stopped enumerating inside it. Since task 9g
	// the flush runs on its own goroutine, so a long SinkFlushMaxMs now means
	// "the database was contended" — read it beside FlushBacklogHits, which is
	// what says the contention actually reached capture.
	SinkFlushMaxMs int64 `json:"sink_flush_max_ms,omitempty"`
	QueueDepthMax  int64 `json:"queue_depth_max,omitempty"`
	// HandoffDepthMax is the high-water mark of the drain→flusher hand-off
	// buffer (in BATCHES) and FlushBacklogHits counts how often the drain found
	// it full. Hits > 0 with no dropped{flush_backlog} is the GOOD outcome: a
	// slow sink was absorbed and capture was delayed, not lost. Hits climbing
	// together with dropped{flush_backlog} means the sink was persistently
	// slower than capture.
	HandoffDepthMax  int64 `json:"handoff_depth_max,omitempty"`
	FlushBacklogHits int64 `json:"flush_backlog_hits,omitempty"`
	// NetworkAccountingMode is one of the processobs.NetworkAccounting*
	// values — "off" (not requested), "unavailable" (requested, could not
	// attach) or "tcp" (live, TCP payload bytes only).
	NetworkAccountingMode string `json:"network_accounting_mode"`
	// NetworkAccountingReason is the human-readable explanation of a
	// non-live mode ("missing CAP_BPF/CAP_PERFMON", "needs elevation", …).
	// It is carried verbatim by every consumer of this record: a mode of
	// "unavailable" without the reason is not actionable.
	//
	// "Verbatim" is about THIS layer. One producer — the cross-OS capturer,
	// which states its own accounting status in a hello frame — is a REMOTE,
	// and its reason is clamped where it enters the daemon
	// (processobs/bridge, netClaim.apply) because nothing on that wire bounds
	// it but the 1 MiB NDJSON line budget. What arrives here is already
	// whatever the daemon decided to keep; this record does not cut it again.
	NetworkAccountingReason string `json:"network_accounting_reason,omitempty"`

	// TransportState is one of the processobs.TransportState* values — "none"
	// (no dial-in capturer transport was requested), "unavailable" (one was
	// requested and could not be created) or "configured" (one exists; the
	// counters below are real). It is the honesty gate on every Transport*
	// field below AND the back-compat gate: a record written by an older
	// daemon has no such key, so it decodes empty, is read as "none", and the
	// surfaces stay silent rather than rendering "0 connections" — which
	// would read as a broken transport on the 99% of installs that have none.
	// Absent, zero and broken must all stay distinguishable (the NetMeasured
	// trap, one state wider).
	TransportState string `json:"transport_state,omitempty"`
	// TransportUnavailableReason explains a TransportState of "unavailable"
	// (a bind conflict on the listen address, an unwritable token file, the
	// ETW block left disabled). Carried verbatim: the state without the
	// reason is not actionable.
	TransportUnavailableReason string `json:"transport_unavailable_reason,omitempty"`
	// TransportAddr is the endpoint the capturer is expected to dial.
	TransportAddr string `json:"transport_addr,omitempty"`
	// TransportConnections counts capturers that connected AND authenticated.
	TransportConnections int64 `json:"transport_connections,omitempty"`
	// TransportAuthFailures counts connections refused at the handshake, for
	// ANY reason. Non-zero with TransportConnections == 0 is the actionable
	// state this surface exists to make visible — but the COUNT NAMES NO
	// CAUSE (a wrong token, a protocol version this daemon does not speak, an
	// unrelated local process probing the port all land here). Only
	// TransportLastAuthError says what actually happened.
	TransportAuthFailures int64 `json:"transport_auth_failures,omitempty"`
	// TransportLastAuthError is the daemon's verbatim record of the most
	// recent refusal. Empty means none was recorded — never "it was a token".
	//
	// It is free-form and quotes a fragment supplied by whatever dialled the
	// port, so it belongs on TEXT surfaces (one line, one value, re-read on
	// demand) and NOT on a metric label, where every distinct value Prometheus
	// has ever seen is retained. TransportLastAuthErrorClass is the bounded
	// field for that.
	TransportLastAuthError string `json:"transport_last_auth_error,omitempty"`
	// TransportLastAuthErrorClass is TransportLastAuthError's bounded
	// classification, one of the processobs.TransportAuthClass* values. Empty
	// on a record written by a daemon that predates the field; readers
	// normalise that to "unknown" rather than guessing a cause.
	TransportLastAuthErrorClass string `json:"transport_last_auth_error_class,omitempty"`
	// TransportConnected reports whether a capturer is streaming right now.
	TransportConnected bool `json:"transport_connected,omitempty"`
	// TransportLastConnectAt / TransportLastDisconnectAt are zero until they
	// first happen; both set with TransportConnected false is a capturer that
	// came and went, which is how a flapping capturer becomes visible.
	TransportLastConnectAt    time.Time `json:"transport_last_connect_at,omitzero"`
	TransportLastDisconnectAt time.Time `json:"transport_last_disconnect_at,omitzero"`

	// TransportCapturerDecodeReported is the honesty gate on the two decode
	// counters below, exactly as TransportState is the gate on the transport
	// fields: false means the connected capturer has NEVER reported its
	// decoder health, which is what a capturer with no running network
	// decoder does (every non-elevated run). It also decodes false on a
	// record written by a daemon that predates the field.
	//
	// "Never reported" and "reported zero drops" are opposite facts — the
	// first says the fixed-offset payload layout was never exercised, the
	// second says it was exercised and held — so a consumer must render this
	// false as ABSENCE and never as a clean zero.
	TransportCapturerDecodeReported bool `json:"transport_capturer_decode_reported,omitempty"`
	// TransportCapturerDropped is the capturer's count of network data events
	// its decoder REFUSED as short or unexpectedly shaped. NON-ZERO IS THE
	// LOUD ONE: it means the payload-length assumptions do not hold on that
	// host, so the per-process byte totals are wrong rather than merely
	// missing. Meaningless unless TransportCapturerDecodeReported is true.
	TransportCapturerDropped int64 `json:"transport_capturer_dropped,omitempty"`
	// TransportCapturerUnsupportedVersion is the capturer's count of data
	// events refused because the OS stamped an event version its layout table
	// does not describe — the "Windows shipped a new template" signal, broken
	// out because its fix differs. Same gate.
	TransportCapturerUnsupportedVersion int64 `json:"transport_capturer_unsupported_version,omitempty"`
	// TransportCapturerDecoded is the capturer's count of network data events
	// its decoder ACCEPTED, and TransportCapturerIgnored its count of events
	// it classified as not-a-data-event. Same presence gate as the two above.
	//
	// They are the POSITIVE half of the report and they exist because the two
	// refusal counters cannot express the failure that matters most: an OS
	// whose Kernel-Network provider renumbered its event ids sends every
	// event to the ignored bucket, so the capturer reports zero drops, zero
	// unsupported versions and zero bytes — clean on every refusal-shaped
	// check while measuring nothing.
	//
	// NEITHER IS A FAULT ON ITS OWN. A large ignored count is normal (control-
	// plane events, connect/disconnect/retransmit, UDP); a zero decoded count
	// on its own is what a decoder that just started looks like. The signal
	// is the conjunction, and it has exactly one owner:
	// processobs.CapturerDecodeStats.NothingClassified, reached from here via
	// CapturerDecodeNothingClassified so no surface re-derives it.
	TransportCapturerDecoded int64 `json:"transport_capturer_decoded,omitempty"`
	TransportCapturerIgnored int64 `json:"transport_capturer_ignored,omitempty"`
	// TransportCapturerDecodeAt is when the DAEMON received that report
	// (never a remote-supplied clock). Zero until the first one.
	TransportCapturerDecodeAt time.Time `json:"transport_capturer_decode_at,omitzero"`
}

// CapturerDecodeStats re-assembles the four decode counters into the value
// type that OWNS the predicates over them, so a surface never re-derives
// "something is wrong" from loose ints (CLAUDE.md rule 4).
//
// It says NOTHING about presence: the counters are meaningless unless
// TransportCapturerDecodeReported is true, and every caller here gates on that
// first.
func (h ProcessHealth) CapturerDecodeStats() processobs.CapturerDecodeStats {
	return processobs.CapturerDecodeStats{
		NetworkDropped:            h.TransportCapturerDropped,
		NetworkUnsupportedVersion: h.TransportCapturerUnsupportedVersion,
		NetworkDecoded:            h.TransportCapturerDecoded,
		NetworkIgnored:            h.TransportCapturerIgnored,
	}
}

// CapturerDecodeNothingClassified reports the renumbered-provider suspicion:
// the capturer reported, its decoder saw events, classified none of them as
// data, and refused none either.
//
// False when nothing has been reported at all — absence is absence, and a
// capturer with no decoder must not read as a decoder that classified
// nothing.
func (h ProcessHealth) CapturerDecodeNothingClassified() bool {
	return h.TransportCapturerDecodeReported && h.CapturerDecodeStats().NothingClassified()
}

const (
	// ProcessHealthRefreshInterval is the cadence at which the daemon is
	// expected to republish its record. Exported so the writer and the
	// staleness classification cannot drift apart.
	ProcessHealthRefreshInterval = 30 * time.Second
	// ProcessHealthStaleAfter is how old a record may be before readers
	// call it stale. Three missed refreshes — tolerant of a busy host,
	// tight enough that a wedged daemon is visible within ~2 minutes.
	ProcessHealthStaleAfter = 3 * ProcessHealthRefreshInterval
)

// processHealthGlob matches per-PID process-observability health records
// written into the DB directory.
const processHealthGlob = "observer-processobs-*.health.json"

// ProcessHealthPath is the path the daemon with the given pid publishes its
// record to. One file per PID, like the lockfiles — concurrent daemons
// therefore report separately instead of overwriting each other.
func ProcessHealthPath(dbDir string, pid int) string {
	return filepath.Join(dbDir, fmt.Sprintf("observer-processobs-%d.health.json", pid))
}

// ProcessHealthDir maps the configured DB path onto the directory the health
// records live in — the same directory as the lockfiles. Callers hold a DB
// path (config, metrics.Options), not a directory, and the configured value
// may still be "~/…"; this is the single place that resolves both.
func ProcessHealthDir(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Dir(expandTilde(dbPath))
}

// WriteProcessHealth publishes one health record for the running daemon and
// sweeps records left behind by dead daemons. PID and WrittenAt default to
// the current process and time when unset. Returns the path written so the
// caller can RemoveProcessHealth it on shutdown.
//
// The write is atomic (temp file + rename) so a concurrent doctor/metrics
// read never observes a half-written record.
func WriteProcessHealth(dbDir string, h ProcessHealth) (string, error) {
	if dbDir == "" {
		return "", errors.New("diag.WriteProcessHealth: dbDir is required")
	}
	if h.PID == 0 {
		h.PID = os.Getpid()
	}
	if h.WrittenAt.IsZero() {
		h.WrittenAt = time.Now().UTC()
	}
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return "", fmt.Errorf("diag.WriteProcessHealth: mkdir %s: %w", dbDir, err)
	}
	// Best-effort housekeeping, same contract as cleanStaleLocks: a failure
	// here only leaves an extra dead record, which readers drop anyway.
	cleanStaleProcessHealth(dbDir)

	body, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return "", fmt.Errorf("diag.WriteProcessHealth: marshal: %w", err)
	}
	path := ProcessHealthPath(dbDir, h.PID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return "", fmt.Errorf("diag.WriteProcessHealth: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("diag.WriteProcessHealth: rename %s: %w", path, err)
	}
	return path, nil
}

// RemoveProcessHealth deletes the named record. Safe to call on a path that
// is already gone.
func RemoveProcessHealth(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// LiveProcessHealth reads every health record in dbDir and returns the ones
// whose writing daemon is still running, newest report first. A record from
// a dead PID is not "the current state" and is therefore dropped, not
// reported as stale.
func LiveProcessHealth(dbDir string) ([]ProcessHealth, error) {
	if dbDir == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(filepath.Join(dbDir, processHealthGlob))
	if err != nil {
		return nil, fmt.Errorf("diag.LiveProcessHealth: glob: %w", err)
	}
	var live []ProcessHealth
	for _, p := range matches {
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			continue
		}
		var h ProcessHealth
		if json.Unmarshal(raw, &h) != nil {
			continue
		}
		if h.PID == 0 || !processAlive(h.PID) {
			continue
		}
		live = append(live, h)
	}
	sort.SliceStable(live, func(i, j int) bool {
		if !live[i].WrittenAt.Equal(live[j].WrittenAt) {
			return live[i].WrittenAt.After(live[j].WrittenAt)
		}
		return live[i].PID < live[j].PID
	})
	return live, nil
}

// LatestProcessHealth returns the most recent live record, if any. ok=false
// means no running daemon has published one — which is the normal state when
// the daemon is not running or process observability is disabled, NOT a
// failure of the feature.
func LatestProcessHealth(dbDir string) (ProcessHealth, bool) {
	live, err := LiveProcessHealth(dbDir)
	if err != nil || len(live) == 0 {
		return ProcessHealth{}, false
	}
	return live[0], true
}

// Age reports how long ago the record was written, relative to now. A zero
// WrittenAt yields 0.
func (h ProcessHealth) Age(now time.Time) time.Duration {
	if h.WrittenAt.IsZero() {
		return 0
	}
	d := now.Sub(h.WrittenAt)
	if d < 0 {
		return 0
	}
	return d
}

// TransportConfigured reports whether the Transport* counters on this record
// are real. It is a convenience over TransportState — the state string is the
// carried fact, so no consumer keeps a second boolean beside it.
func (h ProcessHealth) TransportConfigured() bool {
	return h.TransportState == processobs.TransportStateConfigured
}

// CaptureLine renders the capture-yield half of the record — what the daemon
// resolved and what it threw away — as one operator-facing sentence.
//
// It is ALWAYS rendered, including in the all-zero case, and that is the
// point: the alternative this replaced was silence, and silence is what a
// daemon dropping every batch on a locked database looked like from outside
// for a whole boot. "0 attributed" is a measurement; a missing line is not.
//
// The drop reasons are listed loudest-first (largest count) and then
// alphabetically, so repeated reads are stable and the dominant reason leads.
// A reason this build has never heard of still prints: an older reader must
// not silently swallow a newer daemon's vocabulary.
func (h ProcessHealth) CaptureLine() string {
	line := fmt.Sprintf("%d attributed, %d unattributed", h.Attributed, h.Unattributed)
	if tools := renderCounts(h.AttributedByTool); tools != "" {
		line += " (" + tools + ")"
	}
	if drops := renderCounts(h.Dropped); drops != "" {
		line += fmt.Sprintf("; %d dropped: %s", sumCounts(h.Dropped), drops)
	} else {
		line += "; no drops recorded"
	}
	if h.SinkRetained > 0 {
		line += fmt.Sprintf("; %d run(s) RETAINED — the sink is failing transiently and capture is being buffered, not lost", h.SinkRetained)
	}
	if h.SinkFlushMaxMs > 0 || h.QueueDepthMax > 0 {
		line += fmt.Sprintf("; peak flush %dms, peak queue %d", h.SinkFlushMaxMs, h.QueueDepthMax)
	}
	if h.FlushBacklogHits > 0 {
		line += fmt.Sprintf("; flush backlog hit %d time(s), peak hand-off %d batch(es)", h.FlushBacklogHits, h.HandoffDepthMax)
	}
	return line
}

// sumCounts totals a counter map. Separate from renderCounts so the headline
// number and the breakdown can never disagree about what was counted.
func sumCounts(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total += v
	}
	return total
}

// renderCounts formats a counter map as "key=n, key=n", largest first then
// alphabetical. Zero-valued entries are skipped — a reason recorded as zero
// carries no information and only crowds out the ones that do. Empty map
// (or a map of nothing but zeroes) renders as "".
func renderCounts(m map[string]int64) string {
	type kv struct {
		k string
		v int64
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		if v == 0 {
			continue
		}
		pairs = append(pairs, kv{k, v})
	}
	if len(pairs) == 0 {
		return ""
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, fmt.Sprintf("%s=%d", p.k, p.v))
	}
	return strings.Join(out, ", ")
}

// staleQualified prefixes a headline with the record's age when the daemon
// has stopped refreshing. Every message built from a ProcessHealth is
// present-tense ("is REFUSING", "is NOT running"), and present tense about a
// report that stopped arriving minutes ago is a claim the record cannot
// support — the reader has to be told it is reading history.
func staleQualified(h ProcessHealth, now time.Time, msg string) string {
	if !h.Stale(now) {
		return msg
	}
	return fmt.Sprintf("%s [as of the daemon's last report %s ago — STALE]", msg, h.Age(now).Round(time.Second))
}

// Stale reports whether the record is older than ProcessHealthStaleAfter —
// the daemon is alive but has stopped refreshing, so the values below it are
// a last-known report, not current truth.
func (h ProcessHealth) Stale(now time.Time) bool {
	return h.Age(now) > ProcessHealthStaleAfter
}

// NetworkAccountingLine renders the per-process network-byte accounting
// state as one honest operator-facing sentence. It is the single owner of
// that wording, shared by `observer doctor` and any other text surface, and
// it deliberately differs per mode:
//
//   - off         — the operator did not ask for this; state it, do not nag.
//   - unavailable — requested and NOT measured; the reason is the whole
//     point, so it is always included, verbatim.
//   - tcp         — live, but TCP payload only: a QUIC/UDP-heavy workload
//     legitimately reads near zero and the UI must not imply otherwise.
//
// An empty/unknown mode is reported as unknown rather than guessed.
func (h ProcessHealth) NetworkAccountingLine() string {
	switch h.NetworkAccountingMode {
	case processobs.NetworkAccountingOff:
		// The backend's own reason already names the config key, so use it
		// when present rather than printing the key twice.
		if h.NetworkAccountingReason != "" {
			return "off — not requested: " + h.NetworkAccountingReason
		}
		return "off — not requested ([observer.process.network].process_bytes)"
	case processobs.NetworkAccountingUnavailable:
		reason := h.NetworkAccountingReason
		if reason == "" {
			reason = "no reason reported by the backend"
		}
		return "UNAVAILABLE — requested but per-process bytes are NOT measured: " + reason
	case processobs.NetworkAccountingTCP:
		return "live (tcp) — TCP payload bytes only; UDP/QUIC and Windows-side " +
			"processes are not counted, so a QUIC-heavy workload legitimately reads near zero"
	case "":
		return "unknown — the daemon reported no accounting mode"
	default:
		return fmt.Sprintf("%s — unrecognised accounting mode", h.NetworkAccountingMode)
	}
}

// TransportLine renders the cross-OS capture transport's connection state as
// one honest operator-facing sentence, and is the single owner of that
// wording (shared by `observer doctor`, and by anything else that grows a
// text surface). Like NetworkAccountingLine it deliberately differs per state
// rather than printing one templated line:
//
//   - no transport requested ("none", or an older daemon's record) — returns
//     "" and the CALLER SKIPS THE LINE ENTIRELY. Most installs have no
//     dial-in capturer, and inventing a "0 connections" line for them would
//     report a failure that does not exist.
//   - requested but unavailable — the operator DID ask for the cross-OS feed
//     and it is NOT running (a bind conflict, an unwritable token file, the
//     ETW block left disabled). Silence here would be indistinguishable from
//     the case above, so the state and the daemon's verbatim reason are both
//     stated.
//   - configured, never connected, no auth failures — WAITING, not an error:
//     the elevated capturer may simply not be running yet, or its Scheduled
//     Task may never have been set up. Both are stated; neither is guessed.
//   - auth failures with zero successful connections — the actionable one:
//     something is dialling and nothing is getting through. The daemon's
//     VERBATIM refusal reason leads, because the counter alone names no
//     cause; the token keys follow as one candidate among several, never as
//     the diagnosis.
//   - connected — live, with how long ago the connection was made.
//   - was connected, now not — last connect AND last disconnect, so a
//     capturer that keeps flapping is visible instead of looking idle.
//
// now anchors the "… ago" phrasing, matching Age/Stale on this type, and a
// STALE record is prefixed as such: every state below is present-tense, and
// present tense about a daemon that stopped refreshing minutes ago is a claim
// the record cannot support.
func (h ProcessHealth) TransportLine(now time.Time) string {
	body := h.transportLineBody(now)
	if body == "" {
		return ""
	}
	if decode := h.CapturerDecodeLine(); decode != "" {
		body += "; " + decode
	}
	if !h.Stale(now) {
		return body
	}
	return fmt.Sprintf("as of the daemon's last report %s ago (STALE): %s", h.Age(now).Round(time.Second), body)
}

// CapturerDecodeLine renders the connected capturer's decode health as one
// sentence — and ONLY when something is actually wrong.
//
// It is deliberately silent in the two quiet cases, which are different from
// each other and neither of which is an incident:
//
//   - never reported (the capturer has no running network decoder — every
//     non-elevated run) — there is nothing to say, and saying "0 refused"
//     would claim the payload-length assumptions were tested and held;
//   - reported, nothing refused, and data events WERE decoded — the good
//     state. The structured surfaces (/api/process/etw/status, /metrics) DO
//     carry those zeroes, because there they are a positive measurement an
//     operator validating the feed needs to read; a text line repeating them
//     on every healthy run would only be noise.
//
// The loud cases get the whole reasoning, because neither makes the byte
// totals merely absent. A refused decode makes them WRONG with no error
// anywhere; a decoder that classified NOTHING makes them a flat zero that
// every refusal-shaped check reads as healthy. The second is the one this
// line exists to stop being silent about — it is the only surface an operator
// following the six-step validation reads without asking for it.
func (h ProcessHealth) CapturerDecodeLine() string {
	if !h.TransportCapturerDecodeReported {
		return ""
	}
	switch {
	case h.TransportCapturerDropped > 0 && h.TransportCapturerUnsupportedVersion > 0:
		return fmt.Sprintf("DECODE FAILURES — the capturer refused %d network event(s) as short or unexpectedly shaped "+
			"and %d more for an event version its layout table does not describe; the per-process byte totals from that "+
			"host are WRONG, not merely missing, and the payload-layout assumptions need re-checking against the live provider",
			h.TransportCapturerDropped, h.TransportCapturerUnsupportedVersion)
	case h.TransportCapturerDropped > 0:
		return fmt.Sprintf("DECODE FAILURES — the capturer refused %d network event(s) as short or unexpectedly shaped; "+
			"the per-process byte totals from that host are WRONG, not merely missing, and the payload-length assumption "+
			"needs re-checking against the live provider", h.TransportCapturerDropped)
	case h.TransportCapturerUnsupportedVersion > 0:
		return fmt.Sprintf("DECODE FAILURES — the capturer refused %d network event(s) whose event version its layout "+
			"table does not describe; the OS has shipped a new template and this build's field offsets may no longer apply",
			h.TransportCapturerUnsupportedVersion)
	case h.CapturerDecodeNothingClassified():
		return fmt.Sprintf("NO DATA EVENTS CLASSIFIED — the capturer refused nothing, but it also accepted nothing: "+
			"%d event(s) were classified as not-a-data-event and %d as data. Ignoring events is normal on its own; "+
			"ignoring ALL of them is not, and it means the byte totals from that host are a flat zero that every "+
			"refusal check reads as healthy. If the host was moving TCP traffic, the provider's event ids no longer "+
			"match this build's layout table; if it was idle, this is not yet evidence either way — drive TCP traffic "+
			"and re-read",
			h.TransportCapturerIgnored, h.TransportCapturerDecoded)
	default:
		return ""
	}
}

func (h ProcessHealth) transportLineBody(now time.Time) string {
	if h.TransportState == processobs.TransportStateUnavailable {
		reason := h.TransportUnavailableReason
		if reason == "" {
			reason = "no reason reported by the daemon"
		}
		return "UNAVAILABLE — a cross-OS capture transport was requested ([observer.process.etw].enabled) " +
			"but is NOT running, so no elevated capturer can connect: " + reason
	}
	if h.TransportState != processobs.TransportStateConfigured {
		return ""
	}
	at := ""
	if h.TransportAddr != "" {
		at = " at " + h.TransportAddr
	}
	switch {
	case h.TransportAuthFailures > 0 && h.TransportConnections == 0:
		return fmt.Sprintf(
			"AUTH FAILURE — %d connection(s)%s were REFUSED and none authenticated; %s. The cause is NOT assumed here: "+
				"candidates are a mismatched shared token (make [observer.process.etw].token, or the file named by "+
				".token_path, identical on both sides), the two halves running different observer versions, or an "+
				"unrelated local process probing this port (a WSL loopback bind is reachable from the whole Windows host). "+
				"The reason above is the one the daemon actually recorded — read it first",
			h.TransportAuthFailures, at, h.authReasonClause(),
		)
	case h.TransportConnected:
		line := fmt.Sprintf("live — an elevated capturer is connected%s (%s; %d connection(s) so far)",
			at, sinceOrUnknown(h.TransportLastConnectAt, now, "connected"), h.TransportConnections)
		if h.TransportAuthFailures > 0 {
			line += fmt.Sprintf("; %d earlier connection(s) were refused at the handshake — %s",
				h.TransportAuthFailures, h.authReasonClause())
		}
		return line
	case h.TransportConnections > 0:
		line := fmt.Sprintf("DISCONNECTED — no capturer is streaming now%s (%s, %s; %d connection(s) so far)",
			at,
			sinceOrUnknown(h.TransportLastConnectAt, now, "last connected"),
			sinceOrUnknown(h.TransportLastDisconnectAt, now, "disconnected"),
			h.TransportConnections)
		if h.TransportAuthFailures > 0 {
			line += fmt.Sprintf("; %d connection(s) were refused at the handshake — %s",
				h.TransportAuthFailures, h.authReasonClause())
		}
		return line
	default:
		return "waiting — no capturer has ever connected" + at +
			": normal until the elevated Windows capturer starts, and permanent if its Scheduled Task was never set up"
	}
}

// authReasonClause renders the daemon's verbatim refusal reason, or says
// plainly that none was recorded. It never substitutes a guess for the
// missing reason — "the token is wrong" is a diagnosis, and this surface only
// has a counter.
func (h ProcessHealth) authReasonClause() string {
	if h.TransportLastAuthError == "" {
		return "no refusal reason was recorded (an older daemon, or a refusal that predates this field)"
	}
	return fmt.Sprintf("most recent reason: %q", h.TransportLastAuthError)
}

// sinceOrUnknown renders "<label> <d> ago", or says the timestamp was never
// recorded rather than printing a zero-time epoch.
func sinceOrUnknown(t, now time.Time, label string) string {
	if t.IsZero() {
		return label + " at an unrecorded time"
	}
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%s %s ago", label, d.Round(time.Second))
}

// cleanStaleProcessHealth removes records whose PID is no longer running.
// Errors are swallowed — best-effort housekeeping, same as cleanStaleLocks.
func cleanStaleProcessHealth(dbDir string) {
	matches, _ := filepath.Glob(filepath.Join(dbDir, processHealthGlob))
	for _, p := range matches {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var h ProcessHealth
		if json.Unmarshal(raw, &h) != nil {
			// Unparseable — leave it alone rather than deleting a file we
			// cannot identify.
			continue
		}
		if h.PID > 0 && !processAlive(h.PID) {
			_ = os.Remove(p)
		}
	}
}
