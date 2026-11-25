package config

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
)

// This file holds the config types of [observer.process].

// ProcessConfig is the [observer.process] surface — the optional
// OS-level process-capture layer (docs/process-observability.md §11).
//
// UNLIKE CacheTrack/Guard/Advisor, this feature is OPT-IN: Enabled
// defaults to FALSE (D1). It may require elevated privileges and captures
// sensitive process metadata, so an install with no [observer.process]
// section makes zero process-backend calls and behaves byte-identically to
// a build without the feature (MVP acceptance criterion 1).
//
// The non-zero defaults below (Backend, RetentionDays, QueueSize,
// BatchSize, and the sub-section fields) only take effect once the operator
// flips Enabled. They are set in Default() so a partial [observer.process]
// section (e.g. just `enabled = true`) inherits sane values rather than
// zero — the same partial-merge discipline CacheTrackConfig documents.
type ProcessConfig struct {
	// Enabled gates the whole backend lifecycle. False = no backend is
	// constructed, no process_runs/process_events rows are written.
	// Restart-gated: flipping this in a running daemon takes effect on the
	// next start (the dashboard setup flow says so — §11).
	Enabled bool `toml:"enabled"`
	// Backend selects the capture source: "auto" (pick the best available
	// for the host OS), "linux_ebpf", "etw", "endpointsecurity", "poll"
	// (low-fidelity dev/test fallback), or "off". Default "auto".
	Backend string `toml:"backend"`
	// CaptureUnattributed stores process rows that could not be joined to a
	// session (D5/§9.2.7). Default false: unattributed processes are counted
	// for health only, never persisted, to bound the privacy blast radius.
	CaptureUnattributed bool `toml:"capture_unattributed"`
	// RetentionDays is the process_runs/process_events prune horizon, swept
	// by the retention pass — startup + the [observer.retention].
	// interval_hours periodic tick (cmd/observer/prune.go::runRetention).
	// Default 30. ≤ 0 disables the process prune.
	//
	// WHAT IT MEANS CHANGES WITH [archive].enabled, and the change is a
	// strict improvement. With archival OFF it is what it has always been:
	// the point at which process capture is DELETED, unrecoverably. With
	// archival ON it becomes the ARCHIVE FILE's own delete horizon, and
	// ArchiveDays below becomes the (earlier) point at which capture leaves
	// the hot database. So the same 30 means "hot for 14 days, recoverable
	// from cold storage for 30" rather than "hot for 30, then gone".
	RetentionDays int `toml:"retention_days"`
	// ArchiveDays is the horizon past which process capture is MOVED to
	// ~/.observer/archive.db instead of staying in the hot database. Default
	// 14. ≤ 0 disables the archive sweep (capture then stays hot until
	// RetentionDays deletes it, i.e. today's behaviour).
	//
	// Read only when [archive].enabled is true; with archival off this knob
	// does nothing and the process prune behaves exactly as before.
	//
	// The default sits WELL INSIDE RetentionDays deliberately. Process
	// capture is the arc's ONLY-COPY bucket (design §2.2) — live eBPF/ETW
	// records of processes that have since exited, with no artifact on disk
	// to re-derive them from — so the two horizons must not race: capture has
	// to reach cold storage with room to spare before anything deletes it.
	// 14 days also keeps the hot working set aligned with the window in which
	// an operator actually opens a process trail, which is the whole point of
	// separating hot from cold (design §1.3).
	ArchiveDays int `toml:"archive_days"`
	// QueueSize bounds the userspace enrichment queue between the backend
	// and the store batch writer. Overflow drops newest low-value events
	// after a health counter (§15). Default 10000.
	QueueSize int `toml:"queue_size"`
	// BatchSize is the store insert batch size (§15 targets 100–500 rows
	// per transaction). Default 250.
	BatchSize int `toml:"batch_size"`

	// WindowsBinaryPath is the Windows observer.exe the cross-OS bridge
	// (§5.5) execs over WSL interop — a /mnt/<drive>/... path (a C:\… path is
	// accepted and translated). Empty = auto-resolve. Used only by the
	// "bridge" backend (and "auto" on WSL). LOCAL-ONLY, never distributed.
	WindowsBinaryPath string `toml:"windows_binary_path"`
	// PollIntervalMS is the unified process-table snapshot cadence (the
	// "process poll rate" the dashboard Settings page exposes). It drives BOTH
	// the Linux /proc poll backend AND the Windows cross-OS bridge capturer, so
	// a single knob controls how often every process source is sampled. Default
	// 2000 (2s). Lower = fresher capture + more CPU; higher = cheaper but more
	// likely to miss short-lived commands (the poll backend can't see a process
	// that starts and exits inside one interval). LOCAL-ONLY, never distributed.
	PollIntervalMS int `toml:"poll_interval_ms"`
	// BridgePollIntervalMS optionally overrides PollIntervalMS for the bridge
	// capturer only (back-compat / asymmetric-cadence escape hatch). Zero =
	// inherit PollIntervalMS. Default 0. LOCAL-ONLY, never distributed.
	BridgePollIntervalMS int `toml:"bridge_poll_interval_ms"`
	// CorrelateIntervalMS is the cadence of the daemon's periodic background
	// cross-OS correlation sweep (docs/process-observability.md §9.2.5). The
	// deferred CorrelateCrossOS pass — the join that makes an unattributed
	// process row VISIBLE to a session — otherwise runs only lazily (a human
	// opening the dashboard Processes drawer, or `observer process tree`), so
	// captured rows stay invisible until someone looks. The sweep re-runs that
	// same idempotent, confidence-guarded store pass over the recent-active
	// session set every interval, so attribution converges without a viewer.
	// Default 90000 (90s); <= 0 inherits that default. RESTART-BOUND: the sweep
	// goroutine reads this once at daemon start (like Enabled / the poll loop),
	// so a change takes effect on the next start. LOCAL-ONLY, never distributed.
	CorrelateIntervalMS int `toml:"correlate_interval_ms"`

	Argv       ProcessArgvConfig       `toml:"argv"`
	Executable ProcessExecutableConfig `toml:"executable"`
	Env        ProcessEnvConfig        `toml:"env"`
	Network    ProcessNetworkConfig    `toml:"network"`
	Filesystem ProcessFilesystemConfig `toml:"filesystem"`
	Metrics    ProcessMetricsConfig    `toml:"metrics"`
	ETW        ProcessETWConfig        `toml:"etw"`
	Capture    ProcessCaptureConfig    `toml:"capture"`
}

// ProcessCaptureConfig is the [observer.process.capture] surface: the process
// capture budget (docs/process-observability.md §11 "Capture budget", plan
// docs/plans/process-capture-budget-plan-2026-11-04.md §9.1). It bounds how
// many process rows one session stores: every captured run goes through one
// ordered decision table (internal/proccapture) that keeps it as a row, folds
// it into its parent, tracks it under a service the agent started, rolls it up
// into a counted group, or drops it (counted). Findings, failures and
// tool-call links are always kept; counts stay exact either way.
//
// Partial-merge like the sibling process blocks: Default() seeds every value,
// so a block that sets one key inherits the rest. LOCAL-ONLY, never
// distributed. Restart-bound (read once at daemon start).
type ProcessCaptureConfig struct {
	// Enabled applies the capture budget. Default true. False restores the
	// pre-budget behaviour: every captured process becomes its own row with a
	// metric ring, which on a busy session is tens of thousands of rows a day
	// (one measured session stored 92,428). With it on, the same session keeps
	// a few thousand rows and the rest become a few hundred rollup rows.
	Enabled bool `toml:"enabled"`

	Budget       ProcessCaptureBudgetConfig       `toml:"budget"`
	Services     ProcessCaptureServicesConfig     `toml:"services"`
	Fold         ProcessCaptureFoldConfig         `toml:"fold"`
	Metrics      ProcessCaptureMetricsConfig      `toml:"metrics"`
	Rollups      ProcessCaptureRollupsConfig      `toml:"rollups"`
	Unattributed ProcessCaptureUnattributedConfig `toml:"unattributed"`
}

// ProcessCaptureBudgetConfig is [observer.process.capture.budget]: how many
// individual process rows (exemplars) are kept before further short-lived runs
// are rolled up into counted groups. Findings, failures, tool-call roots and
// runs alive 30 s or more never count against a full budget.
type ProcessCaptureBudgetConfig struct {
	// PerToolCall is the number of individual rows kept per tool call before
	// the call's remaining short-lived children roll up. Default 200. Raising
	// it stores more rows for big build or test fan-outs (each row is about
	// 1.5 KB); 0 removes the cap.
	PerToolCall int `toml:"per_tool_call"`
	// PerSession is the number of individual rows kept per session. Default
	// 5000. It is the ceiling on one session's process rows; 0 removes the
	// cap (unbounded rows on a busy session).
	PerSession int `toml:"per_session"`
	// PerMinute is the burst guard: individual rows kept per session per
	// minute. Default 300. Lower it to flatten bursts; 0 removes the cap.
	PerMinute int `toml:"per_minute"`
}

// ProcessCaptureServicesConfig is [observer.process.capture.services]:
// services and GUI apps the agent starts (Docker Desktop, an editor, a dev
// server that outlives its tool call). They are tracked, not hidden: the
// service's root row and its first exemplars are kept, the rest of its
// subtree is rolled up under the root, and tracking stops a while after the
// session's last activity.
type ProcessCaptureServicesConfig struct {
	// Track tracks services the agent spawns. Default true. False keeps only
	// each service's root row and drops (counts) everything it starts, the
	// smallest volume, at the cost of not seeing what the service did.
	Track bool `toml:"track"`
	// DetachAfterMinutes: a process that outlives the tool call that started
	// it by this many minutes and keeps starting children becomes a service
	// root, so its later children are capped like a service's. Default 10.
	// Lower values cap long-running dev servers sooner; 0 disables the
	// heuristic (only the built-in service list applies).
	DetachAfterMinutes int `toml:"detach_after_minutes"`
	// ExemplarsPerService is how many individual rows are kept under one
	// service root before the rest roll up. Default 20. Each extra exemplar is
	// one more stored row per service.
	ExemplarsPerService int `toml:"exemplars_per_service"`
	// TailMinutes stops tracking a service this many minutes after the
	// session's last activity; later runs are dropped and counted. Default
	// 30. A service polling every few seconds adds about one rollup row a
	// minute until then; 0 tracks it for as long as it runs.
	TailMinutes int `toml:"tail_minutes"`
	// ExtraBasenames adds executables (for example "mydaemon.exe") to the
	// built-in service list (Docker Desktop, com.docker.backend, Code,
	// explorer, devenv, idea64). Matching ignores case and ".exe".
	ExtraBasenames []string `toml:"extra_basenames"`
}

// ProcessCaptureFoldConfig is [observer.process.capture.fold]: helper
// processes that carry no meaning of their own (console hosts, plugin
// metadata probes, credential helpers) are folded into their parent row as a
// count instead of being stored.
type ProcessCaptureFoldConfig struct {
	// Enabled applies the fold list. Default true. On Windows every console
	// program has a conhost.exe child, so turning this off roughly doubles the
	// stored rows of a Windows session.
	Enabled bool `toml:"enabled"`
	// ExtraBasenames adds executables that always fold into their parent row.
	// Matching ignores case and ".exe".
	ExtraBasenames []string `toml:"extra_basenames"`
}

// ProcessCaptureMetricsConfig is [observer.process.capture.metrics].
type ProcessCaptureMetricsConfig struct {
	// RingMinLifetimeSeconds keeps the CPU/memory chart samples only for
	// processes alive at least this long; shorter ones keep their totals.
	// Default 30. The samples are the largest column (about 165 bytes per
	// stored row on the measured session), so 0 stores a ring for every row.
	RingMinLifetimeSeconds int `toml:"ring_min_lifetime_seconds"`
}

// ProcessCaptureRollupsConfig is [observer.process.capture.rollups].
type ProcessCaptureRollupsConfig struct {
	// BucketSeconds is the rollup bucket width: runs of the same program and
	// argument shape under the same parent are summed per bucket. Default 60.
	// A wider bucket means fewer rollup rows and a coarser timeline.
	BucketSeconds int `toml:"bucket_seconds"`
}

// ProcessCaptureUnattributedConfig is [observer.process.capture.unattributed]:
// what happens to process rows that are stored without a session so a later
// correlation pass can join them (the cross-OS bridge, AI-tool subtrees).
type ProcessCaptureUnattributedConfig struct {
	// PendingHours is how long an unattributed row waits for correlation
	// before the policy below applies. Default 24. Longer waits keep more
	// session-less rows on disk at any time.
	PendingHours int `toml:"pending_hours"`
	// Mode is what happens once the wait is over: "rollup" (default) sums the
	// rows into a machine-level rollup and deletes them; "drop" deletes them
	// without a rollup.
	Mode string `toml:"mode"`
}

// CaptureConfig maps the block onto the pure proccapture.Config the decision
// table runs on (the one boundary between the TOML and the capture core).
func (c ProcessCaptureConfig) CaptureConfig() proccapture.Config {
	return proccapture.Config{
		Enabled:               c.Enabled,
		PerToolCall:           c.Budget.PerToolCall,
		PerSession:            c.Budget.PerSession,
		PerMinute:             c.Budget.PerMinute,
		TrackServices:         c.Services.Track,
		DetachAfter:           time.Duration(c.Services.DetachAfterMinutes) * time.Minute,
		ExemplarsPerService:   c.Services.ExemplarsPerService,
		ServiceTail:           time.Duration(c.Services.TailMinutes) * time.Minute,
		ExtraServiceBasenames: c.Services.ExtraBasenames,
		FoldEnabled:           c.Fold.Enabled,
		ExtraFoldBasenames:    c.Fold.ExtraBasenames,
		RingMinLifetime:       time.Duration(c.Metrics.RingMinLifetimeSeconds) * time.Second,
		Bucket:                time.Duration(c.Rollups.BucketSeconds) * time.Second,
		PendingHours:          c.Unattributed.PendingHours,
		UnattributedMode:      c.Unattributed.Mode,
	}
}

// ProcessETWConfig is the [observer.process.etw] surface: the daemon-side
// ACCEPT listener for the elevated Windows ETW capturer
// (docs/process-observability.md §5.5,
// docs/plans/process-obs-etw-windows-parity-plan-2026-07-26.md §W3).
//
// It is its OWN sub-block on purpose. [observer.process.network] is already
// taken by capture of the TARGET process's own connections (§7.2), and
// overloading that name would make two unrelated features share a namespace.
//
// WHY THE DAEMON LISTENS AND THE CAPTURER DIALS (measured 2026-07-26, not a
// preference): WSL cannot reach a Windows-bound listener — 127.0.0.1 is WSL's
// own loopback and the default gateway is dropped by Defender on the WSL vNIC
// — while Windows→WSL loopback works via localhostForwarding. So the elevated
// capturer dials out to this listener; the daemon never dials Windows. That
// needs no firewall rule and no host-IP discovery.
//
// SECURITY: localhostForwarding also means a WSL-side loopback listener is
// reachable from ANY process on the Windows host, including other users'. The
// shared token is therefore load-bearing, not decorative, and the listener has
// NO unauthenticated mode.
//
// This is an ADDITIVE feed, never a replacement: with it enabled the
// zero-privilege poll/bridge baseline runs exactly as before, and an install
// where no elevated capturer ever connects behaves identically to one without
// the block. LOCAL-ONLY, never distributed.
type ProcessETWConfig struct {
	// Enabled starts the daemon-side accept listener. Default FALSE: it opens
	// a port and the feed behind it needs an elevated Windows Scheduled Task,
	// so it follows the opt-in posture of the rest of [observer.process].
	Enabled bool `toml:"enabled"`
	// ListenAddr is the loopback bind. Default "127.0.0.1:8823" — its own
	// port, like every other loopback rail (proxy :8820, browser ingest
	// :8821). Kept in lock-step with processobs/bridge.DefaultListenAddr.
	ListenAddr string `toml:"listen_addr"`
	// AllowNonLoopback permits a non-loopback bind. Default false; the
	// listener refuses one otherwise (ErrNonLoopback). An explicit operator
	// decision, never a fallback.
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// Token is the shared secret the capturer must present as its first act.
	// Empty (the default) means the daemon GENERATES one and persists it 0600
	// at TokenPath, so the capturer can read it with --token-file. A token set
	// here is never written to disk — the operator who set it owns its
	// distribution.
	Token string `toml:"token"`
	// TokenPath overrides where a generated token is persisted. Empty =
	// "process-bridge-token" next to the observer DB.
	TokenPath string `toml:"token_path"`
	// HandshakeTimeoutMS bounds the authentication exchange only; an
	// authenticated stream is legitimately idle for long stretches and is not
	// deadlined. Default 10000 (10s). 0 inherits the default.
	HandshakeTimeoutMS int `toml:"handshake_timeout_ms"`
}

// ProcessMetricsConfig is the [observer.process.metrics] surface: the live
// CPU / memory / disk / network chart's ring buffer.
//
// THE WRITE-AMPLIFICATION TRAP this section exists to solve. The ring is
// persisted inside ONE column (process_runs.metric_samples_json), so every
// persist rewrites the whole row. Before this section the two cadences were
// welded together: the poll backend emitted a metrics event every
// poll_interval_ms (2s) and EVERY one of them rewrote the row, while the ring
// itself only accepted a new point every 15s — the worst of both worlds
// (30 row-rewrites/minute/process for a 4-point/minute chart). Sampling
// faster without splitting them would have multiplied those writes on a DB
// already in the multi-GB range.
//
// So SampleIntervalMS (how fresh the chart is) and PersistIntervalMS (how
// often we touch the DB) are independent, and PersistMaxSamples downsamples
// the stored copy so the column size does not grow with the sample rate. At
// the defaults: samples every 2s (7.5× finer than before), rows rewritten
// every 15s (7.5× fewer writes than before), ≤60 points stored (the same
// column size as before).
//
// LOCAL-ONLY, never distributed. Restart-bound (read once at daemon start).
type ProcessMetricsConfig struct {
	// SampleIntervalMS is the in-memory ring append cadence. Default 2000,
	// matching PollIntervalMS.
	//
	// CEILING: a sample can never be fresher than the poll that produced it.
	// Setting this BELOW [observer.process].poll_interval_ms does not make the
	// chart finer — it just makes every poll append a point instead of
	// refreshing one in place. To genuinely get 1s resolution you must ALSO
	// set poll_interval_ms = 1000, which doubles the /proc scan cost. The
	// daemon logs a WARN at start when this is below the poll interval rather
	// than silently promising resolution it cannot deliver.
	SampleIntervalMS int `toml:"sample_interval_ms"`
	// WindowSeconds is the retained live window: points older than
	// newest-window are evicted on append, so memory is bounded by TIME
	// regardless of how long a process lives. Default 300 (5 min).
	WindowSeconds int `toml:"window_seconds"`
	// MaxSamples hard-caps the in-memory ring whatever window/interval imply.
	// Default 300 (≈24 KB per tracked process, worst case).
	MaxSamples int `toml:"max_samples"`
	// PersistIntervalMS throttles DB row rewrites for metrics-only refreshes.
	// Lifecycle events (exec/exit) always persist, so a finished process
	// always lands with its final ring; at most this much of the tail is lost
	// if the daemon is killed. Default 15000. <= 0 persists every refresh (the
	// pre-decoupling behaviour — NOT recommended).
	PersistIntervalMS int `toml:"persist_interval_ms"`
	// PersistMaxSamples downsamples the persisted ring (evenly, always keeping
	// the oldest AND newest points). Default 60. <= 0 stores the whole ring.
	//
	// The stored ring still spans the whole window, but at
	// window_seconds/persist_max_samples resolution (5s at the defaults). To
	// store the full in-memory resolution set this to
	// window_seconds / (sample_interval_ms/1000) — 150 at the defaults — which
	// grows the bytes per rewrite but NOT the number of rewrites.
	PersistMaxSamples int `toml:"persist_max_samples"`
}

// ProcessArgvConfig controls argv capture (§8 Command group, §12.1).
type ProcessArgvConfig struct {
	// Mode: "preview" (scrubbed + capped preview plus full-argv hash),
	// "hash_only" (hash only, no preview — the enterprise posture), or
	// "off". Default "preview" (§19 Q1: on by default, capped, scrubbed).
	Mode string `toml:"mode"`
	// MaxPreviewBytes caps the stored argv preview. Default 512.
	MaxPreviewBytes int `toml:"max_preview_bytes"`
	// StoreArgCount keeps the integer argc even when the preview is off.
	// Default true.
	StoreArgCount bool `toml:"store_arg_count"`
}

// ProcessExecutableConfig controls executable hashing (§8 Executable group).
type ProcessExecutableConfig struct {
	// HashEnabled turns on content hashing of the resolved exe. Default
	// false (§19 Q6: useful but adds I/O cost).
	HashEnabled bool `toml:"hash_enabled"`
	// MaxHashFileSizeMB caps the file size eligible for hashing. Default 25.
	MaxHashFileSizeMB int `toml:"max_hash_file_size_mb"`
}

// ProcessEnvConfig controls environment posture capture (§8.1). Values
// always flow through the scrubber and a max-byte cap; this is posture
// (presence/hash), never full env.
type ProcessEnvConfig struct {
	// Enabled captures env posture (proxy-var presence, PATH hash,
	// virtualenv/node/CI hints). Default true.
	Enabled bool `toml:"enabled"`
	// Allowlist names additional env keys whose (scrubbed, capped) values
	// may be stored. Default empty.
	Allowlist []string `toml:"allowlist"`
	// StorePathHash stores a hash of PATH rather than its value. Default
	// true.
	StorePathHash bool `toml:"store_path_hash"`
}

// ProcessNetworkConfig controls network_connect capture (§7.2). Off until
// the privacy UX lands (§19 Q3).
type ProcessNetworkConfig struct {
	// Enabled turns on outbound-connect capture for attributed processes.
	// Default false.
	Enabled bool `toml:"enabled"`
	// CaptureRemoteHost stores the resolved remote host (scrubbed). Default
	// true (only meaningful when Enabled).
	CaptureRemoteHost bool `toml:"capture_remote_host"`
	// RedactPrivateIPs drops RFC1918/loopback destinations. Default false.
	RedactPrivateIPs bool `toml:"redact_private_ips"`
	// CaptureBodies stores capped/scrubbed request + response excerpts when a
	// capture source can see plaintext. Supported values:
	// "off" (metadata only), "proxied" (Observer proxy flows only), "available"
	// (any future plaintext/instrumented backend). Default "off".
	CaptureBodies string `toml:"capture_bodies"`
	// MaxRequestBytes caps the stored request-body excerpt. Default 65536.
	MaxRequestBytes int `toml:"max_request_bytes"`
	// MaxResponseBytes caps the stored response-body excerpt. Default 65536.
	MaxResponseBytes int `toml:"max_response_bytes"`
	// CaptureHeaders stores a scrubbed, compact allowlist of request/response
	// headers with body captures. Default true.
	CaptureHeaders bool `toml:"capture_headers"`
	// ScrubBodies applies the secret scrubber before body excerpts are stored.
	// Default true.
	ScrubBodies bool `toml:"scrub_bodies"`
	// StoreBinary allows non-text/binary response bodies to be stored as text
	// excerpts after best-effort UTF-8 conversion. Default false: binary bodies
	// get hashes/byte counts only.
	StoreBinary bool `toml:"store_binary"`
	// ProcessBytes turns on per-process CUMULATIVE socket byte counters, which
	// feed the live network series of the process metric samples. Default
	// FALSE: it attaches extra privileged eBPF programs (fentry/fexit on
	// tcp_sendmsg / tcp_cleanup_rbuf), so it follows the same opt-in posture as
	// the rest of [observer.process].
	//
	// LINUX ONLY, TCP ONLY. It needs CAP_BPF+CAP_PERFMON (or root), a
	// BTF-carrying kernel with BPF trampolines (≥5.5, x86-64/arm64), and it
	// counts TCP payload bytes only — no UDP/QUIC, no unix sockets, no
	// headers. Windows-side processes (the WSL cross-OS bridge) are NEVER
	// counted; that needs ETW and is not implemented. When the probes cannot
	// attach, capture degrades to lifecycle-only and samples are marked
	// UNMEASURED (never a fabricated zero).
	//
	// It yields BYTE COUNTS on sockets — never plaintext. TLS payloads stay
	// invisible to this path; body capture remains the proxy's job
	// (CaptureBodies).
	ProcessBytes bool `toml:"process_bytes"`
}

// ProcessFilesystemConfig controls file_write/file_open_sensitive capture
// (§7.2). Off outside high-signal paths.
type ProcessFilesystemConfig struct {
	// Enabled turns on filesystem side-effect capture. Default false.
	Enabled bool `toml:"enabled"`
	// Mode: "sensitive" (credential/config/SSH/token-like paths only),
	// "writes" (writes outside the project root), or
	// "all_attributed_writes". Default "sensitive".
	Mode string `toml:"mode"`
}
