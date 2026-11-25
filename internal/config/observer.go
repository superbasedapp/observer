package config

import "time"

// This file holds the config types of [observer].

// ObserverConfig groups settings for the capture side of the system.
type ObserverConfig struct {
	DBPath      string            `toml:"db_path"`
	LogLevel    string            `toml:"log_level"`
	Watch       WatchConfig       `toml:"watch"`
	Freshness   FreshnessConfig   `toml:"freshness"`
	Secrets     SecretsConfig     `toml:"secrets"`
	Retention   RetentionConfig   `toml:"retention"`
	Hooks       HooksConfig       `toml:"hooks"`
	MCP         ObserverMCPConfig `toml:"mcp"`
	Antigravity AntigravityConfig `toml:"antigravity"`
	Process     ProcessConfig     `toml:"process"`
	DB          DBConfig          `toml:"db"`

	// ConfigVersion is the schema-migration stamp written by the config
	// auto-migration rail (internal/config/migrate). It records the
	// highest migration step applied to this file so the migrator can
	// skip an already-current config cheaply. Absent/0 on legacy files.
	// The migration DECISION reads the version from the raw file text;
	// this field only keeps the key out of the decoder's Undecoded set
	// and available to any in-process consumer. See MigrateFile.
	ConfigVersion int `toml:"config_version"`
}

// DBConfig controls the SQLite connection/pragma layer that
// internal/db.Open drives for the main observer.db (docs/plans/observer-
// disk-compute-remediation-plan-2026-08-26.md Phase 1, P0-B). It exists so
// an operator can tune the memory/disk tradeoff without a rebuild; the
// zero-value defaults below match internal/db.Options' own built-in
// defaults, so an unconfigured [observer.db] block is safe.
type DBConfig struct {
	// HardHeapLimitMB sets SQLite's process-global PRAGMA hard_heap_limit in
	// megabytes — the memory backstop that makes TempStore == "memory" safe:
	// a runaway unindexed sort or VACUUM fails fast with SQLITE_NOMEM
	// instead of exhausting host RAM. Zero (unset) applies the built-in
	// 1024 MB (1 GiB) default. A negative value explicitly disables the
	// pragma (omitted from the DSN entirely) — use with caution, and only
	// alongside TempStore == "file".
	HardHeapLimitMB int `toml:"hard_heap_limit_mb"`
	// TempStore selects SQLite's PRAGMA temp_store: "file" (spill temp
	// b-trees / VACUUM scratch to disk — the default), "memory" (hold temp
	// in RAM, bounded by HardHeapLimitMB), or "default" (inherit whatever
	// the driver/SQLite build ships with). Empty (unset) applies "file".
	// FILE is the default so the operator's `observer prune --vacuum` still
	// works on a multi-GB DB (MEMORY would fail SQLITE_NOMEM building the
	// whole-file temp copy in RAM) and nothing can OOM; see
	// internal/db.Options.TempStore for the full rationale.
	TempStore string `toml:"temp_store"`
	// MaxOpenConns bounds the connection pool (see
	// database/sql.DB.SetMaxOpenConns). Zero (unset) applies the built-in
	// default of 16.
	MaxOpenConns int `toml:"max_open_conns"`
	// ConnMaxIdleSeconds bounds how long an idle pooled connection is kept
	// before being closed (see database/sql.DB.SetConnMaxIdleTime). Zero
	// (unset) applies a 300s (5-minute) default.
	ConnMaxIdleSeconds int `toml:"conn_max_idle_seconds"`
	// IntegrityCheckMaxGB caps the AUTOMATIC `PRAGMA quick_check` the
	// daemon runs once per process, off its readiness path, via
	// db.RunStartupMaintenance (cmd/observer/diag.go::
	// runStartupDBMaintenance). quick_check checksums every page of the
	// file, so its cost scales with the database, not with the work the
	// daemon came to do — on a 41.8 GB install it was measured as the
	// dominant startup CPU cost (P1-D, docs/audits/observer-disk-compute-
	// exhaustion-audit-2026-08-26.md). Above this many GB the automatic
	// pass is skipped with one calm log line; the schema-034 path-hash
	// backfill still runs regardless (idempotent, cheap after its
	// done-marker). `observer doctor` asks the SAME gate
	// (db.IntegrityCheckShouldSkip): an unscoped doctor over the cap
	// reports the probe as skipped, a per-tool doctor defers it, and
	// `observer doctor db` / `observer doctor --integrity` run it on
	// demand regardless of size. Default 8 (GB). ≤ 0 disables the
	// gate (quick_check always runs, matching pre-2026-08-26 behavior).
	IntegrityCheckMaxGB int `toml:"integrity_check_max_gb"`
}

// AntigravityConfig controls the Antigravity adapter's behavior.
//
// NetworkRecovery selects the fallback strategy when local .pb file
// decryption fails (which is currently the case on Windows hosts —
// the documented AES-128-CTR scheme doesn't match the Windows-side
// cipher). Values:
//
//   - "" / "off" (default): no fallback. Decrypt failure → warning,
//     skip the file. Pure-local, no network calls, no process tree
//     introspection.
//   - "local": try the running language_server's gRPC API on
//     localhost, falling back through the article-described
//     ConvertTrajectoryToMarkdown path. Requires Antigravity to be
//     running. The language_server has the in-memory key and decrypts
//     locally; we just consume the Markdown response and parse it
//     into events. Lossy compared to direct decryption (no per-tool
//     args, no token counts) but recovers the conversation flow.
//
// The "local" mode is opt-in because:
//   - It introspects running processes (visible cmdline args, CSRF
//     tokens) — strictly local, but a behavior change worth surfacing.
//   - On WSL2-with-Windows-Antigravity, the call requires a Windows-
//     side bridge (PowerShell shell-out) which adds per-call latency.
//   - The Markdown parser produces approximate events, not the
//     full-fidelity ToolEvent stream a real .pb decrypt would yield.
type AntigravityConfig struct {
	NetworkRecovery string `toml:"network_recovery"`

	// DumpShapeMismatchesDir, when non-empty, enables an opt-in
	// debug mode that writes the raw GetCascadeTrajectory gRPC
	// response bytes to disk whenever the adapter's
	// ParseStructuredTrajectory yields zero tokens AND empty model
	// on a non-trivial payload (≥ 10 KiB). Each dump goes to
	// <dir>/<conversation_id>.bin so the operator can compare wire
	// shapes between known-working and known-broken sessions when
	// investigating the v1.6.10 audit residual: some sessions
	// return 100s of KB of structured data but the proto-path
	// mapping at structured.go:122-185 doesn't extract anything
	// (e.g. maintainer session e371fdb1-… returned 430,202 bytes,
	// 0 tokens, model="").
	//
	// Default empty = no dumping. Set to an absolute path like
	// "/tmp/antigravity-shape-dumps/" to enable. The directory is
	// created on first dump (mkdir -p semantics). Files are owned
	// by the observer process; rotate or delete manually. (Issue
	// #5 follow-up — first pass only added the tracef warning.)
	DumpShapeMismatchesDir string `toml:"dump_shape_mismatches_dir"`
}

// WatchConfig controls the file watcher daemon.
type WatchConfig struct {
	PollIntervalSeconds int      `toml:"poll_interval_seconds"`
	MaxFileSizeMB       int      `toml:"max_file_size_mb"`
	EnabledAdapters     []string `toml:"enabled_adapters"`
	// HomeWalk allows adapters with no project index of their own (aider)
	// to find transcripts by a bounded background walk of the home folder.
	// Default true. With false they use only their environment overrides
	// and the project roots Observer already knows. On macOS the walk never
	// opens the privacy-guarded home folders (Desktop, Documents,
	// Downloads, Library, ...) unless a known project root lives in one.
	HomeWalk bool `toml:"home_walk"`
}

// FreshnessConfig controls content hashing and classification.
type FreshnessConfig struct {
	EnableContentHashing bool     `toml:"enable_content_hashing"`
	MaxHashFileSizeMB    int      `toml:"max_hash_file_size_mb"`
	FastPathStatOnly     bool     `toml:"fast_path_stat_only"`
	IgnorePatterns       []string `toml:"ignore_patterns"`
}

// SecretsConfig controls the scrubbing pipeline.
type SecretsConfig struct {
	EnableScrubbing bool     `toml:"enable_scrubbing"`
	ExtraPatterns   []string `toml:"extra_patterns"`
}

// RetentionConfig controls DB pruning.
type RetentionConfig struct {
	MaxAgeDays            int  `toml:"max_age_days"`
	MaxDBSizeMB           int  `toml:"max_db_size_mb"`
	PruneOnStartup        bool `toml:"prune_on_startup"`
	ObserverLogMaxAgeDays int  `toml:"observer_log_max_age_days"`
	// IntervalHours is the cadence of the daemon's periodic maintenance
	// tick: `observer start` re-runs the full retention pass (the same
	// cmd/observer/prune.go::runRetention that prune_on_startup and
	// `observer prune` invoke) every IntervalHours while the daemon is
	// up, so a daemon that stays up for weeks still prunes. Default 24
	// (daily). ≤ 0 disables the tick (startup + manual prune only —
	// the pre-v1.20 behavior).
	IntervalHours int `toml:"interval_hours"`
	// WALAlertMB is the §1e follow-through (2026-08-22 write-stall arc):
	// the daemon's WAL watchdog WARNs and attempts a TRUNCATE checkpoint
	// once observer.db-wal exceeds this size. The 2026-08-21 stall left
	// the WAL pinned at 15.5 GB for hours because frames were long
	// checkpointed but the file was never released — bounded visibility
	// plus a reclaim attempt turns that from silent into actionable.
	// Default 1024 (1 GiB). ≤ 0 disables the watchdog.
	WALAlertMB int `toml:"wal_alert_mb"`
	// WALWatchMinutes is the watchdog cadence. Default 10. ≤ 0 disables.
	WALWatchMinutes int `toml:"wal_watch_minutes"`
	// CompactionEventsDays drops compaction_events rows whose timestamp is
	// older than this. Default 30. 0 keeps them forever.
	//
	// Each row carries a whole point-in-time file-state blob
	// (file_state_snapshot plus ghost_files_after), which averaged ~1.1 MB
	// per row on the operator's live node — 1.4 GiB in 1,333 rows, with no
	// horizon of any kind until 2026-09-16. The snapshot exists to
	// reconstruct what a session knew across a context compaction, which
	// stops being actionable long before the session's own actions age out,
	// so its horizon is deliberately much shorter than max_age_days.
	CompactionEventsDays int `toml:"compaction_events_days"`
	// CompressionEventsDays drops compression_events rows whose timestamp is
	// older than this. Default 90. 0 keeps them forever.
	//
	// One row per compression decision per proxied turn: small rows, but
	// 3.59M of them / 915 MB on the live node. The savings figures the
	// dashboard and `observer compression` report are rolled up from
	// api_turns, so this table is the per-decision debugging tail behind
	// them and can age out on its own, longer horizon.
	CompressionEventsDays int `toml:"compression_events_days"`
	// HeldMaxMB caps the data an ENROLLED node keeps only because the org
	// has not accepted it yet (T-839 / D-673). Retention never deletes a row
	// above the org push cursor while the node is enrolled, whether
	// [org_client].enabled is true or false (a pause), so a push that is
	// paused or refused for weeks would otherwise grow the database until
	// the disk fills. Past this estimate the OLDEST held rows are deleted
	// anyway, at ERROR in the daemon log, and `observer doctor` FAILs
	// (retention.push_hold): those rows never reached the org. Default 2048
	// (about 2 GB). 0 removes the ceiling (hold without limit). Has no
	// effect on a node that is not enrolled.
	HeldMaxMB int `toml:"held_max_mb"`
}

// ObserverMCPConfig controls how Observer registers its own MCP server entry.
type ObserverMCPConfig struct {
	// StableCommand, when true on an org-managed Linux or macOS node,
	// registers the bare `observer` as the MCP entry's command whenever the
	// first `observer` on PATH runs this same install (surface-gap FU-24),
	// so one managed allowedMcpServers entry matches every node. Default
	// false: it waits on a live check (a GUI-launched host such as VS Code or
	// Claude Desktop on a managed Mac must still resolve the bare name on its
	// own PATH), so until that check passes it is an explicit opt-in.
	StableCommand bool `toml:"stable_command"`
}

// HooksConfig controls hook runtime.
type HooksConfig struct {
	TimeoutMS int `toml:"timeout_ms"`
	// AutoRegister, when true, has `observer start` install hooks for
	// every detected tool on every launch (idempotent). New tools
	// installed after the daemon was first started are picked up on
	// the next restart without a manual `observer init`. Safe by
	// default: never overwrites user-authored hook entries — conflicts
	// log a warning and skip. Default: true.
	AutoRegister bool `toml:"auto_register"`
	// PeriodicRegister controls whether the daemon re-runs the same
	// idempotent auto-registration on the policy-state heartbeat (about 5
	// minutes), so a removed or weakened hook is repaired and reported
	// without waiting for a restart (T-849):
	//
	//   - "managed" (default): only on a managed-tenancy enrolment;
	//   - "always": on every node;
	//   - "off": never (start-time registration only, the pre-T-849
	//     behaviour).
	//
	// auto_register = false disables it in every mode. Unknown values read
	// as "managed".
	PeriodicRegister string `toml:"periodic_register"`
}

// The [observer.hooks] periodic_register values.
const (
	HooksPeriodicRegisterManaged = "managed"
	HooksPeriodicRegisterAlways  = "always"
	HooksPeriodicRegisterOff     = "off"
)

// HookTimeout returns the hook timeout as a time.Duration.
func (c HooksConfig) HookTimeout() time.Duration {
	return time.Duration(c.TimeoutMS) * time.Millisecond
}
