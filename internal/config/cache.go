package config

// This file holds the config types of [cachewarm] and [cachetrack].

// CacheWarmConfig is the [cachewarm] surface — the cache-expiry warning
// system + the opt-in smart keep-warm
// (docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md).
// LOCAL-ONLY, never distributed (same posture as [predict]/[routing]).
//
// The WARNING half (Part A) is default-ON: it is a pure read over the
// cache_entries the engine already writes, with zero LLM cost and no
// outward network call. The KEEP-WARM half (Part B, the nested Keepwarm
// block) is OFF by default — it is an outward-facing, money-spending
// action and is treated like routing enforce: explicit operator opt-in.
//
// Same partial-merge invariant as CacheTrackConfig: an install with no
// [cachewarm] section MUST get Enabled=true (Default() seeds it); a
// partial section keeps the unset fields at their Default() values.
type CacheWarmConfig struct {
	// Enabled gates the warning system. When false the dashboard/CLI/MCP
	// cache-expiry surfaces stay empty and no keep-warm runs.
	Enabled bool `toml:"enabled"`
	// WarnAtSeconds is the time-to-expiry threshold for the 'soon'
	// severity. Default 90.
	WarnAtSeconds int `toml:"warn_at_seconds"`
	// CriticalAtSeconds is the time-to-expiry threshold for the
	// 'critical' severity. Default 30. Clamped to ≤ WarnAtSeconds.
	CriticalAtSeconds int `toml:"critical_at_seconds"`
	// MinValueUSD suppresses warnings for caches whose value-at-risk is
	// below this floor (not worth keeping warm). Default 0.05.
	MinValueUSD float64 `toml:"min_value_usd"`
	// Implicit (OpenAI/Codex) caches expose NO fixed TTL — survival is a
	// best-effort retention policy, not a lease (see
	// docs/general_info/openai_cache_expiry.md). We model it as a GRADED
	// idle-risk progression keyed on time since last activity, surfaced as
	// an ESTIMATE (the card hedges with "~"):
	//   idle < ImplicitWarnSeconds          → ok    (high-confidence reuse)
	//   ImplicitWarnSeconds ≤ idle < Crit    → soon  ("at risk of expiry")
	//   ImplicitCriticalSeconds ≤ idle < Max → critical ("significantly
	//                                           increased risk of expiry")
	//   idle ≥ ImplicitMaxSeconds            → expired (hard max)
	// Defaults follow the extended-cache reality for gpt-5.5/gpt-5/gpt-4.1:
	// 1h / 2h / 24h. Anthropic explicit caches ignore these — they carry a
	// real TTL and use WarnAtSeconds/CriticalAtSeconds.
	ImplicitWarnSeconds int `toml:"implicit_warn_seconds"`
	// ImplicitCriticalSeconds — idle age at which an implicit cache is at
	// significantly increased risk of eviction. Default 7200 (2h).
	ImplicitCriticalSeconds int `toml:"implicit_critical_seconds"`
	// ImplicitMaxSeconds — idle age at which an implicit cache is treated as
	// expired (OpenAI's hard 24h retention ceiling). Default 86400 (24h).
	ImplicitMaxSeconds int `toml:"implicit_max_seconds"`
	// Keepwarm is the Part B keep-warm sub-surface (advise/enforce).
	Keepwarm KeepWarmConfig `toml:"keepwarm"`
}

// KeepWarmConfig is the [cachewarm.keepwarm] sub-surface — the Part B
// economics + action mode. Default OFF: it is the only outward-facing,
// money-spending action in this feature.
type KeepWarmConfig struct {
	// Mode is "off" | "advise" | "enforce". Default "off". advise
	// surfaces a recommendation (e.g. switch to the 1h tier) but sends
	// nothing; enforce additionally permits the proxy in-memory replay
	// path (Anthropic proxied sessions only) — built in a later phase.
	Mode string `toml:"mode"`
	// MinValueUSD is the value-at-risk floor below which keep-warm is
	// never recommended. Default 0.20 (higher than the warning floor —
	// it is not worth acting on small caches).
	MinValueUSD float64 `toml:"min_value_usd"`
	// MinResumeConfidence gates a keep-warm bet on the likelihood the
	// session actually resumes (a warm cache nobody returns to is wasted
	// spend). 0..1. Default 0.5.
	MinResumeConfidence float64 `toml:"min_resume_confidence"`
}

// CacheTrackConfig gates the proxy-side cache observation engine
// (docs/plans/cache-tracking-implementation-spec-2026-06-08.md §11).
// Default-ON per spec §11: the feature is local, passive, network-
// free, and writes only hashes/counts/enums (no content). An
// install with no [cachetrack] section MUST get Enabled=true via
// the loader's partial-merge against Default() (NOT zero-valued
// false) — the live-daemon-captures-nothing bug traced to this.
type CacheTrackConfig struct {
	// Enabled gates the engine. When false, the proxy still
	// parses request bodies for cache_control markers (cheap;
	// already in the requestShape single pass) but the engine
	// is not constructed and no cache_* rows are written.
	Enabled bool `toml:"enabled"`
	// MaxTrackedSessions is the LRU bound on the engine's
	// per-session CacheModel map. Default 64. ≤ 0 disables the
	// cap (unbounded; not recommended).
	MaxTrackedSessions int `toml:"max_tracked_sessions"`
	// CalibrateLogPath enables the per-block diagnostic sidecar
	// when non-empty: every block fed to Engine.ObserveTurn is
	// written as one JSON line carrying (api_turn_id, seq, level,
	// kind, len_raw, sha_raw, len_canon, sha_canon) — plus a
	// bounded canonical-bytes prefix for tools+system levels
	// (message-level stays hash-only per CLAUDE.md "no content"
	// rule).
	//
	// Off by default (""). When set, auto-stops after ~200 blocks
	// so the file stays small and the daemon's hot path is
	// untouched for the rest of the soak. Used to localize chain-
	// hash drift to the lowest-seq differing block (the 39326aa9
	// soak post Fix B left seq=29 tools boundary still drifting
	// — this sidecar is the next-step diagnostic).
	CalibrateLogPath string `toml:"calibrate_log_path"`
	// RetentionDays is the per-table horizon for the cache_* row
	// sweep (spec §9). cache_segments + cache_events past this
	// horizon are deleted; cache_entries in terminal states
	// (expired / invalidated / unverified) past a tighter 14-day
	// horizon are also deleted (live entries are never pruned
	// regardless of age — they may still be in the provider).
	// Default 90. ≤ 0 disables the cache prune entirely.
	//
	// The sweep runs from the retention pass (startup + the
	// [observer.retention].interval_hours periodic tick) — the
	// same pass that handles actions / observer_log /
	// file_state. See cmd/observer/prune.go::runRetention. Each
	// call is idempotent: a second run within the same horizon
	// is a no-op (TestPruneCacheRows_SecondRunNoop).
	//
	// NOT pushed to the org server: cache_* tables are NODE-LOCAL
	// per `tests/invariant/privacy_test.go::TestSelectUnpushedSinceExcludesCacheTables`.
	// The sweep stays node-local; no org-push coupling.
	RetentionDays int `toml:"retention_days"`
	// ---
	// DELIBERATE OMISSION — R7 cache_scope salt.
	//
	// Spec §11 + §24.4 R7 names `sha256(upstream_host + ":" +
	// auth_identity + scope_salt)[:16]` as the eventual cache_scope
	// derivation. Today both seam call sites
	// (`internal/proxy/proxy.go::966` Tier-1 +
	// `internal/store/store.go::1376` Tier-2) use the literal
	// "default" — workspace-blind, single-scope. The R7 derivation
	// landing means wiring an auth_identity source (header parse?
	// operator email? machine ID?) at BOTH seams, then composing
	// with this salt. That's a cross-cutting change touching
	// proxy + store + per-adapter Tier-2 emit. Out of scope for
	// the v1 cachetrack closure; tracked as backlog item 9 in
	// `docs/plans/cachetrack-p3-backlog-2026-06-09.md` (R7
	// cache_scope derivation). DO NOT add ScopeSalt as an empty
	// field — the absence of the field IS the documentation that
	// this is deferred. If/when R7 lands, the field shape is
	// likely `string` plus a non-empty default per install.
}
