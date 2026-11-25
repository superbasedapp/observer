package config

// This file holds the config types of [handoff].

// HandoffConfig is the [handoff] surface — session handoff /
// continue-anywhere (docs/plans/session-handoff-plan-2026-07-03.md §12).
// LOCAL-ONLY, never distributed via the org policy registry. Read-side
// feature: default-ON with the same partial-merge rule as CacheTrack.
type HandoffConfig struct {
	// Enabled gates the handoff surfaces (CLI today; dashboard/MCP in P2).
	Enabled bool `toml:"enabled"`
	// TailMessages is the verbatim-tail length for the distilled_tail
	// carry mode. Default 6.
	TailMessages int `toml:"tail_messages"`
	// MaxDocTokens budgets the rendered HandoverDoc (file/MCP lanes);
	// sections degrade tail-first past it. Default 12000 (≈48KB).
	MaxDocTokens int `toml:"max_doc_tokens"`
	// DefaultCarry is the carry mode when the caller names none. Default
	// "distilled_tail".
	DefaultCarry string `toml:"default_carry"`
	// FileName templates the inject_file artifact; {shortid} expands.
	// Default "HANDOFF-{shortid}.md".
	FileName string `toml:"file_name"`
	// HookMaxBytes budgets the P3 hook lane (Phase 0 D-P0.2: SessionStart
	// additionalContext delivers intact only to ~8KB). Default 8192.
	HookMaxBytes int `toml:"hook_max_bytes"`
	// HookTTLMinutes bounds how long an armed inject_hook handoff waits for
	// the next target session before it expires (plan §10/§12). It is also
	// one-shot: the first delivery marks the row delivered. Default 240
	// (4h) — a stale armed handoff must never fire days later.
	HookTTLMinutes int `toml:"hook_ttl_minutes"`
	// RetentionDays is the horizon for the handoffs-table prune sweep
	// (plan §15 P4), swept by runRetention through
	// store.PruneHandoffRows. handoffs rows are tiny content-free
	// metadata (hashes/enums/paths), so the default is generous —
	// 180 days keeps ~6 months of handoff history for the target-session
	// linker while still bounding growth. 0 = keep forever.
	RetentionDays int `toml:"retention_days"`
	// AllowDashboardLaunch gates the dashboard's "Launch <tool> here"
	// embedded web terminal (docs/session-handoff.md launch section): the
	// daemon spawns `observer <tool> --continue-from <id>` in a PTY and
	// streams its TUI into the browser over a websocket. Default TRUE — it
	// lives entirely within the dashboard's loopback + browserGuard trust
	// boundary (opaque token minted only by an Origin-checked POST; the ws
	// upgrade rejects cross-origin by default). Set false to disable the
	// launch surface entirely (the endpoints 503 and the button hides).
	// LOCAL-ONLY, like the rest of [handoff].
	AllowDashboardLaunch bool `toml:"allow_dashboard_launch"`
	// ContextWarnTokens is the conservative context-window floor the handoff
	// estimate warns against: when the FULL carry exceeds it, the modal/CLI
	// flag that the target tool's (often unknown) default model may be too
	// small to rehydrate the whole context in one shot — the "350K in Opus
	// into a 200K free model" mismatch. Default 200000; 0 disables the
	// warning. LOCAL-ONLY.
	ContextWarnTokens int `toml:"context_warn_tokens"`
	// MaxCacheBytes is the safety cap on the `full_cache` carry doc — the
	// only mode that inlines the actual UN-EXCERPTED read bodies (the "full
	// incl cache" mode; docs/session-handoff.md). full_cache deliberately
	// bypasses the ~100KB inline-prompt bound so the warm context travels
	// from the first prompt, so this cap is the guard against a pathological
	// multi-hundred-MB session writing an unusable doc: past it the doc is
	// truncated with an honest note. Default 8388608 (8MB); 0 = uncapped.
	// LOCAL-ONLY.
	MaxCacheBytes int `toml:"max_cache_bytes"`
}
