package config

// This file holds the config types of [compression].

// CompressionConfig groups all four compression layers' toggles.
type CompressionConfig struct {
	Shell        ShellConfig        `toml:"shell"`
	Indexing     IndexingConfig     `toml:"indexing"`
	Conversation ConversationConfig `toml:"conversation"`
}

// ShellConfig controls shell output filtering.
type ShellConfig struct {
	Enabled         bool     `toml:"enabled"`
	ExcludeCommands []string `toml:"exclude_commands"`
}

// IndexingConfig controls FTS5 tool output indexing.
type IndexingConfig struct {
	// Enabled is the one switch for every writer of action_excerpts: the
	// watcher and the hook processes both obey it (T-420). Off skips only the
	// FTS5 excerpt insert; capture is unchanged, and search_past_outputs and
	// the dashboard search find only excerpts indexed while it was on.
	Enabled         bool `toml:"enabled"`
	MaxExcerptBytes int  `toml:"max_excerpt_bytes"`
	Embeddings      bool `toml:"embeddings"`
}

// ConversationConfig controls conversation-level compression.
//
// Mode selects the strategy:
//   - "token": legacy default. Per-type compression then drop the
//     lowest-scored non-preserved messages until target_ratio is met.
//   - "cache": restricts drops to the tail half of the conversation
//     and injects a cache_control marker at the prefix boundary.
//   - "cache_aware": designed for Anthropic Pro/Max where the SDK
//     already places cache_control markers. Skips drops entirely
//     (drop ranking is budget-relative and shifts across turns,
//     invalidating Anthropic's prefix cache), narrows per-type
//     compression eligibility to RoleTool only, and skips cache_control
//     injection. The cross-turn determinism this preserves is what
//     makes cache_creation tokens fall on subsequent turns. No-ops
//     gracefully (effectively ModeToken without drops) when no SDK
//     marker is present.
type ConversationConfig struct {
	Enabled       bool     `toml:"enabled"`
	Mode          string   `toml:"mode"`
	TargetRatio   float64  `toml:"target_ratio"`
	PreserveLastN int      `toml:"preserve_last_n"`
	CompressTypes []string `toml:"compress_types"`
	// DisableDrops turns off the budget enforcer's lossy Pass-2
	// eviction (dropping the lowest-importance messages and replacing
	// runs with a `[N messages compressed — use search_past_outputs]`
	// marker). When true, the budget target becomes best-effort: only
	// the content-preserving per-type compressors run, and the body
	// ships with whatever compression they achieved — even 0% — never
	// truncated, never dropped.
	//
	// Default false = drops allowed = the historical behaviour for every
	// existing config and profile. Set true on a profile (see the
	// codex-safe recipe) whose per-type compressors frequently no-op, so
	// the enforcer can't degenerate into a drop-only pass. This is a
	// PROVIDER-NEUTRAL capability, distinct from the Anthropic-shaped
	// `mode = "cache_aware"` (which ALSO skips drops but additionally
	// narrows per-type eligibility to tool_result messages for prefix-
	// cache determinism). Added 2026-07-16.
	DisableDrops bool             `toml:"disable_drops"`
	Logs         LogsConfig       `toml:"logs"`
	Stash        StashConfig      `toml:"stash"`
	Compaction   CompactionConfig `toml:"compaction"`
	Rolling      RollingConfig    `toml:"rolling"`
}

// LogsConfig tunes LogsCompressor's final head+tail truncation pass
// (step 8 in the LogsCompressor pipeline; see
// internal/compression/conversation/logs.go). The earlier
// content-preserving steps (ANSI strip, CR collapse, dedup, blank-run
// cap) are not configurable — they have no destructive failure mode.
//
// The truncation pass is the only step that can elide content the
// agent may want to re-read. For codex-variant models (gpt-5.3-codex
// family) the post-truncation elision marker is treated as missing
// data and triggers re-derivation — see V7-11 in
// docs/v4-codex-compression-recipe-and-issues.md. Operators tuning
// for codex-variant workloads can disable truncation entirely by
// setting `max_lines = 0`, or raise the head/tail budgets so typical
// source-file reads (200-500 lines) survive verbatim.
type LogsConfig struct {
	// MaxLines is the ceiling on the post-dedup line count; zero
	// disables the truncation pass entirely. Default 200.
	MaxLines int `toml:"max_lines"`
	// Head is the line count preserved at the head of an over-budget
	// body; zero falls back to MaxLines/2. Default 100.
	Head int `toml:"head"`
	// Tail is the line count preserved at the tail of an over-budget
	// body; zero falls back to MaxLines/2. Default 100.
	Tail int `toml:"tail"`
}

// RollingConfig controls the v1.4.43+ / Tier 2 / D20 rolling-
// summarisation feature: when a session's conversation crosses
// ThresholdTokens, the proxy calls Anthropic with the user's captured
// auth to get a one-paragraph summary of older messages, then
// replaces them inline with a `[<N> earlier messages summarized: ...]`
// marker. Cross-turn invariance is preserved via a per-session
// sticky boundary — see internal/compression/conversation/rolling.go.
//
// Disabled by default. Opt-in via
// `compression.conversation.rolling.enabled = true`. Once dogfood on
// long sessions shows the cost/benefit (Haiku call cost vs. the
// avoided context blow-up + cache_creation premium) lands net-
// positive, the default may flip.
type RollingConfig struct {
	Enabled         bool `toml:"enabled"`
	ThresholdTokens int  `toml:"threshold_tokens"`
	// SummaryModel is the Anthropic-side rolling-summary model.
	// Default: "claude-haiku-4-5".
	SummaryModel string `toml:"summary_model"`
	// OpenAISummaryModel is the OpenAI-side rolling-summary model used
	// when the proxy is forwarding codex (or any other OpenAI-flavoured)
	// traffic. Default: "gpt-5-nano" (free per OpenAI's 2026-04-29
	// catalog). The two summary models are independent — Anthropic and
	// OpenAI traffic each pick their own.
	OpenAISummaryModel string `toml:"openai_summary_model"`
	AuthCacheSize      int    `toml:"auth_cache_size"`
}

// CompactionConfig controls the v1.4.43+ / Tier 3 / D23 compaction-
// survival feature: when enabled, the proxy detects Anthropic requests
// whose session_id has a recent compaction event in the observer DB
// and prepends a synthetic system block carrying recovery context
// (last reads, last edits, recent failures, learned rules) so the
// model can re-orient without re-Reading every file.
//
// Disabled by default. Opt-in via
// `compression.conversation.compaction.inject_post_compact = true`.
// Once dogfood shows recovery-context utility (model uses the data
// rather than ignoring it) and cross-turn invariance holds in
// practice, this may flip default-on.
type CompactionConfig struct {
	InjectPostCompact bool `toml:"inject_post_compact"`
}

// StashConfig controls the v1.4.41 / Tier 1 / G31 (CCR — Compressed
// Content Retrieval) feature: tool_result bodies whose post-per-type-
// compression size still exceeds ThresholdBytes are written to a
// content-addressed on-disk stash and replaced inline with a marker
// referencing the SHA. The model retrieves originals via the
// `retrieve_stashed` MCP tool.
//
// Disabled by default for the first release; opt-in via
// `compression.conversation.stash.enabled = true`. Once dogfood data
// shows the retrieve-rate is healthy and threshold tuning lands, this
// will flip to default-on.
type StashConfig struct {
	Enabled        bool   `toml:"enabled"`
	Dir            string `toml:"dir"`             // default: ~/.observer/stash
	ThresholdBytes int    `toml:"threshold_bytes"` // default: 8192
	MaxTotalMB     int    `toml:"max_total_mb"`    // default: 1024
}
