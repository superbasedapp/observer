package config

// This file holds the config types of [codeintel].

// CodeIntelConfig is the [codeintel] surface — the in-process code-
// intelligence module (docs/codeintel/). LOCAL-ONLY, never distributed
// to an org (same posture as [routing]/[predict]/[cachewarm]). Same
// partial-merge invariant as CacheTrackConfig: Default() seeds every
// field, a TOML section only overrides the keys it names. The module is
// OPT-IN (operator ruling D-307, 2026-10-05: indexing is CPU and disk
// heavy, so it runs only when the user asks): an install with no
// [codeintel] section, or a partial section that does not name
// `enabled`, gets Enabled=false; an explicit `enabled = true` turns it on.
//
// Defaults are conservative: indexing is read-only on the repo; the
// only model-visible change (compression.code_aggressive) is OFF and
// opt-in per project AND language.
type CodeIntelConfig struct {
	// Enabled gates the whole module. Default false (opt-in). When false
	// the indexer doesn't run, the native provider reports unavailable,
	// the MCP symbol tools answer with the codeintel_disabled warning, and
	// body-collapse compression is a no-op. Turn it on from Settings >
	// Intelligence > Code intelligence, or set it to true here.
	Enabled bool `toml:"enabled"`
	// Languages, when non-empty, restricts indexing to this subset of
	// the embedded language set. Empty = all supported languages.
	Languages []string `toml:"languages"`
	// AutoIndexLimit consent-gates a NEW project whose file count
	// exceeds it (a huge monorepo waits for `observer index <path>`).
	// Default 25000.
	AutoIndexLimit int `toml:"auto_index_limit"`
	// MaxFileBytes skips files larger than this. Default 2_000_000.
	MaxFileBytes int64 `toml:"max_file_bytes"`
	// IgnorePaths lists project-root path prefixes the auto-indexer must
	// never index. A project at or under any of these is skipped on
	// `observer start` (an explicit `observer index <path>` still works,
	// with a warning). Use absolute paths. Local-only; never distributed
	// to an org server.
	IgnorePaths []string `toml:"ignore_paths"`
	// RetentionDays is the codeintel_* prune horizon: a project whose
	// most recent index pass (MAX(codeintel_files.indexed_at)) is older
	// than this is deleted wholesale — files, nodes, edges, sites,
	// minhash, embeddings, FTS — via the same per-project delete path
	// `observer index delete -r` uses. The index is rebuildable from
	// the repo, so age-pruning is safe; a project still being indexed
	// always has a fresh indexed_at and is never touched, and a project
	// with NO successful index pass yet (MAX(indexed_at)=0, e.g.
	// freshly registered pending files) is also never touched. Swept by
	// the retention pass (startup + the [observer.retention] periodic
	// tick + `observer prune`). Default 90 — conservative, so an
	// actively-used index is never nuked. ≤ 0 disables the codeintel
	// prune entirely.
	RetentionDays int `toml:"retention_days"`

	Index       CodeIntelIndexConfig       `toml:"index"`
	Compression CodeIntelCompressionConfig `toml:"compression"`
	Semantic    CodeIntelSemanticConfig    `toml:"semantic"`
}

// CodeIntelIndexConfig is the [codeintel.index] block — resource +
// scheduling controls for the offline indexer.
type CodeIntelIndexConfig struct {
	// OnStart indexes known projects when `observer start` boots.
	// Default true.
	OnStart bool `toml:"on_start"`
	// Watch incrementally re-indexes on save (reuses fsnotify
	// mechanics, distinct from the session-file watcher). Default true.
	Watch bool `toml:"watch"`
	// Mode is "auto" (index/watch automatically) or "manual" (only
	// `observer index`). Default "auto".
	Mode string `toml:"mode"`
	// Workers caps index parallelism (0 = auto). Default 0.
	Workers int `toml:"workers"`
	// IdleOnly pauses indexing while the machine is busy. Default false.
	IdleOnly bool `toml:"idle_only"`
	// NOTE: `disk_budget_mb` used to be declared here and was never read
	// by anything. It is REMOVED, not renamed — see
	// migrateRemovedCodeIntelKeys for the disposition and the warning an
	// existing config still gets.
	//
	// OnStartTimeoutMinutes bounds the AGGREGATE wall-clock time
	// runCodeIntelOnStart (cmd/observer/codeintel.go) spends indexing
	// every known project on one `observer start` boot (T2.4, 2026-08-26
	// disk/compute remediation plan, P2-H). Per-project consent-gating
	// (auto_index_limit) and the home/drive-root block
	// (index.isAutoIndexBlocked) are unaffected — this is an orthogonal
	// outer bound for a large PROJECT SET (historically a 384K-file
	// Windows home directory's worth of discovered project roots), not a
	// per-project limit. When the deadline passes, indexing of any
	// remaining projects is skipped for this boot; they're picked up
	// again next start or by `observer index`. Default 10. ≤ 0 disables
	// the bound (unbounded, matching pre-2026-08-26 behavior).
	OnStartTimeoutMinutes int `toml:"on_start_timeout_minutes"`
}

// CodeIntelCompressionConfig is the [codeintel.compression] block — the
// ONLY model-visible behaviour, all OFF by default.
type CodeIntelCompressionConfig struct {
	// CodeAggressive enables opt-in body-collapse. DEFAULT OFF.
	CodeAggressive bool `toml:"code_aggressive"`
	// AggressiveLanguages opts in body-collapse per language; empty =
	// none even when CodeAggressive is true.
	AggressiveLanguages []string `toml:"aggressive_languages"`
	// PreviewOnly logs what WOULD collapse and changes nothing.
	PreviewOnly bool `toml:"preview_only"`
}

// CodeIntelSemanticConfig is the [codeintel.semantic] block.
type CodeIntelSemanticConfig struct {
	// Embedder selects the embedding backend: "tfidf" (default) or
	// (future) "neural".
	Embedder string `toml:"embedder"`
	// SimilarTo enables MinHash/LSH near-clone edges. Default true.
	SimilarTo bool `toml:"similar_to"`
}
