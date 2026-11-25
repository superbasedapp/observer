package config

// This file holds the config types of [tasks].

// TasksConfig is the [tasks] surface — session-level task/todo/plan
// checklist tracking (docs/task-tracking.md,
// docs/audits/task-tracking-capture-audit-2026-09-07.md). Default-ON,
// same partial-merge invariant as CacheTrackConfig/PredictConfig: an
// install with no [tasks] section gets Enabled=true, because it is a
// pure re-decode of data already captured in actions.raw_tool_input/
// raw_tool_output (internal/taskflow + internal/store/taskflow.go) —
// no new capture surface, no adapter change, no proxy hook. LOCAL-ONLY
// — task_items/task_transitions (migration 109) never enter the org
// push wire (tests/invariant/privacy_test.go's forbiddenCacheTables).
type TasksConfig struct {
	// Enabled gates the ingest-time decode + the (out-of-scope-for-v1)
	// backfill default. false makes Store.Ingest's task-tracking pass a
	// pure no-op — the pre-feature baseline.
	Enabled bool `toml:"enabled"`
	// MatchMode selects how Snapshot-kind (whole-list-rewrite) items are
	// identified across consecutive calls when the tool carries no
	// vendor id. "exact" (the default, per §R2.3.4's measured guidance:
	// fuzzy matching trades a known, countable loss for an unknown,
	// silent mis-join) matches on the trimmed content string
	// (taskflow.ContentKey). "normalized" additionally lowercases and
	// collapses internal whitespace before hashing
	// (taskflow.NormalizedContentKey) — tolerates a vendor's own cosmetic
	// re-wording between two consecutive snapshot calls, at the cost of
	// silently merging two genuinely different items whose text happens
	// to normalize the same. CONSUMED: threaded into every taskflow.Decode
	// call as ActionInput.MatchMode (internal/store/taskflow.go), applied
	// post-decode by applyMatchMode — see that function's doc comment for
	// why it is a single recompute seam rather than a parameter threaded
	// through every one of decoderTable's ~10 decode functions.
	MatchMode string `toml:"match_mode"`
	// ConcurrentAttribution selects how a token/action row is bucketed
	// when two or more tasks are simultaneously in_progress (§R2.3.2).
	// "shared" (the recommended, measured default — 6.6% of tokens on
	// the grounding corpus) buckets the row into a per-session `shared`
	// total rather than splitting it evenly or picking a "dominant"
	// task, both of which would invent a precision the data does not
	// contain. "none" drops the row from every task's total instead
	// (still counted, just not attributed to a specific task) — for an
	// operator who would rather under-report than see a shared bucket.
	// There is deliberately no "split" option (see MatchMode's note).
	// CONSUMED: passed to taskflow.Attributor.SetConcurrentAttribution by
	// the Phase-2 cost/report layer (internal/store's
	// LoadSessionTaskReport) — "none" makes Attributor.At report
	// BucketBetweenTasks instead of BucketShared.
	ConcurrentAttribution string `toml:"concurrent_attribution"`
	// IncludeSidechains folds a spawned sub-agent's OWN token_usage rows
	// (is_sidechain=1, migration 087) into whichever task happened to be
	// open in the PARENT session at the same wall-clock time. Default
	// false: sub-agent usage is reported as a separate `sidechain` total
	// instead (§3.3's option (a) — option (b), resolving a
	// TaskUpdate.owner string to the actual spawned session, is not
	// implementable: owner is free text, not a session id, §R2.6 item 6).
	// CONSUMED: passed straight through as the includeSidechains argument
	// to Store.LoadTaskTokenRows/LoadTaskActionTimestamps, via an
	// explicit taskflow.Options each Phase-2 read surface (dashboard/
	// CLI/MCP) builds from this config directly — not read off a store
	// instance's TasksOptions(), which none of those per-request/
	// per-invocation store instances had SetTasksOptions called on.
	IncludeSidechains bool `toml:"include_sidechains"`
	// BackfillOnStart re-derives task_items/task_transitions from
	// historical actions rows once at daemon start (same work as
	// `observer backfill --tasks`, run automatically). Default false —
	// the explicit CLI flag is the v1 path; an operator upgrading onto
	// a build with [tasks] newly enabled runs it once by hand. CONSUMED:
	// cmd/observer/main.go calls Store.BackfillTaskItems(ctx, 0) once,
	// in a background goroutine, right after SetTasksEnabled, when this
	// is true.
	BackfillOnStart bool `toml:"backfill_on_start"`
	// RetentionDays bounds how long task_items/task_transitions are kept
	// before pruning. 0 = never prune (the CacheTrackConfig.RetentionDays
	// shape) — v1 ships no pruning sweep at all; the field exists so a
	// future one has a home without a config-shape change.
	RetentionDays int `toml:"retention_days"`
}
