package config

// This file holds the config types of [benchmark].

// BenchmarkConfig is the [benchmark] surface — the Benchmarks Harness
// (docs/plans/benchmarks-harness-plan-2026-07-11.md). LOCAL-ONLY, never
// distributed to an org (same posture as [routing]/[predict]). The harness
// itself is CLI-driven and operator-invoked; the only persistent config today
// is the retention horizon for the node-local benchmark_* tables.
type BenchmarkConfig struct {
	// RetentionDays is the horizon for the benchmark_* prune sweep (plan
	// §3.12), swept by runRetention through store.PruneBenchmarkRows. Benchmark
	// rows hold repo paths, prompts, final-answer excerpts, and judge
	// rationales, so the default is bounded — 180 days keeps ~6 months of run
	// history for baseline diffs. 0 = keep forever.
	RetentionDays int `toml:"retention_days"`
	// ArenaAllowSkipPermissions lets an Agent Arena candidate or judge_merge
	// keep run a harness with its own permission checks skipped (claude-code
	// --dangerously-skip-permissions, grok --always-approve, aider --yes, an
	// opencode run that asks nothing) when the harness has no grounded mode
	// that keeps them on. Default false: a candidate then runs in its
	// harness's edit-only mode (claude-code acceptEdits, codex
	// workspace-write), and a harness with no such mode is refused. The Arena
	// judge never skips permissions. On a managed node the organization's AI
	// tool settings still win: an enforced approval mode stricter than
	// full_auto (or claude-code's disableBypassPermissionsMode) refuses the
	// skip whatever this says (OSH-R-005). Read at every run, no restart.
	ArenaAllowSkipPermissions bool `toml:"arena_allow_skip_permissions"`
}
