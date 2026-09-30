// Package scoring computes per-session quality metrics (spec §15.2) and
// writes them back into the sessions table.
//
// The quality score is a linear combination:
//
//	quality_score = 0.4 × (1 - redundancy_ratio) + 0.3 × (1 - error_rate)
//	              + 0.2 × exploration_efficiency + 0.1 × continuity_score
//
// The inputs are sourced entirely from rows this package can see — no hooks,
// no tool-specific logic. Callers invoke Scorer.ScoreSession for one session,
// or Scorer.BatchScore to walk the DB.
//
// Spec §15.2 says the score is "computed when session ends". The daemon does
// that through AutoScorer (started from `observer start`, gated by
// [intelligence.scoring].auto, default on): a session is scored once it has
// been idle for [intelligence.scoring].idle_minutes, re-scored when it sees new
// activity, and the never-scored backlog is worked off in capped batches.
// `observer score` remains the manual / --all recompute path. Scorer.Write is
// the one writer of the sessions score columns.
package scoring
