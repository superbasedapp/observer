-- 137_session_quality_components.sql — BL2 (post-Agent-Access backlog item 2,
-- 2026-09-27): the session quality score (spec §15.2,
-- internal/intelligence/scoring) becomes a daemon-computed, dashboard-shown
-- number instead of a manual-CLI-only one.
--
-- WHY. The scorer computed four weighted components but persisted only two of
-- them (redundancy_ratio, error_rate) plus the blended quality_score, and it
-- recorded neither WHEN it scored nor HOW MANY actions it saw. The Session
-- detail Quality card needs all four to show the formula honestly, and needs
-- the stamp + count to say "scored before N newer actions" instead of passing
-- an old score off as current.
--
--   exploration_efficiency  REAL     distinct files edited / distinct files
--                                    touched, clamped to [0,1].
--   continuity_score        REAL     1 - exp(-total_actions / 20).
--   scored_at               TEXT     RFC3339 UTC time the score was written.
--   scored_action_count     INTEGER  actions the scorer saw for this session.
--
-- Nullable, no DEFAULT: a session scored before this migration keeps NULLs
-- here (the card shows the persisted inputs it has and says the breakdown
-- predates the stamp) until it is re-scored. Written by exactly one seam,
-- scoring.Scorer.Write.
--
-- Org wire: NONE. These columns are NODE-LOCAL; orgpush.go selects explicit
-- session columns and never names them. See the BL2 follow-up in
-- docs/plans/post-agent-access-backlog-tracker-2026-09-27.md for the org
-- drawer plan.
ALTER TABLE sessions ADD COLUMN exploration_efficiency REAL;
ALTER TABLE sessions ADD COLUMN continuity_score REAL;
ALTER TABLE sessions ADD COLUMN scored_at TEXT;
ALTER TABLE sessions ADD COLUMN scored_action_count INTEGER;
