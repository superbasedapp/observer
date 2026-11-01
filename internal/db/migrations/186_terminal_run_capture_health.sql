-- 186_terminal_run_capture_health.sql - what lowered a sandboxed terminal
-- run's capture after launch (sandbox plan v2 sections 5.2 and 8.4; plans
-- decision log P-032, lane sbx-p2c).
--
-- Migration 179's capture_degraded says THAT a run lost capture after
-- launch; these two columns say why, for the run pill and `observer sandbox
-- status`. Both are NODE-LOCAL: they do not ride on TerminalRunRow, so the
-- org wire shape is unchanged (the org row already carries
-- capture_degraded and the resealed evidence digest).
--   capture_degraded_causes  comma list of internal/sandboxrelayd's closed
--                            DegradedCause vocabulary, in its order:
--                            refused, rate_limited, dropped, replayed,
--                            hooks_drifted, heartbeat_missed ('' = none)
--   missed_heartbeats        heartbeats a side of the capture relay missed
-- Both only ever grow (a lowering is never undone), written through
-- store.LowerTerminalRunCapture, terminal_run's one store seam.

ALTER TABLE terminal_run ADD COLUMN capture_degraded_causes TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN missed_heartbeats INTEGER NOT NULL DEFAULT 0;
