-- 003_archive_process_capture.sql - keep archive_process_runs in lockstep with
-- agent migration 212 (the process capture budget,
-- docs/plans/process-capture-budget-plan-2026-11-04.md §9.2).
--
-- The mover copies BY COLUMN NAME using the hot table's own column list
-- (migration 002, note 1), so a hot column missing here fails the copy loudly
-- before any delete. Agent 212 added three process_runs columns; they are
-- mirrored here with the same shapes. The two new hot tables
-- (process_rollups, process_capture_stats) are NOT archived: they are small,
-- pruned by time with the rest of the process capture, and not part of the
-- archive.ProcessTables fan-out.

ALTER TABLE archive_process_runs ADD COLUMN capture_class    TEXT;
ALTER TABLE archive_process_runs ADD COLUMN service_root_key TEXT;
ALTER TABLE archive_process_runs ADD COLUMN fold_count       INTEGER NOT NULL DEFAULT 0;
