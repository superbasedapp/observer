-- 171_delivery_project_settings.sql - per-project delivery switches
-- (commit-pr-merge-tracking plan 12.2, D-689).
--
-- Written ONLY by internal/store/delivery.go. NODE-LOCAL (privacy sentinel).
-- A project with no row has the zero value: no mirror, no schedule.
--
--   mirror_enabled    opt this project's remote into an Observer mirror
--   schedule_minutes  refresh the mirror every N minutes (minimum 30);
--                     0 = "Check now" only

CREATE TABLE IF NOT EXISTS delivery_project_settings (
    project_id        INTEGER PRIMARY KEY REFERENCES projects(id),
    mirror_enabled    INTEGER NOT NULL DEFAULT 0,
    schedule_minutes  INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL
);
