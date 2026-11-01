-- 181_terminal_run_evidence_producer.sql - the producer half of a terminal
-- run's execution evidence envelope (sandbox plan v2 section 8.4, roadmap
-- F0-13; lane sbx-p1a2, audit finding P-006 (3)).
--
-- Migration 179 stored the isolation facts and the envelope digest, but the
-- digest also covers the producer (kind, catalog component, the Observer
-- build that recorded the run), which was not stored, so nobody could
-- recompute it. These three columns hold those inputs:
--   evidence_producer          execevidence.ProducerKind (terminal_run)
--   evidence_component         the node catalog id that owned the run
--   evidence_component_version the Observer build that recorded it
-- '' means not recorded (rows older than this migration, and runs that
-- recorded no evidence). The digest is unkeyed: recomputing it shows the
-- stored facts are the ones the recorder sealed, not that nobody with write
-- access to the database edited them (ledger SHR-6).
--
-- Rides on TerminalRunRow like 179's columns; paired with server migration
-- 242 and PostgreSQL 0109 (terminal_run_rows).

ALTER TABLE terminal_run ADD COLUMN evidence_producer TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN evidence_component TEXT NOT NULL DEFAULT '';
ALTER TABLE terminal_run ADD COLUMN evidence_component_version TEXT NOT NULL DEFAULT '';
