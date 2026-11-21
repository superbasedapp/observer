-- 256: move legacy Plane A rows out of api_turns (plan-of-record F10 / D6,
-- lane A6 W1d-1, lead ruling 2026-11-19 option (a)).
--
-- Before the merge-only rule (store.MergeTurnByRequestID), an SDK or OTLP
-- LLM span from a hosted app (source 'otlp_trace' / 'sdk_otlp', written only
-- on a node with [observability] enabled) was INSERTED into api_turns with
-- time = now and no session, project or cache split, and shipped on the
-- Plane B push. A hosted app's spend then read as the developer's coding
-- spend, on the node and on the org.
--
-- This step relocates every such row, it destroys nothing:
--   1. api_turns_planea_legacy receives a verbatim copy of each row (every
--      api_turns column as of this step, plus relocated_at);
--   2. the nullable references other node tables hold to those rows are
--      cleared (compression_events cascades, as it already does for every
--      api_turns delete);
--   3. the rows are deleted from api_turns, so the existing delete triggers
--      tombstone them on the org (org_push_delete_api_turns, only above the
--      enrolment floor; a node that never pushed them records nothing) and
--      mark their spend verdicts dirty.
-- Every Plane B read and the org history are then clean with no read-site
-- change. A node with no such rows (every node that never enabled
-- [observability]) creates an empty table and changes nothing else.
--
-- Cost (review R-A11): the Plane A row ids are read ONCE into a temp table
-- (one api_turns scan; api_turns has no index on source). Every later
-- statement drives off that set: the copy and the delete by rowid, and each
-- reference clear through a CROSS JOIN with the id set as the OUTER loop, so
-- on the common node with no Plane A rows the five referencing tables
-- (cache_segments, cache_events, guard_events, router_decisions,
-- process_network_bodies; several are large and have no api_turn_id index)
-- are never scanned. With rows present SQLite builds an automatic index on
-- the inner table, one scan each, the same cost as before.
--
-- Who reads api_turns_planea_legacy: nothing in the product. It is a
-- RECOVERY copy only, kept so this step destroys nothing: an operator can
-- read a hosted app's pre-fix spend back with sqlite3 if it is ever wanted
-- (Plane A spend now lives in the obs_* tables). The only code that names
-- it is the component purge (internal/store/componentpurge.go, which keeps
-- the sessions it points at) and the privacy sentinel. Nothing writes it
-- after this step. The org copy of those rows is tombstoned by design
-- (D6); release notes say so.
--
-- NODE-LOCAL: api_turns_planea_legacy never crosses the push wire
-- (tests/invariant/privacy_test.go lists it as a forbidden name in
-- orgpush.go).

CREATE TABLE IF NOT EXISTS api_turns_planea_legacy AS
    SELECT * FROM api_turns WHERE 0;
ALTER TABLE api_turns_planea_legacy ADD COLUMN relocated_at TEXT;

CREATE TEMP TABLE planea_turn_ids AS
    SELECT id FROM api_turns WHERE COALESCE(source, '') IN ('otlp_trace', 'sdk_otlp');

INSERT INTO api_turns_planea_legacy
    SELECT *, strftime('%Y-%m-%dT%H:%M:%fZ', 'now') FROM api_turns
     WHERE id IN (SELECT id FROM temp.planea_turn_ids);

UPDATE cache_segments SET api_turn_id = NULL WHERE rowid IN (
    SELECT t.rowid FROM temp.planea_turn_ids p CROSS JOIN cache_segments t WHERE t.api_turn_id = p.id);
UPDATE cache_events SET api_turn_id = NULL WHERE rowid IN (
    SELECT t.rowid FROM temp.planea_turn_ids p CROSS JOIN cache_events t WHERE t.api_turn_id = p.id);
UPDATE guard_events SET api_turn_id = NULL WHERE rowid IN (
    SELECT t.rowid FROM temp.planea_turn_ids p CROSS JOIN guard_events t WHERE t.api_turn_id = p.id);
UPDATE router_decisions SET api_turn_id = NULL WHERE rowid IN (
    SELECT t.rowid FROM temp.planea_turn_ids p CROSS JOIN router_decisions t WHERE t.api_turn_id = p.id);
UPDATE process_network_bodies SET api_turn_id = NULL WHERE rowid IN (
    SELECT t.rowid FROM temp.planea_turn_ids p CROSS JOIN process_network_bodies t WHERE t.api_turn_id = p.id);

DELETE FROM api_turns WHERE id IN (SELECT id FROM temp.planea_turn_ids);

DROP TABLE temp.planea_turn_ids;
