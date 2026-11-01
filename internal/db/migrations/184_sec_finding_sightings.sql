-- 184_sec_finding_sightings.sql - where each open finding was last seen
-- (security pillar plan sections 4.5.1 and 5.11(a); lane sec-gate2,
-- decision log P-021 follow-up). A finding's lifecycle key is location-free
-- (secfinding.LocalKey), so the same secret in two files is ONE finding row;
-- this table lists every file it was seen in, so removing the secret from
-- one file closes the finding only when no other sighting is left.
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list, so
-- internal/store/orgpush.go can never select it by name. NO server pair.
-- One writer: internal/store/secfindings.go (UpsertSecFinding adds or
-- refreshes a sighting, CloseGoneSecFindings removes the ones a run proved
-- gone). Never content: a project-relative path and a timestamp.

CREATE TABLE IF NOT EXISTS sec_finding_sightings (
    finding_id TEXT NOT NULL,
    rel_path   TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (finding_id, rel_path)
);

CREATE INDEX IF NOT EXISTS idx_sec_finding_sightings_path ON sec_finding_sightings (rel_path);

-- Every finding stored before this table existed keeps its one known
-- location as its one sighting.
INSERT OR IGNORE INTO sec_finding_sightings (finding_id, rel_path, last_seen)
    SELECT id, rel_path, last_seen FROM sec_findings WHERE rel_path <> '';
