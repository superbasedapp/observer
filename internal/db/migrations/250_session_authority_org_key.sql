-- 250: sessions.authority_org_key - WHICH organization a session's data
-- belongs to (managed SaaS plan 07 row M8.1; plan 06 section 5.6; operator
-- rulings D-43 and I-8, 2026-11-12: data captured under one organization
-- never reaches another).
--
-- sessions.authority (migration 096) says only 'org' or 'personal', never
-- which org. This column names it, so every org-bound selection (the push
-- cursor and re-send lanes, the org-intel sweep, `observer org backfill`)
-- can keep to the rows of the org enrolled NOW. Values:
--
--   <64 hex>          the enrolment's org key, hex(SHA256(normalized org
--                     server URL || 0x00 || org id)) - the same identity key
--                     orgclient.OrgKey computes (two orgs behind one server
--                     URL never share a key). Stamped at capture by
--                     store.UpsertSession from the LIVE enrolment, in the
--                     same transaction as the authority stamp. Sticky: an org
--                     key is never rewritten to another org.
--   'personal'        captured with no enrolment in force. Never matches an
--                     org destination, so it never ships. A session that
--                     keeps capturing after the node enrols upgrades to that
--                     org's key, exactly like sessions.authority
--                     (dataauthority.Combine).
--   'pending-250'     transient, existing rows only (below): the enrolment in
--                     force when this migration ran, whose key SQL cannot
--                     compute (SQLite has no SHA-256). store resolves it to
--                     the hex key from the pre-image recorded in schema_meta
--                     before any org-bound selection reads the column, and
--                     until then it matches no destination (fail closed).
--   NULL              unknown: a capture whose enrolment could not be read
--                     (the resolver fails closed, like authority), or a row
--                     written by a path that does not stamp (a database
--                     import). Never matches a destination.
--
-- EXISTING ROWS are stamped HERE, so no unkeyed row predates the column:
--   * authority = 'personal'  -> 'personal' (captured while unenrolled);
--   * otherwise, enrolled now -> the enrolment in force (via 'pending-250');
--   * otherwise               -> 'personal'.
-- An 'org' row of an organization this node has since left cannot be named
-- (authority never recorded which org), so it is stamped with whatever the
-- node is enrolled in now, or 'personal' when it is not enrolled; the plan
-- accepts that one-time attribution (plan 06 section 5.6, revision 8).
--
-- NODE-LOCAL: the push seam never selects the column onto the wire (it is a
-- selection predicate, not a wire field), the privacy sentinel
-- (tests/invariant/privacy_test.go) stuffs a marker into it and asserts the
-- marker never ships, and the column is NOT in the org_push_change_sessions
-- trigger's column list, so stamping or resolving it never re-pushes a
-- session. No server pair.
ALTER TABLE sessions ADD COLUMN authority_org_key TEXT;

-- The pre-image of the enrolment in force now, for the Go-side resolution of
-- 'pending-250' (store.resolvePendingAuthorityOrgKeys). Written only when
-- enrolled; both keys are deleted once the pending rows are resolved.
INSERT OR REPLACE INTO schema_meta (key, value)
SELECT 'authority_org_key_250_org_id', org_id
  FROM org_enrolment WHERE id = 1 AND org_id <> '';
INSERT OR REPLACE INTO schema_meta (key, value)
SELECT 'authority_org_key_250_org_server_url', org_server_url
  FROM org_enrolment WHERE id = 1 AND org_id <> '';

UPDATE sessions SET authority_org_key = CASE
    WHEN authority = 'personal' THEN 'personal'
    WHEN EXISTS (SELECT 1 FROM org_enrolment WHERE id = 1 AND org_id <> '') THEN 'pending-250'
    ELSE 'personal'
END;
