-- 218_guard_approvals_unique.sql - one guard approval grant per key (P-232).
--
-- guard_approvals (040) had only a NON-unique index on (rule_id, scope) and
-- store.InsertGuardApproval was a plain INSERT, so pressing approve twice on
-- the Security page (or running `observer guard approve` twice) added a
-- second identical grant (docs/audits/guard-approvals-investigation-2026-11-03.md:
-- two S-794 global rows on the operator's node, ids 9 and 10). The store seam
-- is now grant-or-extend (store.GrantGuardApproval) keyed on
-- (rule_id, scope, session_id, project_root_hash); this step gives that key
-- a unique index so no writer can add a duplicate again.
--
-- Cleanup first, or the index cannot be built. For every key with more than
-- one row the LOWEST id survives and takes the group's LATEST expiry, where a
-- non-expiring grant ('' expires_at) is later than any expiry; the other rows
-- are deleted. Expired rows count too: the unique key covers the whole table
-- (the store re-grants an expired row in place instead of adding a new one),
-- so expired duplicates collapse the same way. Times compare through
-- julianday, not as text: the stored spelling is RFC3339Nano, whose trimmed
-- fraction does not sort. Nothing references guard_approvals.id (the org
-- snapshot names a grant by id as approval_key and simply drops a deleted
-- row on its next snapshot).
--
-- NODE-LOCAL table, never on the org push wire in its own right: no server
-- pair. Numbered 213 on the release line (lane appr); renumbered to 218 when
-- main merged into the release line (plans decision log P-247), because main
-- had also used 213. Numbers 213, 214 and 216 are retired on both lines. On
-- a database that already ran the old 213 the cleanup is a no-op (one row
-- per key) and the index is IF NOT EXISTS, so the re-run is harmless.

UPDATE guard_approvals
   SET expires_at = CASE
         WHEN EXISTS (SELECT 1 FROM guard_approvals d
                       WHERE d.rule_id = guard_approvals.rule_id
                         AND d.scope = guard_approvals.scope
                         AND d.session_id = guard_approvals.session_id
                         AND d.project_root_hash = guard_approvals.project_root_hash
                         AND d.expires_at = '')
           THEN ''
         ELSE (SELECT d.expires_at FROM guard_approvals d
                WHERE d.rule_id = guard_approvals.rule_id
                  AND d.scope = guard_approvals.scope
                  AND d.session_id = guard_approvals.session_id
                  AND d.project_root_hash = guard_approvals.project_root_hash
                ORDER BY julianday(d.expires_at) DESC, d.id ASC
                LIMIT 1)
       END
 WHERE id IN (SELECT MIN(id) FROM guard_approvals
               GROUP BY rule_id, scope, session_id, project_root_hash
              HAVING COUNT(*) > 1);

DELETE FROM guard_approvals
 WHERE id NOT IN (SELECT MIN(id) FROM guard_approvals
                   GROUP BY rule_id, scope, session_id, project_root_hash);

CREATE UNIQUE INDEX IF NOT EXISTS idx_guard_approvals_key
    ON guard_approvals(rule_id, scope, session_id, project_root_hash);
