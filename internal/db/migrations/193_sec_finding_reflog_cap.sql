-- 193_sec_finding_reflog_cap.sql - a held commit reached only past a
-- reflog cap (security pillar plan sections 4.8 and 5.3, SECP-18 "the
-- reflog caps"; lane LEFT-SEC).
--
-- sec_finding_commits.reflog_cap names the [security.scanning] cap
-- ("reflog_cap_age" or "reflog_cap_entries") past which the only reflog
-- entries that still reach this held commit lie. '' for every other hold.
-- A finding every holding commit of which carries a cap is no longer held
-- for a deny: the push gate asks (S-792's capped row), never allows. The
-- column is written by the daemon's history check and cleared when the
-- commit is held again inside the caps.
--
-- NODE-LOCAL: sec_finding_commits is in the privacy sentinel's
-- forbidden-table list and the org row builder never selects it. NO server
-- pair. One writer: internal/store/secfindings.go. Never content: a closed
-- reason code.

ALTER TABLE sec_finding_commits ADD COLUMN reflog_cap TEXT NOT NULL DEFAULT '';
