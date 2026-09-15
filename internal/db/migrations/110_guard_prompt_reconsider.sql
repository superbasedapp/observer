-- 110_guard_prompt_reconsider.sql — "reconsider-once" state for the
-- prompt-submit intervention feature
-- (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md §5).
--
-- The prompt-submit guard detects secrets/PII a developer is about to
-- TYPE INTO their own prompt (§4) and, in `ask-once` mode, interrupts the
-- first send of a given finding set and lets an IDENTICAL resend within
-- a TTL through (§5.2/§5.3 state machine). This table is that grant's
-- persistence.
--
-- WHY A TABLE AND NOT IN-MEMORY STATE (§5.4):
--   (a) On the hook lane, the process that would hold that state is
--       SHORT-LIVED — one hook invocation per prompt, no memory shared
--       with the next invocation. It already opens the daemon's DB for
--       approval lookups (cmd/observer/hook.go), so persisting here is
--       the same cost, not new cost.
--   (b) The proxy's existing in-memory dedup set (`g.proxySeen`,
--       internal/proxy/proxyguard.go) silently DROPS its whole signature
--       set on overflow. Reusing that mechanism for this grant would mean
--       an overflow could silently forget a warning was ever issued —
--       the opposite of what "reconsider-once" promises a developer.
--   (c) A daemon restart must not re-interrupt a developer mid-flow (they
--       already read the warning and are in the middle of resending), nor
--       silently un-warn them (treating a live grant as never-issued).
-- A durable row is the only structure that survives both a process
-- boundary (a) and a restart (c) without the overflow risk of (b).
--
-- FINGERPRINT COMPOSITION (§5.2) — `fingerprint` is
--
--   sha256("v1" 0x1e session_id 0x1e
--          join(sorted(detector_id ":" sha256(normalized_span)), 0x1f))
--
-- i.e. a hash over the SESSION plus the SORTED SET of (detector id,
-- hash-of-normalized-matched-span) pairs — never the raw matched value,
-- and never even a per-span hash alone (a short value like a 9-digit SSN
-- is trivially rainbow-tabled; mixing in session_id defeats that). The
-- set-not-sequence composition is deliberate: a developer who resends the
-- same secret with extra commentary has not changed the finding set, so
-- the resend confirms; a developer who edits or removes the value
-- produces a different (or empty) set, so the interrupt does not fire
-- again — without ever diffing prompt text.
--
-- COLUMNS
--   fingerprint  — sha256 hex, PRIMARY KEY (one row per reconsider-once
--                  grant; RecordPromptWarned REPLACEs on collision so a
--                  re-interrupt after expiry resets the grant cleanly).
--   session_id   — scopes the grant (empty session_id degrades ask-once
--                  to block, never allow — §5.2, the same fail-closed
--                  stance proxyAlreadySeen takes on an empty session).
--   tool         — reporting only, no enforcement meaning.
--   detectors    — comma-joined detector ids (e.g. "credit_card,us_ssn"),
--                  no values, no spans.
--   warned_at    — when the first interrupt for this fingerprint fired
--                  (INTEGER unix nanoseconds UTC — see the F8 note below).
--   confirmed_at — NULL until the identical resend lands; stamped then
--                  (INTEGER unix nanoseconds UTC, nullable).
--   expires_at   — the TTL horizon (default 30 min, §5.4); past this, a
--                  lookup treats the row as a miss (fresh interrupt)
--                  (INTEGER unix nanoseconds UTC).
--
-- TIMESTAMP REPRESENTATION (F8, round-2 review; this migration is
-- unreleased so the fix is edited in place rather than added as 110):
-- warned_at/confirmed_at/expires_at are INTEGER unix nanoseconds, NOT
-- the store package's usual `timestamp()` RFC3339Nano TEXT format.
-- RFC3339Nano trims trailing zero fractional digits (Go's
-- time.Format), so two stamps compare LEXICOGRAPHICALLY inconsistent
-- with their chronological order across a sub-second boundary —
-- "…10:00:00Z" (no fraction) sorts AFTER "…10:00:00.5Z" as TEXT, even
-- though it is chronologically LATER — and this table's
-- ConfirmPromptReconsider/PrunePromptReconsider queries compare
-- expires_at directly in SQL (`WHERE expires_at > ?` / `< ?`), so a
-- TEXT column would intermittently mis-order a genuinely live grant as
-- expired (or vice versa) whenever warned_at/now happen to land on
-- exact-second boundaries. INTEGER unix nanoseconds compare correctly
-- with ordinary numeric `<`/`>` regardless of fractional width — the
-- same representation internal/store/remotesession.go already uses for
-- remote_sessions.created_at/last_seen for the identical reason.
--
-- PRIVACY / CLAUDE.md "no contents in the DB": no matched value, prefix,
-- suffix, character-class profile, or unsalted per-span hash is ever
-- stored here or anywhere else — only the composite fingerprint, which by
-- construction cannot be reversed to any one finding's value.
--
-- NODE-LOCAL. This table is added to the org-push privacy sentinel
-- (tests/invariant/privacy_test.go's forbiddenCacheTables) — even though
-- the matched value is never stored, `detectors` + `session_id` reveal
-- WHICH KIND of sensitive content a developer typed and when, which the
-- node operator should control disclosure of like the other guard-layer
-- node-local tables (guard_pins / guard_policy_state / guard_approvals,
-- migration 040). It gets NO paired org-server migration, by design —
-- same posture as limit_snapshots (migration 049) and cache_segments
-- (migration 036).
--
-- Owner: internal/store/guardprompt.go is the sole read/write seam
-- (CLAUDE.md module-boundary rule 4 — one owner per table).

CREATE TABLE IF NOT EXISTS guard_prompt_reconsider (
    fingerprint  TEXT PRIMARY KEY,      -- sha256 hex, reconsider-once fingerprint over the finding SET (detector ids + normalized spans + session), never the matched value itself
    session_id   TEXT NOT NULL,
    tool         TEXT,                  -- reporting only
    detectors    TEXT NOT NULL,         -- comma-joined detector ids, no values
    warned_at    INTEGER NOT NULL,      -- unix nanoseconds UTC (F8: not RFC3339Nano TEXT — see note above)
    confirmed_at INTEGER,               -- unix nanoseconds UTC, NULL until the identical resend
    expires_at   INTEGER NOT NULL       -- unix nanoseconds UTC
);
CREATE INDEX IF NOT EXISTS idx_gpr_session ON guard_prompt_reconsider(session_id);
CREATE INDEX IF NOT EXISTS idx_gpr_expires ON guard_prompt_reconsider(expires_at);
