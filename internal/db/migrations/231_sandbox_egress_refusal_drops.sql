-- 231_sandbox_egress_refusal_drops.sql - the dropped count beside the
-- sandbox egress refusal audit (OpenShell build lane OC, audit findings
-- O3-W2, OC-A1 and OC-A2; agent migration block 230 to 239 reserved by
-- plan 05 section 4).
--
-- One row per sandboxed run whose refusals were dropped before they could
-- be written: a refusal feed past its own bound (the openshell row's OCSF
-- receiver drops a run's denials past its per-second bound, and held
-- denials of a box whose id was not recorded yet), the refusal receiver's
-- flood bound when it drops a distinct refusal (past the per-run cap of
-- distinct hosts in a minute, from a minute earlier than the run's, or
-- with its run table full), or its write queue with no room. A run whose
-- refusal rows look complete is then not silently incomplete: the read
-- route answers its counts beside its rows. Only a repeat of a host the
-- run's minute already wrote is not counted (nothing new was lost).
--
--   run_id      the run id the refusal rows carry (the stored terminal run,
--               or the relay run of a run with no stored row)
--   dropped     refusals of this run dropped so far, added to on every
--               write
--   uncertain   refusals that may be this run's, dropped while its box id
--               was not recorded yet and the receiver could not remember
--               which box they claimed (its table of dropped box ids was
--               full); each such drop is added to every run waiting for
--               its box id at the time, so it can over-count but never
--               reads as zero
--   updated_at  fixed-width RFC 3339 UTC of the last add; rows older than
--               store.SandboxEgressRefusalRetention are pruned with the
--               refusal rows
--
-- NODE-LOCAL: never selected by internal/store/orgpush.go (decision D6);
-- pinned in tests/invariant/privacy_test.go (forbiddenCacheTables). NO
-- server pair. Single writer internal/store/sandboxegress.go.

CREATE TABLE IF NOT EXISTS sandbox_egress_refusal_drops (
    run_id     TEXT    PRIMARY KEY,
    dropped    INTEGER NOT NULL DEFAULT 0,
    uncertain  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sandbox_egress_refusal_drops_at ON sandbox_egress_refusal_drops(updated_at);
