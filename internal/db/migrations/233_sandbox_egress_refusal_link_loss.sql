-- 233_sandbox_egress_refusal_link_loss.sql - why a sandboxed run's refusals
-- were lost or removed, beside the dropped count (OpenShell build lane FU5,
-- tracker F-012 audit finding N4-A4 and F-009 audit finding N1-A4; agent
-- migration block 230 to 239 reserved by plan 05 section 4, number 233
-- assigned to lane FU5 by decision OB-062).
--
-- A run's host helper sends each refusal to the daemon on the relay link.
-- When that link is lost mid-run (the daemon restarts or dies), the helper
-- counts what it could not send and, when the org's require_refusal_audit
-- floor was in force at launch, refuses the run's new connections until the
-- link is back. The first report that gets through carries the counts:
--
--   link_lost      refusals of this run that could not be sent to Observer
--                  (the link down, or the daemon busy or its queue full; they
--                  are also in dropped, which counts every lost refusal)
--   egress_closed  new requests of this run refused while its link was down
--                  (the floor in force); nothing left, so these are not
--                  refusals and not in dropped
--   evicted        rows of this run removed, oldest first, to keep the run
--                  under store.SandboxEgressRefusalMaxPerRun (the per-run
--                  total bound); they were written and are no longer kept
--
-- Additive: all three default to 0, so a row written before this step reads as
-- nothing lost or removed. NODE-LOCAL like the table (decision D6; privacy sentinel
-- forbiddenCacheTables). Single writer internal/store/sandboxegress.go.

ALTER TABLE sandbox_egress_refusal_drops ADD COLUMN link_lost INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandbox_egress_refusal_drops ADD COLUMN egress_closed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sandbox_egress_refusal_drops ADD COLUMN evicted INTEGER NOT NULL DEFAULT 0;
