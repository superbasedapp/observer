-- webhook-5xx-and-audit-bursts.sql — Postgres-side scheduled queries for
-- three of the gap-4.6 alert asks: webhook 5xx rate, and bursts of
-- paddle_webhook_signature_invalid / portal_workos_state_mismatch.
--
-- HONEST LIMITATION (why this is SQL, not a Log Analytics KQL file like the
-- rest of this directory): the API has no per-request access log (no status
-- code is ever logged, per-route or otherwise — grep confirms it), and the
-- Paddle webhook signature failure / WorkOS state-mismatch events are
-- recorded ONLY as rows in Postgres `security_audit_events`
-- (internal/cloudserver/api/middleware.go::audit calls store.RecordAudit;
-- there is no matching slog line). Azure Monitor's Log Analytics scheduled-
-- query alerts run over Log Analytics/Application Insights data, not
-- arbitrary Postgres tables, so these three cannot be built as KQL against
-- the existing Log Analytics workspace without first adding a structured
-- stdout log line alongside every audit() call (an owed follow-up — see
-- alerts.sh for the exact TODO).
--
-- Until that follow-up lands, run these AS a scheduled operator query — e.g.
-- a cron'd `psql` invocation piping to the [alerts].action_group email, or an
-- Azure Automation Runbook / Logic App on a Postgres-compatible trigger. Each
-- query is READ-ONLY and safe to run on any interval.

-- 1) Webhook signature-verification failures (bursts here usually mean
--    either a secret rotation went out of sync between Key Vault and the
--    Paddle dashboard, or a genuine forged-webhook attempt).
-- Threshold suggestion: alert if count >= 5 in 15 minutes.
SELECT count(*) AS failures_last_15m
FROM security_audit_events
WHERE event_type = 'paddle_webhook_signature_invalid'
  AND created_at > now() - interval '15 minutes';

-- 2) Portal WorkOS sign-in state-parameter mismatches (bursts here usually
--    mean either a CSRF/open-redirect probing attempt, or a broken
--    redirect_uri configuration change).
-- Threshold suggestion: alert if count >= 5 in 15 minutes.
SELECT count(*) AS mismatches_last_15m
FROM security_audit_events
WHERE event_type = 'portal_workos_state_mismatch'
  AND created_at > now() - interval '15 minutes';

-- 3) Job park rate (provider_policy_unverified and its siblings — see
--    internal/cloudserver/store/jobs.go's Reason* constants). A SUSTAINED
--    100% park rate post-approval (i.e. once a real Foundry credential is
--    wired) would mean the attestation gate itself is stuck unhealthy, not
--    the expected pre-approval state.
-- Threshold suggestion: alert if parked/total >= 0.5 over the last hour,
-- ONLY once SBCI_FOUNDRY_API_KEY is provisioned (pre-approval this ratio is
-- expected to be 1.0 by design and must NOT page anyone).
SELECT
  count(*) FILTER (WHERE state = 'parked') AS parked,
  count(*) AS total,
  round(
    count(*) FILTER (WHERE state = 'parked')::numeric / greatest(count(*), 1),
    3
  ) AS park_ratio
FROM analysis_jobs
WHERE created_at > now() - interval '1 hour';
