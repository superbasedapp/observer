# Security audit read path (gap 2.10)

`security_audit_events` (Postgres, `internal/cloudserver/store/control.go::RecordAudit`)
is written on every auth/billing outcome, retained 24 months. Today there is
no operator read surface for it beyond `psql`/a one-off script. This file is
the saved-query half of gap 2.10 (the KQL half of D7); the alerting half is
`webhook-5xx-and-audit-bursts.sql` in this directory.

These are plain read-only SQL, run via `psql` against the DSN in
`sbci-pg-dsn` (or the admin DSN for an unrestricted read — `security_audit_events`
has no RLS scoping since it is a system table, see migration `0002_core_schema.sql`).
None of these mutate anything.

## Recent events, any type

```sql
SELECT id, account_id, event_type, detail, created_at
FROM security_audit_events
ORDER BY created_at DESC
LIMIT 100;
```

## Events for one account (support/incident triage)

```sql
SELECT event_type, detail, created_at
FROM security_audit_events
WHERE account_id = $1::uuid
ORDER BY created_at DESC
LIMIT 200;
```

## Event-type counts over a window (shape of what's happening)

```sql
SELECT event_type, count(*) AS n
FROM security_audit_events
WHERE created_at > now() - interval '24 hours'
GROUP BY event_type
ORDER BY n DESC;
```

## The two security-sensitive burst signals (also in webhook-5xx-and-audit-bursts.sql)

```sql
SELECT event_type, count(*) AS n
FROM security_audit_events
WHERE event_type IN ('paddle_webhook_signature_invalid', 'portal_workos_state_mismatch')
  AND created_at > now() - interval '1 hour'
GROUP BY event_type;
```

## Owed: a real CLI/dashboard surface

This is still a `psql`-only read path. `observer-cloud` has no `audit-log`
verb and web2/webcloud has no audit page. Wiring either is out of this wave's
scope (D4-D6 add exactly three new verbs — kill-switch, schema-check, and the
attest token-source change — and touching `cmd/observer-cloud/main.go` beyond
the two documented one-line edits is explicitly out of scope). Track this as
a follow-up alongside the webhook-5xx/audit-burst Log Analytics gap noted in
`webhook-5xx-and-audit-bursts.sql`.
