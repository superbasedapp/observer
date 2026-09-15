package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// cloudautoenrich.go is the store seam behind the background-by-default
// enrichment loop (value-upgrade plan of record §W3,
// docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md). It answers
// three questions cmd/observer/cloudautoenrich.go and `observer cloud sync`
// need, and owns no new privacy-sensitive state beyond migration 117's two
// additions (cloud_enrich_policy.since, cloud_sync_last):
//
//   - which finished, personal-authority sessions are candidates for an
//     unattended `observer cloud consent` (ListCloudAutoEnrichCandidates);
//   - what the last `observer cloud sync` run reported, content-free
//     (RecordCloudSyncLast / GetCloudSyncLast); and
//   - which enrichment results landed recently, for the dashboard's
//     Sessions-page toast (ListCloudResultsSince).
//
// Same discipline as cloudpolicy.go: no import of internal/cloudcontract,
// internal/cloudclient/cloudpop/cloudcred, and every table here is
// NODE-LOCAL — cloud_sync_last joins the forbidden-table sentinel
// tests/invariant/privacy_test.go walks, exactly like cloud_enrich_policy.

// CloudAutoEnrichCandidate is one session the background sweep may enqueue.
// "Ended" is inferred, never stamped: adapters rarely set sessions.ended_at,
// so a session counts as finished when its newest action is older than the
// sweep's quiet window (see ListCloudAutoEnrichCandidates).
type CloudAutoEnrichCandidate struct {
	SessionID    string
	StartedAt    time.Time
	LastActionAt time.Time
	Actions      int
}

// cloudSentResultGrace is how long a `sent` cloud_outbox row blocks a fresh
// candidacy for the same session. A result is normally back within seconds
// of a send, so a `sent` row still standing after this long with no
// cloud_results row means the hosted job was PARKED (e.g. pre-flip,
// credential absent) and its evidence deleted server-side — the only re-run
// path left is a node re-submit, and the hosted canonical key may since have
// changed (e.g. `route_registry.prompt_version` bumped) so a re-submit is
// accepted. cloudSentRowCap bounds how many times a session may be
// re-submitted this way, so a session whose result can genuinely never
// arrive doesn't retry forever.
const (
	cloudSentResultGrace = 24 * time.Hour
	cloudSentRowCap      = 3
)

// ListCloudAutoEnrichCandidates returns up to limit personal-authority
// sessions started at/after since whose newest action is older than quietFor
// (and not in the future relative to now), with total_actions >= minActions,
// excluding a session that:
//
//   - has a cloud_outbox row of kind session_evidence in a NON-terminal
//     state (pending, sending, failed_retryable, reconfirmation_required —
//     it is already in flight or awaiting the developer);
//   - has a `sent` row younger than cloudSentResultGrace (its result may
//     still be on the way);
//   - has cloudSentRowCap or more `sent` rows in total (the stale-sent
//     re-submit path below is capped, not unlimited); or
//   - has any cloud_results row at all (already enriched).
//
// A `sent` row older than the grace period with no result is the ONE case
// that becomes a candidate again (see cloudSentResultGrace) — everything
// else that reached `cancelled` or `failed_terminal` also does not block,
// unchanged from before this rule was added.
//
// A session with a durable cloud_enrich_skips row (a session whose consent
// spawn recently failed, see internal/store/cloudenrichskip.go) whose
// next_at has not yet passed is also excluded.
//
// Oldest-ended first (the session that has been waiting longest goes
// first). One SQL statement, joined through idx_actions_session
// (actions.session_id) — it never scans the actions table without a session
// id predicate. `since` is the caller's cloud_enrich_policy.Since: a session
// that started before the developer turned background enrichment on is
// never a candidate, so turning it on never reaches back and enqueues
// history.
func (s *Store) ListCloudAutoEnrichCandidates(ctx context.Context, since time.Time, quietFor time.Duration, minActions, limit int, now time.Time) ([]CloudAutoEnrichCandidate, error) {
	const pfx = "store.ListCloudAutoEnrichCandidates"
	if limit <= 0 {
		limit = 25
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-quietFor)
	sentGraceCutoff := now.Add(-cloudSentResultGrace)

	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.started_at, MAX(a.timestamp) AS last_action_at, COALESCE(s.total_actions, 0)
		  FROM sessions s
		  JOIN actions a ON a.session_id = s.id
		 WHERE s.authority = 'personal'
		   AND s.started_at >= ?
		   AND COALESCE(s.total_actions, 0) >= ?
		   AND NOT EXISTS (
		         SELECT 1 FROM cloud_outbox o
		          WHERE o.session_id = s.id AND o.kind = 'session_evidence'
		            AND o.state IN ('pending', 'sending', 'failed_retryable', 'reconfirmation_required')
		       )
		   AND NOT EXISTS (
		         SELECT 1 FROM cloud_outbox o
		          WHERE o.session_id = s.id AND o.kind = 'session_evidence' AND o.state = 'sent'
		            AND o.updated_at > ?
		       )
		   AND (
		         SELECT COUNT(*) FROM cloud_outbox o
		          WHERE o.session_id = s.id AND o.kind = 'session_evidence' AND o.state = 'sent'
		       ) < ?
		   AND NOT EXISTS (SELECT 1 FROM cloud_results r WHERE r.session_id = s.id)
		   AND NOT EXISTS (
		         SELECT 1 FROM cloud_enrich_skips k WHERE k.session_id = s.id AND k.next_at > ?
		       )
		 GROUP BY s.id
		HAVING MAX(a.timestamp) <= ?
		 ORDER BY last_action_at ASC
		 LIMIT ?`,
		cloudFormatTime(since), minActions, cloudFormatTime(sentGraceCutoff), cloudSentRowCap,
		cloudFormatTime(now), timestamp(cutoff), limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = rows.Close() }()

	var out []CloudAutoEnrichCandidate
	for rows.Next() {
		var (
			id, startedAt, lastActionAt string
			actions                     int
		)
		if err := rows.Scan(&id, &startedAt, &lastActionAt, &actions); err != nil {
			return nil, fmt.Errorf("%s: %w", pfx, err)
		}
		out = append(out, CloudAutoEnrichCandidate{
			SessionID:    id,
			StartedAt:    cloudParseTime(startedAt),
			LastActionAt: cloudParseTime(lastActionAt),
			Actions:      actions,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}

// CloudSyncLast is the outcome of the most recent `observer cloud sync` run
// (migration 117's cloud_sync_last singleton). Content-free by construction:
// counts and a closed error-class vocabulary only, never a session id, a
// title, or raw command output.
type CloudSyncLast struct {
	StartedAt       time.Time
	FinishedAt      time.Time
	OK              bool
	Sent            int
	WaitingProvider int
	Reconfirm       int
	Failed          int
	Results         int
	SignInExpired   bool
	ErrorClass      string
	// PlanName / PlanLabel are the account plan GET /v1/usage reported on
	// this run (migration 118, value-upgrade plan §W5) — e.g. "free" /
	// "Free" or "plus" / "Plus". "" means unknown (no sync has ever
	// recorded a plan, or a usage fetch failed on every run so far).
	PlanName, PlanLabel string
	// DigestWeekly reports whether the resolved plan includes the weekly
	// project digest job kind, as 0/1; nil means unknown (an older server
	// that predates this wave never emits the field at all, or the usage
	// fetch on this run failed) — never treated as false.
	DigestWeekly *int
	// ResultsRetentionDays is how long the resolved plan keeps hosted
	// results; nil means unknown, same convention as DigestWeekly.
	ResultsRetentionDays *int
	// DailyCap / MonthlyCap are the resolved plan's per-window allowances;
	// nil means unknown (no successful usage fetch yet).
	DailyCap, MonthlyCap *int
}

// RecordCloudSyncLast upserts the singleton (id=1) row every `observer cloud
// sync` run writes at its end, on both its success and failure paths — so
// `observer cloud status` and GET /api/cloud/status always reflect the last
// attempt, not just the last one that happened to succeed.
func (s *Store) RecordCloudSyncLast(ctx context.Context, r CloudSyncLast) error {
	ok := 0
	if r.OK {
		ok = 1
	}
	signInExpired := 0
	if r.SignInExpired {
		signInExpired = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cloud_sync_last
		  (id, started_at, finished_at, ok, sent, waiting_provider, reconfirm, failed, results,
		   sign_in_expired, error_class, plan_name, plan_label, digest_weekly,
		   results_retention_days, daily_cap, monthly_cap)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			started_at              = excluded.started_at,
			finished_at             = excluded.finished_at,
			ok                      = excluded.ok,
			sent                    = excluded.sent,
			waiting_provider        = excluded.waiting_provider,
			reconfirm               = excluded.reconfirm,
			failed                  = excluded.failed,
			results                 = excluded.results,
			sign_in_expired         = excluded.sign_in_expired,
			error_class             = excluded.error_class,
			plan_name               = excluded.plan_name,
			plan_label              = excluded.plan_label,
			digest_weekly           = excluded.digest_weekly,
			results_retention_days  = excluded.results_retention_days,
			daily_cap               = excluded.daily_cap,
			monthly_cap             = excluded.monthly_cap`,
		timestamp(r.StartedAt), timestamp(r.FinishedAt), ok, r.Sent, r.WaitingProvider, r.Reconfirm,
		r.Failed, r.Results, signInExpired, r.ErrorClass, r.PlanName, r.PlanLabel,
		nullableIntPtr(r.DigestWeekly), nullableIntPtr(r.ResultsRetentionDays),
		nullableIntPtr(r.DailyCap), nullableIntPtr(r.MonthlyCap))
	if err != nil {
		return fmt.Errorf("store.RecordCloudSyncLast: %w", err)
	}
	return nil
}

// nullInt64PtrFromSQL converts a scanned sql.NullInt64 into an *int, nil
// when the column is NULL (unknown) — the inverse of nullableIntPtr.
func nullInt64PtrFromSQL(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

// GetCloudSyncLast reads the singleton row. ok=false means `observer cloud
// sync` has never run to completion on this device.
func (s *Store) GetCloudSyncLast(ctx context.Context) (CloudSyncLast, bool, error) {
	var (
		r                     CloudSyncLast
		startedAt, finishedAt string
		ok, signInExpired     int
		digestWeekly          sql.NullInt64
		resultsRetentionDays  sql.NullInt64
		dailyCap, monthlyCap  sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT started_at, finished_at, ok, sent, waiting_provider, reconfirm, failed, results,
		       sign_in_expired, error_class, plan_name, plan_label, digest_weekly,
		       results_retention_days, daily_cap, monthly_cap
		  FROM cloud_sync_last WHERE id = 1`).
		Scan(&startedAt, &finishedAt, &ok, &r.Sent, &r.WaitingProvider, &r.Reconfirm, &r.Failed,
			&r.Results, &signInExpired, &r.ErrorClass, &r.PlanName, &r.PlanLabel, &digestWeekly,
			&resultsRetentionDays, &dailyCap, &monthlyCap)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudSyncLast{}, false, nil
	}
	if err != nil {
		return CloudSyncLast{}, false, fmt.Errorf("store.GetCloudSyncLast: %w", err)
	}
	r.StartedAt = cloudParseTime(startedAt)
	r.FinishedAt = cloudParseTime(finishedAt)
	r.OK = ok != 0
	r.SignInExpired = signInExpired != 0
	r.DigestWeekly = nullInt64PtrFromSQL(digestWeekly)
	r.ResultsRetentionDays = nullInt64PtrFromSQL(resultsRetentionDays)
	r.DailyCap = nullInt64PtrFromSQL(dailyCap)
	r.MonthlyCap = nullInt64PtrFromSQL(monthlyCap)
	return r, true, nil
}

// CloudResultEvent is one enrichment result the Sessions-page toast/poll
// reports (GET /api/cloud/events). Title is the AI-suggested title already
// rendered elsewhere on the dashboard (LoadCloudEnrichedTitles) — still
// node-local, never uploaded.
type CloudResultEvent struct {
	ResultID   string
	SessionID  string
	Title      string
	ReceivedAt time.Time
}

// ListCloudResultsSince returns current (non-superseded) results received
// after `since`, newest first, capped at limit.
func (s *Store) ListCloudResultsSince(ctx context.Context, since time.Time, limit int) ([]CloudResultEvent, error) {
	const pfx = "store.ListCloudResultsSince"
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, session_id, COALESCE(json_extract(result_json, '$.title'), ''), received_at
		  FROM cloud_results
		 WHERE superseded_by IS NULL AND received_at > ?
		 ORDER BY received_at DESC
		 LIMIT ?`,
		cloudFormatTime(since), limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	defer func() { _ = rows.Close() }()

	var out []CloudResultEvent
	for rows.Next() {
		var id, sessionID, title, receivedAt string
		if err := rows.Scan(&id, &sessionID, &title, &receivedAt); err != nil {
			return nil, fmt.Errorf("%s: %w", pfx, err)
		}
		out = append(out, CloudResultEvent{
			ResultID:   id,
			SessionID:  sessionID,
			Title:      title,
			ReceivedAt: cloudParseTime(receivedAt),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", pfx, err)
	}
	return out, nil
}
