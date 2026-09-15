package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// digest.go is the W5 project-digest scheduling seam (cloud-intelligence
// value-upgrade plan 2026-09-15 §4): the cross-tenant candidate scan
// (SECURITY DEFINER, mirroring the sbci_lease_next_job precedent as the ONLY
// way to enumerate across accounts) plus the tenant-scoped evidence read the
// scheduler folds into one cloudcontract.DigestEvidence per candidate.

// WeekBoundsUTC returns the half-open [Monday 00:00 UTC, next Monday 00:00
// UTC) bounds of the ISO week containing t.
func WeekBoundsUTC(t time.Time) (monday, nextMonday time.Time) {
	u := t.UTC()
	// time.Weekday: Sunday=0 ... Saturday=6; ISO weeks start Monday, so shift
	// Sunday to the END of the week (offset 6) rather than the start.
	offset := (int(u.Weekday()) + 6) % 7
	day := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	monday = day.AddDate(0, 0, -offset)
	nextMonday = monday.AddDate(0, 0, 7)
	return monday, nextMonday
}

// DigestCandidate is one (account, project) pair due for a project_digest
// this scheduler tick.
type DigestCandidate struct {
	AccountID      string
	ProjectPK      string
	CloudProjectID string
	SessionCount   int
}

// ListProjectDigestCandidates returns every (account, project) whose
// account's CURRENT plan carries digest_weekly=true, which has at least
// minSessions non-superseded session_enrichment results in
// [rangeStart, rangeEnd), and which has NO project_digest result yet for the
// exact (periodStart, periodEnd) pair — so calling this again after a
// successful submission naturally returns nothing new for that period
// (idempotent by construction, not merely by canonical-key dedup on submit).
// It runs the cross-tenant SECURITY DEFINER sbci_project_digest_candidates,
// the only way to enumerate across accounts (the lease function's
// precedent).
func (s *Store) ListProjectDigestCandidates(ctx context.Context, periodStart, periodEnd, rangeStart, rangeEnd time.Time, minSessions, limit int, now time.Time) ([]DigestCandidate, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if minSessions <= 0 {
		minSessions = 3
	}
	if now.IsZero() {
		now = time.Now()
	}
	var out []DigestCandidate
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT account_id::text, project_pk::text, cloud_project_id, session_count
			   FROM sbci_project_digest_candidates($1, $2, $3, $4, $5, $6, $7)`,
			periodStart.Format("2006-01-02"), periodEnd.Format("2006-01-02"), rangeStart, rangeEnd, minSessions, now, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c DigestCandidate
			var n int64
			if e := rows.Scan(&c.AccountID, &c.ProjectPK, &c.CloudProjectID, &n); e != nil {
				return e
			}
			c.SessionCount = int(n)
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListProjectDigestCandidates: %w", err)
	}
	return out, nil
}

// DigestSessionRow is one enriched session folded into project-digest
// evidence — read straight from the tenant's own already-stored result +
// content-free session metrics snapshot (migration 0037). No new content is
// read from anywhere the node did not already send.
type DigestSessionRow struct {
	CloudSessionID string
	CreatedAt      time.Time
	Title          string
	Description    string
	TaxonomyTags   []string
	Limitations    []string
	// Metrics is the session's cloud_sessions.metrics snapshot, or nil when
	// none was captured (a pre-migration session, or a submit that predates
	// the metrics column).
	Metrics map[string]any
}

// LoadProjectDigestEvidence reads up to 40 of a project's most recent
// non-superseded session_enrichment results in [rangeStart, rangeEnd),
// newest-first, for the digest scheduler to fold into
// cloudcontract.DigestEvidence. Tenant-scoped (RLS).
func (s *Store) LoadProjectDigestEvidence(ctx context.Context, accountID, projectPK string, rangeStart, rangeEnd time.Time) ([]DigestSessionRow, error) {
	const maxRows = 40
	var out []DigestSessionRow
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT cs.cloud_session_id, r.created_at, r.result, cs.metrics
			   FROM analysis_results r
			   JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
			   JOIN cloud_sessions cs ON cs.account_id = r.account_id AND cs.id = j.session_pk
			  WHERE r.account_id = $1::uuid AND cs.project_pk = $2::uuid
			    AND r.kind = $3 AND r.superseded = false
			    AND r.created_at >= $4 AND r.created_at < $5
			  ORDER BY r.created_at DESC
			  LIMIT $6`,
			accountID, projectPK, ResultKindSessionEnrichment, rangeStart, rangeEnd, maxRows)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var d DigestSessionRow
			var resultRaw, metricsRaw []byte
			if e := rows.Scan(&d.CloudSessionID, &d.CreatedAt, &resultRaw, &metricsRaw); e != nil {
				return e
			}
			var res struct {
				Title        string   `json:"title"`
				Description  string   `json:"description"`
				TaxonomyTags []string `json:"taxonomy_tags"`
				Limitations  []string `json:"limitations"`
			}
			_ = json.Unmarshal(resultRaw, &res)
			d.Title, d.Description = res.Title, res.Description
			d.TaxonomyTags, d.Limitations = res.TaxonomyTags, res.Limitations
			if len(metricsRaw) > 0 {
				var m map[string]any
				if json.Unmarshal(metricsRaw, &m) == nil {
					d.Metrics = m
				}
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.LoadProjectDigestEvidence: %w", err)
	}
	return out, nil
}

// ProjectDigestSummary is one project's LATEST project_digest result — the
// portal Overview "Project digests" section reads a list of these.
type ProjectDigestSummary struct {
	CloudProjectID string
	PeriodStart    string
	PeriodEnd      string
	CreatedAt      time.Time
	Headline       string
	Themes         []string
}

// ListLatestProjectDigests returns the account's latest project_digest result
// per project (newest period first), for the portal Overview page. A digest
// is never marked superseded (D21's supersede path groups by session_pk,
// which is NULL on a digest job), so "latest" is simply the newest created_at
// per project. Tenant-scoped (RLS).
func (s *Store) ListLatestProjectDigests(ctx context.Context, accountID string) ([]ProjectDigestSummary, error) {
	var out []ProjectDigestSummary
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT DISTINCT ON (cp.cloud_project_id)
			        cp.cloud_project_id, r.period_start, r.period_end, r.created_at, r.result
			   FROM analysis_results r
			   JOIN cloud_projects cp ON cp.account_id = r.account_id AND cp.id = r.project_pk
			  WHERE r.account_id = $1::uuid AND r.kind = $2
			  ORDER BY cp.cloud_project_id, r.created_at DESC`,
			accountID, ResultKindProjectDigest)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var d ProjectDigestSummary
			var periodStart, periodEnd time.Time
			var raw []byte
			if e := rows.Scan(&d.CloudProjectID, &periodStart, &periodEnd, &d.CreatedAt, &raw); e != nil {
				return e
			}
			d.PeriodStart = periodStart.Format("2006-01-02")
			d.PeriodEnd = periodEnd.Format("2006-01-02")
			var res struct {
				Headline string   `json:"headline"`
				Themes   []string `json:"themes"`
			}
			_ = json.Unmarshal(raw, &res)
			d.Headline, d.Themes = res.Headline, res.Themes
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListLatestProjectDigests: %w", err)
	}
	return out, nil
}

// countDigestsThisWeekTx counts the account's project_digest results created
// within the ISO week (Mon-Sun UTC) containing now.
func countDigestsThisWeekTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) (int, error) {
	monday, nextMonday := WeekBoundsUTC(now)
	var n int
	e := tx.QueryRow(ctx,
		`SELECT count(*) FROM analysis_results
		  WHERE account_id = $1::uuid AND kind = $2
		    AND created_at >= $3 AND created_at < $4`,
		accountID, ResultKindProjectDigest, monday, nextMonday).Scan(&n)
	return n, e
}
