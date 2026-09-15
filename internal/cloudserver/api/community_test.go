package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// community_test.go covers the W5 own-percentile READ endpoint
// (GET /v1/community/percentile): the materialized-band read, the caller's own
// placement, and the forbidden-metric / unknown-cohort validation.

const (
	cMetric = "sessions_per_active_day"
	cWindow = "2025-01" // long-elapsed → finalized
)

// seedCohortAndContribution inserts n other accounts' contributions plus the
// caller's own value, then materializes the window (worker path). Direct pool
// inserts (superuser) stand in for the not-yet-built upload path.
func seedCohortAndContribution(t *testing.T, pool *pgxpool.Pool, ownAccount string, ownValue float64) {
	t.Helper()
	ctx := context.Background()
	// cWindow is a finalized (past) window — frozen against writes by the F5
	// trigger. Seed inside one transaction with session_replication_role=replica
	// (trigger-bypassing) to simulate contributions made while the window was in
	// progress, which later finalized (what the aggregation reads).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin seed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("bypass trigger: %v", err)
	}
	// 30 other accounts, split across two bands so the histogram is non-trivial.
	if _, err := tx.Exec(ctx, `
		WITH a AS (INSERT INTO accounts(account_id) SELECT gen_random_uuid() FROM generate_series(1,15) RETURNING account_id)
		INSERT INTO leaderboard_contributions(account_id,cohort_key,metric_id,metric_version,window_id,value)
		SELECT account_id,'global',$1,1,$2,0.5 FROM a`, cMetric, cWindow); err != nil {
		t.Fatalf("seed band0: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		WITH a AS (INSERT INTO accounts(account_id) SELECT gen_random_uuid() FROM generate_series(1,15) RETURNING account_id)
		INSERT INTO leaderboard_contributions(account_id,cohort_key,metric_id,metric_version,window_id,value)
		SELECT account_id,'global',$1,1,$2,6 FROM a`, cMetric, cWindow); err != nil {
		t.Fatalf("seed band4: %v", err)
	}
	// The caller's own contribution.
	if _, err := tx.Exec(ctx,
		`INSERT INTO leaderboard_contributions(account_id,cohort_key,metric_id,metric_version,window_id,value)
		 VALUES ($1::uuid,'global',$2,1,$3,$4)`, ownAccount, cMetric, cWindow, ownValue); err != nil {
		t.Fatalf("seed own: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit seed: %v", err)
	}
}

func TestCommunityPercentileEndpoint(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "carol")
	ctx := context.Background()

	seedCohortAndContribution(t, h.store.Pool(), c.accountID, 6) // own value 6 → band 4
	if _, err := h.store.MaterializeCommunityWindow(ctx, "global", cMetric, 1, cWindow); err != nil {
		t.Fatalf("materialize: %v", err)
	}

	resp := c.do(c.signedReq("GET", "/v1/community/percentile?metric="+cMetric+"&version=1&cohort=global&window="+cWindow, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("percentile status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var view struct {
		CohortSize int64 `json:"cohort_size"`
		Bands      []struct {
			Band  int   `json:"band"`
			Count int64 `json:"count"`
		} `json:"bands"`
		Own struct {
			Contributed bool     `json:"contributed"`
			Value       *float64 `json:"value"`
			Band        *int     `json:"band"`
		} `json:"own"`
	}
	decode(t, resp, &view)
	if view.CohortSize != 31 { // 30 others + the caller
		t.Errorf("cohort_size = %d, want 31", view.CohortSize)
	}
	if len(view.Bands) == 0 {
		t.Fatalf("no bands returned")
	}
	if !view.Own.Contributed || view.Own.Band == nil || *view.Own.Band != 4 {
		t.Errorf("own placement wrong: contributed=%v band=%v (want band 4)", view.Own.Contributed, view.Own.Band)
	}
}

func TestCommunityPercentileRejectsForbiddenMetric(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "dave")

	resp := c.do(c.signedReq("GET", "/v1/community/percentile?metric=made_up&version=1&cohort=global&window="+cWindow, nil))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forbidden metric status=%d, want 400 (body=%s)", resp.StatusCode, readAll(resp))
	}

	resp = c.do(c.signedReq("GET", "/v1/community/percentile?metric="+cMetric+"&version=1&cohort=not-a-cohort&window="+cWindow, nil))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown cohort status=%d, want 400 (body=%s)", resp.StatusCode, readAll(resp))
	}
}

func TestCommunityPercentileOwnAbsentWhenNoContribution(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "erin")
	ctx := context.Background()

	// Seed a cohort of OTHERS only (caller did not contribute). Finalized window
	// ⇒ bypass the freeze trigger for the historical seed.
	tx, err := h.store.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("bypass: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		WITH a AS (INSERT INTO accounts(account_id) SELECT gen_random_uuid() FROM generate_series(1,30) RETURNING account_id)
		INSERT INTO leaderboard_contributions(account_id,cohort_key,metric_id,metric_version,window_id,value)
		SELECT account_id,'global',$1,1,$2,6 FROM a`, cMetric, cWindow); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := h.store.MaterializeCommunityWindow(ctx, "global", cMetric, 1, cWindow); err != nil {
		t.Fatalf("materialize: %v", err)
	}

	resp := c.do(c.signedReq("GET", "/v1/community/percentile?metric="+cMetric+"&version=1&cohort=global&window="+cWindow, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var view struct {
		Own struct {
			Contributed bool `json:"contributed"`
		} `json:"own"`
	}
	decode(t, resp, &view)
	if view.Own.Contributed {
		t.Error("own.contributed should be false when the caller never contributed")
	}
}
