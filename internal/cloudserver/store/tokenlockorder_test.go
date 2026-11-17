package store_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// tokenlockorder_test.go pins the token-budget lock order on the live schema.
// A re-enrichment SUBMITTED while the worker CLOSES the previous job of the
// SAME session (a settle, or a release when the job parks or fails) used to
// take the session row first (ensureSessionTx's upsert) and the daily/monthly
// windows second, while the close took the windows first and the session row
// last: PostgreSQL broke the cycle with SQLSTATE 40P01. Every path now takes
// the canonical order session ledger -> token daily -> token monthly ->
// concurrency -> budget pool (reserve_tokens.go).

const lockOrderSession = "re-enriched"

// lockOrderActual is what a settled job of these tests books (100 in + 20 out).
const lockOrderActual = 120

func is40P01(err error) bool {
	var pge *pgconn.PgError
	return errors.As(err, &pge) && pge.Code == "40P01"
}

// lockOrderAccount is an account on a token plan whose budgets never refuse,
// with one job of lockOrderSession already queued.
func lockOrderAccount(t *testing.T, s *store.Store, pool *pgxpool.Pool) string {
	t.Helper()
	acct := makeAccount(t, s)
	publishTier(t, pool, enrichbudget.Tier{
		Name: "free", RouteID: gptOSS20b, EvidenceTokens: 4000,
		SessionTokens: 1_000_000_000, DailyTokens: 1_000_000_000, MonthlyTokens: 1_000_000_000,
	})
	if _, err := submitTokenJob(s, acct, "k0", lockOrderSession, 2000, time.Now()); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	return acct
}

// lockWaiters counts this test database's backends waiting on a lock.
func lockWaiters(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
		t.Fatalf("count lock waiters: %v", err)
	}
	return n
}

func waitForLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for lockWaiters(t, pool) < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d lock waiter(s)", want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// closeKind is how the worker closes the leased job: a settle (the job
// succeeded) or a release (the job failed and its hold is refunded).
type closeKind int

const (
	closeSettle closeKind = iota
	closeRelease
)

// booked is what one close of this kind leaves on the session ledger.
func (k closeKind) booked() int64 {
	if k == closeSettle {
		return lockOrderActual
	}
	return 0
}

func (k closeKind) run(ctx context.Context, s *store.Store, acct string, lj *store.LeasedJob, now time.Time) error {
	if k == closeRelease {
		return s.FailJob(ctx, acct, lj.JobID, store.ReasonProviderInvalidOutput, now)
	}
	_, settled, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID, "w1", lj.LeaseGeneration,
		"session_enrichment.v2-candidate", []byte(`{"title":"t","schema_version":"session_enrichment.v2-candidate"}`),
		store.ResultProvenance{ModelRouteID: luna, TokensIn: 100, TokensOut: 20}, now)
	if err == nil && !settled {
		return errors.New("the settle stored nothing")
	}
	return err
}

// raceCloseAndSubmit leases the queued job of lockOrderSession, then closes it
// while submitting the next re-enrichment of the same session (key). With
// pin, the interleaving that deadlocked the old order is forced: a third
// transaction holds the monthly window, the close is started first and parks
// on it, the submit is started second and parks, and only then is the
// monthly window released.
func raceCloseAndSubmit(t *testing.T, s *store.Store, pool *pgxpool.Pool, acct, key string, kind closeKind, pin bool) (closeErr, submitErr error) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("%s: lease: %v (%v)", key, err, lj)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("%s: mark running: %v", key, err)
	}

	release := func() {}
	if pin {
		hold, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin pin: %v", err)
		}
		if _, err := hold.Exec(ctx,
			`SELECT 1 FROM usage_token_windows
			  WHERE account_id = $1::uuid AND feature = $2 AND window_kind = 'monthly' AND window_key = $3 FOR UPDATE`,
			acct, store.FeatureSessionEnrichment, store.MonthlyWindowKey(now)); err != nil {
			t.Fatalf("pin monthly window: %v", err)
		}
		release = func() {
			if err := hold.Commit(ctx); err != nil {
				t.Errorf("release pin: %v", err)
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		closeErr = kind.run(ctx, s, acct, lj, now)
	}()
	if pin {
		waitForLockWaiters(t, pool, 1)
	}
	go func() {
		defer wg.Done()
		_, submitErr = submitTokenJob(s, acct, key, lockOrderSession, 2000, now)
	}()
	if pin {
		waitForLockWaiters(t, pool, 2)
	}
	release()
	wg.Wait()
	return closeErr, submitErr
}

func requireNoDeadlock(t *testing.T, round string, closeErr, submitErr error) {
	t.Helper()
	if is40P01(closeErr) || is40P01(submitErr) {
		t.Fatalf("%s: SQLSTATE 40P01 between a submit and a close on one session (close: %v, submit: %v)", round, closeErr, submitErr)
	}
	if closeErr != nil || submitErr != nil {
		t.Fatalf("%s: close %v, submit %v", round, closeErr, submitErr)
	}
}

// TestTokenSubmitVsCloseSameSessionPinnedInterleaving forces the exact
// interleaving that deadlocked, for a release and a settle: the close holds
// the daily window when the submit, already holding the session row, asks
// for it.
func TestTokenSubmitVsCloseSameSessionPinnedInterleaving(t *testing.T) {
	for _, kind := range []closeKind{closeRelease, closeSettle} {
		s, pool := newStore(t)
		acct := lockOrderAccount(t, s, pool)
		const rounds = 4
		for i := 1; i <= rounds; i++ {
			closeErr, submitErr := raceCloseAndSubmit(t, s, pool, acct, "pinned-"+strconv.Itoa(i), kind, true)
			requireNoDeadlock(t, "kind "+strconv.Itoa(int(kind))+" round "+strconv.Itoa(i), closeErr, submitErr)
		}
		if got, want := sessionLedger(t, pool, acct, lockOrderSession), rounds*kind.booked()+lunaHold(2000); got != want {
			t.Fatalf("kind %d: session ledger = %d, want %d (%d closes plus one open hold)", kind, got, want, rounds)
		}
	}
}

// TestTokenSubmitVsCloseSameSessionNoDeadlock races a close (alternating
// settle and release) and the next submit of the same session many times,
// unpinned, and requires no 40P01 and an exact session ledger at the end.
func TestTokenSubmitVsCloseSameSessionNoDeadlock(t *testing.T) {
	s, pool := newStore(t)
	acct := lockOrderAccount(t, s, pool)
	const iters = 60
	var want int64
	for i := 1; i <= iters; i++ {
		kind := closeKind(i % 2)
		closeErr, submitErr := raceCloseAndSubmit(t, s, pool, acct, "k"+strconv.Itoa(i), kind, false)
		requireNoDeadlock(t, "iteration "+strconv.Itoa(i), closeErr, submitErr)
		want += kind.booked()
	}
	// Every settled job booked its actual, every released one nothing; the
	// one still queued holds its worst case.
	if got := sessionLedger(t, pool, acct, lockOrderSession); got != want+lunaHold(2000) {
		t.Fatalf("session ledger after %d raced closes = %d, want %d", iters, got, want+lunaHold(2000))
	}
}
