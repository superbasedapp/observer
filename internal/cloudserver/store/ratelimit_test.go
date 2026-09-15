package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

func TestAllowRateLimitAtomicConcurrency(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("NewForRole(api): %v", err)
	}

	const (
		limit = 25
		total = 64
	)
	ctx := context.Background()
	var wg sync.WaitGroup
	var allowed atomic.Int64
	var denied atomic.Int64
	errCh := make(chan error, total)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			gotAllowed, retryAfter, callErr := s.AllowRateLimit(ctx, "atomic", "same-key", limit, time.Minute)
			if callErr != nil {
				errCh <- callErr
				return
			}
			if gotAllowed {
				allowed.Add(1)
				return
			}
			if retryAfter <= 0 {
				errCh <- errors.New("denied decision has no positive RetryAfter")
				return
			}
			denied.Add(1)
		}()
	}
	wg.Wait()
	close(errCh)
	for callErr := range errCh {
		t.Errorf("concurrent AllowRateLimit: %v", callErr)
	}
	if got := allowed.Load(); got != limit {
		t.Fatalf("allowed=%d, want exactly %d", got, limit)
	}
	if got := denied.Load(); got != total-limit {
		t.Fatalf("denied=%d, want %d", got, total-limit)
	}

	var hitCount int64
	if err := pool.QueryRow(ctx,
		`SELECT hit_count FROM sbci_rate_limit_counters
		  WHERE bucket='atomic' AND counter_key_hash=$1`, testRateLimitKeyHash("atomic", "same-key")).Scan(&hitCount); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if hitCount != limit+1 {
		t.Fatalf("stored hit_count=%d, want %d (one over-cap marker)", hitCount, limit+1)
	}
}

func TestAllowRateLimitBucketsAndKeysAreIndependent(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("NewForRole(api): %v", err)
	}
	ctx := context.Background()

	firstAllowed, firstRetry, err := s.AllowRateLimit(ctx, "bucket-a", "key-a", 1, time.Minute)
	if err != nil || !firstAllowed || firstRetry != 0 {
		t.Fatalf("first bucket-a hit: allowed=%v retry=%v err=%v", firstAllowed, firstRetry, err)
	}
	secondAllowed, secondRetry, err := s.AllowRateLimit(ctx, "bucket-a", "key-a", 1, time.Minute)
	if err != nil || secondAllowed || secondRetry <= 0 {
		t.Fatalf("second bucket-a hit: allowed=%v retry=%v err=%v", secondAllowed, secondRetry, err)
	}
	otherBucketAllowed, otherBucketRetry, err := s.AllowRateLimit(ctx, "bucket-b", "key-a", 1, time.Minute)
	if err != nil || !otherBucketAllowed || otherBucketRetry != 0 {
		t.Fatalf("independent bucket hit: allowed=%v retry=%v err=%v", otherBucketAllowed, otherBucketRetry, err)
	}
	otherKeyAllowed, otherKeyRetry, err := s.AllowRateLimit(ctx, "bucket-a", "key-b", 1, time.Minute)
	if err != nil || !otherKeyAllowed || otherKeyRetry != 0 {
		t.Fatalf("independent key hit: allowed=%v retry=%v err=%v", otherKeyAllowed, otherKeyRetry, err)
	}
}

func callRateLimitAt(t *testing.T, pool *pgxpool.Pool, bucket, key string, limit int, windowMS int64, now time.Time) (bool, int64) {
	t.Helper()
	var allowed bool
	var retryMS int64
	if err := pool.QueryRow(context.Background(),
		`SELECT allowed, retry_after_ms
		   FROM sbci_rate_limit_at($1, $2, $3, $4, $5)`,
		bucket, testRateLimitKeyHash(bucket, key), limit, windowMS, now.UTC()).Scan(&allowed, &retryMS); err != nil {
		t.Fatalf("sbci_rate_limit at %s: %v", now, err)
	}
	return allowed, retryMS
}

// callRateLimitAtWithCount performs one admission and then reads the resulting
// counter row. The two must be SEPARATE statements: sbci_rate_limit_at is
// VOLATILE, so its counter write is not reliably visible to a sibling table
// scan JOINed against it in the same statement (the planner may scan the table
// before the function has run, yielding an intermittent "no rows in result
// set"). We run the function first to capture the decision, then read
// hit_count/over_cap for the same bucket/key/window in a second statement.
func callRateLimitAtWithCount(t *testing.T, pool *pgxpool.Pool, bucket, key string, limit int, windowMS int64, now time.Time) (bool, int64, int64, bool) {
	t.Helper()
	ctx := context.Background()
	keyHash := testRateLimitKeyHash(bucket, key)

	var allowed bool
	var retryMS int64
	if err := pool.QueryRow(ctx,
		`SELECT allowed, retry_after_ms
		   FROM sbci_rate_limit_at($1, $2, $3, $4, $5)`,
		bucket, keyHash, limit, windowMS, now.UTC()).Scan(&allowed, &retryMS); err != nil {
		t.Fatalf("sbci_rate_limit_at at %s: %v", now, err)
	}

	var hitCount int64
	var overCap bool
	if err := pool.QueryRow(ctx,
		`SELECT hit_count, over_cap
		   FROM sbci_rate_limit_counters
		  WHERE bucket = $1
		    AND counter_key_hash = $2
		    AND window_start = to_timestamp((
				floor(extract(epoch FROM $3::timestamptz) * 1000.0 / $4)
				* $4 / 1000.0
			)::double precision)`,
		bucket, keyHash, now.UTC(), windowMS).Scan(&hitCount, &overCap); err != nil {
		t.Fatalf("read rate-limit counter at %s: %v", now, err)
	}
	return allowed, retryMS, hitCount, overCap
}

func testRateLimitKeyHash(bucket, key string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("sbci-rate-limit-key/v1\x00"))
	_, _ = h.Write([]byte(bucket))
	_, _ = h.Write([]byte{'\x00'})
	_, _ = h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

func TestRateLimitWindowBoundaryIsDeterministic(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	// This is exactly on a Unix second boundary, so a one-second window starts
	// at t0 and the request at t0+1s must belong to the next window.
	t0 := time.Unix(1_700_000_000, 0).UTC()
	if allowed, retry := callRateLimitAt(t, pool, "boundary", "key", 1, 1000, t0); !allowed || retry != 0 {
		t.Fatalf("first boundary hit: allowed=%v retry=%d", allowed, retry)
	}
	if allowed, retry := callRateLimitAt(t, pool, "boundary", "key", 1, 1000, t0); allowed || retry <= 0 {
		t.Fatalf("second hit in same window: allowed=%v retry=%d", allowed, retry)
	}
	if allowed, retry := callRateLimitAt(t, pool, "boundary", "key", 1, 1000, t0.Add(999*time.Millisecond)); allowed || retry <= 0 {
		t.Fatalf("hit immediately before boundary: allowed=%v retry=%d", allowed, retry)
	}
	if allowed, retry := callRateLimitAt(t, pool, "boundary", "key", 1, 1000, t0.Add(time.Second)); !allowed || retry != 0 {
		t.Fatalf("hit exactly at next boundary: allowed=%v retry=%d", allowed, retry)
	}
}

func TestRateLimitRaisedLimitRecoversExactHeadroom(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	t0 := time.Unix(1_700_000_000, 0).UTC()

	// Ratified invariant (see 0017_rate_limits.sql): a "limit N" window admits
	// EXACTLY N requests; hit_count while over_cap=false is the admitted count
	// (first admitted request => 1); the first denial stores marker N+1 with
	// over_cap=true; a raise N->M restores the admitted count to marker-1 and
	// then admits, so the full sequence for limit 2 then a raise to 4 is:
	//   1(allow) 2(allow) 3/deny/marker 3/deny/marker | raise-> 3(allow) 4(allow) 5/deny/marker
	//
	// Limit two: two hits are admitted, and the first denial leaves one
	// explicit marker without allowing the counter to grow on later denials.
	if allowed, _, _, _ := callRateLimitAtWithCount(t, pool, "raise", "key", 2, 60_000, t0); !allowed {
		t.Fatal("first hit: want allowed")
	}
	if allowed, _, _, _ := callRateLimitAtWithCount(t, pool, "raise", "key", 2, 60_000, t0.Add(time.Millisecond)); !allowed {
		t.Fatal("second hit: want allowed")
	}
	if allowed, _, count, marker := callRateLimitAtWithCount(t, pool, "raise", "key", 2, 60_000, t0.Add(2*time.Millisecond)); allowed || count != 3 || !marker {
		t.Fatalf("first denial: allowed=%v count=%d marker=%v; want false/3/true", allowed, count, marker)
	}
	if allowed, _, count, marker := callRateLimitAtWithCount(t, pool, "raise", "key", 2, 60_000, t0.Add(3*time.Millisecond)); allowed || count != 3 || !marker {
		t.Fatalf("repeat denial: allowed=%v count=%d marker=%v; want false/3/true", allowed, count, marker)
	}

	// Raising two→four must admit exactly two requests. The marker's old
	// denied attempt must not consume one of those two new slots: the first
	// post-raise request restores the admitted count to marker-1 (=2) and then
	// admits as count 3, and the second admits as count 4.
	if allowed, retry, count, marker := callRateLimitAtWithCount(t, pool, "raise", "key", 4, 60_000, t0.Add(4*time.Millisecond)); !allowed || retry != 0 || count != 3 || marker {
		t.Fatalf("first raised hit: allowed=%v retry=%d count=%d marker=%v; want true/0/3/false", allowed, retry, count, marker)
	}
	if allowed, retry, count, marker := callRateLimitAtWithCount(t, pool, "raise", "key", 4, 60_000, t0.Add(5*time.Millisecond)); !allowed || retry != 0 || count != 4 || marker {
		t.Fatalf("second raised hit: allowed=%v retry=%d count=%d marker=%v; want true/0/4/false", allowed, retry, count, marker)
	}
	if allowed, _, count, marker := callRateLimitAtWithCount(t, pool, "raise", "key", 4, 60_000, t0.Add(6*time.Millisecond)); allowed || count != 5 || !marker {
		t.Fatalf("post-raise denial: allowed=%v count=%d marker=%v; want false/5/true", allowed, count, marker)
	}
}

func TestRateLimitExpirySweepRemovesAbandonedKeys(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	t0 := time.Unix(1_700_000_000, 0).UTC()
	if allowed, _ := callRateLimitAt(t, pool, "abandoned", "one-off", 1, 1000, t0); !allowed {
		t.Fatal("initial abandoned-key hit was denied")
	}

	// The abandoned row is not touched by another call for its key. A later
	// request for a different key drives the bounded global expiry sweep.
	if allowed, _ := callRateLimitAt(t, pool, "active", "new-key", 1, 1000, t0.Add(2*time.Hour)); !allowed {
		t.Fatal("active-key hit was denied")
	}
	var abandonedRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sbci_rate_limit_counters
		  WHERE bucket='abandoned' AND counter_key_hash=$1`,
		testRateLimitKeyHash("abandoned", "one-off")).Scan(&abandonedRows); err != nil {
		t.Fatalf("count abandoned counter: %v", err)
	}
	if abandonedRows != 0 {
		t.Fatalf("abandoned counter survived expiry sweep: %d rows", abandonedRows)
	}
}

func TestAllowRateLimitDisabledAndInvalidInputs(t *testing.T) {
	// Disabled dimensions must not touch the pool. This also pins the no-I/O
	// behavior by using a Store with no pool at all.
	noPool := store.New(nil)
	allowed, retryAfter, err := noPool.AllowRateLimit(context.Background(), "", "", 0, 0)
	if err != nil || !allowed || retryAfter != 0 {
		t.Fatalf("disabled limiter: allowed=%v retry=%v err=%v", allowed, retryAfter, err)
	}

	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	for _, tc := range []struct {
		name   string
		bucket string
		key    string
		window time.Duration
	}{
		{name: "empty bucket", bucket: "", key: "key", window: time.Second},
		{name: "empty key", bucket: "bucket", key: "", window: time.Second},
		{name: "zero window", bucket: "bucket", key: "key", window: 0},
		{name: "sub-millisecond window", bucket: "bucket", key: "key", window: time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotAllowed, gotRetry, callErr := s.AllowRateLimit(context.Background(), tc.bucket, tc.key, 1, tc.window)
			if !errors.Is(callErr, store.ErrInvalidRateLimit) {
				t.Fatalf("allowed=%v retry=%v err=%v, want ErrInvalidRateLimit", gotAllowed, gotRetry, callErr)
			}
			if gotAllowed || gotRetry != 0 {
				t.Fatalf("invalid limiter returned usable decision: allowed=%v retry=%v", gotAllowed, gotRetry)
			}
		})
	}
}

// TestRateLimitRolePrivilegesAndFailureClosed pins the two-function callable
// surface of migration 0017:
//   - the 4-arg wrapper sbci_rate_limit(text,text,integer,bigint) is executable
//     by sbci_api and sbci_app only (server clock authoritative);
//   - the 5-arg deterministic helper sbci_rate_limit_at(...,timestamptz) is
//     ungranted to every application role AND to PUBLIC;
//   - neither api nor worker can read or mutate the counter table directly;
//   - both functions are SECURITY DEFINER, owned by sbci_defs, with a pinned
//     search_path; and a direct helper call under api/worker roles is denied.
func TestRateLimitRolePrivilegesAndFailureClosed(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	const (
		wrapperSig = "sbci_rate_limit(text, text, integer, bigint)"
		helperSig  = "sbci_rate_limit_at(text, text, integer, bigint, timestamp with time zone)"
	)

	// The 4-arg wrapper: api and app may EXECUTE; worker and aggregator may not.
	for _, role := range []string{"sbci_api", "sbci_app"} {
		if !funcPriv(t, pool, role, wrapperSig) {
			t.Errorf("%s is MISSING EXECUTE on the 4-arg sbci_rate_limit wrapper", role)
		}
	}
	for _, role := range []string{"sbci_worker", "sbci_aggregator"} {
		if funcPriv(t, pool, role, wrapperSig) {
			t.Errorf("%s holds EXECUTE on the 4-arg sbci_rate_limit wrapper; the limiter is api/app-only", role)
		}
	}

	// The 5-arg deterministic helper: no application role may EXECUTE it.
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_worker", "sbci_aggregator"} {
		if funcPriv(t, pool, role, helperSig) {
			t.Errorf("%s holds EXECUTE on the 5-arg sbci_rate_limit_at helper; it must be admin-only", role)
		}
	}
	// ...and PUBLIC must not hold EXECUTE on the helper either. A grantee=0 row
	// in aclexplode is the PUBLIC grant; after REVOKE ... FROM PUBLIC there is
	// none. (has_function_privilege cannot be asked about PUBLIC directly.)
	if publicHasExecute(t, pool, helperSig) {
		t.Error("PUBLIC holds EXECUTE on the 5-arg sbci_rate_limit_at helper")
	}
	// The wrapper was also REVOKEd from PUBLIC (only api/app were re-granted).
	if publicHasExecute(t, pool, wrapperSig) {
		t.Error("PUBLIC holds EXECUTE on the 4-arg sbci_rate_limit wrapper")
	}

	// Neither api nor worker may touch the counter table by ANY DML verb.
	for _, role := range []string{"sbci_api", "sbci_worker"} {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if tablePriv(t, pool, role, "sbci_rate_limit_counters", priv) {
				t.Errorf("%s holds direct %s on sbci_rate_limit_counters; only the SECURITY DEFINER owner may", role, priv)
			}
		}
	}

	// Both functions must be SECURITY DEFINER, owned by sbci_defs, with a safe
	// pinned search_path so the definer's privileges never resolve an
	// attacker-shadowed object.
	for _, sig := range []string{wrapperSig, helperSig} {
		var owner string
		var secDef bool
		var config []string
		if err := pool.QueryRow(ctx,
			`SELECT r.rolname, p.prosecdef, p.proconfig
			   FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
			  WHERE p.oid = $1::regprocedure`, sig).Scan(&owner, &secDef, &config); err != nil {
			t.Fatalf("introspect %s: %v", sig, err)
		}
		if owner != "sbci_defs" {
			t.Errorf("%s owner = %q, want sbci_defs", sig, owner)
		}
		if !secDef {
			t.Errorf("%s is not SECURITY DEFINER (prosecdef=false)", sig)
		}
		if !containsConfig(config, "search_path=pg_catalog, public") {
			t.Errorf("%s proconfig = %v, want a pinned search_path=pg_catalog, public", sig, config)
		}
	}

	// A direct call to the deterministic helper under api/worker must be DENIED
	// (permission error), even though those roles route real traffic through
	// the wrapper. This proves the REVOKE actually blocks execution rather than
	// merely reading as absent in the catalog.
	for _, role := range []string{"sbci_api", "sbci_worker"} {
		assertHelperCallDenied(t, pool, role)
	}

	// The store's worker-bound limiter path fails closed (permission error is a
	// database error, not a silent allow/deny decision).
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(worker): %v", err)
	}
	allowed, retryAfter, err := worker.AllowRateLimit(ctx, "worker", "must-fail", 1, time.Minute)
	if err == nil {
		t.Fatalf("worker limiter call unexpectedly succeeded: allowed=%v retry=%v", allowed, retryAfter)
	}
	if allowed || retryAfter != 0 {
		t.Fatalf("permission failure produced a usable decision: allowed=%v retry=%v", allowed, retryAfter)
	}
}

// publicHasExecute reports whether PUBLIC (aclexplode grantee 0) holds EXECUTE
// on the function named by signature.
func publicHasExecute(t *testing.T, pool *pgxpool.Pool, signature string) bool {
	t.Helper()
	var granted bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (
		   SELECT 1
		     FROM pg_proc p, aclexplode(p.proacl) a
		    WHERE p.oid = $1::regprocedure
		      AND a.grantee = 0
		      AND a.privilege_type = 'EXECUTE'
		 )`, signature).Scan(&granted); err != nil {
		t.Fatalf("public EXECUTE probe for %s: %v", signature, err)
	}
	return granted
}

// containsConfig reports whether proconfig contains the exact SET element want.
func containsConfig(config []string, want string) bool {
	for _, c := range config {
		if c == want {
			return true
		}
	}
	return false
}

// assertHelperCallDenied proves the 5-arg helper cannot be executed while the
// session assumes role. The call is made inside a tx with SET LOCAL ROLE and
// rolled back regardless.
func assertHelperCallDenied(t *testing.T, pool *pgxpool.Pool, role string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire (%s): %v", role, err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin (%s): %v", role, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
		t.Fatalf("set role %s: %v", role, err)
	}
	var allowed bool
	var retryMS int64
	err = tx.QueryRow(ctx,
		`SELECT allowed, retry_after_ms
		   FROM sbci_rate_limit_at($1, $2, $3, $4, $5)`,
		"deny", testRateLimitKeyHash("deny", role), 1, int64(60_000), time.Unix(1_700_000_000, 0).UTC()).Scan(&allowed, &retryMS)
	if err == nil {
		t.Fatalf("role %s executed the admin-only 5-arg helper directly; it must be denied", role)
	}
}

func TestAllowRateLimitDatabaseFailureIsSeparateFromDecision(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	pool.Close()
	allowed, retryAfter, err := s.AllowRateLimit(context.Background(), "failure", "key", 1, time.Minute)
	if err == nil {
		t.Fatalf("closed pool limiter unexpectedly succeeded: allowed=%v retry=%v", allowed, retryAfter)
	}
	if allowed || retryAfter != 0 {
		t.Fatalf("database failure produced a usable decision: allowed=%v retry=%v", allowed, retryAfter)
	}
}
