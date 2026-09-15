package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

func newStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	// Every store test gets a real file-backed deletion journal (W6d makes the
	// journal a hard dependency of the deletion path). A temp file per test.
	j, err := deletionjournal.NewFileJournal(filepath.Join(t.TempDir(), "deletion-journal.jsonl"))
	if err != nil {
		t.Fatalf("deletion journal: %v", err)
	}
	s.SetDeletionJournal(j)
	return s, pool
}

var subjCounter atomic.Int64

// makeAccount creates a fresh account via Exchange (the store does not verify
// the PoP signature — the API does — so a real minted nonce plus any keypair is
// enough to exercise account/device/token creation).
func makeAccount(t *testing.T, s *store.Store) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	nonce, err := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	subject := fmt.Sprintf("subject-%d", subjCounter.Add(1))
	res, err := s.Exchange(ctx, store.ExchangeInput{
		Provider: "dev", Subject: subject, PublicKey: pub, Label: "test-device",
		RawNonce: nonce, Now: now,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return res.AccountID
}

// setEntitlement writes an explicit per-account cap OVERRIDE (migration 0012:
// entitlements is the operator-grant escape hatch layered over the account's
// plan, and overrides_plan is what activates it). Tests use it to isolate one
// window by raising the others far out of the way.
func setEntitlement(t *testing.T, pool *pgxpool.Pool, accountID string, daily, monthly, concurrency int) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`UPDATE entitlements SET daily_cap=$2, monthly_cap=$3, concurrency_cap=$4, overrides_plan=true
		  WHERE account_id=$1::uuid AND feature='session_enrichment'`,
		accountID, daily, monthly, concurrency)
	if err != nil {
		t.Fatalf("setEntitlement: %v", err)
	}
}

func submitJob(t *testing.T, s *store.Store, accountID, canonicalKey, uploadDigest string, now time.Time) store.JobSubmission {
	t.Helper()
	sub, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: accountID, CloudProjectID: "proj-" + canonicalKey, CloudSessionID: "sess-" + canonicalKey,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: canonicalKey, UploadDigest: uploadDigest, ContentDigest: "sha256:content",
		BlobRef: "blob/" + canonicalKey, SizeBytes: 42, ConsentGeneration: 0, Now: now,
	})
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	return sub
}

func TestExchangeNonceAndIntrospect(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	// Replayed nonce is rejected.
	nonce, err := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	in := store.ExchangeInput{Provider: "dev", Subject: "alice", PublicKey: pub, RawNonce: nonce, Now: now}
	res, err := s.Exchange(ctx, in)
	if err != nil {
		t.Fatalf("first Exchange: %v", err)
	}
	if _, err := s.Exchange(ctx, in); !errors.Is(err, store.ErrNonceInvalid) {
		t.Fatalf("replayed nonce: got %v, want ErrNonceInvalid", err)
	}

	// Introspect the minted token.
	p, err := s.IntrospectToken(ctx, res.Token, now)
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !p.Valid || p.AccountID != res.AccountID || p.DeviceID != res.DeviceID {
		t.Fatalf("introspect mismatch: %+v vs %+v", p, res)
	}

	// Same subject re-exchanges to the SAME account.
	nonce2, _ := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	res2, err := s.Exchange(ctx, store.ExchangeInput{Provider: "dev", Subject: "alice", PublicKey: pub, RawNonce: nonce2, Now: now})
	if err != nil {
		t.Fatalf("second Exchange: %v", err)
	}
	if res2.AccountID != res.AccountID {
		t.Fatalf("same subject produced different accounts: %s vs %s", res2.AccountID, res.AccountID)
	}

	// Expired nonce is rejected.
	past := now.Add(-time.Hour)
	expNonce, _ := s.MintNonce(ctx, time.Minute, past) // expires at past+1m, already elapsed
	_, err = s.Exchange(ctx, store.ExchangeInput{Provider: "dev", Subject: "bob", PublicKey: pub, RawNonce: expNonce, Now: now})
	if !errors.Is(err, store.ErrNonceInvalid) {
		t.Fatalf("expired nonce: got %v, want ErrNonceInvalid", err)
	}

	// A revoked device cannot re-exchange.
	if err := s.RevokeDevice(ctx, res.AccountID, res.DeviceID, now); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	nonce3, _ := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	_, err = s.Exchange(ctx, store.ExchangeInput{Provider: "dev", Subject: "alice", PublicKey: pub, RawNonce: nonce3, Now: now})
	if !errors.Is(err, store.ErrDeviceRevoked) {
		t.Fatalf("revoked device re-exchange: got %v, want ErrDeviceRevoked", err)
	}

	// The prior token is now invalid (device revoked).
	p2, err := s.IntrospectToken(ctx, res.Token, now)
	if err != nil {
		t.Fatalf("IntrospectToken after revoke: %v", err)
	}
	if p2.Valid {
		t.Fatal("token still valid after device revoke")
	}
}

func TestRLSCrossAccountIsolation(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	a := makeAccount(t, s)
	b := makeAccount(t, s)

	// Each account's device listing is isolated.
	da, err := s.ListDevices(ctx, a)
	if err != nil {
		t.Fatalf("ListDevices(a): %v", err)
	}
	db, err := s.ListDevices(ctx, b)
	if err != nil {
		t.Fatalf("ListDevices(b): %v", err)
	}
	if len(da) != 1 || len(db) != 1 {
		t.Fatalf("expected 1 device each, got a=%d b=%d", len(da), len(db))
	}
	if da[0].ID == db[0].ID {
		t.Fatal("device ids collided across accounts")
	}

	// Under account A's context, a raw no-WHERE count over a tenant table must
	// see ONLY A's rows (RLS enforced, not a WHERE clause).
	var countA int
	if err := s.WithAccount(ctx, a, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_registrations`).Scan(&countA)
	}); err != nil {
		t.Fatalf("count under A: %v", err)
	}
	if countA != 1 {
		t.Fatalf("account A saw %d device rows (RLS leak); want 1", countA)
	}

	// Missing-context: WithSystem (no account GUC) sees NO tenant rows.
	var countSys int
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_registrations`).Scan(&countSys)
	}); err != nil {
		t.Fatalf("count under system: %v", err)
	}
	if countSys != 0 {
		t.Fatalf("missing-context saw %d rows; want 0 (deny)", countSys)
	}

	// A cannot revoke B's device (out-of-scope ≡ not found).
	if err := s.RevokeDevice(ctx, a, db[0].ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-account revoke: got %v, want ErrNotFound", err)
	}

	// The app role genuinely cannot bypass RLS.
	var isSuper, isBypass bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname='sbci_app'`).Scan(&isSuper, &isBypass); err != nil {
		t.Fatalf("read sbci_app attrs: %v", err)
	}
	if isSuper || isBypass {
		t.Fatalf("sbci_app must be neither superuser nor bypassrls; got super=%v bypass=%v", isSuper, isBypass)
	}
}

func TestReservationDailyCapRace(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	// Isolate the daily-cap test from monthly/concurrency/global by raising them.
	setEntitlement(t, pool, acct, 5, 100000, 100000)

	const goroutines = 16
	var wg sync.WaitGroup
	var ok, daily atomic.Int64
	now := time.Now()
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, store.ErrDailyLimit):
				daily.Add(1)
			default:
				t.Errorf("unexpected reserve error: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Fatalf("daily cap race: %d reservations succeeded, want exactly 5", ok.Load())
	}
	if daily.Load() != goroutines-5 {
		t.Fatalf("daily cap race: %d refused, want %d", daily.Load(), goroutines-5)
	}
}

func TestReservationSettleRelease(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 5, 100, 2)
	now := time.Now()

	r1, err := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 1 || snap.ConcurrencyUsed != 1 {
		t.Fatalf("after reserve: daily=%d concurrency=%d, want 1/1", snap.DailyUsed, snap.ConcurrencyUsed)
	}
	// Release refunds the user unit and the concurrency slot.
	if err := s.ReleaseReservation(ctx, acct, r1, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	snap, _ = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 0 || snap.ConcurrencyUsed != 0 {
		t.Fatalf("after release: daily=%d concurrency=%d, want 0/0", snap.DailyUsed, snap.ConcurrencyUsed)
	}
	// Release is idempotent.
	if err := s.ReleaseReservation(ctx, acct, r1, false); err != nil {
		t.Fatalf("release idempotent: %v", err)
	}

	// Settle keeps the user unit but frees concurrency.
	r2, _ := s.ReserveAllowance(ctx, acct, store.FeatureSessionEnrichment, now)
	if err := s.SettleReservation(ctx, acct, r2); err != nil {
		t.Fatalf("settle: %v", err)
	}
	snap, _ = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 1 || snap.ConcurrencyUsed != 0 {
		t.Fatalf("after settle: daily=%d concurrency=%d, want 1/0", snap.DailyUsed, snap.ConcurrencyUsed)
	}
}

func TestLeaseRaceAndExpiry(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 1000)
	t0 := time.Now()
	sub := submitJob(t, s, acct, "canon-lease-1", "sha256:upload1", t0)

	// Two workers race one job — exactly one wins.
	var got1, got2 *store.LeasedJob
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		got1, _ = s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, t0)
	}()
	go func() {
		defer wg.Done()
		got2, _ = s.LeaseNextJob(ctx, "w2", []string{store.FeatureSessionEnrichment}, time.Hour, t0)
	}()
	wg.Wait()

	winners := 0
	for _, g := range []*store.LeasedJob{got1, got2} {
		if g != nil {
			winners++
			if g.JobID != sub.JobID {
				t.Fatalf("leased wrong job: %s != %s", g.JobID, sub.JobID)
			}
		}
	}
	if winners != 1 {
		t.Fatalf("lease race: %d winners, want exactly 1", winners)
	}

	// While leased and unexpired, the job is invisible to a new lease.
	if lj, _ := s.LeaseNextJob(ctx, "w3", []string{store.FeatureSessionEnrichment}, time.Hour, t0.Add(time.Minute)); lj != nil {
		t.Fatalf("leased job should be invisible before expiry, got %s", lj.JobID)
	}

	// After the lease expires, the job is reclaimable.
	lj, err := s.LeaseNextJob(ctx, "w4", []string{store.FeatureSessionEnrichment}, time.Hour, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("lease after expiry: %v", err)
	}
	if lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("expired lease should requeue the job; got %v", lj)
	}
	if lj.Attempts != 2 {
		t.Fatalf("attempts should be 2 after re-lease, got %d", lj.Attempts)
	}
}

func TestJobIdempotency(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 1000)
	now := time.Now()

	sub1 := submitJob(t, s, acct, "canon-A", "sha256:uploadA", now)
	if sub1.Existing {
		t.Fatal("first submit reported existing")
	}
	sub2 := submitJob(t, s, acct, "canon-A", "sha256:uploadA", now)
	if !sub2.Existing || sub2.JobID != sub1.JobID {
		t.Fatalf("retry should return same job: existing=%v id=%s (orig %s)", sub2.Existing, sub2.JobID, sub1.JobID)
	}
	// No second user unit consumed.
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 1 {
		t.Fatalf("idempotent retry consumed extra unit: daily=%d, want 1", snap.DailyUsed)
	}
	// Different canonical key (e.g. different upload digest) ⇒ new job + unit.
	sub3 := submitJob(t, s, acct, "canon-B", "sha256:uploadB", now)
	if sub3.Existing || sub3.JobID == sub1.JobID {
		t.Fatalf("different key should create a new job")
	}
	snap, _ = s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 2 {
		t.Fatalf("second distinct job: daily=%d, want 2", snap.DailyUsed)
	}
}

func TestJobIdempotencyConcurrent(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 1000)
	now := time.Now()

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sub, err := s.SubmitJob(ctx, store.SubmitJobInput{
				AccountID: acct, CloudProjectID: "p", CloudSessionID: "sconc",
				Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
				RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
				CanonicalKey: "canon-conc", UploadDigest: "sha256:conc", ContentDigest: "sha256:c",
				BlobRef: "b", SizeBytes: 1, Now: now,
			})
			if err != nil {
				t.Errorf("concurrent submit: %v", err)
				return
			}
			ids[i] = sub.JobID
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("concurrent submits produced different jobs: %s != %s", ids[i], ids[0])
		}
	}
	// Exactly one user unit consumed despite the race.
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 1 {
		t.Fatalf("concurrent idempotent submits consumed daily=%d, want 1", snap.DailyUsed)
	}
}

func TestEvidenceTTLImmutableAndTerminalDelete(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	setEntitlement(t, pool, acct, 100, 1000, 1000)
	now := time.Now()
	sub := submitJob(t, s, acct, "canon-ttl", "sha256:ttl", now)

	// Find the evidence pk for the job and prove expires_at cannot be extended.
	var evidencePK string
	var expiresAt time.Time
	if err := s.WithAccount(ctx, acct, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT e.id::text, e.expires_at FROM evidence_objects e
			   JOIN analysis_jobs j ON j.evidence_pk = e.id
			  WHERE j.id = $1::uuid`, sub.JobID).Scan(&evidencePK, &expiresAt)
	}); err != nil {
		t.Fatalf("find evidence: %v", err)
	}
	if expiresAt.Sub(now) < 59*time.Minute || expiresAt.Sub(now) > 61*time.Minute {
		t.Fatalf("expires_at not ~1h from creation: %v", expiresAt.Sub(now))
	}
	err := s.WithAccount(ctx, acct, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE evidence_objects SET expires_at = expires_at + interval '1 hour' WHERE id = $1::uuid`, evidencePK)
		return e
	})
	if err == nil {
		t.Fatal("expected the immutability trigger to reject extending expires_at")
	}

	// Parking the job deletes its evidence and releases the reservation.
	if err := s.ParkJob(ctx, acct, sub.JobID, store.ReasonProviderPolicyUnverified, now); err != nil {
		t.Fatalf("ParkJob: %v", err)
	}
	eo, err := s.GetEvidence(ctx, acct, evidencePK)
	if err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	if eo.DeletedAt == nil {
		t.Fatal("evidence should be deleted after terminal park")
	}
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 0 {
		t.Fatalf("park should refund the user unit: daily=%d, want 0", snap.DailyUsed)
	}
	j, _ := s.GetJob(ctx, acct, sub.JobID)
	if j.State != "parked" || j.TerminalReason != store.ReasonProviderPolicyUnverified {
		t.Fatalf("job not parked correctly: %+v", j)
	}
}

func TestConsentGeneration(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()

	st0, _ := s.CurrentConsent(ctx, acct)
	g1, err := s.SetConsent(ctx, acct, []string{"structural_activity_insights"}, now)
	if err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	if g1 <= st0.Generation {
		t.Fatalf("generation did not advance: %d <= %d", g1, st0.Generation)
	}
	st1, _ := s.CurrentConsent(ctx, acct)
	if len(st1.Purposes) != 1 || st1.Purposes[0] != "structural_activity_insights" {
		t.Fatalf("current purposes wrong: %v", st1.Purposes)
	}

	rid, g2, err := s.RecordPreviewConfirmation(ctx, acct, store.PreviewConfirmationInput{
		Purposes: []string{"bounded_context_enrichment"}, FieldClasses: []string{"content_excerpts"},
		EvidenceSchema: "session-evidence.v1-candidate", ScrubberVersion: "v1",
		UploadDigest: "sha256:preview", Now: now,
	})
	if err != nil {
		t.Fatalf("RecordPreviewConfirmation: %v", err)
	}
	if g2 <= g1 || rid == "" {
		t.Fatalf("preview confirmation should bump generation and return a receipt: g2=%d g1=%d rid=%q", g2, g1, rid)
	}
	gotRid, purposes, gen, err := s.ReceiptForDigest(ctx, acct, "sha256:preview")
	if err != nil {
		t.Fatalf("ReceiptForDigest: %v", err)
	}
	if gotRid != rid || gen != g2 || len(purposes) != 1 {
		t.Fatalf("receipt lookup mismatch: rid=%s gen=%d purposes=%v", gotRid, gen, purposes)
	}
}

// TestDeletionPurgesResultText proves the W6d deletion-completion pass: account
// deletion PURGES every attributable result row (title/description/tags gone,
// row gone), flips the request to 'done', and pseudonymizes the account. It
// also proves a re-run is idempotent (nothing left to purge).
func TestDeletionPurgesResultText(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	now := time.Now()

	// A submitted job gives us a valid FK target for the result row.
	sub := submitJob(t, s, acct, "cjk:tomb", "sha256:tomb", now)

	// Insert a result directly (admin pool bypasses RLS) carrying attributable
	// enrichment text.
	if _, err := pool.Exec(ctx,
		`INSERT INTO analysis_results (account_id, job_id, result, schema_version, ai_source, account_seq, tokens_in)
		 VALUES ($1::uuid, $2::uuid, $3::jsonb, 'v1', true, 1, 123)`,
		acct, sub.JobID,
		`{"title":"secret-title","description":"secret-desc","tags":["alpha","beta"]}`); err != nil {
		t.Fatalf("insert result: %v", err)
	}

	dr, err := s.CreateDeletionRequest(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if dr.State != "done" {
		t.Fatalf("state=%q, want done", dr.State)
	}
	if dr.PurgedRows < 1 {
		t.Fatalf("PurgedRows=%d, want >=1", dr.PurgedRows)
	}

	// The result row is GONE — not tombstoned, purged.
	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM analysis_results WHERE account_id=$1::uuid`,
		acct).Scan(&remaining); err != nil {
		t.Fatalf("count results: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("analysis_results survived deletion: %d rows", remaining)
	}

	// The account is pseudonymized: status='deleted', consent_generation NULL.
	var status string
	var gen *int64
	if err := pool.QueryRow(ctx,
		`SELECT status, consent_generation FROM accounts WHERE account_id=$1::uuid`,
		acct).Scan(&status, &gen); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if status != "deleted" {
		t.Fatalf("account status=%q, want deleted", status)
	}
	if gen != nil {
		t.Fatalf("consent_generation=%v, want NULL (reserved non-authorizing state)", *gen)
	}

	// Idempotent: a second deletion purges nothing further.
	dr2, err := s.CreateDeletionRequest(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequest (2nd): %v", err)
	}
	if dr2.PurgedRows != 0 {
		t.Fatalf("2nd PurgedRows=%d, want 0 (idempotent)", dr2.PurgedRows)
	}
}

// TestWithSystemClearsHostileTenantGUC proves FB2: a system transaction clears
// any pre-existing session-level sbci.account_id on a pooled connection and
// asserts no tenant is in scope, so a DSN options=-c sbci.account_id=<victim>
// or a leftover session-level set_config cannot make WithSystem read a victim
// tenant's RLS rows. A dedicated single-connection pool makes the poison
// deterministically land on the connection WithSystem reuses.
func TestWithSystemClearsHostileTenantGUC(t *testing.T) {
	base := cloudtestpg.NewDB(t)
	cfg := base.Config().Copy()
	cfg.MaxConns = 1
	ctx := context.Background()
	single, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("single-conn pool: %v", err)
	}
	defer single.Close()
	s := store.New(single)

	// Poison the one pooled connection with a SESSION-level tenant GUC.
	victim := "00000000-0000-0000-0000-000000000001"
	if _, err := single.Exec(ctx, `SET sbci.account_id = '`+victim+`'`); err != nil {
		t.Fatalf("poison GUC: %v", err)
	}

	var noTenant bool
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_current_account() IS NULL`).Scan(&noTenant)
	}); err != nil {
		t.Fatalf("WithSystem: %v", err)
	}
	if !noTenant {
		t.Fatal("WithSystem did not clear a hostile session-level sbci.account_id (FB2)")
	}
}

// TestSweepExpiredPoPReplay proves the FC3 sweep bounds the replay cache:
// expired jti rows are deleted purely by expires_at while live ones remain.
func TestSweepExpiredPoPReplay(t *testing.T) {
	s, pool := newStore(t)
	acct := makeAccount(t, s)
	ctx := context.Background()
	now := time.Now()

	if _, err := s.RecordJTI(ctx, acct, "expiredjti0123456789ab", now.Add(-time.Hour), now); err != nil {
		t.Fatalf("RecordJTI expired: %v", err)
	}
	if _, err := s.RecordJTI(ctx, acct, "livejti0123456789abcde", now.Add(time.Hour), now); err != nil {
		t.Fatalf("RecordJTI live: %v", err)
	}

	deleted, err := s.SweepExpiredPoPReplay(ctx, now)
	if err != nil {
		t.Fatalf("SweepExpiredPoPReplay: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("swept %d rows, want 1", deleted)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pop_replay`).Scan(&remaining); err != nil {
		t.Fatalf("count pop_replay: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining pop_replay=%d, want 1 (only the live jti)", remaining)
	}
}
