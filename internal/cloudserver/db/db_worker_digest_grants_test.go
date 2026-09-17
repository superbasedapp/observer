package db_test

// db_worker_digest_grants_test.go pins the fix for the 2026-09-17 production
// defect: the worker process (`SET LOCAL ROLE sbci_worker`) running the
// weekly project-digest scheduler
// (internal/cloudserver/jobs/digest_scheduler.go ->
// store.ListProjectDigestCandidates -> store.LoadProjectDigestEvidence ->
// store.ResolveRouteForFeature -> store.SubmitDigestJob) failed with
// "permission denied for table cloud_sessions" (SQLSTATE 42501), plus eight
// further gaps on the SAME call path proven by the negative tests below — the
// last of them (cloud_projects, on the COMPLETION half of the worker's own
// lease) found by the 2026-09-17 adversarial review of this fix's first cut,
// which stopped at SubmitDigestJob.
// Migration 0040_worker_digest_grants.sql is the fix (see its header comment
// for the full root-cause account and the exact grant-to-code-site mapping).
//
// internal/cloudserver/db has no MigrateTo/target-version primitive — only
// Migrate (always applies the embedded lineage up to its head), Version, and
// MaxEmbeddedVersion (checked against db.go: no other exported entry point
// exists). So the "migrate to 0039 only" half of the requested negative proof
// cannot be driven through the real migrator without reimplementing a
// partial-migration runner here — which would exercise OUR OWN copy of the
// migration-application logic, a weaker proof than it looks, not the
// production Migrate path. Instead, TestWorkerDigestGrantsDeniedBefore0040
// migrates a fresh database to the FULL head (0040 included, via
// cloudtestpg.NewDB), then REVOKEs exactly the nine grants 0040 adds —
// reproducing sbci_worker's pre-0040 privilege state on these tables byte for
// byte, since 0040 is pure additive GRANTs with no schema change — proves the
// SQLSTATE 42501 denial, and then re-applies 0040's OWN embedded file text
// (not a hand-copied grant list) to prove the shipped migration file itself,
// not just "some grants", closes the gap.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// digestFixtureAccount mints a fresh account (via a real Exchange call, the
// same shape every other cloudserver store test uses), assigns it the
// plus_beta plan (digest_weekly=true — required for SubmitDigestJob's
// reserveDigestAllowanceTx to grant the entitlement at all, independent of
// the permission defect this file pins), and drives one session_enrichment
// job all the way to a completed result for cloud project "wdg-proj" — the
// evidence LoadProjectDigestEvidence reads back. Every write here runs
// through appStore (store.New(pool), the default sbci_app role), mirroring
// every existing digest_test.go / results_w6b_test.go seeding helper.
func digestFixtureAccount(t *testing.T, appStore *store.Store, pool *pgxpool.Pool, now time.Time) (accountID, cloudProjectID, projectPK string) {
	t.Helper()
	ctx := context.Background()

	nonce, err := appStore.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var subjBuf [8]byte
	if _, err := rand.Read(subjBuf[:]); err != nil {
		t.Fatalf("random subject: %v", err)
	}
	res, err := appStore.Exchange(ctx, store.ExchangeInput{
		Provider: "dev", Subject: "wdg-" + hex.EncodeToString(subjBuf[:]), PublicKey: pub,
		Label: "wdg-test-device", RawNonce: nonce, Now: now,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	accountID = res.AccountID

	if _, err := appStore.AssignPlan(ctx, accountID, store.PlanPlusBeta, store.LatestPlanVersion, time.Time{}, now); err != nil {
		t.Fatalf("AssignPlan(plus_beta): %v", err)
	}

	cloudProjectID = "wdg-proj"
	sub, err := appStore.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: accountID, CloudProjectID: cloudProjectID, CloudSessionID: "wdg-sess",
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: "wdg-cjk-1", UploadDigest: "sha256:wdg-evidence-1", ContentDigest: "sha256:wdg-content-1",
		BlobRef: "evidence/wdg-1", SizeBytes: 8, EvidenceBytes: []byte(`{"a":1}`), Now: now,
	})
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	lj, err := appStore.LeaseNextJob(ctx, "wdg-worker", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("LeaseNextJob: %v (lj=%v)", err, lj)
	}
	if err := appStore.MarkJobRunning(ctx, accountID, lj.JobID, now); err != nil {
		t.Fatalf("MarkJobRunning: %v", err)
	}
	if _, committed, err := appStore.CompleteJobWithResult(ctx, accountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"wdg-worker", lj.LeaseGeneration, "session_enrichment.v2-candidate",
		[]byte(`{"title":"wdg"}`), store.ResultProvenance{}, now); err != nil || !committed {
		t.Fatalf("CompleteJobWithResult: err=%v committed=%v", err, committed)
	}
	_ = sub

	// LoadProjectDigestEvidence takes the project's internal surrogate uuid
	// (cloud_projects.id), not the human cloud_project_id string — the same
	// distinction ListProjectDigestCandidates' DigestCandidate makes between
	// ProjectPK and CloudProjectID. SubmitJob's ensureProjectTx already
	// created the cloud_projects row; read its pk back directly (this pool
	// is the raw admin/superuser connection cloudtestpg hands the test, so
	// it bypasses RLS for setup reads exactly like every other store test's
	// use of the pool for out-of-band assertions).
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM cloud_projects WHERE account_id = $1::uuid AND cloud_project_id = $2`,
		accountID, cloudProjectID).Scan(&projectPK); err != nil {
		t.Fatalf("resolve project pk: %v", err)
	}
	return accountID, cloudProjectID, projectPK
}

// isPermissionDenied reports whether err is Postgres SQLSTATE 42501
// (insufficient_privilege), mirroring fixround_test.go's is40P01 pattern.
func isPermissionDenied(err error) bool {
	var pge *pgconn.PgError
	return errors.As(err, &pge) && pge.Code == "42501"
}

// workerDigestGrantRevokes mirrors, one to one, the ten grants
// 0040_worker_digest_grants.sql adds — used to reproduce sbci_worker's
// pre-0040 privilege state on a database already migrated to head (see the
// file-level doc comment for why: no MigrateTo primitive exists to migrate
// to 0039 only).
var workerDigestGrantRevokes = []string{
	`REVOKE SELECT ON cloud_sessions FROM sbci_worker`,
	`REVOKE SELECT ON account_plans FROM sbci_worker`,
	`REVOKE SELECT ON plans FROM sbci_worker`,
	revokeAccountsColumnGrant,
	`REVOKE INSERT ON analysis_jobs FROM sbci_worker`,
	`REVOKE INSERT ON usage_reservations FROM sbci_worker`,
	`REVOKE INSERT ON usage_cycles FROM sbci_worker`,
	`REVOKE INSERT ON evidence_objects FROM sbci_worker`,
	`REVOKE INSERT ON evidence_blobs FROM sbci_worker`,
	revokeCloudProjectsGrant,
}

// revokeCloudProjectsGrant / revokeAccountsColumnGrant are named separately
// because each is also revoked ON ITS OWN by a focused test below, proving
// that specific grant is load-bearing rather than merely present in a batch.
const (
	revokeCloudProjectsGrant = `REVOKE SELECT, INSERT, UPDATE ON cloud_projects FROM sbci_worker`
	// COLUMN-level, matching 0040: accounts has NO RLS, so the migration
	// deliberately grants UPDATE on the single updated_at column rather than
	// the whole table (CLOUD-RBAC-1).
	revokeAccountsColumnGrant = `REVOKE UPDATE (updated_at) ON accounts FROM sbci_worker`
)

// reapplyMigration0040 re-executes the SHIPPED migration file's own text
// (read from the embedded migrations.Files, not a hand-copied grant list) so
// the positive half of the negative test proves the actual file content is
// what fixes the defect.
func reapplyMigration0040(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	body, err := fs.ReadFile(migrations.Files, "0040_worker_digest_grants.sql")
	if err != nil {
		t.Fatalf("read embedded 0040_worker_digest_grants.sql: %v", err)
	}
	if _, err := pool.Exec(context.Background(), string(body)); err != nil {
		t.Fatalf("re-apply 0040_worker_digest_grants.sql: %v", err)
	}
}

// digestPeriod is one week's worth of SubmitDigestJob period bounds; each test
// below uses a distinct period so the canonical-key idempotency fast path
// never short-circuits a submit we want to actually execute.
type digestPeriod struct{ start, end string }

// submitDigest runs SubmitDigestJob for one period under the given store,
// returning the raw error so a caller can assert a 42501.
func submitDigest(ctx context.Context, s *store.Store, acct, cloudProjectID string, p digestPeriod, now time.Time) (store.JobSubmission, error) {
	evidence := []byte(fmt.Sprintf(
		`{"schema_version":"project_digest_evidence.v1","project_pseudonym":%q,"period_start":%q,"period_end":%q,"sessions":[]}`,
		cloudProjectID, p.start, p.end))
	return s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: cloudProjectID,
		PeriodStart: p.start, PeriodEnd: p.end,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: evidence,
		BlobRef:       "digest/" + cloudProjectID + "/" + p.start,
		UploadDigest:  "sha256:wdg-digest-" + p.start, ContentDigest: "sha256:wdg-digest-" + p.start,
		SizeBytes: int64(len(evidence)), Now: now,
	})
}

// leaseDigest takes the worker's own lease on the queued digest job and marks
// it running (LeaseNextJob -> MarkJobRunning), the first half of what
// internal/cloudserver/jobs/digest.go's DigestExecutor does per tick.
func leaseDigest(ctx context.Context, s *store.Store, acct, workerName string, now time.Time) (*store.LeasedJob, error) {
	lj, err := s.LeaseNextJob(ctx, workerName, []string{store.FeatureProjectDigest}, time.Hour, now)
	if err != nil {
		return nil, fmt.Errorf("lease digest job: %w", err)
	}
	if lj == nil {
		return nil, fmt.Errorf("lease digest job: no job available")
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		return nil, fmt.Errorf("mark running: %w", err)
	}
	return lj, nil
}

// completeLeasedDigest is the COMPLETION half, exactly as
// internal/cloudserver/jobs/digest.go does it (digest.go lines 260-280: it
// passes the decoded evidence's ProjectPseudonym as the cloudProjectID, which
// is what drives completeJobWithResultTx into ensureProjectTx). The result
// payload is the same minimal valid project_digest.v1 body
// store/digest_test.go's completeDigestJob uses. The raw error is returned so
// a caller can assert a 42501; a denial rolls the whole transaction back, so
// the lease stays valid and the SAME lj can be retried after a re-grant.
func completeLeasedDigest(ctx context.Context, s *store.Store, acct, workerName, cloudProjectID string, lj *store.LeasedJob, p digestPeriod, now time.Time) error {
	resultJSON := []byte(fmt.Sprintf(
		`{"headline":"h","themes":[],"cost_trend":"","recurring_error_classes":[],`+
			`"unfinished_threads":[],"suggested_next_session":"","session_count":0,`+
			`"period_start":%q,"period_end":%q,"confidence":"low","limitations":[],`+
			`"schema_version":"project_digest.v1"}`, p.start, p.end))
	_, committed, err := s.CompleteDigestJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID,
		workerName, lj.LeaseGeneration, "project_digest.v1", resultJSON, store.ResultProvenance{},
		cloudProjectID, p.start, p.end, now)
	if err != nil {
		return err
	}
	if !committed {
		return fmt.Errorf("CompleteDigestJobWithResult reported committed=false")
	}
	return nil
}

// executeDigest is leaseDigest followed by completeLeasedDigest.
func executeDigest(ctx context.Context, s *store.Store, acct, workerName, cloudProjectID string, p digestPeriod, now time.Time) error {
	lj, err := leaseDigest(ctx, s, acct, workerName, now)
	if err != nil {
		return err
	}
	return completeLeasedDigest(ctx, s, acct, workerName, cloudProjectID, lj, p, now)
}

// TestWorkerDigestGrantsFixTheProductionDefect drives the EXACT worker call
// sequence the production log shows (LoadProjectDigestEvidence then
// SubmitDigestJob), through a Store bound to store.RoleWorker — the same
// role the production worker assumes via `SET LOCAL ROLE sbci_worker` —
// against a database migrated to the full lineage head, 0040 included.
// Neither call may return a permission-denied error.
func TestWorkerDigestGrantsFixTheProductionDefect(t *testing.T) {
	pool := cloudtestpg.NewDB(t) // migrates to head, INCLUDING 0040
	appStore := store.New(pool)
	now := time.Now()
	acct, cloudProjectID, projectPK := digestFixtureAccount(t, appStore, pool, now)

	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(RoleWorker): %v", err)
	}
	ctx := context.Background()

	facts, err := worker.LoadProjectDigestEvidence(ctx, acct, projectPK, now.Add(-48*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadProjectDigestEvidence under sbci_worker: %v (want no error — "+
			"migration 0040 must GRANT SELECT ON cloud_sessions TO sbci_worker)", err)
	}
	if len(facts) != 1 {
		t.Fatalf("LoadProjectDigestEvidence returned %d rows, want 1", len(facts))
	}

	period := digestPeriod{"2026-01-05", "2026-01-11"}
	sub, err := submitDigest(ctx, worker, acct, cloudProjectID, period, now)
	if err != nil {
		t.Fatalf("SubmitDigestJob under sbci_worker: %v (want no error — migration 0040 must "+
			"GRANT SELECT ON account_plans, plans, UPDATE (updated_at) ON accounts, and INSERT ON "+
			"analysis_jobs, usage_reservations, usage_cycles, evidence_objects, evidence_blobs "+
			"TO sbci_worker)", err)
	}
	if sub.Existing {
		t.Fatal("first SubmitDigestJob call reported Existing=true")
	}

	// The COMPLETION half of the same lease — the gap the 2026-09-17
	// adversarial review found. Without 0040's cloud_projects grant the worker
	// pays for Luna inference and only then aborts inside ensureProjectTx.
	if err := executeDigest(ctx, worker, acct, "wdg-worker", cloudProjectID, period, now); err != nil {
		t.Fatalf("lease/run/complete digest job under sbci_worker: %v (want no error — migration "+
			"0040 must GRANT SELECT, INSERT, UPDATE ON cloud_projects TO sbci_worker for "+
			"CompleteDigestJobWithResult's ensureProjectTx)", err)
	}
}

// TestWorkerDigestGrantsCloudProjectsIsLoadBearing proves 0040's cloud_projects
// grant carries its own weight: revoking ONLY that grant (every other 0040
// grant left in place) leaves SubmitDigestJob succeeding — the defect is
// invisible to the submit path — while the completion the worker reaches
// SECONDS LATER, after the paid inference call, fails with SQLSTATE 42501
// inside ensureProjectTx. Re-applying 0040's own embedded file text restores
// completion.
func TestWorkerDigestGrantsCloudProjectsIsLoadBearing(t *testing.T) {
	pool := cloudtestpg.NewDB(t) // migrates to head, INCLUDING 0040
	appStore := store.New(pool)
	now := time.Now()
	acct, cloudProjectID, _ := digestFixtureAccount(t, appStore, pool, now)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, revokeCloudProjectsGrant); err != nil {
		t.Fatalf("revoke cloud_projects grant: %v", err)
	}
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(RoleWorker): %v", err)
	}

	period := digestPeriod{"2026-03-02", "2026-03-08"}
	if _, err := submitDigest(ctx, worker, acct, cloudProjectID, period, now); err != nil {
		t.Fatalf("SubmitDigestJob after revoking ONLY the cloud_projects grant: %v "+
			"(want no error — submit never touches cloud_projects; that is exactly why "+
			"the first cut of 0040 missed this)", err)
	}
	lj, err := leaseDigest(ctx, worker, acct, "wdg-worker", now)
	if err != nil {
		t.Fatalf("lease/mark-running after revoking ONLY the cloud_projects grant: %v "+
			"(want no error — neither touches cloud_projects)", err)
	}
	// A denied completion rolls its whole transaction back, so the lease it
	// held is still valid — the retry below reuses the SAME lj, which is what
	// makes this a clean before/after on the one grant under test.
	err = completeLeasedDigest(ctx, worker, acct, "wdg-worker", cloudProjectID, lj, period, now)
	if err == nil {
		t.Fatal("digest completion succeeded after revoking the cloud_projects grant — " +
			"want SQLSTATE 42501 (this pins that grant as load-bearing on its own)")
	}
	if !isPermissionDenied(err) {
		t.Fatalf("digest completion after revoking the cloud_projects grant: got %v, want SQLSTATE 42501", err)
	}

	reapplyMigration0040(t, pool)

	if err := completeLeasedDigest(ctx, worker, acct, "wdg-worker", cloudProjectID, lj, period, now); err != nil {
		t.Fatalf("digest completion after re-applying 0040: %v, want no error", err)
	}
}

// TestWorkerDigestGrantsAccountsColumnGrant proves 0040's deliberately narrow
// `GRANT UPDATE (updated_at) ON accounts` is BOTH load-bearing and SUFFICIENT.
// accounts has no RLS (0004_rls_grants.sql lists it under the system
// control-plane tables), so a table-level UPDATE grant would have been an
// unrestricted all-column, all-rows write grant for the worker plane; the
// column grant is the narrowest shape PostgreSQL accepts for the FE4 fence's
// `SELECT status FROM accounts ... FOR UPDATE` row lock (a row lock needs
// UPDATE on at least one column). Revoking exactly the column grant makes
// SubmitDigestJob fail 42501; re-applying 0040 — which grants nothing wider —
// makes it succeed. If the column grant were insufficient the re-apply leg
// would still 42501, so this test is the sufficiency proof, not just a pin.
func TestWorkerDigestGrantsAccountsColumnGrant(t *testing.T) {
	pool := cloudtestpg.NewDB(t) // migrates to head, INCLUDING 0040
	appStore := store.New(pool)
	now := time.Now()
	acct, cloudProjectID, _ := digestFixtureAccount(t, appStore, pool, now)
	ctx := context.Background()

	// Guard the premise: 0040 must NOT have granted table-wide UPDATE.
	var tableWide bool
	if err := pool.QueryRow(ctx,
		`SELECT bool_or(privilege_type = 'UPDATE') FROM information_schema.table_privileges
		  WHERE grantee = 'sbci_worker' AND table_name = 'accounts'`).Scan(&tableWide); err != nil {
		t.Fatalf("read accounts table privileges: %v", err)
	}
	if tableWide {
		t.Error("sbci_worker holds TABLE-level UPDATE on accounts; 0040 must grant only the " +
			"updated_at column (accounts has NO RLS — CLOUD-RBAC-1)")
	}

	if _, err := pool.Exec(ctx, revokeAccountsColumnGrant); err != nil {
		t.Fatalf("revoke accounts column grant: %v", err)
	}
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(RoleWorker): %v", err)
	}

	if _, err := submitDigest(ctx, worker, acct, cloudProjectID, digestPeriod{"2026-04-06", "2026-04-12"}, now); err == nil {
		t.Fatal("SubmitDigestJob succeeded after revoking the accounts updated_at grant — " +
			"want SQLSTATE 42501 on the FE4 `... FOR UPDATE` row lock")
	} else if !isPermissionDenied(err) {
		t.Fatalf("SubmitDigestJob after revoking the accounts updated_at grant: got %v, want SQLSTATE 42501", err)
	}

	reapplyMigration0040(t, pool)

	// Sufficiency: the ONLY accounts privilege restored is UPDATE(updated_at).
	if _, err := submitDigest(ctx, worker, acct, cloudProjectID, digestPeriod{"2026-04-13", "2026-04-19"}, now); err != nil {
		t.Fatalf("SubmitDigestJob after re-applying 0040 (column grant only): %v — "+
			"want no error; a failure here would mean GRANT UPDATE (updated_at) is NOT "+
			"sufficient for a FOR UPDATE row lock and 0040 must fall back to the table grant", err)
	}
}

// TestWorkerDigestGrantsDeniedBefore0040 is the negative half of the proof
// (see the file-level doc comment for why it is built by REVOKE/re-apply
// rather than a partial migrate): on a database migrated to head, revoking
// exactly the nine grants 0040 adds reproduces sbci_worker's pre-0040
// privilege state, and the SAME LoadProjectDigestEvidence call that succeeds
// in TestWorkerDigestGrantsFixTheProductionDefect now fails with SQLSTATE
// 42501 — pinning that those specific grants (not some other change) are the
// fix. Re-applying 0040's own embedded file text restores success.
func TestWorkerDigestGrantsDeniedBefore0040(t *testing.T) {
	pool := cloudtestpg.NewDB(t) // migrates to head, INCLUDING 0040
	appStore := store.New(pool)
	now := time.Now()
	acct, cloudProjectID, projectPK := digestFixtureAccount(t, appStore, pool, now)

	ctx := context.Background()
	for _, stmt := range workerDigestGrantRevokes {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("revoke %q (simulating pre-0040 state): %v", stmt, err)
		}
	}

	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatalf("NewForRole(RoleWorker): %v", err)
	}
	if _, err := worker.LoadProjectDigestEvidence(ctx, acct, projectPK, now.Add(-48*time.Hour), now.Add(time.Hour)); err == nil {
		t.Fatal("LoadProjectDigestEvidence succeeded after revoking 0040's grants — " +
			"want SQLSTATE 42501 (this pins that 0040 is the actual fix)")
	} else if !isPermissionDenied(err) {
		t.Fatalf("LoadProjectDigestEvidence after revoking 0040's grants: got %v, want SQLSTATE 42501", err)
	}

	reapplyMigration0040(t, pool)

	if _, err := worker.LoadProjectDigestEvidence(ctx, acct, projectPK, now.Add(-48*time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatalf("LoadProjectDigestEvidence after re-applying 0040: %v, want no error", err)
	}
	if _, err := worker.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
		AccountID: acct, CloudProjectID: cloudProjectID,
		PeriodStart: "2026-02-02", PeriodEnd: "2026-02-08",
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		EvidenceBytes: []byte(`{"schema_version":"project_digest_evidence.v1"}`),
		BlobRef:       "digest/" + cloudProjectID + "/2026-02-02",
		UploadDigest:  "sha256:wdg-digest-2", ContentDigest: "sha256:wdg-digest-2",
		SizeBytes: 10, Now: now,
	}); err != nil {
		t.Fatalf("SubmitDigestJob after re-applying 0040: %v, want no error", err)
	}
}
