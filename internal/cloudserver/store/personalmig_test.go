package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/personalmig"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// personalmig_test.go covers the store seam of `observer-cloud
// migrate-personal` (store/personalmig.go; D-IND-4..6; docs/security.md
// IND-5) on PostgreSQL: the footprint and results reads, the personal org
// created once, the ledger's stage machine and audit rows, the re-key in one
// transaction (subscription bound to the org as personal_pro, the account's
// Paddle plan closed), a second run as a no-op, a resume after a crash
// between stages, and the "bills once" proof: a webhook for the re-keyed
// subscription takes the org branch, writes no second row and assigns no
// account plan.

// fullResult is a result body that normalizes as a cloudcontract.Result.
func fullResult(t *testing.T, title string) []byte {
	t.Helper()
	b, err := json.Marshal(cloudcontract.Result{
		Title: title, TaxonomyTags: []string{"debugging"}, SuggestedTags: []string{"go"}, Description: "fixed the flaky test",
		Confidence: cloudcontract.ConfidenceMedium, EvidenceRefs: []string{}, Limitations: []string{},
		SchemaVersion: cloudcontract.ResultSchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedResult drives one enrichment job in session to a stored result.
func seedResult(t *testing.T, s *store.Store, acct, session, key string, body []byte, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	sub, err := s.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: session,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: 4, EvidenceBytes: []byte(`{"a":1}`),
		ConsentGeneration: 0, Now: now,
	})
	if err != nil {
		t.Fatalf("submit %s: %v", key, err)
	}
	lj, err := s.LeaseNextJob(ctx, "w1", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("lease %s: %v (lj=%v)", key, err, lj)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatalf("running %s: %v", key, err)
	}
	rid, ok, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID, "w1",
		lj.LeaseGeneration, cloudcontract.ResultSchemaVersion, body, store.ResultProvenance{}, now)
	if err != nil || !ok {
		t.Fatalf("complete %s: ok=%v err=%v", key, ok, err)
	}
	return rid
}

func countOf(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

// personalMigFixture is one account with two session results (one corrected,
// one regenerated over an older result) and a live plus_beta subscription
// bought on the account path, plus an account with nothing.
type personalMigFixture struct {
	s     *store.Store
	pool  *pgxpool.Pool
	acct  string
	empty string
	t0    time.Time
}

func newPersonalMigFixture(t *testing.T) personalMigFixture {
	t.Helper()
	s, pool := newStore(t)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{testPrice: {Name: "plus_beta", Version: 1}})
	acct := makeAccount(t, s)
	// Wall-clock based: a job's lease is checked against clock_timestamp().
	t0 := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	activatePaid(t, s, acct, "sub_pm", t0)
	ctx := context.Background()
	r1 := seedResult(t, s, acct, "cs-one", "k1", fullResult(t, "ai title one"), t0.Add(time.Minute))
	if _, err := s.ApplyResultCorrection(ctx, acct, r1, 0, "idem-1", []byte(`{"title":"my title"}`), store.CorrectionSourcePortal, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("correction: %v", err)
	}
	seedResult(t, s, acct, "cs-two", "k2", fullResult(t, "old"), t0.Add(3*time.Minute))
	seedResult(t, s, acct, "cs-two", "k3", fullResult(t, "regenerated"), t0.Add(4*time.Minute))
	var empty string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&empty); err != nil {
		t.Fatal(err)
	}
	return personalMigFixture{s: s, pool: pool, acct: acct, empty: empty, t0: t0}
}

func TestPersonalMigrationFootprintAndDecision(t *testing.T) {
	t.Parallel()
	f := newPersonalMigFixture(t)
	ctx := context.Background()
	now := f.t0.Add(time.Hour)

	fp, err := f.s.PersonalMigrationFootprint(ctx, f.acct, now)
	if err != nil {
		t.Fatal(err)
	}
	if fp.AccountStatus != "active" || fp.Results != 3 || fp.Devices != 1 || fp.Org != nil ||
		fp.PlanName != "plus_beta" || fp.PlanSource != "paddle" || fp.OwnerSubject == "" ||
		len(fp.AccountSubscriptions) != 1 || fp.AccountSubscriptions[0].ID != "sub_pm" {
		t.Fatalf("footprint = %+v", fp)
	}
	d := personalmig.Decide(fp)
	if !d.InScope || d.Skip != "" || len(d.Needs) != 3 || d.Rekey == nil || d.Rekey.ID != "sub_pm" {
		t.Fatalf("decision = %+v", d)
	}

	empty, err := f.s.PersonalMigrationFootprint(ctx, f.empty, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := personalmig.Decide(empty); d.InScope {
		t.Fatalf("an account with nothing is in scope: %+v", d)
	}
	if _, err := f.s.PersonalMigrationFootprint(ctx, "00000000-0000-4000-8000-000000000001", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}

	// The walk sees both accounts, in order, and pages.
	page, err := f.s.ListPersonalMigrationAccounts(ctx, "", 1)
	if err != nil || len(page) != 1 {
		t.Fatalf("page 1 = %v %v", page, err)
	}
	rest, err := f.s.ListPersonalMigrationAccounts(ctx, page[0].AccountID, 10)
	if err != nil || len(rest) != 1 || rest[0].AccountID <= page[0].AccountID {
		t.Fatalf("page 2 = %v %v", rest, err)
	}
}

func TestPersonalMigrationExportAppliesCorrection(t *testing.T) {
	t.Parallel()
	f := newPersonalMigFixture(t)
	facts, err := f.s.PersonalMigrationResults(context.Background(), f.acct)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := personalmig.BuildExport(facts)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Total != 3 || len(exp.Records) != 2 || exp.Skipped[personalmig.ResultSkipSuperseded] != 1 {
		t.Fatalf("export = total %d records %d skipped %v", exp.Total, len(exp.Records), exp.Skipped)
	}
	one, two := exp.Records[0], exp.Records[1]
	if one.CloudSessionID != "cs-one" || !one.Corrected || one.Result.Title != "my title" || one.Result.Description != "fixed the flaky test" {
		t.Fatalf("corrected record = %+v", one)
	}
	if two.CloudSessionID != "cs-two" || two.Corrected || two.Result.Title != "regenerated" || two.TenantSessionID() != "personal:cs-two" {
		t.Fatalf("regenerated record = %+v", two)
	}
	if _, _, err := cloudcontract.EncodePersonalImportRecords(exp.Records); err != nil {
		t.Fatalf("encode: %v", err)
	}
}

func TestPersonalMigrationOrgRekeyAndBillsOnce(t *testing.T) {
	t.Parallel()
	f := newPersonalMigFixture(t)
	ctx := context.Background()
	now := f.t0.Add(time.Hour)

	// Ledger: planned (with its audit row), then a refused backwards move.
	row := store.PersonalMigrationRow{AccountID: f.acct, Stage: personalmig.StagePlanned}
	if changed, err := f.s.RecordPersonalMigration(ctx, row); err != nil || !changed {
		t.Fatalf("planned: changed=%v err=%v", changed, err)
	}
	if changed, err := f.s.RecordPersonalMigration(ctx, row); err != nil || changed {
		t.Fatalf("planned again: changed=%v err=%v", changed, err)
	}
	if _, err := f.s.RecordPersonalMigration(ctx, store.PersonalMigrationRow{AccountID: f.acct, Stage: personalmig.StageVerified, OrgID: "x"}); !errors.Is(err, store.ErrPersonalMigrationStage) {
		t.Fatalf("planned -> verified: %v", err)
	}

	// The personal org is created once; a crash before org_ready was
	// recorded resumes onto the same org.
	org, created, err := f.s.EnsurePersonalOrgForMigration(ctx, f.acct, "")
	if err != nil || !created || org.Status != "provisioning" || len(org.Slug) != 10 {
		t.Fatalf("ensure: %+v created=%v err=%v", org, created, err)
	}
	again, created, err := f.s.EnsurePersonalOrgForMigration(ctx, f.acct, "")
	if err != nil || created || again.OrgID != org.OrgID {
		t.Fatalf("ensure again: %+v created=%v err=%v", again, created, err)
	}
	if n := countOf(t, f.pool, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid AND kind='personal'`, f.acct); n != 1 {
		t.Fatalf("%d personal orgs", n)
	}
	row.Stage, row.OrgID = personalmig.StageOrgReady, org.OrgID
	if _, err := f.s.RecordPersonalMigration(ctx, row); err != nil {
		t.Fatalf("org_ready: %v", err)
	}

	// The re-key: one transaction moves the subscription and closes the plan.
	res, err := f.s.RekeyPersonalSubscription(ctx, f.acct, org, row, now)
	if err != nil || res.Refused != "" || !res.Rekeyed || res.SubscriptionID != "sub_pm" || res.ClosedPlanRows != 1 {
		t.Fatalf("rekey = %+v err=%v", res, err)
	}
	var orgID, plan string
	var ver int
	if err := f.pool.QueryRow(ctx, `SELECT coalesce(org_id::text,''), plan_name, plan_version FROM paddle_subscriptions WHERE paddle_subscription_id='sub_pm'`).Scan(&orgID, &plan, &ver); err != nil {
		t.Fatal(err)
	}
	if orgID != org.OrgID || plan != personalmig.OrgPlanName || ver != personalmig.OrgPlanVersion {
		t.Fatalf("subscription = org %s plan %s v%d", orgID, plan, ver)
	}
	if p, err := f.s.ResolvePlanForAccount(ctx, f.acct, now.Add(time.Minute)); err != nil || p.Name != "free" {
		t.Fatalf("account plan after re-key = %+v %v", p, err)
	}
	led, ok, err := f.s.GetPersonalMigration(ctx, f.acct)
	if err != nil || !ok || led.Stage != personalmig.StageRekeyed || led.RekeyedSubscriptionID != "sub_pm" || led.OrgID != org.OrgID {
		t.Fatalf("ledger = %+v ok=%v err=%v", led, ok, err)
	}
	for _, ev := range []string{"personal_migration_planned", "personal_migration_org_ready", "personal_migration_rekeyed"} {
		if n := countOf(t, f.pool, `SELECT count(*) FROM security_audit_events WHERE account_id=$1::uuid AND event_type=$2`, f.acct, ev); n != 1 {
			t.Errorf("%d %s audit rows", n, ev)
		}
	}
	var detail string
	if err := f.pool.QueryRow(ctx, `SELECT detail::text FROM security_audit_events WHERE account_id=$1::uuid AND event_type='personal_migration_rekeyed'`, f.acct).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(detail), &d); err != nil || d["org_id"] != org.OrgID || d["subscription_rekeyed"] != true {
		t.Fatalf("audit detail = %s", detail)
	}

	// A second re-key is a no-op.
	res, err = f.s.RekeyPersonalSubscription(ctx, f.acct, org, led, now.Add(time.Minute))
	if err != nil || res.Rekeyed || res.SubscriptionID != "sub_pm" || res.ClosedPlanRows != 0 || res.Refused != "" {
		t.Fatalf("second rekey = %+v err=%v", res, err)
	}
	fp, err := f.s.PersonalMigrationFootprint(ctx, f.acct, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if dd := personalmig.Decide(fp); dd.Has(personalmig.NeedRekey) || dd.Has(personalmig.NeedEnsureOrg) || len(fp.RekeyedSubscriptions) != 1 {
		t.Fatalf("after re-key: footprint %+v decision %+v", fp, dd)
	}

	// Bills once: a renewal for the re-keyed subscription takes the org
	// branch, keeps one row and assigns no account plan; a cancellation does
	// the same.
	in, err := f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_after_rekey", EventType: "subscription.updated", CustomerID: "ctm_1",
		SubscriptionID: "sub_pm", Status: "active", PriceID: testPrice,
		OccurredAt: now.Add(2 * time.Hour), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(2 * time.Hour),
	})
	if err != nil || !in.Applied || in.OrgID != org.OrgID || in.AccountID != f.acct {
		t.Fatalf("renewal intake = %+v err=%v", in, err)
	}
	in, err = f.s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_cancel_after_rekey", EventType: "subscription.canceled", CustomerID: "ctm_1",
		SubscriptionID: "sub_pm", Status: "canceled", PriceID: testPrice,
		OccurredAt: now.Add(3 * time.Hour), CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now.Add(3 * time.Hour),
	})
	if err != nil || !in.Applied || in.OrgID != org.OrgID {
		t.Fatalf("cancel intake = %+v err=%v", in, err)
	}
	if n := countOf(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE account_id=$1::uuid`, f.acct); n != 1 {
		t.Fatalf("%d subscription rows, want 1", n)
	}
	if err := f.pool.QueryRow(ctx, `SELECT coalesce(org_id::text,''), plan_name FROM paddle_subscriptions WHERE paddle_subscription_id='sub_pm'`).Scan(&orgID, &plan); err != nil {
		t.Fatal(err)
	}
	if orgID != org.OrgID || plan != personalmig.OrgPlanName {
		t.Fatalf("after webhooks: org %s plan %s", orgID, plan)
	}
	if n := countOf(t, f.pool, `SELECT count(*) FROM account_plans WHERE account_id=$1::uuid AND source='paddle' AND (effective_until IS NULL OR effective_until > $2)`, f.acct, now); n != 0 {
		t.Fatalf("%d paddle account plan rows in force after the webhooks", n)
	}
	if p, err := f.s.ResolvePlanForAccount(ctx, f.acct, now.Add(4*time.Hour)); err != nil || p.Name != "free" {
		t.Fatalf("account plan after webhooks = %+v %v", p, err)
	}
}

func TestPersonalMigrationRekeyRefusesASecondLiveOrgSubscription(t *testing.T) {
	t.Parallel()
	f := newPersonalMigFixture(t)
	ctx := context.Background()
	now := f.t0.Add(time.Hour)
	org, _, err := f.s.EnsurePersonalOrgForMigration(ctx, f.acct, "")
	if err != nil {
		t.Fatal(err)
	}
	// The org already pays for itself (a Personal Pro bought on the org).
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO paddle_subscriptions (account_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status, org_id)
		 VALUES ($1::uuid, 'ctm_1', 'sub_org', 'personal_pro', 1, 'active', $2::uuid)`, f.acct, org.OrgID); err != nil {
		t.Fatal(err)
	}
	fp, err := f.s.PersonalMigrationFootprint(ctx, f.acct, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := personalmig.Decide(fp); d.Skip == "" {
		t.Fatalf("decision does not skip: %+v", d)
	}
	row := store.PersonalMigrationRow{AccountID: f.acct, Stage: personalmig.StagePlanned}
	if _, err := f.s.RecordPersonalMigration(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Stage, row.OrgID = personalmig.StageOrgReady, org.OrgID
	if _, err := f.s.RecordPersonalMigration(ctx, row); err != nil {
		t.Fatal(err)
	}
	// The in-transaction re-check refuses too (the trigger's one-live rule),
	// and writes nothing.
	res, err := f.s.RekeyPersonalSubscription(ctx, f.acct, org, row, now)
	if err != nil || res.Refused == "" || res.Rekeyed {
		t.Fatalf("rekey = %+v err=%v", res, err)
	}
	if n := countOf(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE paddle_subscription_id='sub_pm' AND org_id IS NULL`); n != 1 {
		t.Fatal("the account subscription moved")
	}
	if p, err := f.s.ResolvePlanForAccount(ctx, f.acct, now); err != nil || p.Name != "plus_beta" {
		t.Fatalf("account plan = %+v %v", p, err)
	}
	if led, _, _ := f.s.GetPersonalMigration(ctx, f.acct); led.Stage != personalmig.StageOrgReady {
		t.Fatalf("ledger moved to %q", led.Stage)
	}
	// Another account's org is never a target.
	other := makeAccount(t, f.s)
	if _, err := f.s.RekeyPersonalSubscription(ctx, other, org, store.PersonalMigrationRow{AccountID: other}, now); err == nil {
		t.Fatal("re-keyed onto another account's org")
	}
}

func TestPersonalMigrationLedgerShape(t *testing.T) {
	t.Parallel()
	f := newPersonalMigFixture(t)
	ctx := context.Background()
	if _, err := f.s.RecordPersonalMigration(ctx, store.PersonalMigrationRow{AccountID: f.acct, Stage: personalmig.StageSkipped, SkipReason: "account has no WorkOS subject"}); err != nil {
		t.Fatal(err)
	}
	noted, err := f.s.RecordPersonalMigrationError(ctx, f.acct, "disk full")
	if err != nil || !noted {
		t.Fatalf("error note: %v %v", noted, err)
	}
	if noted, err := f.s.RecordPersonalMigrationError(ctx, f.empty, "x"); err != nil || noted {
		t.Fatalf("a row was invented: %v %v", noted, err)
	}
	rows, err := f.s.ListPersonalMigrations(ctx)
	if err != nil || len(rows) != 1 || rows[0].SkipReason == "" || rows[0].LastError != "disk full" {
		t.Fatalf("ledger = %+v %v", rows, err)
	}
	// Only the operator role holds the table; no role may delete.
	for role, want := range map[string]bool{"sbci_app": true, "sbci_api": false, "sbci_worker": false} {
		var can bool
		if err := f.pool.QueryRow(ctx, `SELECT has_table_privilege($1, 'personal_migrations', 'SELECT')`, role).Scan(&can); err != nil {
			t.Fatal(err)
		}
		if can != want {
			t.Errorf("%s SELECT = %v, want %v", role, can, want)
		}
		if err := f.pool.QueryRow(ctx, `SELECT has_table_privilege($1, 'personal_migrations', 'DELETE')`, role).Scan(&can); err != nil {
			t.Fatal(err)
		}
		if can {
			t.Errorf("%s holds DELETE", role)
		}
	}
	// The CHECKs: a skipped row needs its reason, an exported one its digest.
	if _, err := f.pool.Exec(ctx, `UPDATE personal_migrations SET skip_reason = NULL WHERE account_id=$1::uuid`, f.acct); err == nil {
		t.Error("a skipped row without a reason was accepted")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE personal_migrations SET stage='exported', skip_reason=NULL, org_id=NULL WHERE account_id=$1::uuid`, f.acct); err == nil {
		t.Error("an exported row without org and digest was accepted")
	}
	// The stage CHECK lists exactly personalmig.KnownStages.
	for _, st := range personalmig.KnownStages() {
		if !st.Valid() {
			t.Fatal(st)
		}
	}
	var def string
	if err := f.pool.QueryRow(ctx,
		`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
		  WHERE c.conrelid = 'personal_migrations'::regclass AND c.conname = 'personal_migrations_stage_check'`).Scan(&def); err != nil {
		t.Fatal(err)
	}
	for _, st := range personalmig.KnownStages() {
		if !containsQuoted(def, string(st)) {
			t.Errorf("stage CHECK %s lacks %q", def, st)
		}
	}
}

func containsQuoted(s, word string) bool { return strings.Contains(s, "'"+word+"'") }
