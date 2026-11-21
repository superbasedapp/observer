package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/personalmig"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// migratepersonal_test.go drives `observer-cloud migrate-personal` plan, run
// (dry and --apply), verify and status through their run functions against a
// real PostgreSQL and temporary directories (D-IND-4..6).

const mpPrice = "pri_mp_plus"

func mpAccount(t *testing.T, s *store.Store, subject string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	nonce, err := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Exchange(ctx, store.ExchangeInput{Provider: "workos", Subject: subject, PublicKey: pub, Label: "d", RawNonce: nonce, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return res.AccountID
}

func mpResult(t *testing.T, s *store.Store, acct, session, key, title string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	body, _ := json.Marshal(cloudcontract.Result{
		Title: title, TaxonomyTags: []string{}, SuggestedTags: []string{}, Description: "d",
		Confidence: cloudcontract.ConfidenceLow, EvidenceRefs: []string{}, Limitations: []string{},
		SchemaVersion: cloudcontract.ResultSchemaVersion,
	})
	sub, err := s.SubmitJob(ctx, store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: session,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "evidence/" + key, SizeBytes: 4, EvidenceBytes: []byte(`{"a":1}`), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	lj, err := s.LeaseNextJob(ctx, "w", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil || lj.JobID != sub.JobID {
		t.Fatalf("lease: %v %v", lj, err)
	}
	if err := s.MarkJobRunning(ctx, acct, lj.JobID, now); err != nil {
		t.Fatal(err)
	}
	rid, ok, err := s.CompleteJobWithResult(ctx, acct, lj.JobID, lj.EvidencePK, lj.ReservationID, "w", lj.LeaseGeneration,
		cloudcontract.ResultSchemaVersion, body, store.ResultProvenance{}, now)
	if err != nil || !ok {
		t.Fatalf("complete: %v %v", ok, err)
	}
	return rid
}

func TestMigratePersonalPlanRunVerify(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	s.SetPaddlePriceMap(map[string]store.PaddlePlan{mpPrice: {Name: "plus_beta", Version: 1}})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }

	// paid: results (one corrected) and a live plus_beta subscription.
	paid := mpAccount(t, s, "user_paid")
	nonce, _, err := s.CreateCheckoutIntent(ctx, paid, mpPrice, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if in, err := s.ProcessPaddleEvent(ctx, store.PaddleEvent{
		EventID: "evt_mp", EventType: "subscription.activated", AccountID: paid, CheckoutNonce: nonce,
		CustomerID: "ctm_mp", SubscriptionID: "sub_mp", Status: "active", PriceID: mpPrice,
		OccurredAt: now, CurrentPeriodEnd: now.AddDate(0, 1, 0), Now: now,
	}); err != nil || !in.Applied {
		t.Fatalf("activate: %+v %v", in, err)
	}
	r1 := mpResult(t, s, paid, "cs-a", "k1", "ai one", now)
	mpResult(t, s, paid, "cs-b", "k2", "ai two", now.Add(time.Second))
	if _, err := s.ApplyResultCorrection(ctx, paid, r1, 0, "i1", []byte(`{"title":"mine"}`), store.CorrectionSourceNode, now); err != nil {
		t.Fatal(err)
	}
	// device: only a device registration (Exchange makes one).
	device := mpAccount(t, s, "user_device")
	// stuck: results, and a run that crashed after recording planned.
	stuck := mpAccount(t, s, "user_stuck")
	mpResult(t, s, stuck, "cs-c", "k3", "ai three", now.Add(2*time.Second))
	if _, err := s.RecordPersonalMigration(ctx, store.PersonalMigrationRow{AccountID: stuck, Stage: personalmig.StagePlanned}); err != nil {
		t.Fatal(err)
	}
	// nothing: an account with no footprint.
	if _, err := pool.Exec(ctx, `INSERT INTO accounts DEFAULT VALUES`); err != nil {
		t.Fatal(err)
	}

	// plan: read-only.
	var out bytes.Buffer
	if err := runMigratePersonalPlan(ctx, &out, s, "", now); err != nil {
		t.Fatal(err)
	}
	plan := out.String()
	for _, want := range []string{
		"read-only", "4 walked, 3 in scope, 1 out of scope", "stage: none 2, planned 1,",
		paid + "  stage=none", "rekey=sub_mp", "next=plan>ensure_org>rekey>export",
		device + "  stage=none", "next=plan>ensure_org>rekey>finish",
		stuck + "  stage=planned", "next=ensure_org>rekey>export",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan lacks %q:\n%s", want, plan)
		}
	}
	t.Logf("plan output:\n%s", plan)
	if n := countRows(t, pool, `SELECT count(*) FROM orgs`); n != 0 {
		t.Fatalf("plan created %d orgs", n)
	}

	// The dry run writes nothing.
	dir := t.TempDir()
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir}, clock); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), paid+"  would: plan > ensure_org > rekey > export") {
		t.Fatalf("dry run:\n%s", out.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 || countRows(t, pool, `SELECT count(*) FROM personal_migrations`) != 1 {
		t.Fatal("the dry run wrote")
	}
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Apply: true}, clock); err == nil {
		t.Fatal("--apply without --out accepted")
	}

	// --limit 1 then the rest: resumable.
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true, Limit: 1}, clock); err != nil {
		t.Fatalf("run --limit 1: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "accounts 1:") {
		t.Fatalf("limit:\n%s", out.String())
	}
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true}, clock); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	t.Logf("run output:\n%s", out.String())

	rows, err := s.ListPersonalMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byAcct := map[string]store.PersonalMigrationRow{}
	for _, r := range rows {
		byAcct[r.AccountID] = r
	}
	if r := byAcct[paid]; r.Stage != personalmig.StageExported || r.ResultsExported != 2 || r.RekeyedSubscriptionID != "sub_mp" || r.BundleSHA256 == "" {
		t.Fatalf("paid ledger = %+v", r)
	}
	if r := byAcct[stuck]; r.Stage != personalmig.StageExported || r.ResultsExported != 1 {
		t.Fatalf("stuck ledger = %+v", r)
	}
	if r := byAcct[device]; r.Stage != personalmig.StageVerified || r.OrgID == "" || r.BundleSHA256 != "" {
		t.Fatalf("device ledger = %+v", r)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM orgs WHERE kind='personal'`); n != 3 {
		t.Fatalf("%d personal orgs", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM paddle_subscriptions WHERE paddle_subscription_id='sub_mp' AND org_id IS NOT NULL AND plan_name='personal_pro'`); n != 1 {
		t.Fatal("subscription not re-keyed")
	}
	if n := countRows(t, pool, `SELECT count(*) FROM security_audit_events WHERE event_type='personal_migration_run'`); n != 2 {
		t.Fatalf("%d run audit rows", n)
	}

	// The paid bundle: manifest + records verify, the correction applied.
	paidDir := filepath.Join(dir, byAcct[paid].OrgID)
	manRaw, err := os.ReadFile(filepath.Join(paidDir, bundleManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var man cloudcontract.PersonalImportManifest
	if err := json.Unmarshal(manRaw, &man); err != nil {
		t.Fatal(err)
	}
	recs, err := os.ReadFile(filepath.Join(paidDir, bundleRecordsFile))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cloudcontract.VerifyPersonalImport(man, recs)
	if err != nil {
		t.Fatalf("VerifyPersonalImport: %v", err)
	}
	if len(decoded) != 2 || decoded[0].Result.Title != "mine" || !decoded[0].Corrected || man.OwnerSubject != "user_paid" || man.AccountID != paid {
		t.Fatalf("bundle = %+v / %+v", man, decoded)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(paidDir, bundleManifestFile), filepath.Join(paidDir, bundleRecordsFile)} {
			if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", p, fi.Mode().Perm())
			}
		}
		if fi, _ := os.Stat(paidDir); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v", paidDir, fi.Mode().Perm())
		}
	}

	// A second run is a no-op.
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true}, clock); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "accounts 0:") {
		t.Fatalf("second run acted:\n%s", out.String())
	}
	// --replace re-exports the same bundle, which is kept.
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true, Replace: true, Account: paid}, clock); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(keep)") {
		t.Fatalf("replace of the same bundle:\n%s", out.String())
	}

	// verify with no receipts: incomplete, non-zero.
	receipts := t.TempDir()
	out.Reset()
	err = runMigratePersonalVerify(ctx, &out, s, receipts)
	var ee *exitCodeError
	if !errors.As(err, &ee) || !strings.Contains(out.String(), "2 incomplete") {
		t.Fatalf("verify without receipts: %v\n%s", err, out.String())
	}
	// A complete receipt for paid, a short one for stuck.
	writeReceipt(t, receipts, cloudcontract.PersonalImportReceipt{
		Format: cloudcontract.PersonalImportFormat, OrgID: man.OrgID, RecordsSHA256: man.RecordsSHA256,
		RecordCount: 2, Inserted: 2, Present: 2, ImportedAt: now.Format(time.RFC3339),
	})
	st := byAcct[stuck]
	writeReceipt(t, receipts, cloudcontract.PersonalImportReceipt{
		Format: cloudcontract.PersonalImportFormat, OrgID: st.OrgID, RecordsSHA256: st.BundleSHA256,
		RecordCount: 1, Inserted: 0, Present: 0, ImportedAt: now.Format(time.RFC3339),
	})
	out.Reset()
	err = runMigratePersonalVerify(ctx, &out, s, receipts)
	if !errors.As(err, &ee) || !strings.Contains(out.String(), "1 verified now, 1 incomplete") || !strings.Contains(out.String(), "not every record is present") {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}
	writeReceipt(t, receipts, cloudcontract.PersonalImportReceipt{
		Format: cloudcontract.PersonalImportFormat, OrgID: st.OrgID, RecordsSHA256: st.BundleSHA256,
		RecordCount: 1, Inserted: 1, Present: 1, ImportedAt: now.Format(time.RFC3339),
	})
	out.Reset()
	if err := runMigratePersonalVerify(ctx, &out, s, receipts); err != nil {
		t.Fatalf("verify: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "1 verified now, 0 incomplete; 2 verified before") {
		t.Fatalf("verify:\n%s", out.String())
	}
	got, _, _ := s.GetPersonalMigration(ctx, paid)
	if got.Stage != personalmig.StageVerified || got.ReceiptPresent == nil || *got.ReceiptPresent != 2 || *got.ReceiptInserted != 2 {
		t.Fatalf("paid after verify = %+v", got)
	}

	out.Reset()
	if err := runMigratePersonalStatus(ctx, &out, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "3 account(s) in the ledger") || !strings.Contains(out.String(), "verified 3") ||
		!strings.Contains(out.String(), "records: 3 exported, 3 confirmed present") {
		t.Fatalf("status:\n%s", out.String())
	}
}

func writeReceipt(t *testing.T, dir string, r cloudcontract.PersonalImportReceipt) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, r.OrgID), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(dir, r.OrgID, bundleReceiptFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, sql string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", sql, err)
	}
	return n
}

func TestWriteBundleNeverOverwritesADifferentBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	org := "0b6a8f0e-8a0e-4c3b-9d8e-2f3c4b5a6d7e"
	rec := func(title string) []cloudcontract.PersonalImportRecord {
		return []cloudcontract.PersonalImportRecord{{
			ImportRef: "personal:r1", CloudSessionID: "cs", CreatedAt: "2026-11-16T00:00:00Z",
			Result: cloudcontract.Result{Title: title, Confidence: cloudcontract.ConfidenceLow, SchemaVersion: cloudcontract.ResultSchemaVersion},
		}}
	}
	bundle := func(title string) (cloudcontract.PersonalImportManifest, []byte) {
		data, sha, err := cloudcontract.EncodePersonalImportRecords(rec(title))
		if err != nil {
			t.Fatal(err)
		}
		return personalmig.NewManifest("a", personalmig.PersonalOrg{OrgID: org, Slug: "u-abcdefgh"}, "user", 1, sha, time.Now()), data
	}
	m1, d1 := bundle("one")
	if a, err := writeBundle(dir, m1, d1, false); err != nil || a != personalmig.BundleWrite {
		t.Fatalf("first write: %v %v", a, err)
	}
	if a, err := writeBundle(dir, m1, d1, false); err != nil || a != personalmig.BundleKeep {
		t.Fatalf("same bundle: %v %v", a, err)
	}
	m2, d2 := bundle("two")
	if _, err := writeBundle(dir, m2, d2, false); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("different bundle: %v", err)
	}
	if back, _ := readExistingBundle(filepath.Join(dir, org)); back.RecordsSHA256 != m1.RecordsSHA256 {
		t.Fatal("the refused write changed the bundle")
	}
	if a, err := writeBundle(dir, m2, d2, true); err != nil || a != personalmig.BundleWrite {
		t.Fatalf("replace: %v %v", a, err)
	}
	if back, _ := readExistingBundle(filepath.Join(dir, org)); back.RecordsSHA256 != m2.RecordsSHA256 || back.Manifest.RecordsSHA256 != m2.RecordsSHA256 {
		t.Fatal("replace did not write")
	}
	bad := m1
	bad.OrgID = "../escape"
	if _, err := writeBundle(dir, bad, d1, true); err == nil {
		t.Fatal("a non-uuid org id was used as a path")
	}
}

// TestMigratePersonalDriftAfterVerify pins FR-13: the personal plane keeps
// serving after an account is verified, so a result created afterwards is
// found by a later run (the account is reopened and re-exported), and the
// retirement gate (check-drift) fails until the account is verified again.
func TestMigratePersonalDriftAfterVerify(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }

	acct := mpAccount(t, s, "user_drift")
	mpResult(t, s, acct, "cs-a", "d1", "ai one", now)
	dir, receipts := t.TempDir(), t.TempDir()

	var out bytes.Buffer
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true}, clock); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	finish := func(wantRecords int) {
		t.Helper()
		row, _, err := s.GetPersonalMigration(ctx, acct)
		if err != nil || row.Stage != personalmig.StageExported || row.ResultsExported != wantRecords {
			t.Fatalf("exported ledger = %+v err=%v", row, err)
		}
		writeReceipt(t, receipts, cloudcontract.PersonalImportReceipt{
			Format: cloudcontract.PersonalImportFormat, OrgID: row.OrgID, RecordsSHA256: row.BundleSHA256,
			RecordCount: wantRecords, Inserted: wantRecords, Present: wantRecords, ImportedAt: now.Format(time.RFC3339),
		})
		out.Reset()
		if err := runMigratePersonalVerify(ctx, &out, s, receipts); err != nil {
			t.Fatalf("verify: %v\n%s", err, out.String())
		}
	}
	finish(1)

	// Verified and unchanged: the gate is clear and a run does nothing.
	out.Reset()
	if err := runMigratePersonalCheckDrift(ctx, &out, s, false, now); err != nil || !strings.Contains(out.String(), "clear 1, drift 0") {
		t.Fatalf("clear gate: %v\n%s", err, out.String())
	}

	// A result created after verification is drift: the gate fails and the
	// plan says why.
	mpResult(t, s, acct, "cs-b", "d2", "ai two", now.Add(time.Second))
	out.Reset()
	var ee *exitCodeError
	if err := runMigratePersonalCheckDrift(ctx, &out, s, false, now); !errors.As(err, &ee) || !strings.Contains(out.String(), "DRIFT") {
		t.Fatalf("drift gate: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := runMigratePersonalPlan(ctx, &out, s, "", now); err != nil || !strings.Contains(out.String(), "drift: ") || !strings.Contains(out.String(), "next=reopen") {
		t.Fatalf("plan: %v\n%s", err, out.String())
	}

	// A run reopens the account and replaces its bundle; verify closes it.
	out.Reset()
	if err := runMigratePersonal(ctx, &out, s, migratePersonalOptions{Out: dir, Apply: true}, clock); err != nil || !strings.Contains(out.String(), "reopened") {
		t.Fatalf("reopen run: %v\n%s", err, out.String())
	}
	finish(2)
	out.Reset()
	if err := runMigratePersonalCheckDrift(ctx, &out, s, false, now); err != nil || !strings.Contains(out.String(), "no drift") {
		t.Fatalf("gate after the second pass: %v\n%s", err, out.String())
	}
}
