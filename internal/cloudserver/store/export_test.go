package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// export_test.go holds the W6d export invariants (divergence-remediation plan §3
// W6d; closes D11): the assembly is complete and content-scoped, RLS isolates
// the download, expiry is enforced two ways (read + sweep), the WorkOS step-up
// consumes atomically with assembly, deletion purges artifacts, and the
// production role holds the sweep-function EXECUTE. Ground truth for the
// assembled shape was established by calling the path against live PG before
// these were written (a temporary probe, deleted).

// seedExportableAccount populates one account with a device (from login), a
// consent receipt+event, a session with a result and a user correction, and a
// structural day — every "in export" object class the assembly reads.
func seedExportableAccount(t *testing.T, s *store.Store, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	acct := makeAccount(t, s)
	rid := completeResultInSession(t, s, acct, "wk", "cs-1", "k-1", "AI title", now)
	if _, err := s.ApplyResultCorrection(ctx, acct, rid, 0, "kk1", []byte(`{"title":"edited title"}`), store.CorrectionSourcePortal, now); err != nil {
		t.Fatalf("correction: %v", err)
	}
	if _, _, err := s.RecordPreviewConfirmation(ctx, acct, store.PreviewConfirmationInput{
		Purposes: []string{"bounded_context_enrichment"}, FieldClasses: []string{"content_excerpts"},
		EvidenceSchema: "session-evidence.v1-candidate", ScrubberVersion: "v1",
		UploadDigest: "sha256:preview", Now: now,
	}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	return acct
}

// TestExportAssemblesAccountData proves the assembly is complete and correctly
// shaped: the immutable AI result, the user revision, the consent receipt, the
// device summary, and the schema/TTL are all present.
func TestExportAssemblesAccountData(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := seedExportableAccount(t, s, now)

	meta, err := s.CreateExportArtifact(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateExportArtifact: %v", err)
	}
	if meta.ExpiresAt.Sub(meta.CreatedAt) != store.ExportArtifactTTL {
		t.Fatalf("TTL = %v, want %v", meta.ExpiresAt.Sub(meta.CreatedAt), store.ExportArtifactTTL)
	}
	if meta.SizeBytes <= 0 {
		t.Fatalf("size = %d, want > 0", meta.SizeBytes)
	}

	body, gmeta, err := s.GetExportArtifact(ctx, acct, meta.ID, now)
	if err != nil {
		t.Fatalf("GetExportArtifact: %v", err)
	}
	if gmeta.ID != meta.ID || gmeta.SizeBytes != meta.SizeBytes {
		t.Fatalf("download meta mismatch: %+v vs %+v", gmeta, meta)
	}

	var doc cloudcontract.AccountExport
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != cloudcontract.AccountExportSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", doc.SchemaVersion, cloudcontract.AccountExportSchemaVersion)
	}
	if doc.AccountID != acct {
		t.Fatalf("account_id = %q, want %q", doc.AccountID, acct)
	}
	if len(doc.Devices) != 1 || doc.Devices[0].Label == "" {
		t.Fatalf("devices = %+v, want 1 with a label", doc.Devices)
	}
	if len(doc.Consents.Receipts) != 1 || len(doc.Consents.Events) == 0 {
		t.Fatalf("consents = %+v, want a receipt + at least one event", doc.Consents)
	}
	if len(doc.Sessions) != 1 || len(doc.Sessions[0].Results) != 1 {
		t.Fatalf("sessions = %+v, want 1 session with 1 result", doc.Sessions)
	}
	res := doc.Sessions[0].Results[0]
	if !strings.Contains(string(res.Result), "AI title") {
		t.Fatalf("result body did not carry the immutable AI original: %s", res.Result)
	}
	if len(res.Revisions) != 1 || !strings.Contains(string(res.Revisions[0].Correction), "edited title") {
		t.Fatalf("revision history missing the user correction: %+v", res.Revisions)
	}
	if len(doc.Usage.Entitlements) == 0 {
		t.Fatalf("usage entitlements empty")
	}
}

// TestExportOmitsCredentialsAndForeignData proves the export carries the
// account's own data ONLY — never device credentials, identity email/subject, or
// evidence bytes (the matrix's "no"/"excluded" objects).
func TestExportOmitsCredentialsAndForeignData(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := seedExportableAccount(t, s, now)

	// Read the device thumbprint that MUST NOT appear in the export.
	var thumbprint string
	if err := pool.QueryRow(ctx,
		`SELECT thumbprint FROM device_registrations WHERE account_id=$1::uuid LIMIT 1`, acct).Scan(&thumbprint); err != nil {
		t.Fatalf("read thumbprint: %v", err)
	}
	// And the identity subject.
	var subject string
	if err := pool.QueryRow(ctx,
		`SELECT subject FROM identity_links WHERE account_id=$1::uuid LIMIT 1`, acct).Scan(&subject); err != nil {
		t.Fatalf("read subject: %v", err)
	}

	meta, err := s.CreateExportArtifact(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateExportArtifact: %v", err)
	}
	body, _, err := s.GetExportArtifact(ctx, acct, meta.ID, now)
	if err != nil {
		t.Fatalf("GetExportArtifact: %v", err)
	}
	blob := string(body)
	for _, forbidden := range []string{thumbprint, subject, "public_key", "ciphertext", "\"subject\""} {
		if forbidden != "" && strings.Contains(blob, forbidden) {
			t.Errorf("export leaked %q (credential/identity/foreign data must never appear)", forbidden)
		}
	}
}

// TestExportRLSIsolation proves one account can never download another's export:
// the read is RLS-scoped, so a foreign id is indistinguishable from a missing
// one (ErrNotFound — the correct non-disclosure).
func TestExportRLSIsolation(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	a := seedExportableAccount(t, s, now)
	b := makeAccount(t, s)

	meta, err := s.CreateExportArtifact(ctx, a, now)
	if err != nil {
		t.Fatalf("CreateExportArtifact: %v", err)
	}
	if _, _, err := s.GetExportArtifact(ctx, b, meta.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-account download: got %v, want ErrNotFound", err)
	}
	// A malformed id is likewise simply not-found, never a 500.
	if _, _, err := s.GetExportArtifact(ctx, a, "not-a-uuid", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed id: got %v, want ErrNotFound", err)
	}
}

// TestExportExpiryEnforcedByReadAndSweep proves both expiry triggers: a read
// past expires_at returns ErrExportExpired even before the sweep runs, and the
// sweep deletes the expired artifact while leaving a live one.
func TestExportExpiryEnforcedByReadAndSweep(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := seedExportableAccount(t, s, now)

	old, err := s.CreateExportArtifact(ctx, acct, now.Add(-store.ExportArtifactTTL-time.Hour)) // already expired
	if err != nil {
		t.Fatalf("CreateExportArtifact(old): %v", err)
	}
	fresh, err := s.CreateExportArtifact(ctx, acct, now)
	if err != nil {
		t.Fatalf("CreateExportArtifact(fresh): %v", err)
	}

	// The expired one reads as ErrExportExpired (read-time enforcement).
	if _, _, err := s.GetExportArtifact(ctx, acct, old.ID, now); !errors.Is(err, store.ErrExportExpired) {
		t.Fatalf("expired read: got %v, want ErrExportExpired", err)
	}
	// The fresh one still downloads.
	if _, _, err := s.GetExportArtifact(ctx, acct, fresh.ID, now); err != nil {
		t.Fatalf("fresh read: %v", err)
	}

	// Sweep deletes exactly the expired one.
	n, err := s.SweepExpiredExports(ctx, now)
	if err != nil {
		t.Fatalf("SweepExpiredExports: %v", err)
	}
	if n != 1 {
		t.Fatalf("sweep deleted %d, want 1", n)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM export_artifacts WHERE account_id=$1::uuid`, acct).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("remaining artifacts = %d, want 1 (the fresh one)", remaining)
	}

	// A live listing shows only the fresh one.
	metas, err := s.ListExportArtifacts(ctx, acct, now)
	if err != nil {
		t.Fatalf("ListExportArtifacts: %v", err)
	}
	if len(metas) != 1 || metas[0].ID != fresh.ID {
		t.Fatalf("live listing = %+v, want just the fresh artifact", metas)
	}
}

// exportStepUpFixture signs in and mints an EXPORT step-up bound to the session.
func exportStepUpFixture(t *testing.T, s *store.Store, subject string, now time.Time) (account, sessionID, authzID string) {
	t.Helper()
	ctx := context.Background()
	sess, err := s.PortalLogin(ctx, "dev", subject, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	authz, err := s.CreateStepUpAuthorization(ctx, sess.AccountID, bp.SessionID, store.StepUpActionExport, now)
	if err != nil {
		t.Fatalf("CreateStepUpAuthorization(export): %v", err)
	}
	return sess.AccountID, bp.SessionID, authz.ID
}

// TestExportWithStepUpAtomicity proves the WorkOS export path: a valid step-up
// assembles AND is consumed (a replay is refused); an invalid step-up refuses
// and writes NO artifact (a refused reauth never leaks data).
func TestExportWithStepUpAtomicity(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	acct, sessionID, authzID := exportStepUpFixture(t, s, "export-erin", now)

	meta, err := s.CreateExportArtifactWithStepUp(ctx, acct, sessionID, authzID, now)
	if err != nil {
		t.Fatalf("CreateExportArtifactWithStepUp: %v", err)
	}
	if meta.ID == "" {
		t.Fatal("no artifact id returned")
	}
	// The authorization is spent: a replay is refused.
	if _, err := s.CreateExportArtifactWithStepUp(ctx, acct, sessionID, authzID, now); !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("replayed step-up: got %v, want ErrStepUpInvalid", err)
	}

	// A brand-new account with a bogus step-up: refused AND no artifact written.
	acct2, sessionID2, _ := exportStepUpFixture(t, s, "export-eve", now)
	if _, err := s.CreateExportArtifactWithStepUp(ctx, acct2, sessionID2, "00000000-0000-0000-0000-000000000000", now); !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("bogus step-up: got %v, want ErrStepUpInvalid", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM export_artifacts WHERE account_id=$1::uuid`, acct2).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("a refused step-up wrote %d artifact(s); want 0", n)
	}
}

// TestDeletionPurgesExportArtifacts proves an assembled export is deleted by the
// account-deletion pass (an export is itself account data).
func TestDeletionPurgesExportArtifacts(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := seedExportableAccount(t, s, now)

	if _, err := s.CreateExportArtifact(ctx, acct, now); err != nil {
		t.Fatalf("CreateExportArtifact: %v", err)
	}
	var before int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM export_artifacts WHERE account_id=$1::uuid`, acct).Scan(&before)
	if before == 0 {
		t.Fatal("fixture did not create an export artifact")
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	var after int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM export_artifacts WHERE account_id=$1::uuid`, acct).Scan(&after); err != nil {
		t.Fatalf("count: %v", err)
	}
	if after != 0 {
		t.Fatalf("export artifacts survived deletion: %d rows", after)
	}
}

// TestExportSweepFunctionDeployedShape pins the SECURITY DEFINER sweep primitive
// (mirrors the W5 deployed-shape discipline): owned by sbci_defs, SECURITY
// DEFINER, search_path pinned to public, and EXECUTE granted to the PRODUCTION
// serve role (sbci_api) — the functional tests run as sbci_app, so without this
// a missing sbci_api grant would pass the suite but fail the serve loop.
func TestExportSweepFunctionDeployedShape(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	var owner, cfg string
	var secdef bool
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig,','),'')
		   FROM pg_proc WHERE proname='sbci_sweep_expired_exports'`).Scan(&owner, &secdef, &cfg); err != nil {
		t.Fatalf("introspect sweep fn: %v", err)
	}
	if owner != "sbci_defs" {
		t.Errorf("sweep fn owner = %q, want sbci_defs", owner)
	}
	if !secdef {
		t.Error("sweep fn is not SECURITY DEFINER")
	}
	if cfg != "search_path=public" {
		t.Errorf("sweep fn proconfig = %q, want search_path=public", cfg)
	}
	var canExec bool
	if err := pool.QueryRow(ctx,
		`SELECT has_function_privilege('sbci_api', 'sbci_sweep_expired_exports(timestamptz)', 'EXECUTE')`).Scan(&canExec); err != nil {
		t.Fatalf("has_function_privilege: %v", err)
	}
	if !canExec {
		t.Error("sbci_api lacks EXECUTE on sbci_sweep_expired_exports — the serve-loop sweep would fail")
	}
}
