package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// grantIntegrityFixture stands up a governed node exactly as enrolment does:
// an enrolment row, a generation, the pinned org policy key, the key MATERIAL
// row (the thing that makes runtime re-verification possible at all), and a
// signed grant.
func grantIntegrityFixture(t *testing.T) (*store.Store, *sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const orgID = "org-grant-integrity"
	const orgURL = "https://org.example.test"
	orgKey := orgclient.OrgKey(orgURL, orgID)

	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: orgID, OrgName: "Integrity Test", OrgServerURL: orgURL,
		UserID: "member-1", Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	generation, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	pinHash := orgcontract.PublicKeyPinHash(pub)
	if _, _, err := st.EstablishOrgPolicyKeyPin(ctx, orgURL+"#policy-key", pinHash, "enrolment"); err != nil {
		t.Fatalf("EstablishOrgPolicyKeyPin: %v", err)
	}
	// The key MATERIAL row — orgclient.recordEnrolmentKeyMaterial's shape.
	if _, err := st.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        orgURL + orgclient.OrgKeyMaterialSuffix,
		Version:     base64.StdEncoding.EncodeToString(pub),
		ContentHash: pinHash,
		LoadedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordGuardPolicyState: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	wire := orgcontract.EnrolmentGrant{
		OrgID:        orgID,
		OrgServerURL: orgURL,
		KeyPinSHA256: pinHash,
		Authority:    orgcontract.CanonicalAuthority([]string{govern.AuthorityDashboardVisibility}),
		GrantedAt:    now.Format(time.RFC3339),
		ExpiresAt:    now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	wire.Signature = orgcontract.SignEnrolmentGrant(priv, wire)
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgKey, Generation: generation, OrgID: orgID, OrgName: "Integrity Test",
		OrgServerURL: orgURL, KeyPinSHA256: pinHash, Authority: wire.Authority,
		GrantedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Signature: wire.Signature, ReceiptHash: orgcontract.EnrolmentGrantReceiptHash(wire),
	}); err != nil {
		t.Fatalf("WriteEnrolmentGrant: %v", err)
	}
	return st, database, orgKey
}

// TestGovernanceIdentityLoaderReVerifiesStoredGrant is the Track C item 1
// end-to-end boundary assertion: an untouched grant resolves exactly as it
// did before, and a grant whose authority list was rewritten in the DB
// resolves LOUD instead of granting the rewritten authority.
func TestGovernanceIdentityLoaderReVerifiesStoredGrant(t *testing.T) {
	ctx := context.Background()
	st, database, orgKey := grantIntegrityFixture(t)
	load := governanceIdentityLoader(st)

	grant, live, err := load(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if grant == nil {
		t.Fatal("no grant loaded")
	}
	if grant.Integrity != govern.GrantIntegrityValid {
		t.Fatalf("untouched grant Integrity = %q, want valid", grant.Integrity)
	}
	if got := govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC()).State; got != govern.StateNoPolicy {
		t.Fatalf("untouched grant resolved %q, want no_policy (today's behaviour)", got)
	}

	// The tamper the feature exists to catch: widen the authority list in
	// the node-local SQLite row, which needs no root and no patched binary.
	widened, _ := json.Marshal([]string{
		govern.AuthorityDashboardVisibility,
		govern.AuthorityEnforceBudget,
		govern.AuthorityExtractManaged,
	})
	if _, err := database.ExecContext(ctx,
		`UPDATE org_enrolment_grant SET authority_json = ? WHERE org_key = ?`,
		string(widened), orgKey); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	grant, live, err = load(ctx)
	if err != nil {
		t.Fatalf("load after tamper: %v", err)
	}
	if grant.Integrity != govern.GrantIntegrityInvalid {
		t.Fatalf("tampered grant Integrity = %q, want invalid", grant.Integrity)
	}
	eff := govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC())
	if eff.State != govern.StateGrantSignatureInvalid {
		t.Fatalf("tampered grant resolved %q, want grant_signature_invalid", eff.State)
	}
	if eff.GrantsBudgetEnforcement() {
		t.Fatal("a tampered grant granted budget enforcement — the rewrite took effect")
	}
}

// TestGovernanceIdentityLoaderUncheckableWithoutKeyMaterial pins the honest
// degradation: a node with no recorded org key material reports UNCHECKED and
// keeps today's behaviour, rather than being accused of tampering.
func TestGovernanceIdentityLoaderUncheckableWithoutKeyMaterial(t *testing.T) {
	ctx := context.Background()
	st, database, _ := grantIntegrityFixture(t)
	if _, err := database.ExecContext(ctx,
		`DELETE FROM guard_policy_state WHERE path LIKE '%'||?`, orgclient.OrgKeyMaterialSuffix); err != nil {
		t.Fatalf("remove key material: %v", err)
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if grant.Integrity != govern.GrantIntegrityUnchecked {
		t.Fatalf("Integrity = %q, want unchecked", grant.Integrity)
	}
	if got := govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC()).State; got != govern.StateNoPolicy {
		t.Fatalf("unchecked grant resolved %q, want no_policy (unchanged behaviour)", got)
	}
}
