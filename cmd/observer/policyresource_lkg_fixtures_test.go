package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The policy-resource last-known-good (LKG) test fixtures, shared by the
// obs-tagged policy-resource wire tests and the untagged sandbox floors
// source test (R-035). They carry no build tag and import no obs package,
// so the public tree, which drops the obs-tagged files, still builds and
// vets cmd/observer with its tests (TestReleasePublicPatchBuildsThePublicCmd).

// lkgSignedResource builds a verifiable admission.input SignedPolicyResource,
// mirroring internal/orgclient's own (unexported) signedTestResource helper.
func lkgSignedResource(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, body string) orgcontract.SignedPolicyResource {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	r := orgcontract.SignedPolicyResource{
		ID: "default", Version: version, Family: policyfam.FamilyAdmissionInput,
		CompilerVersion: "v1", Body: body, BodyHash: hex.EncodeToString(sum[:]),
		SelectorsJSON: "{}", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		SignedAt: "2026-08-12T00:00:00Z",
	}
	sig, err := orgcontract.SignPolicyResource(priv, r)
	if err != nil {
		t.Fatalf("SignPolicyResource: %v", err)
	}
	r.Signature = sig
	return r
}

// seedLKGEnrolment writes a live enrolment + bumps its generation to 1,
// mirroring what a real orgclient.Enroll leaves durably in the store.
func seedLKGEnrolment(t *testing.T, st *store.Store, orgURL string) string {
	t.Helper()
	ctx := context.Background()
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: orgURL,
		UserID: "u1", UserEmail: "dev@acme.example", BearerKeyID: "test",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	orgKey := orgclient.OrgKey(orgURL, "org-1")
	if _, err := st.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	return orgKey
}

// pinLKGKey records the org policy signing-key pin that SF2 / plan §4.4
// require before LKG will trust an on-disk cache (live fetch may still TOFU).
func pinLKGKey(t *testing.T, st *store.Store, orgURL string, pub ed25519.PublicKey) {
	t.Helper()
	if _, err := st.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
		Layer: "org", Path: orgclient.PolicyKeyPinPath(orgURL),
		ContentHash: orgcontract.PublicKeyPinHash(pub), LoadedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordGuardPolicyState pin: %v", err)
	}
}

// writeLKGCache writes a signed resource to the exact on-disk path
// loadPolicyResourceLKGFamily reads from
// (<cacheDir>/<orgKey>/<generation>/<family>.json — the same layout
// FetchAndAcceptPolicyResource itself writes to).
func writeLKGCache(t *testing.T, cacheDir, orgKey string, generation int64, resource orgcontract.SignedPolicyResource) {
	t.Helper()
	dir := filepath.Join(cacheDir, orgKey, strconv.FormatInt(generation, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, policyfam.FamilyAdmissionInput+".json"), raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// lkgTestSetup opens a fresh temp-dir DB + store and returns the base config
// (org-only-admission-service shaped: [org_client] on, admission.input
// accepted) plus the cache dir loadPolicyResourceLKG/policyResourceOptionsFor
// will resolve for it.
func lkgTestSetup(t *testing.T, preauthorizeEnforce []string) (config.Config, *store.Store, string) {
	t.Helper()
	pinToolHomes(t) // config.Default() puts the guard org-bundle cache under the home (FU-20)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	ctx := context.Background()
	conn, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	st := store.New(conn)

	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.Policy.AcceptFamilies = []string{policyfam.FamilyAdmissionInput}
	cfg.OrgClient.Policy.PreauthorizeEnforce = preauthorizeEnforce
	return cfg, st, policyResourceCacheDir(cfg)
}
