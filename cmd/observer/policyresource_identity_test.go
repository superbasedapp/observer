package main

// AA-67 / T-673: the org-policy install gate is the org client's identity
// read, never the Plane A admission handle. This file carries NO build tag,
// so it runs in the full build AND in every build without obs
// (sbo_omit_obs, no_obs, sbo_omit_judge_client), where the admission handle
// is always nil. Before the fix every org policy family (node.features,
// node.governance, tools.mcp_access, gateway.providers) was dropped in those
// builds because the gate asked the nil handle.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
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

const identTestOrgURL = "https://org.example"

// identTestStore opens a fresh DB and returns its store plus a config with
// the org rail on and node.features accepted and preauthorized.
func identTestStore(t *testing.T) (config.Config, *store.Store) {
	t.Helper()
	pinToolHomes(t) // config.Default() puts the guard org-bundle cache under the home (FU-20)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	conn, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = identTestOrgURL
	cfg.OrgClient.Policy.AcceptFamilies = []string{policyfam.FamilyNodeFeatures}
	cfg.OrgClient.Policy.PreauthorizeEnforce = []string{policyfam.FamilyNodeFeatures}
	return cfg, store.New(conn)
}

// identSeedEnrolment writes a live enrolment at generation 1 and returns its
// org key.
func identSeedEnrolment(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := context.Background()
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: identTestOrgURL,
		UserID: "u1", UserEmail: "dev@acme.example", BearerKeyID: "test",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	orgKey := orgclient.OrgKey(identTestOrgURL, "org-1")
	if _, err := st.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	return orgKey
}

// identNoBearer is an empty orgclient.BearerStore: a family with no cache
// makes the loader refetch, and a missing bearer ends that refetch as "not
// enrolled" without any network call.
type identNoBearer struct{}

func (identNoBearer) SaveBearer(string) error                   { return nil }
func (identNoBearer) LoadBearer() (string, error)               { return "", orgclient.ErrNoSecret }
func (identNoBearer) SaveAgentKey(ed25519.PrivateKey) error     { return nil }
func (identNoBearer) LoadAgentKey() (ed25519.PrivateKey, error) { return nil, orgclient.ErrNoSecret }
func (identNoBearer) Clear() error                              { return nil }
func (identNoBearer) Backend() string                           { return "none" }
func (identNoBearer) SaveVirtualKey(string, uint64) error       { return nil }
func (identNoBearer) LoadVirtualKey() (string, uint64, error)   { return "", 0, nil }

func identTestClient(st *store.Store) *orgclient.Client {
	return orgclient.New(config.OrgClientConfig{OrgServerURL: identTestOrgURL}, st, identNoBearer{}, "test", nil, slog.Default())
}

// TestOrgIdentityGateTable pins the gate's answer per enrolment state, one
// row per state. It never consults any admission handle.
func TestOrgIdentityGateTable(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(t *testing.T, st *store.Store) (orgKey string, gen int64)
		nilOC  bool
		expect bool
	}{
		{"nil org client fails closed", func(t *testing.T, st *store.Store) (string, int64) { return identSeedEnrolment(t, st), 1 }, true, false},
		{"not enrolled fails closed", func(t *testing.T, st *store.Store) (string, int64) {
			return orgclient.OrgKey(identTestOrgURL, "org-1"), 1
		}, false, false},
		{"live enrolment at the same generation matches", func(t *testing.T, st *store.Store) (string, int64) { return identSeedEnrolment(t, st), 1 }, false, true},
		{"a stale generation does not match", func(t *testing.T, st *store.Store) (string, int64) {
			k := identSeedEnrolment(t, st)
			if _, err := st.BumpEnrolmentGeneration(context.Background(), k, false); err != nil {
				t.Fatalf("bump: %v", err)
			}
			return k, 1
		}, false, false},
		{"a tombstoned generation fails closed", func(t *testing.T, st *store.Store) (string, int64) {
			k := identSeedEnrolment(t, st)
			g, err := st.BumpEnrolmentGeneration(context.Background(), k, true)
			if err != nil {
				t.Fatalf("tombstone: %v", err)
			}
			return k, g
		}, false, false},
		{"another org key does not match", func(t *testing.T, st *store.Store) (string, int64) {
			identSeedEnrolment(t, st)
			return orgclient.OrgKey(identTestOrgURL, "org-2"), 1
		}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, st := identTestStore(t)
			key, gen := tc.setup(t, st)
			oc := identTestClient(st)
			if tc.nilOC {
				oc = nil
			}
			if got := orgIdentityGateFor(context.Background(), oc).matches(key, gen); got != tc.expect {
				t.Errorf("gate(%s..., %d) = %v, want %v", key[:8], gen, got, tc.expect)
			}
		})
	}
	var nilGate orgIdentityGate
	if nilGate.matches("k", 1) {
		t.Error("a nil gate must fail closed")
	}
}

// TestLKGInstallsNodeFeaturesWithoutAdmissionHandle is the AA-67 regression:
// a verified on-disk node.features envelope installs through the LKG loader
// with a NIL admission handle (what every build without obs passes). Run it
// with -tags sbo_omit_obs to prove the developer distro installs org policy.
func TestLKGInstallsNodeFeaturesWithoutAdmissionHandle(t *testing.T) {
	cfg, st := identTestStore(t)
	orgKey := identSeedEnrolment(t, st)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := `{"remote":{"enabled":false}}`
	sum := sha256.Sum256([]byte(body))
	res := orgcontract.SignedPolicyResource{
		ID: "default", Version: 3, Family: policyfam.FamilyNodeFeatures,
		CompilerVersion: "v1", Body: body, BodyHash: hex.EncodeToString(sum[:]),
		SelectorsJSON: "{}", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		SignedAt: "2026-10-08T00:00:00Z",
	}
	sig, err := orgcontract.SignPolicyResource(priv, res)
	if err != nil {
		t.Fatalf("SignPolicyResource: %v", err)
	}
	res.Signature = sig
	if _, err := st.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
		Layer: "org", Path: orgclient.PolicyKeyPinPath(identTestOrgURL),
		ContentHash: orgcontract.PublicKeyPinHash(pub), LoadedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("pin key: %v", err)
	}
	dir := filepath.Join(policyResourceCacheDir(cfg), orgKey, strconv.FormatInt(1, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, policyfam.FamilyNodeFeatures+".json"), raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The envelope must verify on its own, so the loader takes the
	// install path (no network) rather than a refetch.
	if _, err := verifyCachedPolicyResource(context.Background(), st, identTestOrgURL, policyfam.FamilyNodeFeatures,
		filepath.Join(dir, policyfam.FamilyNodeFeatures+".json"), policyResourceOptionsFor(cfg, nil).NodeAttrs); err != nil {
		t.Fatalf("test envelope does not verify: %v", err)
	}

	nf := newNodeFeaturesHandle()
	loadPolicyResourceLKG(context.Background(), cfg, identTestClient(st), st, nil, nil, nil, nf, slog.Default())

	f := nf.Facts()
	if !f.HasOrgRail || !f.InEffect || f.Version != 3 {
		t.Fatalf("node.features after LKG with a nil admission handle: %+v; want installed and in effect at version 3 (AA-67)", f)
	}
}
