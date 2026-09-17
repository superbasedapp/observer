package main

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestReloadConvergesPendingRestartToEffective is the JOINT P0-6 + P0-7
// convergence e2e (plan §7.3, fold SF9): the elevated acceptance bar for the
// guard + router live hot-reload. It drives the REAL `observer start` path
// (newStartCmd + ExecuteContext) with guard AND routing turned ON and pointed
// at a fake org server serving SIGNED, MUTABLE v1->v2 documents, and proves that
// when the org publishes a new policy version, BOTH org-rail enforcement points
// converge accepted -> effective LIVE — via the real poll loops
// (PolicyPollLoop + the PushLoop routing fetch), with NO daemon restart — so the
// P0-6 snapshot flips from effective@v1 to effective@v2 and NEVER gets stuck at
// pending_restart.
//
// Seeding (the "effective@v1 first" bar): the node is pre-seeded so both points
// start EFFECTIVE at v1 before any poll runs —
//   - the guard org-bundle CACHE file holds a signed v1 bundle + the org signing
//     key is pinned in guard_policy_state, so guard.New loads the org layer at v1;
//   - org_routing_policies holds a signed v1 row, so wireRouting composes the
//     router's org layer at v1.
//
// The fake server serves v1 for both endpoints initially; the first policy-ack
// snapshot therefore already reads effective@v1 for guard + router. Then the
// served docs flip to v2 (a v2-only guard override / a v2-only routing rule, so
// the content hash actually changes) WITHOUT restarting the daemon; the next
// converged snapshot must report effective@v2 (running == cached == 2, a new
// hash) for both.
//
// MUTATION PROOF (SF9, the convergence proof): neuter BOTH reloads
// (guard.Guard.ReloadOrgLayer + liveRouter.ReloadOrgPolicy to early `return nil`
// no-ops) and this test FAILS — the cache advances to v2 but the live engines
// stay at v1, so the snapshot stays pending_restart at running-v1/cached-v2.
func TestReloadConvergesPendingRestartToEffective(t *testing.T) {
	dir := t.TempDir()
	// Isolate the daemon's home so the real start path can never read/write the
	// developer's ~/.claude etc. t.Setenv forbids t.Parallel — intentionally serial.
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")

	// The ONE org distribution identity: a single Ed25519 keypair signs BOTH the
	// guard bundles and the routing docs (the org server signs every rail with
	// the same key — orgpin.go). The guard pins its pin-hash; the routing rail
	// TOFU-pins the raw key on the seeded v1 row.
	orgPub, orgPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("org keygen: %v", err)
	}
	orgKeyPinHash := orgcontract.PublicKeyPinHash(orgPub)

	// --- the signed, mutable v1 -> v2 documents ------------------------------
	// Guard bundles: escalating org overrides (lint-clean as an org layer). v2
	// adds a SECOND override so sha256(BundleTOML) — the guard's EffectiveHash —
	// actually changes.
	guardTOMLv1 := "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n"
	guardTOMLv2 := guardTOMLv1 + "\n[[override]]\nrule = \"R-111\"\ndecision = \"deny\"\nenforce = true\n"
	guardV1JSON := signedGuardBundleJSON(t, orgPriv, orgPub, 1, guardTOMLv1)
	guardV2JSON := signedGuardBundleJSON(t, orgPriv, orgPub, 2, guardTOMLv2)

	// Routing docs: a single org soft rule (composes + lints clean onto the
	// local "value" spec). v2 uses a DIFFERENT rule so the recomposed
	// routing.Policy.Hash() — the router's EffectiveHash — changes.
	routingBodyV1 := "[routing]\n[[routing.rules]]\nname = \"org_v1\"\n" +
		"when = { turn_kind = \"edit\", tier_at_least = \"opus-class\" }\n" +
		"action = { route_to_tier = \"sonnet-class\", reason = \"phase_pin\" }\n"
	routingBodyV2 := "[routing]\n[[routing.rules]]\nname = \"org_v2\"\n" +
		"when = { turn_kind = \"test_run\", tier_at_least = \"sonnet-class\" }\n" +
		"action = { route_to_tier = \"haiku-class\", reason = \"overpowered_test_run\" }\n"
	routingV1Doc := signedRoutingDocMain(orgPriv, orgPub, 1, routingBodyV1)
	routingV2Doc := signedRoutingDocMain(orgPriv, orgPub, 2, routingBodyV2)

	// The server's current view of each rail, flipped v1 -> v2 under the test's
	// control via atomic pointers the handler reads.
	var servedGuard atomic.Pointer[string]
	var servedRouting atomic.Pointer[orgcontract.RoutingPolicyDoc]
	servedGuard.Store(&guardV1JSON)
	servedRouting.Store(&routingV1Doc)

	// Fake org server: serve the two signed rails + capture the policy-ack POST
	// (how we READ the P0-6 snapshot back). Everything else 200s so the push /
	// announcement loops never fail the daemon.
	reports := make(chan orgcontract.PolicyStateReport, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/policy-ack":
			if gz, err := gzip.NewReader(r.Body); err == nil {
				if raw, err := io.ReadAll(gz); err == nil {
					var rep orgcontract.PolicyStateReport
					if json.Unmarshal(raw, &rep) == nil {
						select {
						case reports <- rep:
						default:
						}
					}
				}
			}
			w.WriteHeader(http.StatusOK)
		case "/api/v1/policy-bundle":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, *servedGuard.Load())
		case "/api/agent/routing-policy":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(*servedRouting.Load())
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	svc := make([]byte, 8)
	_, _ = rand.Read(svc)
	keychainID := "sbo-e2e-convergence-" + hex.EncodeToString(svc)

	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Observer.LogLevel = "error"
	cfg.Observer.Retention.PruneOnStartup = false
	cfg.Observer.Watch.EnabledAdapters = []string{}
	cfg.Observer.Hooks.AutoRegister = false
	cfg.Proxy.Port = port
	cfg.CodeIntel.Enabled = false
	cfg.Compression.Conversation.Enabled = false
	cfg.Terminal.Attach.Enabled = false
	// Guard ON (default enabled+observe): the guard point is always enforceIntent
	// for P0-6, and mode != "off" arms the org policy-bundle poll loop.
	cfg.Guard.Enabled = true
	cfg.Guard.Mode = "observe"
	// Routing ON in ENFORCE mode: enforce is required for the router point to
	// resolve to `effective` (observe -> accepted_inert, which would never prove
	// the pending_restart -> effective transition). Enforce also yields a
	// non-nil RoutingStateHandle so the router reports at all.
	cfg.Routing.Enabled = true
	cfg.Routing.Mode = "enforce"
	// P0-6 reverse channel on.
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = srv.URL
	cfg.OrgClient.KeychainID = keychainID
	cfg.OrgClient.Share.PolicyState = true
	// Drive the real poll loops fast: guard poll (PolicyPollLoop) + routing fetch
	// (rides PushLoop) + the reporter heartbeat all at ~1s.
	cfg.OrgClient.PolicyPollIntervalSeconds = 1
	cfg.OrgClient.PushIntervalSeconds = 1
	cfg.OrgClient.PolicyStateHeartbeatSeconds = 1
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}

	// --- pre-seed the node so BOTH points start EFFECTIVE at v1 --------------
	seedCtx := context.Background()
	database, err := dbtemplate.Open(seedCtx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open seed: %v", err)
	}
	st := store.New(database)
	// Enrolment (client is "enrolled" and knows the org URL).
	if err := st.WriteEnrolment(seedCtx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL,
		UserID: "u1", UserEmail: "dev@acme.example", BearerKeyID: keychainID,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	// Guard org key pin (the daemon's buildGuardForStore reads this so the org
	// bundle loader requires the cached envelope's key to match it).
	if _, err := st.RecordGuardPolicyState(seedCtx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        orgclient.PolicyKeyPinPath(srv.URL),
		ContentHash: orgKeyPinHash,
		LoadedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed guard key pin: %v", err)
	}
	// Routing org policy v1 (wireRouting composes this at construction -> router
	// running v1; the ServerPubkey is the routing rail's TOFU pin, so the served
	// v2 must present the SAME key).
	{
		sum := sha256.Sum256([]byte(routingBodyV1))
		if err := st.UpsertOrgRoutingPolicy(seedCtx, store.OrgRoutingPolicyRow{
			Version: 1, Body: routingBodyV1, BodyHash: hex.EncodeToString(sum[:]),
			Signature:    routingV1Doc.Signature,
			ServerPubkey: base64.StdEncoding.EncodeToString(orgPub),
			ReceivedAt:   time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seed routing policy v1: %v", err)
		}
	}
	_ = database.Close()

	// Guard org-bundle CACHE file v1 (guard.New loads the org layer from here).
	cachePath := orgBundleCachePath(cfg)
	if cachePath == "" {
		t.Fatal("orgBundleCachePath resolved empty — the guard org rail would be off")
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	if err := os.WriteFile(cachePath, []byte(guardV1JSON), 0o600); err != nil {
		t.Fatalf("seed guard bundle cache: %v", err)
	}

	// Credential store: bearer (so the client authenticates) + a node push key
	// (so PostPolicyState / PushOnce can sign). This agent key is DISTINCT from
	// the org signing key above.
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}
	bs := orgclient.OpenBearerStore(keychainID, dir, newLogger("error"))
	if err := bs.SaveBearer("test-bearer-value"); err != nil {
		t.Fatalf("SaveBearer: %v", err)
	}
	if err := bs.SaveAgentKey(agentPriv); err != nil {
		t.Fatalf("SaveAgentKey: %v", err)
	}
	t.Cleanup(func() { _ = bs.Clear() })

	// --- drive the real `observer start` -------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	startCmd := newStartCmd()
	// newStartCmd records its --config process-wide (setDaemonConfigPath) so
	// dashboard children inherit it; reset so the value cannot leak into
	// later tests in this package.
	t.Cleanup(func() { setDaemonConfigPath("") })
	startCmd.SetArgs([]string{"--no-dashboard", "--no-open", "--config", cfgPath})
	startCmd.SetOut(io.Discard)
	startCmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- startCmd.ExecuteContext(ctx) }()
	// Clean shutdown even on a Fatalf: cancel + bounded wait for exit.
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("observer start did not exit within 10s of cancel")
		}
	})

	// Step 1: both points converge to EFFECTIVE at v1 (running == desired == 1).
	// With the pre-seed this is the very first snapshot; drain until we see it.
	guardHashV1, routerHashV1 := awaitConverged(t, reports, 1, 20*time.Second)

	// Step 2: publish v2 for BOTH rails — WITHOUT restarting the daemon.
	servedGuard.Store(&guardV2JSON)
	servedRouting.Store(&routingV2Doc)

	// Step 3: both points converge to EFFECTIVE at v2 (running == desired == 2),
	// i.e. they NEVER got stuck at pending_restart. This is the P0-7 convergence.
	guardHashV2, routerHashV2 := awaitConverged(t, reports, 2, 20*time.Second)

	// The running identity actually changed with the version (a new hash), not
	// just the version counter — proof the LIVE engines recomposed, not merely
	// that the cache advanced.
	if guardHashV2 == "" || guardHashV2 == guardHashV1 {
		t.Fatalf("guard EffectiveHash did not change on the v2 reload: v1=%q v2=%q", guardHashV1, guardHashV2)
	}
	if routerHashV2 == "" || routerHashV2 == routerHashV1 {
		t.Fatalf("router EffectiveHash did not change on the v2 reload: v1=%q v2=%q", routerHashV1, routerHashV2)
	}
}

// awaitConverged drains policy-ack snapshots until ONE reports BOTH the guard
// and router org-rail points EFFECTIVE at wantVersion (running == desired ==
// wantVersion), returning that snapshot's guard + router EffectiveHash. On
// timeout it FAILs with the last snapshot's guard/router rows so a
// stuck-at-pending_restart regression (the SF9 mutation) is legible.
func awaitConverged(t *testing.T, reports <-chan orgcontract.PolicyStateReport, wantVersion int64, timeout time.Duration) (guardHash, routerHash string) {
	t.Helper()
	deadline := time.After(timeout)
	var last orgcontract.PolicyStateReport
	haveLast := false
	for {
		select {
		case rep := <-reports:
			last, haveLast = rep, true
			by := make(map[string]orgcontract.PolicyStateRow, len(rep.Rows))
			for _, row := range rep.Rows {
				by[row.EnforcementPoint] = row
			}
			g, gok := by["guard"]
			rt, rok := by["router"]
			if gok && rok &&
				g.Status == orgcontract.StatusEffective && g.RunningVersion == wantVersion && g.DesiredVersion == wantVersion &&
				rt.Status == orgcontract.StatusEffective && rt.RunningVersion == wantVersion && rt.DesiredVersion == wantVersion {
				if g.EffectiveHash == "" || rt.EffectiveHash == "" {
					t.Fatalf("effective@v%d but an EffectiveHash is empty: guard=%+v router=%+v", wantVersion, g, rt)
				}
				return g.EffectiveHash, rt.EffectiveHash
			}
		case <-deadline:
			if !haveLast {
				t.Fatalf("no policy-state snapshot within %s while awaiting effective@v%d", timeout, wantVersion)
			}
			by := make(map[string]orgcontract.PolicyStateRow, len(last.Rows))
			for _, row := range last.Rows {
				by[row.EnforcementPoint] = row
			}
			t.Fatalf("guard+router did not converge to effective@v%d within %s (P0-7 reload did not fire — stuck?):\n  guard=%+v\n  router=%+v",
				wantVersion, timeout, by["guard"], by["router"])
		}
	}
}

// signedGuardBundleJSON builds a verifiable org policy-bundle envelope JSON the
// same way internal/guard/bundle_test.go's signedEnvelope does (Ed25519 over
// PolicyBundleSigningMessage(version, bundleTOML); base64url public key).
func signedGuardBundleJSON(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, bundleTOML string) string {
	t.Helper()
	b := orgcontract.PolicyBundle{
		Version:    version,
		BundleTOML: bundleTOML,
		Signature:  orgcontract.SignPolicyBundle(priv, version, []byte(bundleTOML)),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:   "2026-08-12T00:00:00Z",
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal guard bundle: %v", err)
	}
	return string(raw)
}

// signedRoutingDocMain builds a verifiable orgcontract.RoutingPolicyDoc the same
// way internal/orgclient/routingpolicy_test.go's signedRoutingDoc does (raw
// Ed25519 over the body bytes; hash = hex(sha256(body)); base64-std key).
func signedRoutingDocMain(priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, body string) orgcontract.RoutingPolicyDoc {
	sum := sha256.Sum256([]byte(body))
	return orgcontract.RoutingPolicyDoc{
		Version:   version,
		Body:      body,
		BodyHash:  hex.EncodeToString(sum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(body))),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}
