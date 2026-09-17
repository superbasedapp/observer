package main

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestStartupEmitsFullSnapshot is a cross-phase integration test that drives
// the REAL `observer start` path (newStartCmd + ExecuteContext) and proves the
// P0-6 effective-policy-state reporter is registered as a start-loop
// goroutine: the daemon emits a complete desired/effective snapshot at startup
// and POSTs it to the org server's policy-ack endpoint. Deleting the
// `g.Go(rep.run…)` registration (Task 2) makes this test time out — it is the
// mutation proof that the reporter is wired into start.go, not merely
// constructible.
//
// It is ALSO the v2 wiring proof: the snapshot must carry FIVE rows including
// proxy-gateway / gateway.providers
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md). Dropping
// the gateway reader from buildPolicyStateReporter, or failing to thread the
// shared *gatewayProvidersHandle into it from start.go, fails this test.
//
// The node is guard-off + routing-off + admission-off with no configured
// proxy lanes, so the guard and router rows must report none / empty-hash /
// zero versions (R2-B3) and the gateway row must report none / no_policy.
func TestStartupEmitsFullSnapshot(t *testing.T) {
	dir := t.TempDir()
	// Isolate the daemon's home so the real start path can never read or write
	// the developer's ~/.claude etc. (t.Setenv forbids t.Parallel — this test
	// is intentionally serial).
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")

	// Fake org server: capture the policy-ack POST body, 200 everything else
	// (the push loop / policy poll are WARN-only and must not fail the daemon).
	reports := make(chan orgcontract.PolicyStateReport, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/policy-ack" {
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
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Free proxy port + isolated, minimal daemon config with the P0-6 channel on.
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	// Unique keychain service id so seeding never collides with, or leaks into,
	// a real OS keychain across runs; Clear() below removes it.
	svc := make([]byte, 8)
	_, _ = rand.Read(svc)
	keychainID := "sbo-e2e-policystate-" + hex.EncodeToString(svc)

	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Observer.LogLevel = "error"
	cfg.Observer.Retention.PruneOnStartup = false
	cfg.Observer.Watch.EnabledAdapters = []string{}
	cfg.Observer.Hooks.AutoRegister = false
	cfg.Proxy.Port = port
	cfg.CodeIntel.Enabled = false
	cfg.Compression.Conversation.Enabled = false
	cfg.Guard.Enabled = false
	cfg.Terminal.Attach.Enabled = false
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = srv.URL
	cfg.OrgClient.KeychainID = keychainID
	cfg.OrgClient.Share.PolicyState = true
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}

	// Pre-seed the agent enrolment (so the client is "enrolled" and knows the
	// org URL) and the credential store (so PostPolicyState can sign). Seeding
	// via OpenBearerStore mirrors exactly what the daemon's buildOrgClient
	// reads back — same keychain service id + same DB directory.
	seedCtx := context.Background()
	database, err := dbtemplate.Open(seedCtx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open seed: %v", err)
	}
	st := store.New(database)
	if err := st.WriteEnrolment(seedCtx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL,
		UserID: "u1", UserEmail: "dev@acme.example", BearerKeyID: keychainID,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	_ = database.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bs := orgclient.OpenBearerStore(keychainID, dir, newLogger("error"))
	if err := bs.SaveBearer("test-bearer-value"); err != nil {
		t.Fatalf("SaveBearer: %v", err)
	}
	if err := bs.SaveAgentKey(priv); err != nil {
		t.Fatalf("SaveAgentKey: %v", err)
	}
	t.Cleanup(func() { _ = bs.Clear() })

	// Drive the real `observer start` under a cancelable context.
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

	var rep orgcontract.PolicyStateReport
	select {
	case rep = <-reports:
	case <-time.After(15 * time.Second):
		cancel()
		// Bounded wait: a shutdown regression must not hang the failure path to
		// the outer test timeout (mirrors the clean-shutdown select below).
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		t.Fatal("no policy-state report received within 15s — the reporter is not registered in start.go's org loop")
	}

	// Clean shutdown: cancel and wait for ExecuteContext to return.
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("observer start did not exit within 10s of cancel")
	}

	// The snapshot is the four core rows plus every OPTIONAL point
	// (proxy-gateway v2, node-dashboard v3).
	if want := 4 + len(policystate.OptionalPoints); len(rep.Rows) != want {
		t.Fatalf("report rows = %d, want %d: %+v", len(rep.Rows), want, rep.Rows)
	}
	byPoint := make(map[string]orgcontract.PolicyStateRow, len(rep.Rows))
	for _, row := range rep.Rows {
		byPoint[row.EnforcementPoint] = row
	}
	// Guard + router: guard-off / routing-off node ⇒ none, empty hash, zero
	// versions (R2-B3).
	for _, pt := range []string{"guard", "router"} {
		row, ok := byPoint[pt]
		if !ok {
			t.Fatalf("no %q row in snapshot: %+v", pt, rep.Rows)
		}
		if row.Status != "none" {
			t.Fatalf("%s status = %q, want none", pt, row.Status)
		}
		if row.EffectiveHash != "" {
			t.Fatalf("%s effective_hash = %q, want empty", pt, row.EffectiveHash)
		}
		if row.DesiredVersion != 0 || row.RunningVersion != 0 {
			t.Fatalf("%s versions = desired %d / running %d, want 0/0", pt, row.DesiredVersion, row.RunningVersion)
		}
	}

	// v2: the gateway.providers row is present and honest. This node has no
	// [proxy.upstreams] and no org rail, so nothing is routing.
	gw, ok := byPoint["proxy-gateway"]
	if !ok {
		t.Fatalf("no proxy-gateway row in snapshot: %+v", rep.Rows)
	}
	if gw.Family != "gateway.providers" {
		t.Fatalf("gateway family = %q, want gateway.providers", gw.Family)
	}
	if gw.Status != "none" || gw.Reason != "no_policy" {
		t.Fatalf("gateway status/reason = %s/%s, want none/no_policy", gw.Status, gw.Reason)
	}
	if gw.EffectiveHash != "" || gw.RunningVersion != 0 || gw.RestartRequired {
		t.Fatalf("gateway row = %+v, want an empty hash, zero versions, no restart", gw)
	}
}
