package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgEmptyURLResult is what runOrgEmptyURLTestNode reports back to each
// of the three truth-table cases below.
type orgEmptyURLResult struct {
	output      string // combined stdout+stderr (both point at the same buffer)
	hits        int64  // requests the fake org server actually received
	pushLogRows int    // rows in org_push_log after the run
}

// runOrgEmptyURLTestNode drives the REAL `observer start` path (same
// pattern as TestStartupEmitsFullSnapshot) against a scratch node with
// [org_client].enabled = true, an optional config org_server_url, and an
// optional PERSISTED org_enrolment DB row — the two independent axes of
// orgClientShouldStart's truth table (cmd/observer/start.go). The fake
// org server is reachable ONLY via the URL this harness controls, so a
// hit against it proves a specific dial path fired: either the config
// URL (useConfigURL) or the DB-persisted row's own URL (seedRow), which
// orgclient.Client.PushOnce reads from the store, never from config.
//
// PushIntervalSeconds=1 with a 3s wait gives an un-gated loop several
// cycles' worth of time to have hit the server at least once.
func runOrgEmptyURLTestNode(t *testing.T, useConfigURL, seedRow bool) orgEmptyURLResult {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	svc := make([]byte, 8)
	_, _ = rand.Read(svc)
	keychainID := "sbo-e2e-orgemptyurl-" + hex.EncodeToString(svc)

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
	if useConfigURL {
		cfg.OrgClient.OrgServerURL = srv.URL
	} else {
		cfg.OrgClient.OrgServerURL = ""
	}
	cfg.OrgClient.KeychainID = keychainID
	cfg.OrgClient.PushIntervalSeconds = 1
	if err := config.WriteToml(cfgPath, cfg); err != nil {
		t.Fatalf("WriteToml: %v", err)
	}

	if seedRow {
		// The "was enrolled once" shape: a PERSISTED enrolment row pointing
		// at the fake server, independent of whatever config says. This is
		// what the push/announcement/routing-policy loops actually dial
		// (internal/orgclient.Client.PushOnce reads it from the store, not
		// from cfg.OrgClient.OrgServerURL).
		seedCtx := context.Background()
		database, err := db.Open(seedCtx, db.Options{Path: dbPath})
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
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	startCmd := newStartCmd()
	t.Cleanup(func() { setDaemonConfigPath("") })
	startCmd.SetArgs([]string{"--no-dashboard", "--no-open", "--config", cfgPath})
	var out bytes.Buffer
	startCmd.SetOut(&out)
	startCmd.SetErr(&out)
	done := make(chan error, 1)
	go func() { done <- startCmd.ExecuteContext(ctx) }()

	time.Sleep(3 * time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("observer start did not exit within 10s of cancel")
	}

	database2, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open verify: %v", err)
	}
	defer database2.Close()
	var n int
	if err := database2.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM org_push_log`).Scan(&n); err != nil {
		t.Fatalf("count org_push_log: %v", err)
	}

	return orgEmptyURLResult{output: out.String(), hits: hits.Load(), pushLogRows: n}
}

// TestStartupSkipsOrgClientWhenNeverEnrolled is case (a) of
// orgClientShouldStart's truth table: [org_client].enabled = true, a
// blank config org_server_url, and NO persisted org_enrolment row — a
// genuinely never-enrolled node. This is the ONLY shape that should
// print the "not enrolled" startup notice and start no org loop at all
// (no keychain probe, no HTTP, org_push_log stays empty).
func TestStartupSkipsOrgClientWhenNeverEnrolled(t *testing.T) {
	res := runOrgEmptyURLTestNode(t, false /* useConfigURL */, false /* seedRow */)

	const wantLine = "org push disabled — [org_client].enabled = true but org_server_url is empty and no enrolment record was found (not enrolled)"
	if !strings.Contains(res.output, wantLine) {
		t.Errorf("output missing the org-disabled startup notice.\nwant substring: %q\ngot:\n%s", wantLine, res.output)
	}
	if res.hits != 0 {
		t.Errorf("fake org server received %d request(s) — a never-enrolled node must start no org loop", res.hits)
	}
	if res.pushLogRows != 0 {
		t.Errorf("org_push_log has %d row(s), want 0 — the push loop ran despite there being nothing to enrol against", res.pushLogRows)
	}
}

// TestStartupUsesPersistedEnrolmentWhenConfigURLBlank is case (b), the
// BLOCK-1 regression pin: [org_client].enabled = true, a BLANK config
// org_server_url, but a REAL persisted org_enrolment row — the shape
// ensureOrgClientBlock's header-idempotent write (an existing
// [org_client] table header means org_server_url is never added) or a
// pre-tracker-#41 enrolment produces, and that re-enrolling does not
// repair. The old `cfg.OrgClient.Enrolled()` gate (Enabled &&
// OrgServerURL != "") silently killed the org client for this exact
// shape even though the node is genuinely enrolled. The fix: the org
// client MUST start here, exactly as it would with a real config
// org_server_url, and its push loop dials the PERSISTED row's server —
// never the blank config field — so the fake server (reachable ONLY via
// that row's URL) sees at least one hit within the 3s window.
func TestStartupUsesPersistedEnrolmentWhenConfigURLBlank(t *testing.T) {
	res := runOrgEmptyURLTestNode(t, false /* useConfigURL */, true /* seedRow */)

	if strings.Contains(res.output, "org push disabled") {
		t.Errorf("output wrongly disabled org push for an enrolled node whose config org_server_url is blank:\n%s", res.output)
	}
	if res.hits == 0 {
		t.Errorf("fake org server received 0 requests — the org client never started despite a persisted enrolment row (BLOCK-1 regression: a blank config org_server_url must not disable a real enrolment)")
	}
}

// TestStartupRunsNormallyWithConfigURLAndRow is the control case (c):
// [org_client].enabled = true, a real config org_server_url, AND a
// persisted row pointing at the same server. Behavior here is unchanged
// from before this fix — the org client starts and pushes normally.
func TestStartupRunsNormallyWithConfigURLAndRow(t *testing.T) {
	res := runOrgEmptyURLTestNode(t, true /* useConfigURL */, true /* seedRow */)

	if strings.Contains(res.output, "org push disabled") {
		t.Errorf("output wrongly disabled org push for a fully-configured enrolled node:\n%s", res.output)
	}
	if res.hits == 0 {
		t.Errorf("fake org server received 0 requests — the fully-configured case must stay active")
	}
}

// TestStartupConstructsOrgClientWithConfigURLButNoRow is the fourth,
// previously-untested cell of orgClientShouldStart's truth table: a real
// config org_server_url, but NO persisted org_enrolment row (a node whose
// operator has written the [org_client] block but never run `observer
// enroll`). orgClientShouldStart returns true here (ConfiguredServerURL()
// short-circuits before the row check), so the org client IS constructed
// and no "org push disabled" notice fires.
//
// Empirically verified against this exact harness (2026-09-07): despite
// orgClientShouldStart's own doc comment claiming this cell's loops "dial
// the config URL until enrol persists a row", they do not — every actual
// network call (PushOnce, FetchPolicyBundle, FetchRoutingPolicy,
// FetchOrgAnnouncement) starts with store.LoadEnrolment(ctx) and returns
// ErrNotEnrolled/errIdle the instant that comes back nil, before ever
// reading cfg.OrgClient.OrgServerURL again. So a config URL with no row
// constructs a client that idles forever — zero HTTP hits — until
// `observer enroll` (or a seeded row) gives it a server to actually talk
// to. That doc comment's row for this case is stale; see the fix alongside
// this test.
func TestStartupConstructsOrgClientWithConfigURLButNoRow(t *testing.T) {
	res := runOrgEmptyURLTestNode(t, true /* useConfigURL */, false /* seedRow */)

	if strings.Contains(res.output, "org push disabled") {
		t.Errorf("output wrongly disabled org push for a config-URL-configured node (orgClientShouldStart must return true here):\n%s", res.output)
	}
	if res.hits != 0 {
		t.Errorf("fake org server received %d request(s) — a config URL with NO persisted enrolment row must dial nowhere (no bearer/row to authenticate with)", res.hits)
	}
	if res.pushLogRows != 0 {
		t.Errorf("org_push_log has %d row(s), want 0 — nothing should have been pushed without a persisted enrolment", res.pushLogRows)
	}
}
