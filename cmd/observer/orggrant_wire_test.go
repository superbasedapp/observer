package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedVerifiedGrant writes an enrolment and a verified signed grants
// document holding g, the shape orgclient.FetchAccessGrants caches.
func seedVerifiedGrant(t *testing.T, st *store.Store, g orgcontract.AccessGrantWire) {
	t.Helper()
	ctx := context.Background()
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "http://org.invalid",
		UserID: "u-1", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "k",
	}); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	doc, err := orgcontract.SignAccessGrants(priv, "org-1", "u-1|", 1, orgcontract.AccessGrantBody{
		Grants: []orgcontract.AccessGrantWire{g}, ServerNowNs: now.UnixNano(), MaxOfflineS: 86400,
		IssuedAt: now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAccessGrants(ctx, store.AccessGrantState{
		OrgID: "org-1", Subject: "u-1|", Version: 1, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, ServerPubkey: base64.StdEncoding.EncodeToString(pub),
		ServerNowNs: now.UnixNano(), ReceivedAtNs: now.UnixNano(), LastVerifiedNs: now.UnixNano(),
		HighWaterNs: now.UnixNano(), MaxOfflineS: 86400, IssuedAt: now.UTC().Format(time.RFC3339),
	}, []orgcontract.AccessGrantWire{g}); err != nil {
		t.Fatal(err)
	}
}

// TestOrgGrantWiring_HookAndDaemonReadTheSameGrant: the hook process's guard
// (fresh DB open per question) and the daemon's guard (its own store
// handle) both read the one verified grant cache, both let the granted call
// through with the grant id, and between them they count exactly the
// grant's uses: a one-use grant allows one call, whichever process asks
// first.
func TestOrgGrantWiring_HookAndDaemonReadTheSameGrant(t *testing.T) {
	// The guards read the org bundle and user policy under the home; the
	// process temp home's .observer is a file (FU-20), which reads as a
	// failed org layer and keeps the lock.
	pinToolHomes(t)
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	now := time.Now()
	seedVerifiedGrant(t, st, orgcontract.AccessGrantWire{
		ID: 5, Type: accessgrant.TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
		SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "R-101",
		StartsAtNs: now.Add(-time.Minute).UnixNano(), ExpiresAtNs: now.Add(time.Hour).UnixNano(), MaxUses: 2,
	})

	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Guard.Enabled = true
	cfg.Guard.Mode = "enforce"
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Tool: "claude-code",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/tmp/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}

	hookGuard := buildHookGuard(cfg, &bytes.Buffer{})
	daemonGuard := buildGuardForStore(ctx, cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if hookGuard == nil || daemonGuard == nil {
		t.Fatal("guard construction failed")
	}
	for i, g := range []*guard.Guard{hookGuard, daemonGuard} {
		av, _ := g.EvaluateHook(ev)
		if av.Verdict.Decision != policy.DecisionFlag || av.GrantID != 5 || av.DegradedFrom != guard.DegradedFromOrgGrant {
			t.Fatalf("guard %d: %+v grant=%d from=%q", i, av.Verdict, av.GrantID, av.DegradedFrom)
		}
	}
	// Both uses are spent: the next call from either process is denied.
	for i, g := range []*guard.Guard{hookGuard, daemonGuard} {
		if av, _ := g.EvaluateHook(ev); av.Verdict.Decision != policy.DecisionDeny || av.GrantID != 0 {
			t.Fatalf("guard %d after the uses ran out: %+v grant=%d", i, av.Verdict, av.GrantID)
		}
	}
}

// TestRequestAccessBase pins the dashboard origin the org-locked deny line
// links (request-grants G4): always a loopback URL the developer's browser
// can open on this machine, a wildcard bind mapped to loopback, "" when the
// address cannot be parsed (the line then offers the CLI command only).
func TestRequestAccessBase(t *testing.T) {
	requireCompiled(t, "ui.dashboard")
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	for _, tc := range []struct{ addr, want string }{
		{"", "http://127.0.0.1:8081"},
		{"127.0.0.1:9123", "http://127.0.0.1:9123"},
		{"0.0.0.0:9123", "http://127.0.0.1:9123"},
		{":9123", "http://127.0.0.1:9123"},
		{"[::]:9123", "http://127.0.0.1:9123"},
		{"[::1]:9123", "http://[::1]:9123"},
		{"localhost:9123", "http://localhost:9123"},
		{"not-an-addr", ""},
	} {
		cfg := config.Default()
		cfg.Dashboard.Addr = tc.addr
		if got := requestAccessBase(cfg); got != tc.want {
			t.Errorf("addr %q: %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// TestRequestAccessBaseWiredIntoHookAndDaemon: the hook process's guard and
// the daemon's guard stamp the same dashboard origin, so the vendor reply,
// the proxy deny and the dashboard link one request form.
func TestRequestAccessBaseWiredIntoHookAndDaemon(t *testing.T) {
	requireCompiled(t, "ui.dashboard")
	t.Setenv("OBSERVER_DASHBOARD_ADDR", "")
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Guard.Enabled = true
	cfg.Guard.Mode = "enforce"
	cfg.Dashboard.Addr = "0.0.0.0:9123"
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Tool: "claude-code",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/tmp/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	hookGuard := buildHookGuard(cfg, &bytes.Buffer{})
	daemonGuard := buildGuardForStore(ctx, cfg, store.New(database), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i, g := range []*guard.Guard{hookGuard, daemonGuard} {
		if av, _ := g.EvaluateHook(ev); av.RequestBase != "http://127.0.0.1:9123" {
			t.Errorf("guard %d: RequestBase = %q", i, av.RequestBase)
		}
	}
}
