package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/remoteauth"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// leaseAuditHarness is a fully-assembled execute stack whose termsession.Manager
// is wired with the REAL newLeaseAuditSink (the Phase-4 §8.1 writer-lease audit
// tap), pointed at a real node-local DB, so a test can drive lease transitions
// and read back the typed remote_audit rows.
type leaseAuditHarness struct {
	st      *store.Store
	adapter *launchManagerAdapter
	rc      dashboard.RemoteController
	mgr     *termsession.Manager
	device  string
	handle  string
}

func newLeaseAuditHarness(t *testing.T) *leaseAuditHarness {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	// Manager wired with the REAL lease-audit sink → remote_audit.
	mgr := termsession.NewManager(termsession.Options{
		Spawner:      fakeSpawner{},
		OnLeaseEvent: newLeaseAuditSink(database),
	})
	t.Cleanup(mgr.Shutdown)

	svc := termsvc.New(termsvc.Options{
		Recorder: nopRunRecorder{},
		Launcher: mgrLauncher{mgr: mgr},
		Feed:     termfeed.New(termfeed.Options{}),
	})
	res, err := svc.LaunchHandoff(ctx, termsvc.HandoffRequest{
		Tool: "claude-code", Subcommand: "claude", SessionID: "src-session",
	})
	if err != nil {
		t.Fatalf("LaunchHandoff: %v", err)
	}

	raw, enc, err := remoteauth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	hash, err := remoteauth.HashSecret(raw)
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	rc := dashboard.NewRemoteController(dashboard.RemoteOptions{
		HashedSecret:    hash,
		AllowedHosts:    []string{"remote.example:8443"},
		RateLimitPerMin: 60,
		Session:         remoteauth.SessionParams{TTL: time.Hour, Idle: time.Hour, Max: 5},
	})
	device := pairDevice(t, rc, enc)

	adapter := &launchManagerAdapter{svc: svc, mgr: mgr}
	authz, ok := rc.(dashboard.TerminalControlAuthorizer)
	if !ok {
		t.Fatal("controller is not a TerminalControlAuthorizer")
	}
	adapter.wireRemoteExecute(authz, func() bool { return true })

	return &leaseAuditHarness{st: store.New(database), adapter: adapter, rc: rc, mgr: mgr, device: device, handle: res.Handle}
}

// acquireRemote mints a fresh capability + confirm and acquires the remote
// writer lease through the real adapter (real §4.δ conjunction + real lease).
func (h *leaseAuditHarness) acquireRemote(t *testing.T) (dashboard.LaunchWriter, string, string) {
	t.Helper()
	authz := h.rc.(dashboard.TerminalControlAuthorizer)
	capTok, confirm, err := authz.MintTerminalControl(h.rc.Sessions()[0].ID, h.handle)
	if err != nil {
		t.Fatalf("MintTerminalControl: %v", err)
	}
	w, err := h.adapter.AcquireWriterRemote(dashboard.RemoteWriterRequest{
		Handle:          h.handle,
		DeviceSessionID: h.device,
		CapabilityToken: capTok,
		Confirm:         confirm,
		RemoteExposed:   true,
	})
	if err != nil || w == nil {
		t.Fatalf("AcquireWriterRemote: w=%v err=%v", w, err)
	}
	return w, capTok, confirm
}

// TestLeaseWriterAuditLifecycle drives the writer-lease half of the execute-tier
// audit lifecycle (plan §8.1 deliverable 1): remote acquire → local takeover →
// release → remote re-acquire → forced revoke, asserting the typed rows appear
// in order with the handle carried in every row, holders classified by
// capability class, and NO capability / confirm / raw device-session id in any
// row (canary).
func TestLeaseWriterAuditLifecycle(t *testing.T) {
	h := newLeaseAuditHarness(t)

	// 1. Remote acquire → terminal_writer_acquire (holder = device fingerprint).
	_, cap1, cfm1 := h.acquireRemote(t)

	// 2. Local takeover → terminal_local_takeover (revoked remote holder) +
	//    terminal_writer_acquire (holder = local).
	local, err := h.mgr.AcquireWriterLocal(h.handle)
	if err != nil {
		t.Fatalf("AcquireWriterLocal: %v", err)
	}

	// 3. Local release → terminal_writer_release.
	local.Release()

	// 4. Remote re-acquire with a fresh capability → terminal_writer_acquire.
	_, cap2, cfm2 := h.acquireRemote(t)

	// 5. Forced revoke (allow_terminal→false / device revoke path) →
	//    terminal_writer_revoke.
	if !h.mgr.RevokeWriter(h.handle, "config_off") {
		t.Fatal("expected RevokeWriter to revoke the live remote lease")
	}

	rows, err := h.st.RecentRemoteAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("RecentRemoteAudit: %v", err)
	}
	// RecentRemoteAudit is newest-first; reverse to chronological.
	kinds := make([]string, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		e := rows[i]
		if e.Route != h.handle {
			t.Errorf("lease audit row kind=%s has route=%q, want the handle %q in every row", e.Kind, e.Route, h.handle)
		}
		kinds = append(kinds, e.Kind)
	}

	// The five typed transitions, in order (writer_acquire appears three times).
	want := []string{
		"terminal_writer_acquire", // 1: remote
		"terminal_local_takeover", // 2a: incumbent remote revoked by local
		"terminal_writer_acquire", // 2b: local
		"terminal_writer_release", // 3: local release
		"terminal_writer_acquire", // 4: remote re-acquire
		"terminal_writer_revoke",  // 5: forced revoke
	}
	if !containsInOrder(kinds, want) {
		t.Fatalf("lease audit kinds\n got: %v\nwant subsequence: %v", kinds, want)
	}

	// Actor capability class: takeover rows identify the incoming controller,
	// while non-takeover revoke/release rows identify their holder.
	assertHolderPrincipal(t, rows, "terminal_local_takeover", "local")
	assertHolderPrincipal(t, rows, "terminal_writer_revoke", "remote")
	assertHolderPrincipal(t, rows, "terminal_writer_release", "local")

	// Canary: the raw device-session bearer and every minted capability/confirm
	// must be absent from every column of every row.
	assertNoCanary(t, rows, []string{h.device, cap1, cfm1, cap2, cfm2})
}

// TestLeaseTakeoverAuditDirections proves the takeover event records the
// incoming actor rather than mislabeling every direction as a local takeover:
// remote-over-local and remote-over-remote are remote-principal events, while
// local take-back remains a local-principal event.
func TestLeaseTakeoverAuditDirections(t *testing.T) {
	h := newLeaseAuditHarness(t)
	local, err := h.mgr.AcquireWriterLocal(h.handle)
	if err != nil {
		t.Fatalf("AcquireWriterLocal: %v", err)
	}
	_ = local
	h.acquireRemote(t)
	h.acquireRemote(t)
	if _, err := h.mgr.AcquireWriterLocal(h.handle); err != nil {
		t.Fatalf("local take-back: %v", err)
	}

	rows, err := h.st.RecentRemoteAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("RecentRemoteAudit: %v", err)
	}
	remoteTakeovers := 0
	localTakeovers := 0
	for _, row := range rows {
		if row.Route != h.handle {
			continue
		}
		switch row.Kind {
		case "terminal_remote_takeover":
			remoteTakeovers++
			if row.Principal != "remote" || row.SessionID == "local" || !strings.Contains(row.Detail, "superseded") {
				t.Errorf("dishonest remote takeover row: %+v", row)
			}
		case "terminal_local_takeover":
			localTakeovers++
			if row.Principal != "local" || row.SessionID != "local" {
				t.Errorf("dishonest local takeover row: %+v", row)
			}
		}
	}
	if remoteTakeovers != 2 || localTakeovers != 1 {
		t.Fatalf("takeover audit counts remote=%d local=%d, want 2/1", remoteTakeovers, localTakeovers)
	}
}

// TestSetupLeaseAuditRedactsHandle proves FIX A(i) (second adversarial review
// 2026-07-16): a privileged SpecSetup PTY's lease transitions land in remote_audit
// as an opaque "setup:<label>" route, so the opaque handle never reaches the
// View-tier /api/remote/audit route a paired remote device can read — while the
// audit ROW itself (the fact of the setup op) is kept. A NORMAL session's lease
// row still carries its handle (no regression).
func TestSetupLeaseAuditRedactsHandle(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	mgr := termsession.NewManager(termsession.Options{
		Spawner:      fakeSpawner{},
		OnLeaseEvent: newLeaseAuditSink(database),
	})
	t.Cleanup(mgr.Shutdown)

	// A privileged setup PTY (the one-time Tailscale login). Local owner attaches
	// (drives it) → LeaseAcquired; Release → LeaseReleased. Both are setup events.
	setupHandle, err := mgr.Create(termsession.Spec{
		Kind:       termsession.SpecSetup,
		SetupArgv:  []string{"sudo", "tailscale", "up"},
		SetupLabel: "tailscale-login",
	})
	if err != nil {
		t.Fatalf("Create setup: %v", err)
	}
	lw, err := mgr.AcquireWriterLocal(setupHandle)
	if err != nil {
		t.Fatalf("AcquireWriterLocal(setup): %v", err)
	}
	lw.Release()

	// A normal agent session for contrast — its lease row keeps the handle.
	normalHandle, err := mgr.Create(termsession.Spec{
		BinPath: "/usr/local/bin/observer", Subcommand: "claude", ArgvMode: termsession.ArgvModeFresh,
	})
	if err != nil {
		t.Fatalf("Create normal: %v", err)
	}
	nw, err := mgr.AcquireWriterLocal(normalHandle)
	if err != nil {
		t.Fatalf("AcquireWriterLocal(normal): %v", err)
	}
	nw.Release()

	st := store.New(database)
	rows, err := st.RecentRemoteAudit(ctx, 200)
	if err != nil {
		t.Fatalf("RecentRemoteAudit: %v", err)
	}

	var sawSetupRow, sawNormalRow bool
	for _, e := range rows {
		// The raw setup handle must never appear in ANY column of ANY row.
		fields := []string{e.Kind, e.SessionID, e.Principal, e.RemoteAddr, e.Route, e.Decision, e.Detail}
		for _, f := range fields {
			if strings.Contains(f, setupHandle) {
				t.Errorf("setup handle %q leaked into remote_audit field %q (kind=%s)", setupHandle, f, e.Kind)
			}
		}
		if e.Route == "setup:tailscale-login" {
			sawSetupRow = true
		}
		if e.Route == normalHandle {
			sawNormalRow = true
		}
	}
	if !sawSetupRow {
		t.Error(`expected a setup lease audit row with route "setup:tailscale-login" (the op must still be audited)`)
	}
	if !sawNormalRow {
		t.Error("expected the normal session's lease row to still carry its handle (no regression)")
	}
}

func containsInOrder(have, want []string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && h == want[i] {
			i++
		}
	}
	return i == len(want)
}

func assertHolderPrincipal(t *testing.T, rows []store.RemoteAuditEvent, kind, wantPrincipal string) {
	t.Helper()
	for _, e := range rows {
		if e.Kind == kind {
			if e.Principal != wantPrincipal {
				t.Errorf("row kind=%s principal=%q, want %q", kind, e.Principal, wantPrincipal)
			}
			return
		}
	}
	t.Errorf("no row of kind %s found", kind)
}

func assertNoCanary(t *testing.T, rows []store.RemoteAuditEvent, secrets []string) {
	t.Helper()
	for _, e := range rows {
		fields := []string{e.Kind, e.SessionID, e.Principal, e.RemoteAddr, e.Route, e.Decision, e.Detail}
		for _, f := range fields {
			for _, sec := range secrets {
				if sec != "" && strings.Contains(f, sec) {
					t.Errorf("audit row kind=%s leaked a secret/raw id in field %q", e.Kind, f)
				}
			}
		}
	}
}
