package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// TestBuildRemoteControllerWiresSessionAudit pins the seam that made a live
// mobile-auth defect unfalsifiable for three sessions.
//
// There are TWO remote-audit sinks and they are wired in different places:
// dashboard Options.RemoteAudit carries the per-request `http_request` rows,
// while RemoteOptions.Audit carries the session LIFECYCLE — `session_paired`,
// `session_revoked`, and the six `auth_failed` reasons handlePair
// distinguishes (rate_limited / bad_request / bad_secret / session_limit /
// session_create). Only the first was ever set, and remoteController.
// auditSession returns early on a nil func, so the second silently recorded
// nothing at all.
//
// The symptom was not a missing log line. "A paired phone lost authorization"
// has several candidate causes — an idle/absolute TTL expiry, the
// max_sessions cap rejecting a re-pair, a bad secret, the rate limiter — and
// the audit rows that tell them apart were dropped on the floor, so each
// investigation had to guess from `http_request … deny` rows plus disk state.
// Measured on the operator's install 2026-07-28: 17 rows in remote_sessions,
// all inside the audit window, and ZERO session_paired rows to explain any.
//
// This drives the REAL assembly — buildRemoteController's own options, its
// own /api/remote/pair route, a real store — because a unit test asserting
// "the field is non-nil" would not have caught the original miss either.
func TestBuildRemoteControllerWiresSessionAudit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(dir, "observer.db")
	cfg.Remote.Enabled = true
	cfg.Remote.TrustedHosts = []string{"host.example.ts.net"}

	// Any non-empty hash arms the controller. The pair attempt below fails
	// the constant-time verify against it, which is the point: the FAILURE
	// path is the one that has to be observable.
	if err := os.WriteFile(filepath.Join(dir, "remote-secret"), []byte("argon2id$notarealhash"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	database, err := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	ctrl := buildRemoteController(cfg, database)
	if ctrl == nil {
		t.Fatal("buildRemoteController returned nil with remote enabled and a secret present")
	}

	var pair http.HandlerFunc
	for _, rt := range ctrl.Routes() {
		if strings.Contains(rt.Pattern, "/api/remote/pair") {
			pair = rt.Handler
			break
		}
	}
	if pair == nil {
		t.Fatalf("no /api/remote/pair route among %d routes", len(ctrl.Routes()))
	}

	req := httptest.NewRequest(http.MethodPost, "/api/remote/pair", strings.NewReader(`{"secret":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	pair(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pair with a wrong secret: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// The assertion that matters: the rejection reached the audit table.
	var n int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM remote_audit WHERE kind = 'auth_failed'`).Scan(&n); err != nil {
		t.Fatalf("count auth_failed: %v", err)
	}
	if n == 0 {
		t.Fatal("a rejected pairing wrote no auth_failed row — RemoteOptions.Audit is unwired, " +
			"so every session_paired / session_revoked / auth_failed event is silently discarded")
	}

	var detail string
	if err := database.QueryRowContext(ctx,
		`SELECT detail FROM remote_audit WHERE kind = 'auth_failed' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read auth_failed detail: %v", err)
	}
	if detail != "bad_secret" {
		t.Errorf("auth_failed detail = %q, want %q — the reason must survive to the row, "+
			"since discriminating the reasons is the whole point of the sink", detail, "bad_secret")
	}
}

// TestRemoteAuditSinkNilDatabase pins the nil-safety buildRemoteController
// relies on: with no DB there is nowhere to record, and the controller must
// tolerate the nil func rather than panic on the first pairing attempt.
func TestRemoteAuditSinkNilDatabase(t *testing.T) {
	if sink := remoteAuditSink(nil); sink != nil {
		t.Fatal("remoteAuditSink(nil) must return a nil func so the controller's nil check engages")
	}
}
