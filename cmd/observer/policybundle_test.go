package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newTestPolicyBundleRunner builds a runner over a temp DB and a
// directly constructed guard (the injectable acquire seam).
func newTestPolicyBundleRunner(t *testing.T) (*policyBundleRunner, *store.Store) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	g, err := guard.New(guard.Options{Config: config.Default().Guard, Home: t.TempDir()})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return &policyBundleRunner{
		st:      st,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		orgURL:  "https://org.example",
		acquire: func(context.Context) *guard.Guard { return g },
	}, st
}

// countR205 counts persisted R-205 guard events.
func countR205(t *testing.T, st *store.Store) int {
	t.Helper()
	events, err := st.LoadRecentGuardEvents(context.Background(), time.Time{}, 100)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.RuleID == "R-205" {
			n++
		}
	}
	return n
}

// TestPolicyBundleRunner_R205Emission is the rejection-state table:
// one event per rejection state, repeats deduped, a healthy poll
// re-arms, and a NEW rejection (different version or detail) emits
// again.
func TestPolicyBundleRunner_R205Emission(t *testing.T) {
	r, st := newTestPolicyBundleRunner(t)
	rejected := orgclient.PolicyResult{
		Status: orgclient.PolicyRejected, Version: 3,
		Detail: "signature verification failed",
	}

	r.onResult(rejected)
	if got := countR205(t, st); got != 1 {
		t.Fatalf("after first rejection: %d R-205 events, want 1", got)
	}

	// Same rejection state repeated (hourly polls): deduped.
	r.onResult(rejected)
	r.onResult(rejected)
	if got := countR205(t, st); got != 1 {
		t.Fatalf("after repeats: %d R-205 events, want 1 (deduped)", got)
	}

	// A different failure mode is a new state.
	r.onResult(orgclient.PolicyResult{
		Status: orgclient.PolicyRejected, Version: 4,
		Detail: "version regression: served 4 after 5",
	})
	if got := countR205(t, st); got != 2 {
		t.Fatalf("after new rejection state: %d R-205 events, want 2", got)
	}

	// A healthy poll re-arms the dedup; the SAME old rejection then
	// emits again (it is a fresh incident after recovery).
	r.onResult(orgclient.PolicyResult{Status: orgclient.PolicyApplied, Version: 5})
	r.onResult(rejected)
	if got := countR205(t, st); got != 3 {
		t.Fatalf("after recovery + re-rejection: %d R-205 events, want 3", got)
	}

	// The persisted rows carry the channel identity for the audit
	// trail: tool "org" + the bundle endpoint in the reason.
	events, err := st.LoadRecentGuardEvents(context.Background(), time.Time{}, 100)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	for _, e := range events {
		if e.RuleID != "R-205" {
			continue
		}
		if e.Tool != "org" || e.Category != "posture" {
			t.Fatalf("R-205 row identity = tool %q category %q, want org/posture", e.Tool, e.Category)
		}
	}
}

// TestOrgBundleCachePath pins the [guard.rules].org_bundle resolution
// table.
func TestOrgBundleCachePath(t *testing.T) {
	mk := func(p string) config.Config {
		cfg := config.Default()
		cfg.Guard.Rules.OrgBundle = p
		return cfg
	}
	if got := orgBundleCachePath(mk("")); got != "" {
		t.Errorf("empty setting = %q, want \"\"", got)
	}
	if got := orgBundleCachePath(mk("~/.observer/org-policy-bundle.json")); got == "" || got[0] == '~' {
		t.Errorf("~ not expanded: %q", got)
	}
	abs := filepath.Join(t.TempDir(), "b.json")
	if got := orgBundleCachePath(mk(filepath.ToSlash(abs))); got != abs {
		t.Errorf("absolute path = %q, want %q", got, abs)
	}
}
