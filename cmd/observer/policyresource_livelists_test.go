package main

// Demo finding #23 (2026-11-10): a daemon that started as an INDIVIDUAL node
// and was re-enrolled MANAGED while it ran never accepted node.governance,
// because the poller read [org_client.policy] once at start. These tests pin
// the live re-read and the wake-up.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

// writePolicyConfig writes a config.toml whose [org_client.policy] accepts
// (and preauthorizes) families. A later call changes the file's size, so
// the stamp moves even on a filesystem with coarse modification times.
func writePolicyConfig(t *testing.T, path string, families []string) {
	t.Helper()
	q := make([]string, len(families))
	for i, f := range families {
		q[i] = `"` + f + `"`
	}
	list := "[" + strings.Join(q, ", ") + "]"
	body := "[org_client]\n  enabled = true\n[org_client.policy]\naccept_families = " + list +
		"\npreauthorize_enforce = " + list + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestLivePolicyListsRefresh is the reload rule, one row per case.
func TestLivePolicyListsRefresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	writePolicyConfig(t, path, nil)

	l := newLivePolicyLists(config.Default(), path, nil, slog.Default())
	if l.refresh() {
		t.Fatal("first read of an unchanged list reported a change")
	}
	if got := l.options().AcceptFamilies; len(got) != 0 {
		t.Fatalf("accept = %v, want none", got)
	}
	if l.refresh() {
		t.Fatal("an unchanged file reported a change")
	}

	writePolicyConfig(t, path, []string{policyfam.FamilyNodeGovernance})
	if !l.refresh() {
		t.Fatal("the managed enrolment's accept list was not picked up")
	}
	if got := l.options().AcceptFamilies; len(got) != 1 || got[0] != policyfam.FamilyNodeGovernance {
		t.Fatalf("accept = %v, want [node.governance]", got)
	}

	// A config that does not load keeps the lists in force.
	l.load = func(string) (config.Config, error) { return config.Config{}, errors.New("half written") }
	if err := os.WriteFile(path, []byte("[org_client.policy]\naccept_families = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l.refresh() {
		t.Fatal("a config that does not load reported a change")
	}
	if got := l.options().AcceptFamilies; len(got) != 1 {
		t.Fatalf("accept after a failed load = %v, want the previous list", got)
	}

	// A static view (no path) never reloads.
	s := newLivePolicyLists(config.Default(), "", nil, slog.Default())
	if s.refresh() {
		t.Fatal("a static view reported a change")
	}
}

// TestWatcherKicksOnIdentityChange: a re-enrolment that moves the enrolment
// generation wakes the poll even when the lists did not change.
func TestWatcherKicksOnIdentityChange(t *testing.T) {
	var gen atomic.Int64
	gen.Store(1)
	identity := func(context.Context) policyIdentity {
		return policyIdentity{orgKey: "k", generation: gen.Load(), ok: true}
	}
	kicks := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchPolicyListsAndIdentity(ctx, nil, identity, func() { kicks <- struct{}{} }, 10*time.Millisecond, slog.Default())

	select {
	case <-kicks:
		t.Fatal("kicked with no change")
	case <-time.After(100 * time.Millisecond):
	}
	gen.Store(2)
	select {
	case <-kicks:
	case <-time.After(5 * time.Second):
		t.Fatal("a new enrolment generation did not wake the poll")
	}
}

// TestPollerAcceptsAfterLiveManagedEnrolment is the demo shape end to end
// through runPolicyResourcePoller: the daemon starts with no accept list (an
// individual node), the org serves a signed family, and the node reports it
// delivered but not accepted. Then the managed enrolment writes the accept
// list into config.toml while the poller runs. With the hourly poll interval
// untouched, the watcher must wake a fetch that installs the layer, without
// a restart.
func TestPollerAcceptsAfterLiveManagedEnrolment(t *testing.T) {
	prev := policyListsCheckInterval
	policyListsCheckInterval = 20 * time.Millisecond
	t.Cleanup(func() { policyListsCheckInterval = prev })

	var served orgcontract.SignedPolicyResource
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/api/agent/policy/") != policyfam.FamilyNodeFeatures {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no_policy_resource"}`))
			return
		}
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(srv.Close)

	cfg, st, _, res := adoptSetup(t, srv.URL, false)
	served = res
	// The daemon started individual: nothing accepted.
	cfg.OrgClient.Policy.AcceptFamilies = nil
	cfg.OrgClient.Policy.PreauthorizeEnforce = nil
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	writePolicyConfig(t, cfgPath, nil)

	oc := orgclient.New(config.OrgClientConfig{OrgServerURL: srv.URL}, st, adoptBearer{}, "test", srv.Client(), slog.Default())
	nf := newNodeFeaturesHandle()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPolicyResourcePoller(ctx, cfg, cfgPath, oc, nil, nil, nil, nf, nil, slog.Default())
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitForLiveLists(t, "the first (start-time) fetch", func() bool { return fetches.Load() >= 1 })
	// Give the first cycle time to finish its accept decision.
	time.Sleep(100 * time.Millisecond)
	if f := nf.Facts(); f.HasOrgRail {
		t.Fatalf("installed before the node accepted the family: %+v", f)
	}
	before := fetches.Load()

	// The live managed enrolment writes the accept list.
	writePolicyConfig(t, cfgPath, []string{policyfam.FamilyNodeFeatures})

	waitForLiveLists(t, "a fetch after the enrolment wrote the accept list", func() bool { return fetches.Load() > before })
	waitForLiveLists(t, "the layer installed under the new accept list", func() bool {
		f := nf.Facts()
		return f.HasOrgRail && f.Version == res.Version
	})
}

func waitForLiveLists(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
