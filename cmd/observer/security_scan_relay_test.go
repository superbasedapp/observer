//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// TestRelayOnlineMatcher (lane SEC-H2): a managed node's online matching
// goes to the org relay only. A relay-mode answer is a match (the canary's
// ids prove it); a mirror-mode answer is not (the local database decides);
// an error or a failed package leaves the ecosystem unmatched, never clean;
// an unpinned package is withheld; the canary rides the last query.
func TestRelayOnlineMatcher(t *testing.T) {
	useFakeRelayPacer(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	canary, ok := depscan.CanaryFor("npm")
	if !ok {
		t.Skip("no npm canary in this build")
	}
	pkgs := []depscan.Package{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "unpinned", Path: "package-lock.json"},
	}
	prev := depsRelayScanLookup
	t.Cleanup(func() { depsRelayScanLookup = prev })
	var sent []orgcontract.SecurityLookupQuery
	answer := func(mode string, fail bool) func(context.Context, string, orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
		return func(_ context.Context, _ string, req orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
			sent = req.Queries
			resp := orgcontract.SecurityLookupResponse{Mode: mode}
			for _, q := range req.Queries {
				a := orgcontract.SecurityLookupAnswer{Ecosystem: q.Ecosystem, Name: q.Name, Version: q.Version, Status: string(secfeed.OnlineAnswered)}
				switch {
				case fail && q.Name == "lodash":
					a.Status, a.Reason = string(secfeed.OnlineFailed), "rate_limited"
				case q.Name == "lodash" || (q.Name == canary.Name && q.Version == canary.Version):
					a.VulnIDs = []string{"GHSA-test-0001"}
				}
				resp.Answers = append(resp.Answers, a)
			}
			return resp, nil
		}
	}
	e := &depsScanEnv{managed: true}
	match := func() (depscan.EcoResult, bool) {
		return e.relayOnlineMatcher(root)(context.Background(), "npm", pkgs, []int{0, 1, 2})
	}

	depsRelayScanLookup = answer("relay", false)
	res, handled := match()
	if !handled || res.Outcome != depscan.EcoScanned || len(res.Advisories) != 1 || res.Advisories[0].Index != 1 || res.Withheld != 1 {
		t.Fatalf("relay mode: handled=%v %+v", handled, res)
	}
	if len(sent) != 3 || sent[len(sent)-1].Name != canary.Name {
		t.Fatalf("queries sent %+v (want the two pinned packages and the canary last)", sent)
	}
	depsRelayScanLookup = answer("mirror", false)
	if _, handled := match(); handled {
		t.Fatal("a mirror-mode answer must leave the match to the local database")
	}
	depsRelayScanLookup = answer("relay", true)
	if res, _ := match(); res.Outcome == depscan.EcoScanned || len(res.Advisories) != 0 {
		t.Fatalf("a failed package must not read as scanned: %+v", res)
	}
	depsRelayScanLookup = func(context.Context, string, orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
		return orgcontract.SecurityLookupResponse{}, errors.New("relay_unavailable")
	}
	if res, _ := match(); res.Outcome == depscan.EcoScanned {
		t.Fatalf("a relay outage must not read as scanned: %+v", res)
	}
	shown := secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}
	open := &depsScanEnv{managed: true, disclose: shown, cfg: onlineCfg(true)}
	if open.onlineMatcher(root) == nil {
		t.Fatal("a managed node with online checks open gets the relayed matcher")
	}
}

// fakeRelayClock is a fake clock for the scan's relay pacer: a pacer sleep
// advances it and is recorded.
type fakeRelayClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func (c *fakeRelayClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// useFakeRelayPacer swaps the process pacer for one on a fake clock.
func useFakeRelayPacer(t *testing.T) *fakeRelayClock {
	t.Helper()
	c := &fakeRelayClock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	prev := depsRelayScanPacer
	depsRelayScanPacer = &relayPacer{now: c.now, sleep: func(_ context.Context, d time.Duration) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.t = c.t.Add(d)
		c.slept = append(c.slept, d)
		return nil
	}}
	t.Cleanup(func() { depsRelayScanPacer = prev })
	return c
}

// relayTestRoot is a project root with an npm lockfile.
func relayTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestRelayScanPrivatePackageWithheldOnly (SEC-H2 merge, audit finding 1):
// a package the relay refuses as private under the org's own configuration
// is withheld for that package only; the rest of the ecosystem still
// matches.
func TestRelayScanPrivatePackageWithheldOnly(t *testing.T) {
	useFakeRelayPacer(t)
	root := relayTestRoot(t)
	canary, ok := depscan.CanaryFor("npm")
	if !ok {
		t.Skip("no npm canary in this build")
	}
	pkgs := []depscan.Package{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "acme-internal", Version: "2.0.0", Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.0", Path: "package-lock.json"},
	}
	prev := depsRelayScanLookup
	t.Cleanup(func() { depsRelayScanLookup = prev })
	depsRelayScanLookup = func(_ context.Context, _ string, req orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
		resp := orgcontract.SecurityLookupResponse{Mode: "relay"}
		for _, q := range req.Queries {
			a := orgcontract.SecurityLookupAnswer{Ecosystem: q.Ecosystem, Name: q.Name, Version: q.Version, Status: string(secfeed.OnlineAnswered)}
			switch {
			case q.Name == "acme-internal":
				a.Status, a.Reason = string(secfeed.OnlineFailed), orgcontract.SecurityLookupReasonNotPublic
			case q.Name == "lodash" || (q.Name == canary.Name && q.Version == canary.Version):
				a.VulnIDs = []string{"GHSA-test-0002"}
			}
			resp.Answers = append(resp.Answers, a)
		}
		return resp, nil
	}
	e := &depsScanEnv{managed: true}
	res, handled := e.relayOnlineMatcher(root)(context.Background(), "npm", pkgs, []int{0, 1, 2})
	if !handled || res.Outcome != depscan.EcoScanned || res.Withheld != 1 || res.Packages != 2 {
		t.Fatalf("one private package must be withheld alone: handled=%v %+v", handled, res)
	}
	if len(res.Advisories) != 1 || res.Advisories[0].Index != 2 {
		t.Fatalf("the public packages must still match: %+v", res.Advisories)
	}
}

// TestRelayScanHonoursRetryAfter (SEC-H2 merge, audit finding 1): a 429
// from the relay is waited out for its Retry-After and the same batch is
// sent again; batches are paced at half the relay's default rate.
func TestRelayScanHonoursRetryAfter(t *testing.T) {
	clock := useFakeRelayPacer(t)
	root := relayTestRoot(t)
	if _, ok := depscan.CanaryFor("npm"); !ok {
		t.Skip("no npm canary in this build")
	}
	var pkgs []depscan.Package
	var idx []int
	for i := range 100 {
		pkgs = append(pkgs, depscan.Package{Ecosystem: "npm", Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0", Path: "package-lock.json"})
		idx = append(idx, i)
	}
	prev := depsRelayScanLookup
	t.Cleanup(func() { depsRelayScanLookup = prev })
	calls := 0
	depsRelayScanLookup = func(_ context.Context, _ string, req orgcontract.SecurityLookupRequest) (orgcontract.SecurityLookupResponse, error) {
		calls++
		if calls == 2 {
			return orgcontract.SecurityLookupResponse{}, &orgclient.SecurityRelayRateLimitedError{RetryAfter: 45 * time.Second}
		}
		resp := orgcontract.SecurityLookupResponse{Mode: "relay"}
		for _, q := range req.Queries {
			resp.Answers = append(resp.Answers, orgcontract.SecurityLookupAnswer{Ecosystem: q.Ecosystem, Name: q.Name, Version: q.Version, Status: string(secfeed.OnlineAnswered), VulnIDs: []string{"GHSA-test-0003"}})
		}
		return resp, nil
	}
	e := &depsScanEnv{managed: true}
	res, handled := e.relayOnlineMatcher(root)(context.Background(), "npm", pkgs, idx)
	if !handled || res.Outcome != depscan.EcoScanned || len(res.Advisories) != 100 {
		t.Fatalf("the scan must resume after the 429: handled=%v outcome=%v advisories=%d", handled, res.Outcome, len(res.Advisories))
	}
	if calls != 3 {
		t.Fatalf("relay calls = %d, want 3 (batch 1, the 429, batch 2 again)", calls)
	}
	if len(clock.slept) != 2 || clock.slept[0] != 2*time.Second || clock.slept[1] != 45*time.Second {
		t.Fatalf("pacer sleeps %v, want the 2s pacing then the 45s Retry-After", clock.slept)
	}
	if depsRelayScanInterval != 2*time.Second {
		t.Fatalf("scan interval %v, want half the relay's default rate (2s)", depsRelayScanInterval)
	}
}
