package secquickscan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSeamBudgetReachesTheEngine: the seam's deadline (the endpoint sets it
// from the request's budget: a managed floor's 5, 10 or 30 s) is the
// engine's budget, less a small margin so the engine answers first. Before,
// the adapter dropped it and every scan stopped at the engine's own 2 s,
// so a large repository's scan never finished whatever the floor allowed.
func TestSeamBudgetReachesTheEngine(t *testing.T) {
	var mu sync.Mutex
	var timeouts []time.Duration
	git := func(_ context.Context, _ string, _ int, timeout time.Duration, _ ...string) ([]byte, bool, error) {
		mu.Lock()
		timeouts = append(timeouts, timeout)
		mu.Unlock()
		return nil, false, nil
	}
	e := &Engine{Git: git}
	for _, tc := range []struct {
		name     string
		deadline time.Duration // 0: no deadline
		min, max time.Duration
	}{
		{"floor 10 s", 10 * time.Second, 9800 * time.Millisecond, 10 * time.Second},
		{"floor 30 s", 30 * time.Second, 29800 * time.Millisecond, 30 * time.Second},
		{"default 2 s", 2 * time.Second, 1800 * time.Millisecond, 2 * time.Second},
		{"no deadline", 0, IndividualBudget - 50*time.Millisecond, IndividualBudget},
	} {
		timeouts = nil
		ctx := context.Background()
		if tc.deadline > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, tc.deadline)
			defer cancel()
		}
		r, err := e.QuickScanner()(ctx, hookctx.QuickScanRequest{ProjectRoot: "/r", Form: policy.GitWrite{Form: policy.GitWriteCommit}})
		if err != nil || r.Verdict != hookctx.QuickScanClean {
			t.Fatalf("%s: %+v, %v", tc.name, r, err)
		}
		if len(timeouts) == 0 || timeouts[0] < tc.min || timeouts[0] > tc.max {
			t.Errorf("%s: the diff read had %v, want within [%s, %s]", tc.name, timeouts, tc.min, tc.max)
		}
	}
}

// TestSeamUnknownCarriesItsDetail: an unknown scan reaches the seam with
// its reason and numbers (policy.QuickScanDetail), which the commit gate's
// verdict renders; an unmodelled form says so.
func TestSeamUnknownCarriesItsDetail(t *testing.T) {
	failing := func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
		return nil, false, errors.New("fatal: not a git repository")
	}
	r, err := (&Engine{Git: failing}).QuickScanner()(context.Background(), hookctx.QuickScanRequest{ProjectRoot: "/r", Form: policy.GitWrite{Form: policy.GitWriteCommit}})
	if err != nil || r.Verdict != hookctx.QuickScanUnknown || r.Detail.Reason != policy.QuickScanReasonGit || r.Detail.Budget != IndividualBudget {
		t.Fatalf("git failure = %+v, %v", r, err)
	}
	r, _ = (&Engine{Git: failing}).QuickScanner()(context.Background(), hookctx.QuickScanRequest{ProjectRoot: "/r", Form: policy.GitWrite{Form: policy.GitWriteCommit, Dir: "sub"}})
	if r.Verdict != hookctx.QuickScanUnknown || r.Detail.Reason != policy.QuickScanReasonNotModelled {
		t.Fatalf("git -C commit = %+v", r)
	}
	// A diff whose secret scan runs out of budget reports the files it read.
	slow := func(ctx context.Context, _ string, _ int, _ time.Duration, _ ...string) ([]byte, bool, error) {
		return []byte("diff --git a/a.go b/a.go\n+++ b/a.go\n@@ -0,0 +1 @@\n+x := 1\n" +
			"diff --git a/b.go b/b.go\n+++ b/b.go\n@@ -0,0 +1 @@\n+y := 2\n"), false, nil
	}
	clock := time.Unix(1000, 0)
	var cmu sync.Mutex
	now := func() time.Time {
		cmu.Lock()
		defer cmu.Unlock()
		clock = clock.Add(time.Second) // every read of the clock spends a second
		return clock
	}
	r, _ = (&Engine{Git: slow, Now: now}).QuickScanner()(context.Background(), hookctx.QuickScanRequest{ProjectRoot: "/r", Form: policy.GitWrite{Form: policy.GitWriteCommit}})
	if r.Verdict != hookctx.QuickScanUnknown || r.Detail.Reason != policy.QuickScanReasonBudget || r.Detail.Files != 2 || r.Detail.Budget != IndividualBudget {
		t.Fatalf("over budget = %+v", r)
	}
}

// TestReasonSpellingsMatchThePolicyVocabulary pins the engine's reason
// spellings to the policy codes the gate's verdict words key on.
func TestReasonSpellingsMatchThePolicyVocabulary(t *testing.T) {
	for _, tc := range []struct {
		got  UnknownReason
		want string
	}{
		{ReasonBudget, policy.QuickScanReasonBudget},
		{ReasonGit, policy.QuickScanReasonGit},
		{ReasonDiffOverCap, policy.QuickScanReasonDiffOverCap},
		{ReasonIncomplete, policy.QuickScanReasonIncomplete},
		{ReasonNoUpstream, policy.QuickScanReasonNoUpstream},
		{ReasonBadRequest, policy.QuickScanReasonBadRequest},
		{ReasonUnmodelled, policy.QuickScanReasonNotModelled},
	} {
		if string(tc.got) != tc.want {
			t.Errorf("engine reason %q != policy code %q", tc.got, tc.want)
		}
	}
}
