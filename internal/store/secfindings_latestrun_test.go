//go:build !sbo_omit_security

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSecLatestRunWithPasses: the read returns the newest run that recorded
// an extra pass (a full scan behind a later diff run that recorded none)
// and hands back its passes as recorded.
func TestSecLatestRunWithPasses(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	full := SecScanRun{
		ProjectRootHash: "p1", Driver: "opengrep", Scope: policy.FindingScopeManual, Outcome: "findings", StartedAt: now.Add(-time.Hour),
		Coverage: map[string]any{"Outcome": "findings", "Passes": []map[string]any{{"name": "taint_intrafile", "status": "timed_out", "merged": 2}}},
	}
	diff := SecScanRun{
		ProjectRootHash: "p1", Driver: "opengrep", Scope: policy.FindingScopeDiff, Outcome: "clean", StartedAt: now,
		Coverage: map[string]any{"Outcome": "clean"},
	}
	for _, r := range []SecScanRun{full, diff} {
		if err := s.InsertSecScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	latest, ok, err := s.SecLatestRun(ctx, "opengrep")
	if err != nil || !ok || latest.Scope != string(policy.FindingScopeDiff) || latest.Passes != nil {
		t.Fatalf("SecLatestRun %+v %v %v", latest, ok, err)
	}
	got, ok, err := s.SecLatestRunWithPasses(ctx, "opengrep")
	if err != nil || !ok || !got.StartedAt.Equal(full.StartedAt) {
		t.Fatalf("SecLatestRunWithPasses %+v %v %v", got, ok, err)
	}
	var passes []struct {
		Name, Status string
		Merged       int
	}
	if err := json.Unmarshal(got.Passes, &passes); err != nil || len(passes) != 1 || passes[0].Status != "timed_out" || passes[0].Merged != 2 {
		t.Fatalf("passes %s: %v %+v", got.Passes, err, passes)
	}
	if _, ok, err := s.SecLatestRunWithPasses(ctx, "custom.x"); err != nil || ok {
		t.Fatalf("a driver with no pass: %v %v", ok, err)
	}
}
