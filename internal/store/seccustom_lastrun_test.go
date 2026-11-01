//go:build !sbo_omit_security

package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestSecLastDriverRun: the newest run of one driver over one project with
// one scope; other drivers, projects and scopes do not count; none is zero.
func TestSecLastDriverRun(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	runs := []SecScanRun{
		{ProjectRootHash: "p1", Driver: "custom:a", Scope: secfinding.Scope("scheduled"), Outcome: "clean", StartedAt: base},
		{ProjectRootHash: "p1", Driver: "custom:a", Scope: secfinding.Scope("scheduled"), Outcome: "clean", StartedAt: base.Add(2 * time.Hour)},
		{ProjectRootHash: "p1", Driver: "custom:a", Scope: secfinding.Scope("manual"), Outcome: "clean", StartedAt: base.Add(5 * time.Hour)},
		{ProjectRootHash: "p1", Driver: "custom:b", Scope: secfinding.Scope("scheduled"), Outcome: "clean", StartedAt: base.Add(6 * time.Hour)},
		{ProjectRootHash: "p2", Driver: "custom:a", Scope: secfinding.Scope("scheduled"), Outcome: "clean", StartedAt: base.Add(7 * time.Hour)},
	}
	for _, r := range runs {
		if err := s.InsertSecScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, hash, driver, scope string
		want                      time.Time
	}{
		{"newest scheduled run", "p1", "custom:a", "scheduled", base.Add(2 * time.Hour)},
		{"the manual run is its own scope", "p1", "custom:a", "manual", base.Add(5 * time.Hour)},
		{"another driver", "p1", "custom:b", "scheduled", base.Add(6 * time.Hour)},
		{"another project", "p2", "custom:a", "scheduled", base.Add(7 * time.Hour)},
		{"no run", "p3", "custom:a", "scheduled", time.Time{}},
	}
	for _, c := range cases {
		got, err := s.SecLastDriverRun(ctx, c.hash, c.driver, secfinding.Scope(c.scope))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !got.Equal(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
