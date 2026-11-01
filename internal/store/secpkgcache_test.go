//go:build !sbo_omit_security && !sbo_omit_security_deps

package store

import (
	"context"
	"testing"
	"time"
)

func TestSecPkgCache(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	rows := []SecPkgCacheRow{
		{Ecosystem: "npm", Name: "left-pad", Status: "answered", AnswerJSON: `{"a":1}`, FetchedAt: now, ExpiresAt: now.Add(24 * time.Hour)},
		{Ecosystem: "npm", Name: "gone", Status: "not_found", AnswerJSON: `{}`, FetchedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}
	if err := s.UpsertSecPkgCache(ctx, rows); err != nil {
		t.Fatal(err)
	}
	rows[0].AnswerJSON = `{"a":2}`
	if err := s.UpsertSecPkgCache(ctx, rows[:1]); err != nil {
		t.Fatal(err)
	}
	live, err := s.LiveSecPkgCache(ctx, now, 100)
	if err != nil || len(live) != 1 || live[0].AnswerJSON != `{"a":2}` {
		t.Fatalf("live %+v %v", live, err)
	}
	n, newest, err := s.SecPkgCacheStats(ctx)
	if err != nil || n != 2 || !newest.Equal(now) {
		t.Errorf("stats %d %v %v", n, newest, err)
	}
	if k, err := s.PruneSecPkgCache(ctx, now); err != nil || k != 1 {
		t.Errorf("prune %d %v", k, err)
	}
}
