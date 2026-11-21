package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestResolveUsageRetentionConfig: one case per bound row (default, set,
// below the floor, above the ceiling, not a number).
func TestResolveUsageRetentionConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		env     map[string]string
		want    usageRetentionConfig
		wantErr bool
	}{
		{"defaults", nil, usageRetentionConfig{13, 10}, false},
		{"longer periods", map[string]string{envUsageSeatIDsMonths: "24", envUsageRetentionYears: "12"}, usageRetentionConfig{24, 12}, false},
		{"member ids below 13 months", map[string]string{envUsageSeatIDsMonths: "12"}, usageRetentionConfig{}, true},
		{"member ids above the ceiling", map[string]string{envUsageSeatIDsMonths: "121"}, usageRetentionConfig{}, true},
		{"retention below 10 years", map[string]string{envUsageRetentionYears: "9"}, usageRetentionConfig{}, true},
		{"retention not a number", map[string]string{envUsageRetentionYears: "ten"}, usageRetentionConfig{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveUsageRetentionConfig(func(k string) string { return c.env[k] })
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("got %+v, %v; want %+v, error %v", got, err, c.want, c.wantErr)
			}
		})
	}
}

// TestUsageRetentionCutoffs: 13 months back for the member ids, 10 years
// and a day back for the rows, from the UTC day.
func TestUsageRetentionCutoffs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 23, 30, 0, 0, time.FixedZone("x", -5*3600)) // 2026-11-17 04:30 UTC
	m, e := usageRetentionCutoffs(usageRetentionConfig{13, 10}, now)
	if m != "2025-10-17" || e != "2016-11-16" {
		t.Fatalf("cutoffs = %s, %s", m, e)
	}
}

// fakeUsageRetention records the pass's calls.
type fakeUsageRetention struct {
	batches   []int64
	calls     int
	minBefore string
	expBefore string
	expired   int64
	failMin   bool
}

func (f *fakeUsageRetention) MinimiseOrgUsageDays(_ context.Context, before string, _ time.Time) (int64, error) {
	f.minBefore = before
	if f.failMin {
		return 0, errors.New("boom")
	}
	if f.calls >= len(f.batches) {
		f.calls++
		return 0, nil
	}
	n := f.batches[f.calls]
	f.calls++
	return n, nil
}

func (f *fakeUsageRetention) ExpireOrgUsageDays(_ context.Context, before string) (int64, error) {
	f.expBefore = before
	return f.expired, nil
}

// TestRunUsageRetentionPass: batches until one finds nothing, then expires;
// a minimisation error stops the pass before any expiry.
func TestRunUsageRetentionPass(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)
	f := &fakeUsageRetention{batches: []int64{5000, 12}, expired: 3}
	r, err := runUsageRetentionPass(context.Background(), f, usageRetentionConfig{13, 10}, now)
	if err != nil || r.minimised != 5012 || r.expired != 3 || f.calls != 3 || f.minBefore != "2025-10-16" || f.expBefore != "2016-11-15" {
		t.Fatalf("pass = %+v, %v, fake %+v", r, err, f)
	}
	failing := &fakeUsageRetention{failMin: true}
	if _, err := runUsageRetentionPass(context.Background(), failing, usageRetentionConfig{13, 10}, now); err == nil || failing.expBefore != "" {
		t.Fatalf("a failed minimisation went on to expire: %v, %+v", err, failing)
	}
	bounded := &fakeUsageRetention{batches: make([]int64, maxMinimiseBatchesPerPass+5)}
	for i := range bounded.batches {
		bounded.batches[i] = 1
	}
	if r, _ := runUsageRetentionPass(context.Background(), bounded, usageRetentionConfig{13, 10}, now); r.minimised != maxMinimiseBatchesPerPass {
		t.Fatalf("an endless backlog ran %d batches, want the bound %d", r.minimised, maxMinimiseBatchesPerPass)
	}
}

// TestStartUsageRetentionRefusesABadPeriod: the worker does not start on a
// period below its floor.
func TestStartUsageRetentionRefusesABadPeriod(t *testing.T) {
	t.Parallel()
	err := startUsageRetention(t.Context(), nil, &fakeUsageRetention{}, func(k string) string {
		if k == envUsageRetentionYears {
			return "5"
		}
		return ""
	}, time.Now)
	if err == nil {
		t.Fatal("a 5-year retention was accepted")
	}
}
