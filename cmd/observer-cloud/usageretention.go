package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// usageretention.go is the worker's org usage retention pass (managed-SaaS
// plan 07 wave 16 lane plan-policy; lead decision W16-D9; L-124
// C3.ENTL-usage-retention; docs/security.md USAGE-1 to USAGE-3). Once at
// start and then daily it
//
//   - minimises org_usage_days older than SBCI_USAGE_SEAT_IDS_MONTHS
//     (default 13: one annual billing cycle and a month for disputes): the
//     day keeps its seat count and loses its member ids
//     (store.MinimiseOrgUsageDays, bounded batches until none is left);
//   - deletes days older than SBCI_USAGE_RETENTION_YEARS (default 10, the
//     floor) and a day, through the one delete path the database allows
//     (store.ExpireOrgUsageDays over sbci_expire_org_usage_days, which
//     itself refuses any day inside 10 years).
//
// It is always on: minimisation is the data-minimisation half of keeping
// the usage behind an invoice for 10 years, not a feature. The periods may
// only be lengthened: a value below its floor refuses to start the worker.

// Usage retention environment variables and their bounds.
const (
	envUsageSeatIDsMonths   = "SBCI_USAGE_SEAT_IDS_MONTHS"
	envUsageRetentionYears  = "SBCI_USAGE_RETENTION_YEARS"
	defaultUsageSeatMonths  = 13
	minUsageSeatMonths      = 13
	maxUsageSeatMonths      = 120
	defaultUsageRetainYears = 10
	minUsageRetainYears     = 10
	maxUsageRetainYears     = 30
	// usageRetentionEvery is the pass cadence: days age by days.
	usageRetentionEvery = 24 * time.Hour
	// maxMinimiseBatchesPerPass bounds one pass; a larger backlog continues
	// the next day.
	maxMinimiseBatchesPerPass = 100
)

// usageRetentionConfig is the resolved pass configuration.
type usageRetentionConfig struct {
	seatIDsMonths, retentionYears int
}

// usageRetentionBound is one row of the configuration table.
type usageRetentionBound struct {
	env           string
	def, min, max int
	set           func(c *usageRetentionConfig, v int)
}

func usageRetentionBounds() []usageRetentionBound {
	return []usageRetentionBound{
		{
			envUsageSeatIDsMonths, defaultUsageSeatMonths, minUsageSeatMonths, maxUsageSeatMonths,
			func(c *usageRetentionConfig, v int) { c.seatIDsMonths = v },
		},
		{
			envUsageRetentionYears, defaultUsageRetainYears, minUsageRetainYears, maxUsageRetainYears,
			func(c *usageRetentionConfig, v int) { c.retentionYears = v },
		},
	}
}

// resolveUsageRetentionConfig reads the two periods; unset is the default,
// anything else must be a whole number within its bounds.
func resolveUsageRetentionConfig(getenv func(string) string) (usageRetentionConfig, error) {
	var c usageRetentionConfig
	for _, b := range usageRetentionBounds() {
		v := b.def
		if raw := strings.TrimSpace(getenv(b.env)); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < b.min || n > b.max {
				return usageRetentionConfig{}, fmt.Errorf("observer-cloud: %s=%q: want a whole number from %d to %d (default %d)", b.env, raw, b.min, b.max, b.def)
			}
			v = n
		}
		b.set(&c, v)
	}
	return c, nil
}

// usageRetentionCutoffs are the two cutoff days (YYYY-MM-DD) at now: days
// strictly before minimiseBefore are minimised, days strictly before
// expireBefore are deleted. The expiry cutoff is a day earlier than the
// period, so a database clock in another time zone never puts it inside
// the 10-year floor.
func usageRetentionCutoffs(c usageRetentionConfig, now time.Time) (minimiseBefore, expireBefore string) {
	day := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return day.AddDate(0, -c.seatIDsMonths, 0).Format(time.DateOnly),
		day.AddDate(-c.retentionYears, 0, -1).Format(time.DateOnly)
}

// usageRetentionStore is the store as the pass uses it (*store.Store).
type usageRetentionStore interface {
	MinimiseOrgUsageDays(ctx context.Context, before string, now time.Time) (int64, error)
	ExpireOrgUsageDays(ctx context.Context, before string) (int64, error)
}

// usageRetentionResult is what one pass did.
type usageRetentionResult struct {
	minimised, expired int64
}

// runUsageRetentionPass minimises in bounded batches until a batch finds
// nothing (or the pass's batch bound is spent), then expires. An error
// stops the pass with what it did.
func runUsageRetentionPass(ctx context.Context, s usageRetentionStore, c usageRetentionConfig, now time.Time) (usageRetentionResult, error) {
	var r usageRetentionResult
	minimiseBefore, expireBefore := usageRetentionCutoffs(c, now)
	for range maxMinimiseBatchesPerPass {
		n, err := s.MinimiseOrgUsageDays(ctx, minimiseBefore, now)
		if err != nil {
			return r, err
		}
		r.minimised += n
		if n == 0 {
			break
		}
	}
	n, err := s.ExpireOrgUsageDays(ctx, expireBefore)
	if err != nil {
		return r, err
	}
	r.expired = n
	return r, nil
}

// startUsageRetention resolves the configuration (a bad value refuses the
// worker's start) and runs the pass once now and then every
// usageRetentionEvery until ctx ends.
func startUsageRetention(ctx context.Context, log *slog.Logger, s usageRetentionStore, getenv func(string) string, now func() time.Time) error {
	c, err := resolveUsageRetentionConfig(getenv)
	if err != nil {
		return err
	}
	pass := func() {
		r, err := runUsageRetentionPass(ctx, s, c, now())
		if err != nil {
			log.Warn("observer-cloud: org usage retention pass failed", "err", err, "minimised", r.minimised)
			return
		}
		if r.minimised > 0 || r.expired > 0 {
			log.Info("observer-cloud: org usage retention pass", "minimised", r.minimised, "expired", r.expired)
		}
	}
	go func() {
		pass()
		t := time.NewTicker(usageRetentionEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pass()
			}
		}
	}()
	return nil
}
