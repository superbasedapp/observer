package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// evidencesweep.go is the worker's expired-evidence sweeper (findings
// 2026-11-22 CLOUD-01; docs/cloud-intelligence.md "Evidence TTL"). An evidence
// object carries an immutable expires_at = created_at + 1 hour. Evidence is
// also deleted when its job ends and when a leased job fails Gate 3, but a job
// that never ends (no worker leasing, a revalidation error that keeps
// re-leasing it, a feature no worker leases, a backlog longer than the TTL)
// kept its evidence past the hour, because nothing called
// store.SweepExpiredEvidence. This loop calls it once at start and then every
// interval, by expires_at alone and regardless of the job's state.
//
// The worker binds sbci_worker, which holds EXECUTE on the SECURITY DEFINER
// sbci_sweep_expired_evidence since cloud migration 0151. The loop is
// fail-soft (a failed pass is logged and the next tick tries again) and ends
// with the worker's context.

// Evidence sweep interval: the environment variable and its bounds.
const (
	// EnvEvidenceSweepInterval names the sweep interval, a Go duration
	// (for example "5m").
	EnvEvidenceSweepInterval = "SBCI_EVIDENCE_SWEEP_INTERVAL"
	// DefaultEvidenceSweepInterval is the interval when the variable is unset.
	// Expired evidence is deleted within one interval of its expires_at.
	DefaultEvidenceSweepInterval = 5 * time.Minute
	// MinEvidenceSweepInterval keeps the loop from hammering the database.
	MinEvidenceSweepInterval = 10 * time.Second
	// MaxEvidenceSweepInterval keeps the overrun past the one-hour TTL to a
	// quarter of it at most.
	MaxEvidenceSweepInterval = 15 * time.Minute
)

// EvidenceSweepStore is the one store method the sweeper calls
// (*store.Store satisfies it).
type EvidenceSweepStore interface {
	SweepExpiredEvidence(ctx context.Context, now time.Time) (int, error)
}

// EvidenceSweeperConfig tunes RunEvidenceSweeper.
type EvidenceSweeperConfig struct {
	// Interval between passes; zero or negative means
	// DefaultEvidenceSweepInterval.
	Interval time.Duration
	// Logger receives counts and errors only, never an account id or
	// content; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock each pass sweeps at; nil means time.Now.
	Now func() time.Time
}

func (c *EvidenceSweeperConfig) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = DefaultEvidenceSweepInterval
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// ResolveEvidenceSweepInterval reads EnvEvidenceSweepInterval through getenv.
// Unset or blank is DefaultEvidenceSweepInterval. Anything else must be a Go
// duration from MinEvidenceSweepInterval to MaxEvidenceSweepInterval, or the
// error refuses the worker's start: the evidence TTL is a privacy promise, so
// a typo must not silently stretch it.
func ResolveEvidenceSweepInterval(getenv func(string) string) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(EnvEvidenceSweepInterval))
	if raw == "" {
		return DefaultEvidenceSweepInterval, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < MinEvidenceSweepInterval || d > MaxEvidenceSweepInterval {
		return 0, fmt.Errorf("cloudserver/jobs: %s=%q: want a duration from %s to %s (default %s)",
			EnvEvidenceSweepInterval, raw, MinEvidenceSweepInterval, MaxEvidenceSweepInterval, DefaultEvidenceSweepInterval)
	}
	return d, nil
}

// RunEvidenceSweeper sweeps expired evidence once now and then every
// cfg.Interval until ctx ends. A failed pass is logged and the loop goes on.
func RunEvidenceSweeper(ctx context.Context, s EvidenceSweepStore, cfg EvidenceSweeperConfig) {
	cfg.applyDefaults()
	pass := func() {
		n, err := s.SweepExpiredEvidence(ctx, cfg.Now())
		if err != nil {
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return
			}
			cfg.Logger.Warn("cloudserver/jobs: evidence sweep failed", "err", err)
			return
		}
		if n > 0 {
			cfg.Logger.Info("cloudserver/jobs: evidence sweep deleted expired evidence", "deleted", n)
		}
	}
	pass()
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}

// StartEvidenceSweeper resolves the interval from getenv (a bad value returns
// the error and starts nothing) and runs RunEvidenceSweeper in its own
// goroutine for the life of ctx. It is the worker's one call site.
func StartEvidenceSweeper(ctx context.Context, log *slog.Logger, s EvidenceSweepStore, getenv func(string) string) error {
	interval, err := ResolveEvidenceSweepInterval(getenv)
	if err != nil {
		return err
	}
	go RunEvidenceSweeper(ctx, s, EvidenceSweeperConfig{Interval: interval, Logger: log})
	return nil
}
