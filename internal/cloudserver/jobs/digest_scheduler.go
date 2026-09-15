package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// digest_scheduler.go is the W5 project-digest scheduling loop: for every
// (account, project) whose account's CURRENT plan carries digest_weekly and
// which has enough enriched sessions in the previous ISO week (Mon-Sun UTC),
// submit one project_digest job. It runs beside the worker's own lease loop
// (cmd/observer-cloud wires it in the same process) and owns no HTTP/SQL of
// its own — it composes the store seam, exactly like Worker.

// DigestSchedulerConfig configures RunDigestScheduler.
type DigestSchedulerConfig struct {
	// Interval is how often the scheduler ticks. Default 1h.
	Interval time.Duration
	// MinSessions is the minimum non-superseded session_enrichment results a
	// project must have in the previous week to earn a digest. Default 3.
	MinSessions int
	// BatchLimit bounds how many candidates one tick submits (never
	// loop-until-done). Default 200.
	BatchLimit int
	Logger     *slog.Logger
	// Credentials and Attestor are the SAME admission gate the API applies
	// to a session-enrichment submit (api/jobs.go, FA6): a digest is only
	// submitted when the provider key is present and the route's attestation
	// verifies. Without this pre-check a credential-absent worker would
	// reserve the allowance, store the evidence and then PARK the job at the
	// lease (a terminal state that releases everything) - and because the
	// canonical key (account, project, period) is then taken, that project's
	// digest for the week could never be retried once the credential landed.
	// Both nil ⇒ fail closed: nothing is submitted (the production wiring in
	// cmd/observer-cloud passes the worker's own chooser results).
	Credentials CredentialSource
	Attestor    ProviderAttestor
}

func (c *DigestSchedulerConfig) applyDefaults() {
	if c.Interval <= 0 {
		c.Interval = time.Hour
	}
	if c.MinSessions <= 0 {
		c.MinSessions = 3
	}
	if c.BatchLimit <= 0 {
		c.BatchLimit = 200
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// RunDigestScheduler ticks at cfg.Interval (and once at start), submitting one
// project_digest job per (account, project) due for the previous ISO week. It
// is idempotent by construction: ListProjectDigestCandidates excludes a
// (project, period) that already has a project_digest result, and
// SubmitDigestJob is additionally idempotent by canonical key — so re-running
// this loop, or running two instances briefly overlapping, submits nothing
// new. It logs counts only, never account ids or content, and returns when
// ctx is canceled.
func RunDigestScheduler(ctx context.Context, s *store.Store, clock func() time.Time, cfg DigestSchedulerConfig) {
	cfg.applyDefaults()
	if clock == nil {
		clock = time.Now
	}
	run := func() {
		n, err := RunDigestSchedulerOnce(ctx, s, clock(), cfg)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			cfg.Logger.Warn("cloudserver/jobs: digest scheduler pass failed", "err", err)
			return
		}
		if n > 0 {
			cfg.Logger.Info("cloudserver/jobs: digest scheduler submitted jobs", "count", n)
		}
	}
	run() // once at start, mirroring the community-materialization precedent
	t := time.NewTicker(cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// RunDigestSchedulerOnce runs exactly one scheduler pass at instant now and
// returns how many jobs it submitted. RunDigestScheduler is a thin ticking
// loop around this; it is exported separately so a caller (or a test) can
// drive a single deterministic pass without racing a ticker.
func RunDigestSchedulerOnce(ctx context.Context, s *store.Store, now time.Time, cfg DigestSchedulerConfig) (int, error) {
	cfg.applyDefaults()
	currentMonday, _ := store.WeekBoundsUTC(now)
	periodStart := currentMonday.AddDate(0, 0, -7)
	periodEnd := currentMonday.AddDate(0, 0, -1) // the previous week's Sunday
	rangeStart := periodStart
	rangeEnd := currentMonday // half-open [previous Monday, this Monday)

	route, err := s.ResolveRouteForFeature(ctx, store.FeatureProjectDigest)
	if err != nil {
		return 0, fmt.Errorf("resolve digest route: %w", err)
	}

	// Admission pre-check (mirrors the API's up-front refusal): no key or an
	// unverified attestation ⇒ submit NOTHING this tick, so no reservation,
	// evidence or canonical key is spent on a job that would only park.
	if cfg.Credentials == nil || cfg.Attestor == nil {
		cfg.Logger.Warn("cloudserver/jobs: digest scheduler has no credential source or attestor wired (fail closed) - nothing submitted")
		return 0, nil
	}
	if _, ok, cerr := cfg.Credentials.ProviderKey(ctx, route.RouteID); cerr != nil || !ok {
		cfg.Logger.Info("cloudserver/jobs: digest scheduler: provider credential absent for the digest route - nothing submitted this tick (jobs are not parked)")
		return 0, nil
	}
	if att, aerr := cfg.Attestor.Attest(ctx, route, now); aerr != nil || !att.Verified {
		cfg.Logger.Info("cloudserver/jobs: digest scheduler: route attestation not verified - nothing submitted this tick", "reason", att.Reason)
		return 0, nil
	}

	candidates, err := s.ListProjectDigestCandidates(ctx, periodStart, periodEnd, rangeStart, rangeEnd, cfg.MinSessions, cfg.BatchLimit, now)
	if err != nil {
		return 0, fmt.Errorf("list digest candidates: %w", err)
	}

	submitted := 0
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return submitted, err
		}
		facts, err := s.LoadProjectDigestEvidence(ctx, c.AccountID, c.ProjectPK, rangeStart, rangeEnd)
		if err != nil {
			cfg.Logger.Warn("cloudserver/jobs: load digest evidence failed", "err", err)
			continue
		}
		if len(facts) == 0 {
			// The candidate scan and this tenant-scoped read can observe a
			// slightly different snapshot under heavy concurrent writes; skip
			// rather than submit an empty digest.
			continue
		}
		evidence := buildDigestEvidence(c.CloudProjectID, periodStart, periodEnd, facts)
		raw, err := evidence.Serialize()
		if err != nil {
			cfg.Logger.Warn("cloudserver/jobs: serialize digest evidence failed", "err", err)
			continue
		}
		digest := sha256Hex(string(raw))
		blobRef := "digest/" + c.CloudProjectID + "/" + evidence.PeriodStart

		_, err = s.SubmitDigestJob(ctx, store.SubmitDigestJobInput{
			AccountID: c.AccountID, CloudProjectID: c.CloudProjectID,
			PeriodStart: evidence.PeriodStart, PeriodEnd: evidence.PeriodEnd,
			RouteID: route.RouteID, RouteVersion: route.RouteVersion, PromptVersion: route.PromptVersion,
			EvidenceBytes: raw, BlobRef: blobRef,
			UploadDigest: "sha256:" + digest, ContentDigest: "sha256:" + digest,
			SizeBytes: int64(len(raw)), Now: now,
		})
		if err != nil {
			switch {
			case errors.Is(err, store.ErrDailyLimit), errors.Is(err, store.ErrMonthlyLimit),
				errors.Is(err, store.ErrConcurrency), errors.Is(err, store.ErrGlobalBudget),
				errors.Is(err, store.ErrAccountClosed):
				// Capacity exhausted or the account is no longer eligible this
				// tick — try again next tick rather than treating it as a bug.
				continue
			default:
				cfg.Logger.Warn("cloudserver/jobs: submit digest job failed", "err", err)
				continue
			}
		}
		submitted++
	}
	return submitted, nil
}

// buildDigestEvidence folds a project's recent enriched sessions into a
// cloudcontract.DigestEvidence payload.
func buildDigestEvidence(cloudProjectID string, periodStart, periodEnd time.Time, facts []store.DigestSessionRow) cloudcontract.DigestEvidence {
	sessions := make([]cloudcontract.DigestSessionFact, 0, len(facts))
	for _, f := range facts {
		sessions = append(sessions, cloudcontract.DigestSessionFact{
			CloudSessionID: f.CloudSessionID,
			CreatedAt:      f.CreatedAt.UTC().Format(time.RFC3339),
			Title:          f.Title,
			Description:    f.Description,
			TaxonomyTags:   f.TaxonomyTags,
			Limitations:    f.Limitations,
			Metrics:        f.Metrics,
		})
	}
	return cloudcontract.DigestEvidence{
		SchemaVersion:    cloudcontract.DigestEvidenceSchemaVersion,
		ProjectPseudonym: cloudProjectID,
		PeriodStart:      periodStart.Format("2006-01-02"),
		PeriodEnd:        periodEnd.Format("2006-01-02"),
		Sessions:         sessions,
	}
}
