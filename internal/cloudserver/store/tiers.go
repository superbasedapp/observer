package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
)

// Enrichment tiers (ruling R-AI1, migration 0078): the platform
// configuration that maps a tier to a route, an evidence budget and the
// session / daily / monthly token budgets. This file is the one SQL owner of
// enrichment_tiers. Rows are immutable; the highest version of a tier is in
// force, and a change is a new version published through PublishTier, which
// refuses any route that is not active, bound, priced and attested.

// ErrTierNotFound means a plan names an enrichment tier that has no published
// version. It is a configuration fault, never a user condition: the API maps
// it to 503 and nothing is reserved.
var ErrTierNotFound = errors.New("cloudserver/store: enrichment tier not found")

// TierInfo is one published tier version with its audit columns.
type TierInfo struct {
	Tier        enrichbudget.Tier
	PublishedBy string
	Note        string
	CreatedAt   time.Time
}

const tierSelectColumns = `tier, version, route_id, evidence_token_budget, session_token_budget,
	daily_token_budget, monthly_token_budget, published_by, note, created_at`

func scanTier(row pgx.Row) (TierInfo, error) {
	var ti TierInfo
	t := &ti.Tier
	err := row.Scan(&t.Name, &t.Version, &t.RouteID, &t.EvidenceTokens, &t.SessionTokens,
		&t.DailyTokens, &t.MonthlyTokens, &ti.PublishedBy, &ti.Note, &ti.CreatedAt)
	return ti, err
}

// loadTierTx reads the version of tier in force (the highest published) on
// the caller's transaction. enrichment_tiers is a system table, so it reads
// the same under a tenant or a system transaction.
func loadTierTx(ctx context.Context, tx pgx.Tx, tier string) (enrichbudget.Tier, error) {
	ti, err := scanTier(tx.QueryRow(ctx,
		`SELECT `+tierSelectColumns+` FROM enrichment_tiers WHERE tier = $1 ORDER BY version DESC LIMIT 1`, tier))
	if errors.Is(err, pgx.ErrNoRows) {
		return enrichbudget.Tier{}, fmt.Errorf("%w: %q", ErrTierNotFound, tier)
	}
	if err != nil {
		return enrichbudget.Tier{}, fmt.Errorf("load enrichment tier %q: %w", tier, err)
	}
	return ti.Tier, nil
}

// ResolveTier returns the version of tier in force.
func (s *Store) ResolveTier(ctx context.Context, tier string) (enrichbudget.Tier, error) {
	var out enrichbudget.Tier
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var e error
		out, e = loadTierTx(ctx, tx, tier)
		return e
	})
	return out, err
}

// ListTiers returns every published tier version, tier by tier, newest
// version first (the operator's `observer-cloud tier show`).
func (s *Store) ListTiers(ctx context.Context) ([]TierInfo, error) {
	var out []TierInfo
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT `+tierSelectColumns+` FROM enrichment_tiers ORDER BY tier, version DESC`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			ti, e := scanTier(rows)
			if e != nil {
				return e
			}
			out = append(out, ti)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListTiers: %w", err)
	}
	return out, nil
}

// RouteFactsFor resolves what the store knows about a route into the pure
// facts enrichbudget.CheckTier decides on. Attestation is NOT the store's to
// know (it is the process's attestor); the caller fills Attested.
func RouteFactsFor(r RouteInfo) enrichbudget.RouteFacts {
	pv := strings.TrimSpace(r.PriceVersion)
	return enrichbudget.RouteFacts{
		Found:           true,
		Feature:         r.Feature,
		Production:      r.Environment == RouteEnvironmentProduction,
		Active:          r.Active,
		Bound:           RouteBound(r),
		Priced:          r.InputPricePerMTok > 0 && r.OutputPricePerMTok > 0 && pv != "" && pv != "unset",
		MaxOutputTokens: r.MaxOutputTokens,
	}
}

// RouteAttestation is an attestation verdict for one route snapshot: the
// caller ran its attestor against the route at Generation.
type RouteAttestation struct {
	Verified   bool
	Reason     string
	Generation int64
}

// TierPublish is one request to publish a new version of a tier.
type TierPublish struct {
	// Tier is the configuration to publish; its Version is assigned here.
	Tier enrichbudget.Tier
	// Attestation is the verdict of the process's attestor on the route the
	// tier names. It counts only if it was taken against the route's CURRENT
	// generation (re-read inside the publishing transaction).
	Attestation RouteAttestation
	// PublishedBy and Note are recorded on the row.
	PublishedBy string
	Note        string
}

// tierPublishLockKey serializes publishers of one tier so two concurrent
// publishes cannot both take version N+1 (the second would only fail on the
// primary key, after doing its checks against a stale version).
func tierPublishLockKey(tier string) string { return "sbci-enrichment-tier\x1f" + tier }

// PublishTier publishes the next version of a tier. In ONE transaction it
// re-reads the route the tier names, derives the route facts, accepts the
// caller's attestation only for the route's current generation, runs
// enrichbudget.CheckTier, and inserts. A route that is missing, inactive,
// unbound, unpriced or unattested is refused and nothing is written.
func (s *Store) PublishTier(ctx context.Context, p TierPublish) (enrichbudget.Tier, error) {
	t := p.Tier
	by := strings.TrimSpace(p.PublishedBy)
	if by == "" {
		by = "operator"
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, tierPublishLockKey(t.Name)); e != nil {
			return fmt.Errorf("lock tier: %w", e)
		}
		facts := enrichbudget.RouteFacts{}
		var r RouteInfo
		e := scanRoute(tx.QueryRow(ctx, `SELECT `+routeSelectColumns+` FROM route_registry WHERE route_id = $1`, t.RouteID), &r)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
		case e != nil:
			return fmt.Errorf("read route %q: %w", t.RouteID, e)
		default:
			facts = RouteFactsFor(r)
			switch {
			case p.Attestation.Generation != r.Generation:
				facts.AttestReason = fmt.Sprintf("the attestation was taken at route generation %d, the route is now at %d", p.Attestation.Generation, r.Generation)
			case !p.Attestation.Verified:
				facts.AttestReason = p.Attestation.Reason
			default:
				facts.Attested = true
			}
		}
		var next int
		if e := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM enrichment_tiers WHERE tier = $1`, t.Name).Scan(&next); e != nil {
			return fmt.Errorf("next tier version: %w", e)
		}
		t.Version = next
		if e := enrichbudget.CheckTier(t, FeatureSessionEnrichment, facts); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`INSERT INTO enrichment_tiers (tier, version, route_id, evidence_token_budget, session_token_budget,
			                               daily_token_budget, monthly_token_budget, published_by, note)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			t.Name, t.Version, t.RouteID, t.EvidenceTokens, t.SessionTokens, t.DailyTokens, t.MonthlyTokens, by, p.Note); e != nil {
			return fmt.Errorf("insert tier: %w", e)
		}
		return nil
	})
	if err != nil {
		return enrichbudget.Tier{}, fmt.Errorf("cloudserver/store.PublishTier: %w", err)
	}
	return t, nil
}
