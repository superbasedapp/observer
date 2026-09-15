package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RouteInfo is a resolved route-registry row. The server folds RouteVersion +
// PromptVersion into the canonical job key so a route/prompt change makes a
// resubmission a distinct job (Sol SC10). CI-P4 grew it with the Foundry-call
// columns (endpoint/api_version/deployment sizing + price snapshot) and the
// attestation binding identifiers (plan §2.2).
type RouteInfo struct {
	RouteID            string
	Feature            string
	Deployment         string
	Dialect            string
	RouteVersion       int64
	PromptVersion      int64
	PriceVersion       string
	Active             bool
	Generation         int64
	Endpoint           string
	APIVersion         string
	MaxOutputTokens    int
	InputPricePerMTok  float64
	OutputPricePerMTok float64
	TenantID           string
	SubscriptionID     string
	ARMResourceID      string
	EndpointAudience   string
	// Environment is the route's deployment class: RouteEnvironmentProduction or
	// RouteEnvironmentNonProduction (migration 0014, default 'production'). It
	// partitions the registry into two DISJOINT sets — the production worker
	// serves only production routes, the fixture-only proving lane only
	// non-production ones — so neither lane can act on the other's routes, and
	// the provider_attestations cache they share is therefore never shared for
	// the same route_id.
	Environment string
}

// Route environment classes (migration 0014's CHECK vocabulary).
const (
	// RouteEnvironmentProduction is the DEFAULT and the fail-closed value: a
	// route nobody classified is production, which the worker serves and the
	// proving lane refuses.
	RouteEnvironmentProduction = "production"
	// RouteEnvironmentNonProduction marks a route provisioned for the
	// fixture-only proving lane. The worker refuses it.
	RouteEnvironmentNonProduction = "nonproduction"
)

const routeSelectColumns = `route_id, feature, deployment, dialect, route_version, prompt_version,
	price_version, active, generation, endpoint, api_version, max_output_tokens,
	input_price_per_mtok, output_price_per_mtok, tenant_id, subscription_id,
	arm_resource_id, endpoint_audience, environment`

func scanRoute(row pgx.Row, r *RouteInfo) error {
	return row.Scan(
		&r.RouteID, &r.Feature, &r.Deployment, &r.Dialect, &r.RouteVersion, &r.PromptVersion,
		&r.PriceVersion, &r.Active, &r.Generation, &r.Endpoint, &r.APIVersion, &r.MaxOutputTokens,
		&r.InputPricePerMTok, &r.OutputPricePerMTok, &r.TenantID, &r.SubscriptionID,
		&r.ARMResourceID, &r.EndpointAudience, &r.Environment,
	)
}

// ResolveRoute returns the active DEFAULT route for a feature (system table).
//
// A route marked plan_pinned (migration 0039) is excluded: it exists only to be
// named by a plan's route_id, so it must never win the default pick - otherwise
// activating a paid plan's route would silently start serving FREE accounts on
// it, decided by nothing more than the tie-break of two rows at the same
// route_version.
func (s *Store) ResolveRoute(ctx context.Context, feature string) (RouteInfo, error) {
	var r RouteInfo
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := scanRoute(tx.QueryRow(ctx,
			`SELECT `+routeSelectColumns+`
			   FROM route_registry
			  WHERE feature = $1 AND active = true AND plan_pinned = false
			  ORDER BY route_version DESC, route_id LIMIT 1`, feature), &r)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return r, err
}

// Plan-route fallback reasons (migration 0039). Closed vocabulary: every
// degradation an operator can cause has exactly one name, so the audit/log line
// is greppable and the surface never has to interpret free text.
const (
	// PlanRouteInactive - the pinned route exists but active = false (the state
	// migration 0039 seeds the Sol route in: deployed nowhere yet).
	PlanRouteInactive = "inactive"
	// PlanRouteUnbound - the pinned route is active but carries no endpoint /
	// api_version, so nothing could call it.
	PlanRouteUnbound = "unbound"
	// PlanRouteFeatureMismatch - the pinned route belongs to a DIFFERENT
	// feature. A catalogue mistake, not a user condition.
	PlanRouteFeatureMismatch = "feature_mismatch"
)

// PlanRouteFallbackMetric is the one name every surface uses when it reports a
// plan-route degradation (log key, audit action suffix, counter name).
const PlanRouteFallbackMetric = "plan_route_unavailable"

// PlanRouteFallback reports that a plan's PINNED route could not serve and the
// feature default was used instead. The zero value means no fallback happened.
type PlanRouteFallback struct {
	// RouteID is the pinned route that could not serve.
	RouteID string
	// Reason is one of the PlanRoute* constants above.
	Reason string
}

// Fell reports whether a fallback actually happened.
func (f PlanRouteFallback) Fell() bool { return f.RouteID != "" }

// ResolveRouteForPlan resolves the route a job should run on for an account
// whose resolved plan pins planRouteID (Plan.RouteID, migration 0039). An empty
// planRouteID means the plan pins nothing, which is the feature default -
// identical to ResolveRoute, which every pre-0039 caller keeps using unchanged.
//
// DEGRADE, NEVER DENY. A pinned route that is inactive, unbound, or registered
// against another feature resolves the FEATURE DEFAULT and returns a non-zero
// PlanRouteFallback so the caller can log/audit it under
// PlanRouteFallbackMetric. This is deliberate and is the opposite of the
// fail-closed posture the ADMISSION gates take: those protect user evidence
// from a route that cannot legally run, whereas here the default route is
// live, bound and attested - refusing would take a PAYING customer's service
// away to protect them from getting the cheaper model. A paid plan degrades to
// the default model; it never degrades to no service.
//
// The ONE hard error is a pinned route_id that does not exist at all: the plan
// catalogue names a row that was never seeded, which no fallback can make
// correct and which an operator must see immediately.
func (s *Store) ResolveRouteForPlan(ctx context.Context, feature, planRouteID string) (RouteInfo, PlanRouteFallback, error) {
	if strings.TrimSpace(planRouteID) == "" {
		r, err := s.ResolveRoute(ctx, feature)
		return r, PlanRouteFallback{}, err
	}
	pinned, err := s.RouteByID(ctx, planRouteID)
	if err != nil {
		// ErrNotFound included: a plan pinning a route that does not exist is a
		// catalogue error, never a silent downgrade.
		return RouteInfo{}, PlanRouteFallback{}, fmt.Errorf("cloudserver/store.ResolveRouteForPlan: pinned route %q: %w", planRouteID, err)
	}
	reason := ""
	switch {
	case pinned.Feature != feature:
		reason = PlanRouteFeatureMismatch
	case !pinned.Active:
		reason = PlanRouteInactive
	case pinned.Endpoint == "" || pinned.APIVersion == "":
		reason = PlanRouteUnbound
	}
	if reason == "" {
		return pinned, PlanRouteFallback{}, nil
	}
	def, err := s.ResolveRoute(ctx, feature)
	if err != nil {
		return RouteInfo{}, PlanRouteFallback{}, err
	}
	return def, PlanRouteFallback{RouteID: planRouteID, Reason: reason}, nil
}

// ResolveRouteForFeature resolves feature's own active route, falling back to
// the session_enrichment route when feature has none of its own (W5): a
// project digest never needs its own operator-seeded route_registry row —
// same deployment, same binding as session enrichment — so this is the ONE
// documented fallback rather than requiring every deployment to seed a
// duplicate row.
func (s *Store) ResolveRouteForFeature(ctx context.Context, feature string) (RouteInfo, error) {
	r, err := s.ResolveRoute(ctx, feature)
	if errors.Is(err, ErrNotFound) {
		return s.ResolveRoute(ctx, FeatureSessionEnrichment)
	}
	return r, err
}

// RouteByID returns a route by its id (the worker resolves the leased job's
// route to get its binding + Foundry-call columns).
func (s *Store) RouteByID(ctx context.Context, routeID string) (RouteInfo, error) {
	var r RouteInfo
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := scanRoute(tx.QueryRow(ctx,
			`SELECT `+routeSelectColumns+` FROM route_registry WHERE route_id = $1`, routeID), &r)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return r, err
}

// KillSwitchState reports whether the global switch and a specific route's
// switch are active, with their generations (Sol SC4 — the lease compares these).
type KillSwitchState struct {
	GlobalActive     bool
	GlobalGeneration int64
	RouteActive      bool
	RouteGeneration  int64
}

// KillSwitches loads the global + per-route kill-switch state (system table).
// FA7 fail-closed: a MISSING sentinel row (someone deleted the global or the
// per-route switch) is treated as ACTIVE (service paused / policy-unverified),
// never as "not switched" — an ambiguous control-plane state must fail closed
// (§7.5). The seed migration installs exactly one of each row, so a missing row
// is an out-of-band mutation, not a normal state.
func (s *Store) KillSwitches(ctx context.Context, routeID string) (KillSwitchState, error) {
	var st KillSwitchState
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT active, generation FROM kill_switches WHERE scope = 'global' AND key = 'all'`).
			Scan(&st.GlobalActive, &st.GlobalGeneration)
		if errors.Is(e, pgx.ErrNoRows) {
			st.GlobalActive = true // missing global sentinel ⇒ fail closed
		} else if e != nil {
			return e
		}
		e = tx.QueryRow(ctx,
			`SELECT active, generation FROM kill_switches WHERE scope = 'route' AND key = $1`, routeID).
			Scan(&st.RouteActive, &st.RouteGeneration)
		if errors.Is(e, pgx.ErrNoRows) {
			st.RouteActive = true // missing per-route sentinel ⇒ fail closed
		} else if e != nil {
			return e
		}
		return nil
	})
	return st, err
}

// GlobalKillSwitchActive reports whether the GLOBAL free-tier kill switch is
// on. The API consults this to refuse NEW job submissions when the operator has
// paused the free tier (the worker independently gates leased jobs on both the
// global and per-route switches — this is the admission-side wall). Fail-closed
// is the caller's choice: an error here should block submission, not silently
// admit.
func (s *Store) GlobalKillSwitchActive(ctx context.Context) (bool, error) {
	var active bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT active FROM kill_switches WHERE scope = 'global' AND key = 'all'`).Scan(&active)
		if errors.Is(e, pgx.ErrNoRows) {
			// FA7 fail-closed: a deleted global sentinel must NOT reopen admission.
			// Treat a missing row as PAUSED so the caller refuses new submissions.
			active = true
			return nil
		}
		return e
	})
	return active, err
}

// SetRouteActive flips a route's active flag (operator action; tests use it to
// prove an inactive route is refused at admission AND at the execution lease).
// FA7: it also BUMPS the route generation. The executor's final pre-dispatch
// re-check compares the route generation against the snapshot the worker
// attested under, so a deactivation between revalidation and dispatch is caught
// as a generation change — an operator flipping active=false stops an in-flight
// worker from calling the route, not only future admissions.
func (s *Store) SetRouteActive(ctx context.Context, routeID string, active bool) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE route_registry SET active = $2, generation = generation + 1 WHERE route_id = $1`, routeID, active)
		if e != nil {
			return fmt.Errorf("cloudserver/store.SetRouteActive: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetRouteEnvironment classifies a route as production or non-production
// (operator provisioning; tests use it to build a provable route). It BUMPS the
// generation, like every other route mutation: moving a route between lanes
// changes what may call it, so a prior attestation must not carry over.
func (s *Store) SetRouteEnvironment(ctx context.Context, routeID, environment string) error {
	switch environment {
	case RouteEnvironmentProduction, RouteEnvironmentNonProduction:
	default:
		return fmt.Errorf("cloudserver/store.SetRouteEnvironment: unknown environment %q (want %q or %q)",
			environment, RouteEnvironmentProduction, RouteEnvironmentNonProduction)
	}
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE route_registry SET environment = $2, generation = generation + 1 WHERE route_id = $1`,
			routeID, environment)
		if e != nil {
			return fmt.Errorf("cloudserver/store.SetRouteEnvironment: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetKillSwitch flips a kill switch and bumps its generation (operator action;
// used by tests and the CI-P6 kill-switch surface).
func (s *Store) SetKillSwitch(ctx context.Context, scope, key string, active bool) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE kill_switches SET active = $3, generation = generation + 1, updated_at = now()
			  WHERE scope = $1 AND key = $2`, scope, key, active)
		if e != nil {
			return fmt.Errorf("set kill switch: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RecordAudit appends a content-free security audit event (system table).
// accountID "" ⇒ NULL (a pre-auth event).
func (s *Store) RecordAudit(ctx context.Context, accountID, eventType, detailJSON string) error {
	detail := detailJSON
	if detail == "" {
		detail = "{}"
	}
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO security_audit_events (account_id, event_type, detail)
			 VALUES ($1::uuid, $2, $3::jsonb)`,
			nullString(accountID), eventType, detail)
		if e != nil {
			return fmt.Errorf("record audit: %w", e)
		}
		return nil
	})
}
