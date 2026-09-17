package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
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
// A route marked plan_pinned (migration 0039) is excluded from the candidate
// set entirely: it exists only to be named by a plan's route_id, so it must
// never win the default pick - otherwise activating a paid plan's route would
// silently start serving FREE accounts on it.
//
// The winner among what is left is picked in Go by pickDefaultRoute, not by an
// ORDER BY ... LIMIT 1 in the SQL, so the tie-break rule is a pure function a
// test can drive with a literal slice of rows instead of a live database (the
// two ambiguous-tie scenarios - two active same-version routes, neither
// pinned; the same but one pinned - are exactly what pickDefaultRoute's own
// test table exercises without Postgres).
func (s *Store) ResolveRoute(ctx context.Context, feature string) (RouteInfo, error) {
	var out []RouteInfo
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT `+routeSelectColumns+`
			   FROM route_registry
			  WHERE feature = $1 AND active = true AND plan_pinned = false`, feature)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r RouteInfo
			if e := scanRoute(rows, &r); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return RouteInfo{}, err
	}
	r, found := pickDefaultRoute(out)
	if !found {
		return RouteInfo{}, ErrNotFound
	}
	return r, nil
}

// pickDefaultRoute picks the winner among a feature's already-filtered
// candidate routes (active = true, plan_pinned = false - the caller's job, not
// this function's: it does not re-check either flag). Highest route_version
// wins; ties break on route_id ASCENDING.
//
// route_id, not a timestamp, is the tiebreak because it is the one column
// every route_registry row is guaranteed to carry unchanged for its whole
// life: route_version bumps on a genuine route replacement, but two rows can
// still land at the same version (the migration-0039 scenario: the Sol row
// ships at route_version 1, same as Luna's). created_at would work today, but
// SetRouteBinding/SetRouteActive/SetRouteEnvironment all bump `generation`
// without touching a bind/activation timestamp - there is no bound_at column -
// so a created_at tiebreak would silently start depending on migration
// application order the day someone reorders 0039-style seed statements.
// route_id is human-authored, stable, and already part of the same ORDER BY
// the SQL used before this function existed, so this preserves prior
// behaviour exactly while making it independently testable.
//
// Pure (no SQL/HTTP/fsnotify): callers load rows, this function decides.
func pickDefaultRoute(candidates []RouteInfo) (RouteInfo, bool) {
	var best RouteInfo
	found := false
	for _, r := range candidates {
		switch {
		case !found:
			best, found = r, true
		case r.RouteVersion > best.RouteVersion:
			best = r
		case r.RouteVersion == best.RouteVersion && r.RouteID < best.RouteID:
			best = r
		}
	}
	return best, found
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

// FeatureCoverage reports whether ResolveRoute can currently pick a default
// for one feature present in route_registry.
type FeatureCoverage struct {
	// Feature is the route_registry.feature value.
	Feature string
	// HasDefault is true when at least one row for Feature is active and NOT
	// plan_pinned - i.e. ResolveRoute(ctx, Feature) would succeed right now.
	HasDefault bool
}

// routeCoverageRow is the minimal per-row fact FeatureDefaultCoverage needs -
// deliberately NOT RouteInfo/scanRoute, which carries a dozen Foundry-call
// columns this classification never looks at.
type routeCoverageRow struct {
	Feature    string
	Active     bool
	PlanPinned bool
}

// classifyFeatureCoverage is the pure half of the readiness check: given every
// route_registry row's (feature, active, plan_pinned) facts, decide per
// feature whether ResolveRoute has an eligible candidate. No SQL/HTTP here, so
// a test drives it with a literal slice instead of a live database.
//
// WHY THIS EXISTS. ResolveRoute (above) deliberately excludes plan_pinned
// routes from the default pick - that's the whole migration-0039 fix: a plan
// route must never win the free tier by tie-break accident. But excluding a
// row from a query the operator DID make active is also a new way to break a
// feature entirely: if a feature's ONLY active route is plan_pinned (an
// operator deactivates the true default mid-migration, or a feature is seeded
// with just a plan route and nothing else), ResolveRoute now returns
// ErrNotFound for every account that doesn't hold that plan - a fleet-wide
// 503 no_route for the feature's free/default population - and
// ResolveRouteForPlan's "degrade, never deny" promise cannot be kept either:
// there is no live default left to degrade TO. This is a readiness signal for
// exactly that gap, checked and logged, never enforced - the Sol runbook's
// window between activating the pinned route and finishing the paired
// binary/prompt rollout is a real, expected, temporary instance of a route
// existing that is momentarily the only one active for its feature, and
// refusing to start over it would make the runbook itself impossible to
// follow.
func classifyFeatureCoverage(rows []routeCoverageRow) []FeatureCoverage {
	seen := make(map[string]bool)
	hasDefault := make(map[string]bool)
	order := make([]string, 0, len(rows))
	for _, r := range rows {
		if !seen[r.Feature] {
			seen[r.Feature] = true
			order = append(order, r.Feature)
		}
		if r.Active && !r.PlanPinned {
			hasDefault[r.Feature] = true
		}
	}
	sort.Strings(order)
	out := make([]FeatureCoverage, 0, len(order))
	for _, f := range order {
		out = append(out, FeatureCoverage{Feature: f, HasDefault: hasDefault[f]})
	}
	return out
}

// FeatureDefaultCoverage lists, for every feature present in route_registry,
// whether ResolveRoute currently has an eligible (active, non-plan-pinned)
// route to serve as its default. Report-only: callers use this to log/surface
// a gap, never to refuse to start or to gate ResolveRoute itself - see
// classifyFeatureCoverage's doc comment for why a temporary gap is expected
// during a route activation.
func (s *Store) FeatureDefaultCoverage(ctx context.Context) ([]FeatureCoverage, error) {
	var rows []routeCoverageRow
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		q, e := tx.Query(ctx, `SELECT feature, active, plan_pinned FROM route_registry`)
		if e != nil {
			return e
		}
		defer q.Close()
		for q.Next() {
			var row routeCoverageRow
			if e := q.Scan(&row.Feature, &row.Active, &row.PlanPinned); e != nil {
				return e
			}
			rows = append(rows, row)
		}
		return q.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.FeatureDefaultCoverage: %w", err)
	}
	return classifyFeatureCoverage(rows), nil
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
