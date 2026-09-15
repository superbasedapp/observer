package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AttestationRecord is one persisted ContentLogging canary result (plan §2.2).
// It is keyed to the resolved resource identifiers AND the route generation, so
// any route/config change invalidates a prior record; the raw capability value
// is retained (absent/duplicate/malformed/non-`false` are all UNHEALTHY).
type AttestationRecord struct {
	RouteID             string
	RouteGeneration     int64
	TenantID            string
	SubscriptionID      string
	ARMResourceID       string
	EndpointAudience    string
	ContentLoggingValue string
	Healthy             bool
	Reason              string
	FetchedAt           time.Time
	CreatedAt           time.Time
}

// RecordAttestation appends an attestation record (system/control-plane table).
func (s *Store) RecordAttestation(ctx context.Context, a AttestationRecord) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO provider_attestations
			   (route_id, route_generation, tenant_id, subscription_id, arm_resource_id,
			    endpoint_audience, content_logging_value, healthy, reason, fetched_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			a.RouteID, a.RouteGeneration, a.TenantID, a.SubscriptionID, a.ARMResourceID,
			a.EndpointAudience, a.ContentLoggingValue, a.Healthy, a.Reason, a.FetchedAt)
		if e != nil {
			return fmt.Errorf("cloudserver/store.RecordAttestation: %w", e)
		}
		return nil
	})
}

// LatestAttestation returns the most recent persisted attestation for a route,
// or ErrNotFound. The attestor uses it to cache a fresh, matching record within
// the max-age window (avoiding an ARM read on every attempt).
func (s *Store) LatestAttestation(ctx context.Context, routeID string) (AttestationRecord, error) {
	var a AttestationRecord
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT route_id, route_generation, tenant_id, subscription_id, arm_resource_id,
			        endpoint_audience, content_logging_value, healthy, reason, fetched_at, created_at
			   FROM provider_attestations WHERE route_id = $1
			  ORDER BY created_at DESC LIMIT 1`, routeID).Scan(
			&a.RouteID, &a.RouteGeneration, &a.TenantID, &a.SubscriptionID, &a.ARMResourceID,
			&a.EndpointAudience, &a.ContentLoggingValue, &a.Healthy, &a.Reason, &a.FetchedAt, &a.CreatedAt,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return a, err
}

// DialectVerified reports whether a live, unexpired, active verification record
// exists that is BOUND to the resolved route snapshot (FA5 / plan §2.3): it
// matches the route id + dialect AND the route GENERATION + api_version +
// deployment the record was taken against. Because SetRouteBinding bumps the
// route generation (and changes api_version/deployment/endpoint) on any route
// mutation, a record taken for an earlier configuration no longer matches the
// resolved snapshot — so changing the route to a different api-version or
// deployment while leaving an unexpired row intact no longer keeps the dialect
// enabled. The caller passes the SAME RouteInfo it will execute under.
func (s *Store) DialectVerified(ctx context.Context, route RouteInfo, now time.Time) (bool, error) {
	var ok bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM dialect_verification_records
			    WHERE route_id = $1 AND dialect = $2
			      AND route_generation = $3
			      AND api_version = $4
			      AND deployment = $5
			      AND active = true AND expires_at > $6)`,
			route.RouteID, route.Dialect, route.Generation, route.APIVersion, route.Deployment, now).Scan(&ok)
	})
	return ok, err
}

// AddDialectVerification records a dialect verification bound to the route's
// CURRENT snapshot (operator action; tests use it to exercise the
// store:false-forcing path). It resolves the route and stores its generation +
// api_version + deployment, so the record is valid ONLY for that exact
// configuration; any later route mutation (which bumps the generation)
// invalidates it (FA5). Non-empty evidence AND approver metadata are required.
func (s *Store) AddDialectVerification(ctx context.Context, routeID, dialect, evidence, approvedBy string, expiresAt time.Time) error {
	if evidence == "" || approvedBy == "" {
		return fmt.Errorf("cloudserver/store.AddDialectVerification: evidence and approved_by are required")
	}
	route, err := s.RouteByID(ctx, routeID)
	if err != nil {
		return fmt.Errorf("cloudserver/store.AddDialectVerification: resolve route: %w", err)
	}
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO dialect_verification_records
			   (route_id, dialect, api_version, deployment, evidence, approved_by, expires_at, route_generation)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			routeID, dialect, route.APIVersion, route.Deployment, evidence, approvedBy, expiresAt, route.Generation)
		if e != nil {
			return fmt.Errorf("cloudserver/store.AddDialectVerification: %w", e)
		}
		return nil
	})
}

// SetRouteBinding sets a route's attestation-binding identifiers + Foundry-call
// columns (operator provisioning; used by tests to move a route from the
// fail-closed default to a bound, callable state). It BUMPS the generation so a
// prior attestation no longer matches (plan §2.2).
func (s *Store) SetRouteBinding(ctx context.Context, routeID string, b RouteBinding) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE route_registry
			    SET tenant_id = $2, subscription_id = $3, arm_resource_id = $4,
			        endpoint_audience = $5, endpoint = $6, api_version = $7,
			        generation = generation + 1
			  WHERE route_id = $1`,
			routeID, b.TenantID, b.SubscriptionID, b.ARMResourceID, b.EndpointAudience,
			b.Endpoint, b.APIVersion)
		if e != nil {
			return fmt.Errorf("cloudserver/store.SetRouteBinding: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetRouteDialect flips a route's dialect (operator action; tests use it to
// select responses_store_false and prove the route resolver refuses it without
// a verification record).
func (s *Store) SetRouteDialect(ctx context.Context, routeID, dialect string) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE route_registry SET dialect = $2 WHERE route_id = $1`, routeID, dialect)
		if e != nil {
			return fmt.Errorf("cloudserver/store.SetRouteDialect: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RouteBinding is the attestation-binding + endpoint identifiers for a route.
type RouteBinding struct {
	TenantID         string
	SubscriptionID   string
	ARMResourceID    string
	EndpointAudience string
	Endpoint         string
	APIVersion       string
}
