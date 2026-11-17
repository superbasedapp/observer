package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// orgplangrant.go is the operator-only plan grant for ONE org (managed-SaaS
// plan 07 wave 15, lead decision W15-D13; cloud 0095; docs/security.md
// PORTALORG-11): the per-org counterpart of AssignPlan (the account grant,
// `observer-cloud grant-plan`). It is written only by the CLI
// (`observer-cloud grant-plan org`), never by an HTTP route, and read by the
// entitlements plan source (entitlementwork.SubscriptionPlans) after a live
// subscription and before the launch window, so an internal org stays on its
// plan when the 14-day launch ends and there is no live Paddle (L-114).
//
// org_plan_grants is append-only: a grant and a revoke are each a new row
// with the actor ("operator") and a required reason, and the newest row of an
// org decides. The rows are their own audit trail; no application role holds
// UPDATE or DELETE.

// Org plan grant actions (the 0095 CHECK holds the same two).
const (
	OrgPlanGrantActionGrant  = "grant"
	OrgPlanGrantActionRevoke = "revoke"
)

// OrgPlanGrant is one org_plan_grants row. The newest row of an org is its
// grant state: Action "grant" names a plan in force until EffectiveUntil (nil:
// no end); Action "revoke" means no grant.
type OrgPlanGrant struct {
	OrgID          string
	Action         string
	PlanName       string
	PlanVersion    int
	EffectiveUntil *time.Time
	// Actor and Reason are empty on the console's read (the 0095 definer
	// returns neither).
	Actor  string
	Reason string
	At     time.Time
}

// InForce reports whether g grants a plan at now.
func (g OrgPlanGrant) InForce(now time.Time) bool {
	return g.Action == OrgPlanGrantActionGrant && g.PlanName != "" &&
		(g.EffectiveUntil == nil || now.Before(*g.EffectiveUntil))
}

// ErrOrgPlanGrantInput is a GrantOrgPlan / RevokeOrgPlan refusal for bad
// input: no reason, a plan that is not a catalog plan of the org's kind, an
// end in the past, or an org kind with no entitlements.
var ErrOrgPlanGrantInput = errors.New("cloudserver/store: org plan grant input is invalid")

// OrgPlanGrantInput is what the operator passes to GrantOrgPlan.
type OrgPlanGrantInput struct {
	OrgID string
	// Kind is the org's kind, which the caller read (the CLI reads it as the
	// worker role, OrgCreateFacts): the plan must be a catalog plan of it.
	Kind OrgKind
	// Plan is the catalog plan name; Version 0 pins the highest catalog
	// version of it at grant time (the row records the concrete version).
	Plan    string
	Version int
	// Until ends the grant (zero: no end).
	Until  time.Time
	Reason string
}

func normalizeGrantReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len([]rune(reason)) > 1000 {
		return "", fmt.Errorf("a reason of 1 to 1000 characters is required: %w", ErrOrgPlanGrantInput)
	}
	return reason, nil
}

// GrantOrgPlan appends a grant row for one org and returns it with the org's
// previous grant state (nil when the org had no row). Operator role only
// (sbci_app holds INSERT; WithSystem). ErrNotFound when the org does not
// exist.
func (s *Store) GrantOrgPlan(ctx context.Context, in OrgPlanGrantInput, now time.Time) (granted OrgPlanGrant, previous *OrgPlanGrant, err error) {
	now = nowOr(now).UTC()
	if _, err := uuid.Parse(in.OrgID); err != nil {
		return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: %w", ErrNotFound)
	}
	reason, err := normalizeGrantReason(in.Reason)
	if err != nil {
		return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: %w", err)
	}
	kind, ok := OrgEntitlementsKind(in.Kind)
	if !ok {
		return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: org kind %q has no entitlements: %w", in.Kind, ErrOrgPlanGrantInput)
	}
	b, ok := entitlements.Plan(strings.TrimSpace(in.Plan), in.Version)
	if !ok || b.Kind != kind {
		return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: %q v%d is not a catalog plan of kind %s: %w", in.Plan, in.Version, kind, ErrOrgPlanGrantInput)
	}
	var until *time.Time
	if !in.Until.IsZero() {
		u := in.Until.UTC()
		if !u.After(now) {
			return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: the end %s is not after now: %w", u.Format(time.RFC3339), ErrOrgPlanGrantInput)
		}
		until = &u
	}
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		prev, err := latestOrgPlanGrantTx(ctx, tx, in.OrgID)
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return err
		default:
			previous = &prev
		}
		granted = OrgPlanGrant{
			OrgID: in.OrgID, Action: OrgPlanGrantActionGrant, PlanName: b.Plan.Name, PlanVersion: b.Plan.Version,
			EffectiveUntil: until, Actor: "operator", Reason: reason, At: now,
		}
		return insertOrgPlanGrantTx(ctx, tx, granted)
	})
	if err != nil {
		return OrgPlanGrant{}, nil, fmt.Errorf("cloudserver/store.GrantOrgPlan: %w", err)
	}
	return granted, previous, nil
}

// RevokeOrgPlan appends a revoke row for one org. It refuses (ErrNotFound)
// when the org has no grant in force at now, so a revoke always ends
// something. Operator role only.
func (s *Store) RevokeOrgPlan(ctx context.Context, orgID, reason string, now time.Time) (revoked OrgPlanGrant, err error) {
	now = nowOr(now).UTC()
	if _, err := uuid.Parse(orgID); err != nil {
		return OrgPlanGrant{}, fmt.Errorf("cloudserver/store.RevokeOrgPlan: %w", ErrNotFound)
	}
	reason, err = normalizeGrantReason(reason)
	if err != nil {
		return OrgPlanGrant{}, fmt.Errorf("cloudserver/store.RevokeOrgPlan: %w", err)
	}
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		prev, err := latestOrgPlanGrantTx(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if !prev.InForce(now) {
			return ErrNotFound
		}
		revoked = prev
		return insertOrgPlanGrantTx(ctx, tx, OrgPlanGrant{
			OrgID: orgID, Action: OrgPlanGrantActionRevoke, Actor: "operator", Reason: reason, At: now,
		})
	})
	if err != nil {
		return OrgPlanGrant{}, fmt.Errorf("cloudserver/store.RevokeOrgPlan: %w", err)
	}
	return revoked, nil
}

// OrgPlanGrant returns orgID's newest grant row (the worker's read for the
// plan source, and the operator's). ErrNotFound when the org has no row.
// Whether it is in force is the caller's question (OrgPlanGrant.InForce),
// asked with the caller's clock.
func (s *Store) OrgPlanGrant(ctx context.Context, orgID string) (OrgPlanGrant, error) {
	var out OrgPlanGrant
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		g, err := latestOrgPlanGrantTx(ctx, tx, orgID)
		out = g
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return OrgPlanGrant{}, ErrNotFound
	}
	if err != nil {
		return OrgPlanGrant{}, fmt.Errorf("cloudserver/store.OrgPlanGrant: %w", err)
	}
	return out, nil
}

// PortalOrgPlanGrant is the console's read of orgID's newest grant row,
// through the 0095 definer: answered only to an org owner or admin or the
// org's billing owner (else ErrNotFound, the same as no row). No actor and
// no reason.
func (s *Store) PortalOrgPlanGrant(ctx context.Context, accountID, orgID string) (OrgPlanGrant, error) {
	out := OrgPlanGrant{OrgID: orgID}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var name *string
		var version *int32
		err := tx.QueryRow(ctx,
			`SELECT action, plan_name, plan_version, effective_until FROM sbci_portal_org_plan_grant($1::uuid)`, orgID).
			Scan(&out.Action, &name, &version, &out.EffectiveUntil)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		if name != nil {
			out.PlanName = *name
		}
		if version != nil {
			out.PlanVersion = int(*version)
		}
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return OrgPlanGrant{}, ErrNotFound
	}
	if err != nil {
		return OrgPlanGrant{}, fmt.Errorf("cloudserver/store.PortalOrgPlanGrant: %w", err)
	}
	return out, nil
}

// OrgPlanGrantHistory returns every grant row of orgID, newest first (the
// CLI's show). Operator role only.
func (s *Store) OrgPlanGrantHistory(ctx context.Context, orgID string) ([]OrgPlanGrant, error) {
	var out []OrgPlanGrant
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+orgPlanGrantColumns+` FROM org_plan_grants WHERE org_id = $1::uuid ORDER BY seq DESC`, orgID)
		if err != nil {
			if isInvalidUUIDErr(err) {
				return ErrNotFound
			}
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanOrgPlanGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OrgPlanGrantHistory: %w", err)
	}
	return out, nil
}

const orgPlanGrantColumns = `org_id::text, action, coalesce(plan_name, ''), coalesce(plan_version, 0), effective_until, actor, reason, at`

func scanOrgPlanGrant(row pgx.Row) (OrgPlanGrant, error) {
	var g OrgPlanGrant
	err := row.Scan(&g.OrgID, &g.Action, &g.PlanName, &g.PlanVersion, &g.EffectiveUntil, &g.Actor, &g.Reason, &g.At)
	return g, err
}

// latestOrgPlanGrantTx reads orgID's newest row from the table (the worker
// and operator roles' path). ErrNotFound when there is none.
func latestOrgPlanGrantTx(ctx context.Context, tx pgx.Tx, orgID string) (OrgPlanGrant, error) {
	g, err := scanOrgPlanGrant(tx.QueryRow(ctx,
		`SELECT `+orgPlanGrantColumns+` FROM org_plan_grants WHERE org_id = $1::uuid ORDER BY seq DESC LIMIT 1`, orgID))
	if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
		return OrgPlanGrant{}, ErrNotFound
	}
	if err != nil {
		return OrgPlanGrant{}, fmt.Errorf("read org plan grant: %w", err)
	}
	return g, nil
}

// insertOrgPlanGrantTx appends g. A foreign key violation (no such org) is
// ErrNotFound.
func insertOrgPlanGrantTx(ctx context.Context, tx pgx.Tx, g OrgPlanGrant) error {
	var name, version any
	if g.Action == OrgPlanGrantActionGrant {
		name, version = g.PlanName, g.PlanVersion
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO org_plan_grants (org_id, action, plan_name, plan_version, effective_until, actor, reason, at)
		 VALUES ($1::uuid, $2, $3, $4, $5, 'operator', $6, $7)`,
		g.OrgID, g.Action, name, version, g.EffectiveUntil, g.Reason, g.At); err != nil {
		if isForeignKeyViolation(err) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		return fmt.Errorf("insert org plan grant: %w", err)
	}
	return nil
}
