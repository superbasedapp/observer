package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// entitlementwork.go is the store seam of the entitlements issuer (managed-
// SaaS plan 07 M6.3 worker side, internal/cloudserver/entitlementwork): the
// reads of the orgs the worker issues documents for. The writes are
// documents.go (IssueEntitlementDocument). It runs as sbci_worker under
// WithSystem, through 0059's worker policy on orgs, the column grants of
// 0058 and 0089 (org_id, status, kind) and the worker's own outbox grant
// (0058: the acked create_tenant row that dates a tenant's creation on its
// host).

// OrgEntitlementView is one org as the entitlements issuer reads it.
type OrgEntitlementView struct {
	OrgID  string
	Kind   OrgKind
	Status string
	// CreatedOnHostAt is when the org's tenant was created on its host: the
	// done_at of its acked create_tenant outbox row (zero while the create
	// has not been acked). It anchors the launch window (W14-D1a).
	CreatedOnHostAt time.Time
}

// orgEntitlementSelect is the shared projection of both reads.
const orgEntitlementSelect = `
	SELECT g.org_id::text, g.kind, g.status, c.done_at
	  FROM orgs g
	  LEFT JOIN LATERAL (
	        SELECT o.done_at
	          FROM org_outbox o
	         WHERE o.org_id = g.org_id AND o.verb = 'create_tenant' AND o.state = 'acked'
	         ORDER BY o.done_at
	         LIMIT 1) c ON true`

func scanOrgEntitlementView(row pgx.Row) (OrgEntitlementView, error) {
	var v OrgEntitlementView
	var kind string
	var created *time.Time
	if err := row.Scan(&v.OrgID, &kind, &v.Status, &created); err != nil {
		return OrgEntitlementView{}, err
	}
	v.Kind = OrgKind(kind)
	if created != nil {
		v.CreatedOnHostAt = created.UTC()
	}
	return v, nil
}

// ListOrgsForEntitlements returns up to limit orgs with an id above
// afterOrgID ("" for the first page), ordered by id. Purged orgs are left
// out: nothing is ever issued to a tenant that no longer exists.
func (s *Store) ListOrgsForEntitlements(ctx context.Context, afterOrgID string, limit int) ([]OrgEntitlementView, error) {
	if limit <= 0 {
		return nil, errors.New("cloudserver/store.ListOrgsForEntitlements: limit must be positive")
	}
	if afterOrgID == "" {
		afterOrgID = "00000000-0000-0000-0000-000000000000"
	}
	var out []OrgEntitlementView
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, orgEntitlementSelect+`
			 WHERE g.org_id > $1::uuid AND g.status <> 'purged'
			 ORDER BY g.org_id
			 LIMIT $2`, afterOrgID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanOrgEntitlementView(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListOrgsForEntitlements: %w", err)
	}
	return out, nil
}

// OrgForEntitlements returns one org as ListOrgsForEntitlements reads it
// (the issuer's post-create pass, W14-D1a). ErrNotFound when the org does
// not exist, is purged, or the id is malformed.
func (s *Store) OrgForEntitlements(ctx context.Context, orgID string) (OrgEntitlementView, error) {
	var v OrgEntitlementView
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		v, err = scanOrgEntitlementView(tx.QueryRow(ctx, orgEntitlementSelect+`
			 WHERE g.org_id = $1::uuid AND g.status <> 'purged'`, orgID))
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return OrgEntitlementView{}, fmt.Errorf("cloudserver/store.OrgForEntitlements: %w", err)
	}
	return v, nil
}
