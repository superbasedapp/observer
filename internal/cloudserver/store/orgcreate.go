package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// orgcreate.go is the store seam of what a create_tenant request needs beyond
// its outbox payload (managed-SaaS plan 07 M6.4; lead decisions L-43 and
// W14-D2; cloud 0092 and 0093): the org's slug and kind, and its owner's
// WorkOS subject. The worker runs these as sbci_worker under WithSystem. The
// slug and kind come through 0058 / 0089 / 0092's column grants; the subject
// only through the 0093 SECURITY DEFINER function, which answers for ONE org
// still being created and lists nothing. The owner's display address is read
// by OrgCreateOwnerEmailHint in accountprofile.go, the one store file allowed
// to name an address.

// OrgCreateFacts is what the worker reads about an org when it builds the
// org's create_tenant request.
type OrgCreateFacts struct {
	// Slug is the org's current slug (its host name label).
	Slug string
	// Kind is the org's kind.
	Kind OrgKind
}

// OrgCreateFacts returns orgID's slug and kind. ErrNotFound when the org does
// not exist (or the id is malformed).
func (s *Store) OrgCreateFacts(ctx context.Context, orgID string) (OrgCreateFacts, error) {
	var f OrgCreateFacts
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var kind string
		err := tx.QueryRow(ctx, `SELECT g.slug, g.kind FROM orgs g WHERE g.org_id = $1::uuid`, orgID).Scan(&f.Slug, &kind)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		f.Kind = OrgKind(kind)
		return err
	})
	if err != nil {
		return OrgCreateFacts{}, fmt.Errorf("cloudserver/store.OrgCreateFacts: %w", err)
	}
	return f, nil
}

// OrgCreateOwnerSub returns the WorkOS subject of orgID's owner, chosen by the
// rule the platform OIDC issuer uses for the member's sub claim, through the
// 0093 definer function. ErrNotFound when the function answers NULL: the org
// is unknown, not being created (only a provisioning org is answered), has no
// owner member, or the owner has no identity link.
func (s *Store) OrgCreateOwnerSub(ctx context.Context, orgID string) (string, error) {
	var sub *string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT sbci_org_create_owner_sub($1::uuid)`, orgID).Scan(&sub)
		if isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.OrgCreateOwnerSub: %w", err)
	}
	if sub == nil || *sub == "" {
		return "", fmt.Errorf("cloudserver/store.OrgCreateOwnerSub: %w", ErrNotFound)
	}
	return *sub, nil
}
