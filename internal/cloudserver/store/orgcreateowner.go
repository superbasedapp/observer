package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// orgcreateowner.go reads the owner's address of ONE org being created
// together with WorkOS's verification of it, for the create_tenant request
// (managed-SaaS plan 07 wave 15 lane console-fixes; L-113
// C2.tenant-cloud-2; cloud 0093 and 0096; docs/security.md ENTLWORK-8).
//
// Both values come from one statement over the two SECURITY DEFINER
// functions (0093's hint, 0096's flag), so they share one snapshot: a
// sign-in that replaces the address between two reads cannot pair an old
// address with a new flag. The functions answer only for an org still being
// created and pick the owner by the same rule as the subject lookup
// (OrgCreateOwnerSub, which the host still binds by, W14-D2). The address
// stays a display and invitation-matching hint on the tenant; nothing here
// looks anything up by it, and it is never logged.

// OrgCreateOwnerAddress is the owner's provider-asserted address and whether
// WorkOS verified it.
type OrgCreateOwnerAddress struct {
	// Hint is the address exactly as the 0093 hint function returns it.
	Hint string
	// Verified is true only when the owner's account_verified_emails row
	// carries WorkOS's email_verified = true (0074; absent was recorded as
	// false).
	Verified bool
}

// OrgCreateOwnerAddress returns orgID's owner address and its verification
// flag in one statement. ErrNotFound when the hint function answers NULL (the
// same cases as OrgCreateOwnerEmailHint: unknown or not provisioning org, no
// owner member, or no recorded address). A NULL flag beside an address reads
// as not verified.
func (s *Store) OrgCreateOwnerAddress(ctx context.Context, orgID string) (OrgCreateOwnerAddress, error) {
	var hint *string
	var verified *bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT sbci_org_create_owner_email_hint($1::uuid), sbci_org_create_owner_email_verified($1::uuid)`, orgID).
			Scan(&hint, &verified)
		if isInvalidUUIDErr(e) {
			return ErrNotFound
		}
		return e
	})
	if err != nil {
		return OrgCreateOwnerAddress{}, fmt.Errorf("cloudserver/store.OrgCreateOwnerAddress: %w", err)
	}
	if hint == nil || *hint == "" {
		return OrgCreateOwnerAddress{}, fmt.Errorf("cloudserver/store.OrgCreateOwnerAddress: %w", ErrNotFound)
	}
	return OrgCreateOwnerAddress{Hint: *hint, Verified: verified != nil && *verified}, nil
}
