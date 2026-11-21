package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// personalorg.go is the lazy personal org (managed-SaaS individuals
// workstream, decision D-IND-1; plan 06 5.4-5.7; docs/security.md IND-1): an
// individual is an org of one, created the first time it is asked for, by
// either of two callers through the one function here:
//
//	POST /portal/api/orgs/personal        the console (session + CSRF)
//	POST /v1/orgs/personal:ensure         the device (PoP; `observer connect`)
//
// EnsurePersonalOrg never adds a member. The only membership row a personal
// org ever holds is the bootstrap owner row ProvisionOrg writes in the org's
// own transaction; the cloud's sbci_org_member_write_ok rule 3 (cloud 0047)
// refuses every other one, whoever writes it. The one-per-account rule is the
// 0047 partial unique index orgs_one_personal_per_account, so two concurrent
// ensures cannot both create: the loser's insert fails with
// ErrPersonalOrgExists and resolves to the winner's row. A personal org is not
// a team org, so it never counts against the team org cap (teamorglimit.go).

// PersonalOrgDisplayName is the display name of a lazily created personal org.
const PersonalOrgDisplayName = "Personal"

// personalSlugAttempts bounds how many minted personal slugs EnsurePersonalOrg
// tries: a collision of two 40-bit random slugs is not expected, but a retry
// costs nothing and a slug_taken would otherwise surface to the user.
const personalSlugAttempts = 3

// PersonalOrg returns accountID's personal org as accountID sees it, or
// ErrNotFound when the account has none yet. Only the org's own creator can be
// its member (0047 rule 3), so "the personal org the caller belongs to" and
// "the personal org the caller created" are the same row.
func (s *Store) PersonalOrg(ctx context.Context, accountID string) (MyOrg, error) {
	var out MyOrg
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		o, err := personalOrgTx(ctx, tx)
		out = o
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return MyOrg{}, ErrNotFound
	}
	if err != nil {
		return MyOrg{}, fmt.Errorf("cloudserver/store.PersonalOrg: %w", err)
	}
	return out, nil
}

// personalOrgTx reads the caller's personal org through its membership.
func personalOrgTx(ctx context.Context, tx pgx.Tx) (MyOrg, error) {
	o, err := scanMyOrg(tx.QueryRow(ctx,
		`SELECT `+myOrgColumns+`
		   FROM orgs o
		   JOIN org_members m ON m.org_id = o.org_id AND m.account_id = sbci_current_account()
		  WHERE o.kind = 'personal' AND o.created_by = sbci_current_account()`))
	if errors.Is(err, pgx.ErrNoRows) {
		return MyOrg{}, ErrNotFound
	}
	return o, err
}

// EnsurePersonalOrg returns accountID's personal org, provisioning it when the
// account has none (ProvisionOrg: kind personal, display name "Personal",
// individual tenancy, a minted u- slug, the create_tenant intent in the same
// transaction). created is true only when this call created it. A concurrent
// ensure that wins the race makes this one's insert fail on the
// one-per-account index; that answers the winner's org with created false.
//
// tenantDomain is the parent domain of tenant dashboards (the same value the
// team create passes), under which the org's platform OIDC client is
// registered; empty registers none.
//
// The returned org may be in any lifecycle state: an account whose personal
// org is being deleted gets that org back, not a second one (the index is not
// status-scoped). It never writes an org_members row of its own.
func (s *Store) EnsurePersonalOrg(ctx context.Context, accountID, tenantDomain string) (org MyOrg, created bool, err error) {
	existing, err := s.PersonalOrg(ctx, accountID)
	if err == nil {
		return existing, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return MyOrg{}, false, fmt.Errorf("cloudserver/store.EnsurePersonalOrg: %w", err)
	}
	in := ProvisionOrgInput{Kind: OrgPersonal, DisplayName: PersonalOrgDisplayName, Tenancy: TenancyIndividual, TenantDomain: tenantDomain}
	for attempt := 1; ; attempt++ {
		org, err = s.ProvisionOrg(ctx, accountID, in)
		switch {
		case err == nil:
			return org, true, nil
		case errors.Is(err, ErrPersonalOrgExists):
			existing, rerr := s.PersonalOrg(ctx, accountID)
			if rerr != nil {
				return MyOrg{}, false, fmt.Errorf("cloudserver/store.EnsurePersonalOrg: read the concurrent winner: %w", rerr)
			}
			return existing, false, nil
		case errors.Is(err, ErrOrgSlugTaken) && attempt < personalSlugAttempts:
			continue // a minted slug collided; ProvisionOrg mints a fresh one
		default:
			return MyOrg{}, false, fmt.Errorf("cloudserver/store.EnsurePersonalOrg: %w", err)
		}
	}
}
