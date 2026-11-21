package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgportal.go holds the webcloud console's org reads and its one rename
// write (managed-SaaS plan 07 M6.5, wave 14 lane front-door; docs/security.md
// PORTALORG-2 and PORTALORG-7). Every statement runs under WithAccount; what
// the console's role cannot read directly (the slug namespace, the outbox,
// the usage days) it reads through the 0091 definer functions, each of which
// answers for one org the caller belongs to (or one slug).

// Org console errors.
var (
	// ErrOrgProvisioning: the org's tenant is still being created. A rename
	// now would change the host's create digest between two attempts of one
	// create (the host would answer an idempotency conflict, which is
	// parked), so it waits until the create is acked.
	ErrOrgProvisioning = errors.New("cloudserver/store: org is still being created")
	// ErrOrgRenameForbidden: only an org owner or admin may rename it.
	ErrOrgRenameForbidden = errors.New("cloudserver/store: only an org owner or admin may rename the org")
	// ErrOrgNotRenamable: the org is on its way out.
	ErrOrgNotRenamable = errors.New("cloudserver/store: org can no longer be renamed")
)

// OrgSlugAvailable reports whether slug is free for a new org: no org holds
// it (case-folded) and no org_slugs row (a current slug, or a rename alias
// live or expired: the primary key still holds an expired one) has it. It
// does not apply the shape rules; the caller validates with ValidateOrgSlug
// first. Read through the 0091 definer, which answers only inside an account
// context and names no org.
func (s *Store) OrgSlugAvailable(ctx context.Context, accountID, slug string) (bool, error) {
	var ok *bool
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_org_slug_available($1)`, slug).Scan(&ok)
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.OrgSlugAvailable: %w", err)
	}
	return ok != nil && *ok, nil
}

// OrgCreateStatus is the newest create_tenant outbox row of an org, as the
// console shows it: no payload, no key, no host.
type OrgCreateStatus struct {
	// State is the outbox state: pending, sent, acked or failed.
	State    string
	Attempts int
	// LastErrorClass is the host answer's class (e.g.
	// refused:capacity_waitlist); empty before any answer.
	LastErrorClass string
	NextAttemptAt  time.Time
	CreatedAt      time.Time
	// DoneAt is set once the row is acked (the tenant exists on its host) or
	// parked as failed.
	DoneAt *time.Time
}

// OrgCreateStatus returns org orgID's create status for a member caller. It
// returns ErrNotFound when the caller is not a member or the org has no
// create row.
func (s *Store) OrgCreateStatus(ctx context.Context, accountID, orgID string) (OrgCreateStatus, error) {
	if !validOrgID(orgID) {
		return OrgCreateStatus{}, ErrNotFound
	}
	var out OrgCreateStatus
	var lastErr *string
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT state, attempts, last_error_class, next_attempt_at, created_at, done_at
			   FROM sbci_portal_org_create_status($1::uuid)`, orgID).
			Scan(&out.State, &out.Attempts, &lastErr, &out.NextAttemptAt, &out.CreatedAt, &out.DoneAt)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
			return nil
		case e != nil:
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return OrgCreateStatus{}, fmt.Errorf("cloudserver/store.OrgCreateStatus: %w", err)
	}
	if !found {
		return OrgCreateStatus{}, ErrNotFound
	}
	if lastErr != nil {
		out.LastErrorClass = *lastErr
	}
	return out, nil
}

// OrgSeats is the latest usage day an org's tenant host reported.
type OrgSeats struct {
	Day     time.Time
	Seats   int
	Members int64
}

// OrgSeatsInUse returns the latest reported usage day of org orgID for a
// member caller, or ErrNotFound when there is none (or the caller is not a
// member).
func (s *Store) OrgSeatsInUse(ctx context.Context, accountID, orgID string) (OrgSeats, error) {
	if !validOrgID(orgID) {
		return OrgSeats{}, ErrNotFound
	}
	var out OrgSeats
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT day, seats, members FROM sbci_portal_org_seats($1::uuid)`, orgID).
			Scan(&out.Day, &out.Seats, &out.Members)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
			return nil
		case e != nil:
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return OrgSeats{}, fmt.Errorf("cloudserver/store.OrgSeatsInUse: %w", err)
	}
	if !found {
		return OrgSeats{}, ErrNotFound
	}
	return out, nil
}

// orgRenamableStatuses are the states a rename is allowed in. provisioning is
// refused with its own error (ErrOrgProvisioning); the rest are on their way
// out.
var orgRenamableStatuses = map[platformcontract.TenantState]bool{
	platformcontract.StateActive:    true,
	platformcontract.StateSuspended: true,
}

// RenameOrg sets org orgID's display name for an owner or admin caller. The
// slug never changes here (a slug rename needs its 90-day alias and the OIDC
// client's redirect URI moved in one transaction; it is not built). The org
// row is locked FOR UPDATE before its status is read, so a create the worker
// is acking concurrently is either still provisioning (refused) or already
// active. It returns ErrOrgInputInvalid for a bad name, ErrNotFound for a
// non-member, ErrOrgRenameForbidden for a plain member, ErrOrgProvisioning
// while the create is in flight and ErrOrgNotRenamable for an org on its way
// out.
func (s *Store) RenameOrg(ctx context.Context, accountID, orgID, displayName string) (MyOrg, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || !utf8.ValidString(displayName) || utf8.RuneCountInString(displayName) > OrgDisplayNameMaxRunes {
		return MyOrg{}, fmt.Errorf("cloudserver/store.RenameOrg: display name must be 1 to %d characters of valid UTF-8: %w", OrgDisplayNameMaxRunes, ErrOrgInputInvalid)
	}
	var out MyOrg
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		org, err := getMyOrgTx(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if org.ConsoleRole != ConsoleOwner && org.ConsoleRole != ConsoleAdmin {
			return ErrOrgRenameForbidden
		}
		var status string
		if err := tx.QueryRow(ctx,
			`SELECT status FROM orgs WHERE org_id = $1::uuid FOR UPDATE`, org.OrgID).Scan(&status); err != nil {
			return fmt.Errorf("lock org: %w", err)
		}
		st := platformcontract.TenantState(status)
		if st == platformcontract.StateProvisioning {
			return ErrOrgProvisioning
		}
		if !orgRenamableStatuses[st] {
			return ErrOrgNotRenamable
		}
		if displayName != org.DisplayName {
			if _, err := tx.Exec(ctx,
				`UPDATE orgs SET display_name = $2, updated_at = now() WHERE org_id = $1::uuid`,
				org.OrgID, displayName); err != nil {
				return fmt.Errorf("update org: %w", err)
			}
		}
		out, err = getMyOrgTx(ctx, tx, org.OrgID)
		return err
	})
	if err != nil {
		for _, sentinel := range []error{ErrNotFound, ErrOrgRenameForbidden, ErrOrgProvisioning, ErrOrgNotRenamable} {
			if errors.Is(err, sentinel) {
				return MyOrg{}, sentinel
			}
		}
		return MyOrg{}, fmt.Errorf("cloudserver/store.RenameOrg: %w", err)
	}
	return out, nil
}
