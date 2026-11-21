package store

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// accountprofile.go owns `account_profiles` (migration 0033): the DISPLAY-ONLY
// identity of the signed-in portal user — the email and name WorkOS returns in
// the server-side code-exchange response — so the portal can render "you"
// instead of an account UUID.
//
// SCOPE. This is a display cache, not an identity authority. The identity of
// record stays (provider, subject) in `identity_links`; nothing here is a
// lookup key, and no authentication, authorization, or account-resolution path
// reads it (CLAUDE.md #4: one owner per piece of state). It is upserted on
// every sign-in, so a rename or a new primary email at the provider converges
// on the next login without a sync path of its own.

// AccountProfileMaxEmailBytes bounds a stored email. 254 is the RFC 5321
// maximum length of a forward path, which is the widest an address can
// legitimately be; anything longer is a provider defect or an injection
// attempt, not an address.
const AccountProfileMaxEmailBytes = 254

// AccountProfileMaxNameBytes bounds a stored display name. Generous for a
// human name, far short of anything that could be used to smuggle a payload
// through the top bar.
const AccountProfileMaxNameBytes = 128

// AccountProfile is the display identity of one account. Both fields are
// optional: an account can exist with no profile at all (a dev-auth subject
// with no email, or a provider response that carried no user object), and the
// portal renders the account id in that case rather than a blank chip.
type AccountProfile struct {
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Empty reports whether the profile carries nothing worth displaying.
func (p AccountProfile) Empty() bool { return p.Email == "" && p.DisplayName == "" }

// UpsertAccountProfile records (or refreshes) the account's display identity.
// It is called on every successful sign-in, so the stored row always reflects
// the most recent thing the provider said about this user.
//
// Both strings are bounded here rather than trusted from the provider: a value
// over the limit is TRUNCATED on a rune boundary rather than rejected, because
// a sign-in must never fail over a cosmetic field. An upsert with both fields
// empty is a no-op — it would otherwise write a row that says nothing and reset
// updated_at on every page reload.
//
// It never logs, returns, or otherwise re-emits the email: the value goes to
// the tenant-scoped row and to the signed-in browser that owns it, nowhere else.
func (s *Store) UpsertAccountProfile(ctx context.Context, accountID, email, displayName string, now time.Time) error {
	if accountID == "" {
		return errors.New("cloudserver/store.UpsertAccountProfile: empty accountID")
	}
	if now.IsZero() {
		now = time.Now()
	}
	email = truncateRunes(email, AccountProfileMaxEmailBytes)
	displayName = truncateRunes(displayName, AccountProfileMaxNameBytes)
	if email == "" && displayName == "" {
		return nil
	}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// Fence the account status INSIDE this write transaction (Sol F5). The
		// sign-in that triggers this upsert established its session in an
		// EARLIER transaction, so an account deletion can commit in between —
		// and deletion retains the account row as a `status='deleted'`
		// tombstone, which means RLS still matches this tenant and the FK still
		// resolves. Without the fence, the straggling upsert would re-create a
		// plain-text email on a deleted account, silently undoing the purge.
		// FOR SHARE serializes against the deletion fence's UPDATE of the same
		// row without blocking this account's other concurrent writes.
		//
		// Failing closed here is free: rememberProfile treats an upsert error
		// as non-fatal, so the sign-in path is unaffected.
		if e := fenceAccountActiveTx(ctx, tx, accountID); e != nil {
			return e
		}
		_, e := tx.Exec(ctx,
			`INSERT INTO account_profiles (account_id, email, display_name, updated_at)
			 VALUES ($1::uuid, nullif($2, ''), nullif($3, ''), $4)
			 ON CONFLICT (account_id) DO UPDATE
			    SET email        = EXCLUDED.email,
			        display_name = EXCLUDED.display_name,
			        updated_at   = EXCLUDED.updated_at`,
			accountID, email, displayName, now)
		return e
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.UpsertAccountProfile: %w", err)
	}
	return nil
}

// AccountProfile returns the account's display identity. A missing row is NOT
// an error — it is the honest "we have never learned a name for this account"
// state, returned as the zero AccountProfile — because every caller is a
// display path that must degrade to the account id rather than fail.
func (s *Store) AccountProfile(ctx context.Context, accountID string) (AccountProfile, error) {
	var out AccountProfile
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var email, name *string
		e := tx.QueryRow(ctx,
			`SELECT email, display_name, updated_at FROM account_profiles
			  WHERE account_id = $1::uuid`, accountID).Scan(&email, &name, &out.UpdatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			out = AccountProfile{}
			return nil
		}
		if e != nil {
			return e
		}
		if email != nil {
			out.Email = *email
		}
		if name != nil {
			out.DisplayName = *name
		}
		return nil
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("cloudserver/store.AccountProfile: %w", err)
	}
	return out, nil
}

// truncateRunes cuts s to at most maxBytes bytes WITHOUT splitting a rune, so a
// truncated name is still valid UTF-8 (a plain byte slice would leave a
// replacement character in the browser). It is deliberately a truncation, not a
// rejection: see UpsertAccountProfile's contract.
func truncateRunes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// --- the provider-asserted address (migration 0074, operator item A4) ------
//
// account_verified_emails is NOT display data: it is the address the platform
// OIDC issuer signs into a tenant's ID token, with the identity provider's own
// verification flag. It lives in this file only because this is the one store
// file allowed to name an address (the no-merge-by-email tripwire); every
// statement below is keyed by account_id and nothing reads an account back
// out of it. Only the WorkOS sign-in leg writes it; account_profiles stays
// display-only and is no longer read by the issuer.

// UpsertVerifiedEmail records what the identity provider said, at a sign-in,
// about accountID's address: the address as the provider sent it and the
// provider's `email_verified` flag. It is called on every WorkOS sign-in, so
// the row always reflects the latest provider statement. An empty address
// (the provider sent none, or one the API layer refused to shape) DELETES the
// row, so a stale verified address can never outlive a sign-in that did not
// confirm it; the issuer then refuses for want of an address.
//
// Unlike UpsertAccountProfile this is an authentication input for tenants, so
// the caller fails the sign-in when it fails. Like it, it fences the account
// status inside the write and never logs or returns the address.
func (s *Store) UpsertVerifiedEmail(ctx context.Context, accountID, email string, verified bool, now time.Time) error {
	if accountID == "" {
		return errors.New("cloudserver/store.UpsertVerifiedEmail: empty accountID")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if len(email) > AccountProfileMaxEmailBytes {
		// Never truncated: a cut address is a different address.
		email = ""
	}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if e := fenceAccountActiveTx(ctx, tx, accountID); e != nil {
			return e
		}
		if email == "" {
			_, e := tx.Exec(ctx, `DELETE FROM account_verified_emails WHERE account_id = $1::uuid`, accountID)
			return e
		}
		_, e := tx.Exec(ctx,
			`INSERT INTO account_verified_emails (account_id, email, email_verified, updated_at)
			 VALUES ($1::uuid, $2, $3, $4)
			 ON CONFLICT (account_id) DO UPDATE
			    SET email          = EXCLUDED.email,
			        email_verified = EXCLUDED.email_verified,
			        updated_at     = EXCLUDED.updated_at`,
			accountID, email, verified, now)
		return e
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.UpsertVerifiedEmail: %w", err)
	}
	return nil
}

// setOIDCMemberVerifiedAddress fills m's address claim and its verification
// flag for the OIDC issuer (M6.2) from account_verified_emails, keyed by
// account_id only. A missing row leaves the address empty and the flag false;
// the issuer's member rules refuse both (A4: never issue for an address the
// provider did not verify).
func setOIDCMemberVerifiedAddress(ctx context.Context, tx pgx.Tx, accountID string, m *oidcissuer.Member) error {
	e := tx.QueryRow(ctx,
		`SELECT email, email_verified FROM account_verified_emails
		  WHERE account_id = $1::uuid`, accountID).Scan(&m.Email, &m.EmailVerified)
	if errors.Is(e, pgx.ErrNoRows) {
		m.Email, m.EmailVerified = "", false
		return nil
	}
	if e != nil {
		return fmt.Errorf("cloudserver/store.setOIDCMemberVerifiedAddress: %w", e)
	}
	return nil
}

// OrgCreateOwnerEmailHint returns the provider-asserted address of orgID's
// owner, for the create_tenant request (W14-D2), through the 0093 definer
// function, which answers for ONE org still being created and lists nothing.
// It is a DISPLAY HINT only: the request marks it unverified (L-31 is
// unruled), the host binds the owner by subject (OrgCreateOwnerSub,
// orgcreate.go), and nothing looks anything up by it. ErrNotFound when the
// function answers NULL (unknown or not provisioning org, no owner member, or
// the owner has no recorded address). It never logs the address.
func (s *Store) OrgCreateOwnerEmailHint(ctx context.Context, orgID string) (string, error) {
	var hint *string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `SELECT sbci_org_create_owner_email_hint($1::uuid)`, orgID).Scan(&hint)
		if isInvalidUUIDErr(e) {
			return ErrNotFound
		}
		return e
	})
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.OrgCreateOwnerEmailHint: %w", err)
	}
	if hint == nil || *hint == "" {
		return "", fmt.Errorf("cloudserver/store.OrgCreateOwnerEmailHint: %w", ErrNotFound)
	}
	return *hint, nil
}
