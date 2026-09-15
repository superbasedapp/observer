package store

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
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
