package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Nonce/token lifetimes are conservative defaults; callers may override.
const (
	// DefaultNonceTTL bounds how long a minted exchange nonce is valid.
	DefaultNonceTTL = 5 * time.Minute
	// DefaultTokenTTL bounds a minted SuperBased API token. WorkOS remains the
	// sole refresh authority (plan §4): when this expires the client re-exchanges
	// a fresh WorkOS access token; there is no /v1/auth/refresh.
	DefaultTokenTTL = 1 * time.Hour
)

// hashToken/hashNonce store only a hash of the bearer secret; the raw value
// never touches the database.
func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Thumbprint is the canonical device-key thumbprint: base64url(sha256(pubkey)),
// no padding. It binds a token to a device (PoP) and identifies a device across
// re-exchanges.
func Thumbprint(pubKey []byte) string {
	sum := sha256.Sum256(pubKey)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MintNonce creates a single-use exchange nonce and returns its RAW value (the
// caller returns it to the client; only its hash is stored).
func (s *Store) MintNonce(ctx context.Context, ttl time.Duration, now time.Time) (string, error) {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	raw, err := randToken()
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.MintNonce: rand: %w", err)
	}
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO exchange_nonces (nonce_hash, expires_at) VALUES ($1, $2)`,
			hashSecret(raw), now.Add(ttl))
		return e
	})
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.MintNonce: %w", err)
	}
	return raw, nil
}

// ExchangeInput carries the fully-validated exchange request. The API verifies
// the WorkOS/broker token (yielding Provider+Subject) and the Ed25519
// proof-of-possession over the nonce BEFORE calling this — the store consumes
// the nonce single-use and does the account/device/token work atomically.
type ExchangeInput struct {
	Provider  string
	Subject   string
	PublicKey []byte
	Label     string
	RawNonce  string
	TokenTTL  time.Duration
	Now       time.Time
}

// ExchangeResult is what the client receives: a short-lived device-bound token.
type ExchangeResult struct {
	AccountID  string
	DeviceID   string
	Thumbprint string
	Token      string
	ExpiresAt  time.Time
}

// ErrNonceInvalid indicates the nonce was unknown, expired, or already
// consumed (a replay).
var ErrNonceInvalid = errors.New("cloudserver/store: nonce invalid, expired, or already used")

// ErrDeviceRevoked indicates the presented device key belongs to a device that
// has been revoked; a revoked device may not re-exchange (amendment §3.3).
var ErrDeviceRevoked = errors.New("cloudserver/store: device is revoked")

// Exchange consumes the nonce, resolves-or-creates the account and its identity
// link, registers-or-reuses the device, and mints a device-bound API token —
// all in one transaction. Account scope is derived here, never taken from a
// caller-supplied field.
func (s *Store) Exchange(ctx context.Context, in ExchangeInput) (ExchangeResult, error) {
	ttl := in.TokenTTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	rawToken, err := randToken()
	if err != nil {
		return ExchangeResult{}, fmt.Errorf("cloudserver/store.Exchange: rand token: %w", err)
	}
	thumb := Thumbprint(in.PublicKey)

	var res ExchangeResult
	err = s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, s.appRole.setLocalRoleSQL()); e != nil {
			return fmt.Errorf("set role: %w", e)
		}

		// 1) Consume the nonce single-use (system table).
		var nonceID string
		e := tx.QueryRow(ctx,
			`UPDATE exchange_nonces SET consumed_at = $2
			  WHERE nonce_hash = $1 AND consumed_at IS NULL AND expires_at > $2
			  RETURNING id::text`,
			hashSecret(in.RawNonce), now).Scan(&nonceID)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNonceInvalid
		}
		if e != nil {
			return fmt.Errorf("consume nonce: %w", e)
		}

		// 2) Resolve-or-create the account through the SHARED identity-bootstrap
		// seam (the same one PortalLogin uses), which also establishes tenant
		// context and refuses a suspended account with ErrAccountSuspended.
		accountID, e := resolveOrCreateAccountTx(ctx, tx, in.Provider, in.Subject)
		if e != nil {
			return e
		}

		// 3) Register or reuse the device (now RLS-scoped to accountID).
		var deviceID string
		var revokedAt *time.Time
		e = tx.QueryRow(ctx,
			`SELECT id::text, revoked_at FROM device_registrations
			  WHERE account_id = $1::uuid AND thumbprint = $2`,
			accountID, thumb).Scan(&deviceID, &revokedAt)
		switch {
		case errors.Is(e, pgx.ErrNoRows):
			if e2 := tx.QueryRow(ctx,
				`INSERT INTO device_registrations (account_id, public_key, thumbprint, label)
				 VALUES ($1::uuid, $2, $3, $4) RETURNING id::text`,
				accountID, in.PublicKey, thumb, in.Label).Scan(&deviceID); e2 != nil {
				return fmt.Errorf("register device: %w", e2)
			}
		case e != nil:
			return fmt.Errorf("lookup device: %w", e)
		default:
			if revokedAt != nil {
				return ErrDeviceRevoked
			}
		}

		// 4) Mint the device-bound token.
		var expiresAt time.Time
		if e2 := tx.QueryRow(ctx,
			`INSERT INTO api_tokens (account_id, device_id, token_hash, expires_at)
			 VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING expires_at`,
			accountID, deviceID, hashSecret(rawToken), now.Add(ttl)).Scan(&expiresAt); e2 != nil {
			return fmt.Errorf("mint token: %w", e2)
		}

		res = ExchangeResult{
			AccountID:  accountID,
			DeviceID:   deviceID,
			Thumbprint: thumb,
			Token:      rawToken,
			ExpiresAt:  expiresAt,
		}
		return nil
	})
	if err != nil {
		return ExchangeResult{}, err
	}
	return res, nil
}

// TokenPrincipal is the resolved identity behind a bearer token.
type TokenPrincipal struct {
	AccountID  string
	TokenID    string
	DeviceID   string
	PublicKey  []byte
	Thumbprint string
	Valid      bool // token unexpired, unrevoked; device unrevoked; account active
}

// IntrospectToken resolves a raw bearer token to its principal via the
// SECURITY DEFINER lookup, then applies the validity gates (expiry, revocation,
// account status) in Go so the caller gets a single clear verdict.
func (s *Store) IntrospectToken(ctx context.Context, rawToken string, now time.Time) (TokenPrincipal, error) {
	var p TokenPrincipal
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var (
			tokenExpires             time.Time
			tokenRevoked, devRevoked *time.Time
			acctStatus               string
		)
		e := tx.QueryRow(ctx,
			`SELECT account_id::text, token_id::text, device_id::text, public_key,
			        thumbprint, token_expires_at, token_revoked_at, device_revoked_at, account_status
			   FROM sbci_introspect_token($1)`,
			hashSecret(rawToken)).Scan(
			&p.AccountID, &p.TokenID, &p.DeviceID, &p.PublicKey, &p.Thumbprint,
			&tokenExpires, &tokenRevoked, &devRevoked, &acctStatus,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return fmt.Errorf("introspect: %w", e)
		}
		p.Valid = tokenRevoked == nil && devRevoked == nil &&
			acctStatus == "active" && now.Before(tokenExpires)
		return nil
	})
	if err != nil {
		return TokenPrincipal{}, err
	}
	return p, nil
}

// RecordJTI inserts a proof-of-possession jti into the per-account replay cache
// and reports whether it was a REPLAY (already present and unexpired). It runs
// under tenant context (the account is known from the token). Expired entries
// with the same jti are overwritten.
func (s *Store) RecordJTI(ctx context.Context, accountID, jti string, expiresAt, now time.Time) (replay bool, err error) {
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`INSERT INTO pop_replay (account_id, jti, expires_at)
			 VALUES ($1::uuid, $2, $3)
			 ON CONFLICT (account_id, jti) DO UPDATE SET expires_at = EXCLUDED.expires_at, created_at = now()
			 WHERE pop_replay.expires_at < $4`,
			accountID, jti, expiresAt, now)
		if e != nil {
			return fmt.Errorf("record jti: %w", e)
		}
		// Zero rows affected ⇒ the ON CONFLICT WHERE (expired) was false, i.e. a
		// live jti already present ⇒ replay.
		replay = ct.RowsAffected() == 0
		return nil
	})
	return replay, err
}

// RevokeDevice marks a device revoked and revokes its live tokens. Used by
// DELETE /v1/devices/{id} and by deletion requests.
func (s *Store) RevokeDevice(ctx context.Context, accountID, deviceID string, now time.Time) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE device_registrations SET revoked_at = $3
			  WHERE account_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL`,
			accountID, deviceID, now)
		if e != nil {
			return fmt.Errorf("revoke device: %w", e)
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		if _, e := tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at = $3
			  WHERE account_id = $1::uuid AND device_id = $2::uuid AND revoked_at IS NULL`,
			accountID, deviceID, now); e != nil {
			return fmt.Errorf("revoke device tokens: %w", e)
		}
		return nil
	})
}

// RevokeAPIToken revokes ONE api_tokens row — the token the caller presented,
// identified by the token id IntrospectToken already resolved. It is the
// device-initiated sign-out primitive behind POST /v1/logout (plan §3 W1,
// D17): the device gives up its own bearer without touching the device
// registration, so the same device can log in again later.
//
// It is IDEMPOTENT by design: an already-revoked (or unknown) row matches zero
// rows and returns nil rather than ErrNotFound, so a repeated logout is a
// no-op, never an error. The tenant scope makes cross-account revocation
// impossible even with a well-formed foreign token id.
func (s *Store) RevokeAPIToken(ctx context.Context, accountID, tokenID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	if tokenID == "" {
		return fmt.Errorf("cloudserver/store.RevokeAPIToken: empty token id")
	}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at = $3
			  WHERE account_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL`,
			accountID, tokenID, now)
		if e != nil {
			if isInvalidUUIDErr(e) {
				// A malformed token id cannot address a row. Return a sentinel so
				// the aborted transaction ROLLS BACK cleanly (a Postgres error
				// poisons the tx — swallowing it here would fail at commit), then
				// flatten it to the already-gone case outside.
				return errTokenIDMalformed
			}
			return fmt.Errorf("revoke api token: %w", e)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errTokenIDMalformed) {
		return fmt.Errorf("cloudserver/store.RevokeAPIToken: %w", err)
	}
	return nil
}

// errTokenIDMalformed is internal to RevokeAPIToken: it carries "this id could
// never name a row" out of the (now-aborted) transaction so the caller sees the
// same no-op an already-revoked row produces.
var errTokenIDMalformed = errors.New("cloudserver/store: malformed api token id")

// AccessRevocation counts what RevokeAllForAccount revoked. The counts are the
// rows this call FLIPPED (already-revoked rows are not re-counted), so a
// repeated revocation reports zeros honestly.
type AccessRevocation struct {
	DevicesRevoked  int
	TokensRevoked   int
	SessionsRevoked int
	// Suspended reports whether this call moved accounts.status to 'suspended'
	// (false when suspension was not asked for, or the account already was).
	Suspended bool
}

// RevokeAllForAccount revokes every live credential an account holds: device
// registrations, API tokens, and browser sessions — WITHOUT touching the
// account's status. It is the plain revocation primitive (a "sign this account
// out everywhere" that a later legitimate sign-in undoes).
//
// It is ACCESS REVOCATION ONLY — it deletes no data, tombstones nothing, and
// does not close the account (that is CreateDeletionRequest's job, the
// user-initiated deletion path).
func (s *Store) RevokeAllForAccount(ctx context.Context, accountID string, now time.Time) (AccessRevocation, error) {
	return s.revokeAllForAccount(ctx, accountID, now, false)
}

// RevokeAndSuspendAccount revokes every live credential AND moves the account to
// status='suspended', in ONE transaction.
//
// This is the propagation primitive behind the WorkOS lifecycle webhook (plan
// §3 W1, D18 phase 1). Revocation alone is NOT durable there (F8): every
// credential the account holds is re-mintable from the identity — the device
// exchange and the portal sign-in both resolve the SAME (provider, subject)
// link — so a plain revocation would be undone by the very next sign-in, and
// "this user is gone at the provider" would last exactly until someone
// presented a still-valid provider token. Suspension is what makes it stick:
// the two identity entry points refuse a non-active account
// (ErrAccountSuspended), and the two introspection paths already gate on
// account_status = 'active'.
//
// It remains ACCESS revocation, not deletion: no data is removed, and the
// status is reversible by an operator (or by the recovery path E7 will build).
func (s *Store) RevokeAndSuspendAccount(ctx context.Context, accountID string, now time.Time) (AccessRevocation, error) {
	return s.revokeAllForAccount(ctx, accountID, now, true)
}

// revokeAllForAccount is the single implementation both revocation entry points
// share. All updates run in ONE tenant transaction, so a partial revocation
// (devices dead, live tokens still working; or credentials revoked but the
// account still active and re-mintable) is not a reachable state.
func (s *Store) revokeAllForAccount(ctx context.Context, accountID string, now time.Time, suspend bool) (AccessRevocation, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var out AccessRevocation
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE device_registrations SET revoked_at = $2
			  WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID, now)
		if e != nil {
			return fmt.Errorf("revoke devices: %w", e)
		}
		out.DevicesRevoked = int(ct.RowsAffected())

		ct, e = tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at = $2
			  WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID, now)
		if e != nil {
			return fmt.Errorf("revoke tokens: %w", e)
		}
		out.TokensRevoked = int(ct.RowsAffected())

		ct, e = tx.Exec(ctx,
			`UPDATE browser_sessions SET revoked_at = $2
			  WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID, now)
		if e != nil {
			return fmt.Errorf("revoke browser sessions: %w", e)
		}
		out.SessionsRevoked = int(ct.RowsAffected())

		if !suspend {
			return nil
		}
		// accounts is a SYSTEM table (no RLS), so this is scoped by the WHERE
		// clause, not by the tenant GUC. 'closed'/'deleted' are stronger states
		// the user-initiated deletion path owns — do not walk them backwards.
		ct, e = tx.Exec(ctx,
			`UPDATE accounts SET status = 'suspended', updated_at = $2
			  WHERE account_id = $1::uuid AND status = 'active'`, accountID, now)
		if e != nil {
			return fmt.Errorf("suspend account: %w", e)
		}
		out.Suspended = ct.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return AccessRevocation{}, fmt.Errorf("cloudserver/store.RevokeAllForAccount: %w", err)
	}
	return out, nil
}

// ErrAccountNotReactivatable indicates a reactivation was asked for an account
// whose status forbids it: a 'closed' or 'deleted' account is an IRREVERSIBLE
// tombstone (the user-initiated deletion path owns those states and purges the
// identity link), and a still-'active' account has nothing to reactivate.
// Reactivation lifts ONLY a 'suspended' account — the reversible state the
// WorkOS lifecycle webhook and operator abuse actions put an account into.
var ErrAccountNotReactivatable = errors.New("cloudserver/store: account is not in a reactivatable (suspended) state")

// ReactivateAccount is the D18 recovery/reactivation transition: it lifts a
// 'suspended' account back to 'active' so a FRESH sign-in can succeed again. It
// is the reverse of RevokeAndSuspendAccount's status move and NOTHING more —
// the credentials that suspension revoked stay revoked (revoked_at is not
// cleared), so recovery means "you may sign in again and mint new credentials",
// never "your old dead tokens spring back to life".
//
// It is operator-driven by design: there is no self-service HTTP route and no
// provider event that auto-reactivates (WorkOS's user.deleted is terminal at
// the provider). The amendment §3.1/§10 make suspension "reversible by an
// operator", and this is that lever — invoked from an operator console/CLI, out
// of the public auth surface.
//
// The status guard is the whole safety property: the conditional UPDATE moves
// ONLY 'suspended' → 'active'. A 'closed' or 'deleted' tombstone matches zero
// rows and yields ErrAccountNotReactivatable, so the irreversible-deletion
// invariant can never be walked backwards through this path.
func (s *Store) ReactivateAccount(ctx context.Context, accountID string, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	if accountID == "" {
		return fmt.Errorf("cloudserver/store.ReactivateAccount: empty account id")
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// accounts is a SYSTEM table (no RLS); the WHERE clause is the scope AND
		// the guard. Only 'suspended' is a legal source state.
		ct, e := tx.Exec(ctx,
			`UPDATE accounts SET status = 'active', updated_at = $2
			  WHERE account_id = $1::uuid AND status = 'suspended'`, accountID, now)
		if e != nil {
			if isInvalidUUIDErr(e) {
				return ErrAccountNotReactivatable
			}
			return fmt.Errorf("reactivate account: %w", e)
		}
		if ct.RowsAffected() != 1 {
			return ErrAccountNotReactivatable
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrAccountNotReactivatable) {
			return ErrAccountNotReactivatable
		}
		return fmt.Errorf("cloudserver/store.ReactivateAccount: %w", err)
	}
	return nil
}

// AccountStatus reads the lifecycle status of an account ('active', 'suspended',
// 'closed', 'deleted'), or ErrNotFound. It is a forensics/test read on the
// SYSTEM path — accounts carries no RLS, and no secret leaves the process.
func (s *Store) AccountStatus(ctx context.Context, accountID string) (string, error) {
	var status string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT status FROM accounts WHERE account_id = $1::uuid`, accountID).Scan(&status)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	if err != nil {
		return "", err
	}
	return status, nil
}

// Device is a device-registration row for listing.
type Device struct {
	ID         string
	Thumbprint string
	Label      string
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// ListDevices returns the account's devices, newest first.
func (s *Store) ListDevices(ctx context.Context, accountID string) ([]Device, error) {
	var out []Device
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id::text, thumbprint, label, created_at, revoked_at
			   FROM device_registrations WHERE account_id = $1::uuid
			  ORDER BY created_at DESC`, accountID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if e := rows.Scan(&d.ID, &d.Thumbprint, &d.Label, &d.CreatedAt, &d.RevokedAt); e != nil {
				return e
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
