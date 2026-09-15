package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Auth-transaction / step-up lifetimes (plan §3 W1). Both are deliberately
// short: an auth transaction only has to survive one AuthKit round-trip, and a
// step-up authorization only has to survive the user clicking "confirm".
const (
	// DefaultAuthTransactionTTL bounds the OAuth leg (plan: ≤10 min).
	DefaultAuthTransactionTTL = 10 * time.Minute
	// DefaultStepUpTTL bounds a minted step-up authorization (plan: ≤5 min).
	DefaultStepUpTTL = 5 * time.Minute
	// authTransactionSweepBatch bounds one opportunistic expired-row delete so a
	// sign-in never pays for an unbounded cleanup.
	authTransactionSweepBatch = 200
)

// Auth-transaction purposes. A login transaction carries no account binding; a
// step-up transaction binds the browser session + account it re-authenticates.
const (
	// AuthPurposeLogin is the sign-in leg.
	AuthPurposeLogin = "login"
	// AuthPurposeStepUp is the destructive-action re-authentication leg.
	AuthPurposeStepUp = "step_up"
)

// Step-up actions (Doc B §3.2: deletion, export, security changes).
const (
	// StepUpActionDeletion re-authenticates an account-deletion request.
	StepUpActionDeletion = "deletion"
	// StepUpActionExport re-authenticates a data export.
	StepUpActionExport = "export"
	// StepUpActionSecurity re-authenticates a security-settings change.
	StepUpActionSecurity = "security"
)

// ErrStepUpInvalid indicates the presented step-up authorization did not match
// the account/session/action it must, or was expired or already consumed. The
// mutation it guarded MUST NOT proceed.
var ErrStepUpInvalid = errors.New("cloudserver/store: step-up authorization invalid, expired, or already used")

// AuthTransactionInput describes a new pre-auth OAuth transaction. StateHash
// and NonceHash are hashes of raw secrets the caller keeps; PKCEVerifier is the
// PLAINTEXT verifier, which this package encrypts before it touches a row.
type AuthTransactionInput struct {
	StateHash    string
	PKCEVerifier string
	NonceHash    string
	RedirectURI  string
	Purpose      string // AuthPurposeLogin | AuthPurposeStepUp
	Action       string // step-up only; "" for login
	ReturnTo     string // same-origin path, validated by the caller; may be ""
	SessionID    string // step-up only
	AccountID    string // step-up only
	TTL          time.Duration
	Now          time.Time
}

// AuthTransaction is a consumed OAuth transaction: everything the callback
// needs to finish the flow. PKCEVerifier is decrypted on read and never leaves
// the process.
type AuthTransaction struct {
	ID           string
	Purpose      string
	Action       string
	ReturnTo     string
	SessionID    string
	AccountID    string
	RedirectURI  string
	NonceHash    string
	PKCEVerifier string
	ExpiresAt    time.Time
}

// CreateAuthTransaction mints a single-use pre-auth transaction row. It runs on
// the SYSTEM path (no tenant context): the login flavour has no account yet,
// which is exactly why auth_transactions is a system table (the exchange_nonces
// precedent). The PKCE verifier is sealed with the store's Encryptor before
// insert, so a database dump never yields a usable verifier.
//
// It also opportunistically deletes a bounded batch of already-expired rows, so
// abandoned sign-ins cannot grow the table without a separate sweeper.
func (s *Store) CreateAuthTransaction(ctx context.Context, in AuthTransactionInput) (string, error) {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultAuthTransactionTTL
	}
	if in.StateHash == "" || in.NonceHash == "" || in.RedirectURI == "" {
		return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: state, nonce and redirect_uri are required")
	}
	switch in.Purpose {
	case AuthPurposeLogin:
		if in.AccountID != "" || in.SessionID != "" || in.Action != "" {
			return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: a login transaction carries no account/session/action binding")
		}
	case AuthPurposeStepUp:
		if in.AccountID == "" || in.SessionID == "" || in.Action == "" {
			return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: a step_up transaction requires account, session and action")
		}
	default:
		return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: unknown purpose %q", in.Purpose)
	}

	sealed, err := s.enc.Seal([]byte(in.PKCEVerifier))
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: seal verifier: %w", err)
	}

	var txnID string
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`DELETE FROM auth_transactions
			  WHERE txn_id IN (SELECT txn_id FROM auth_transactions WHERE expires_at < $1 LIMIT $2)`,
			now, authTransactionSweepBatch); e != nil {
			return fmt.Errorf("sweep expired transactions: %w", e)
		}
		return tx.QueryRow(
			ctx,
			`INSERT INTO auth_transactions
			   (state_hash, pkce_verifier_enc, nonce_hash, redirect_uri, purpose,
			    action, return_to, session_id, account_id, created_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5,
			         nullif($6, ''), nullif($7, ''), nullif($8, '')::uuid, nullif($9, '')::uuid, $10, $11)
			 RETURNING txn_id::text`,
			in.StateHash, sealed, in.NonceHash, in.RedirectURI, in.Purpose,
			in.Action, in.ReturnTo, in.SessionID, in.AccountID, now, now.Add(ttl),
		).Scan(&txnID)
	})
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.CreateAuthTransaction: %w", err)
	}
	return txnID, nil
}

// ConsumeAuthTransaction atomically claims the transaction whose state hashes to
// stateHash. The single conditional UPDATE ... RETURNING is the whole guard: a
// replay (consumed_at already set) or an expired row matches zero rows and
// yields ErrNotFound, with no read-then-write window for two concurrent
// callbacks to both win.
func (s *Store) ConsumeAuthTransaction(ctx context.Context, stateHash string, now time.Time) (AuthTransaction, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if stateHash == "" {
		return AuthTransaction{}, ErrNotFound
	}
	var (
		out    AuthTransaction
		sealed []byte
	)
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var action, returnTo, sessionID, accountID *string
		e := tx.QueryRow(ctx,
			`UPDATE auth_transactions SET consumed_at = $2
			  WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > $2
			  RETURNING txn_id::text, purpose, action, return_to,
			            session_id::text, account_id::text, redirect_uri,
			            nonce_hash, pkce_verifier_enc, expires_at`,
			stateHash, now).Scan(
			&out.ID, &out.Purpose, &action, &returnTo,
			&sessionID, &accountID, &out.RedirectURI,
			&out.NonceHash, &sealed, &out.ExpiresAt,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return fmt.Errorf("consume auth transaction: %w", e)
		}
		out.Action = derefString(action)
		out.ReturnTo = derefString(returnTo)
		out.SessionID = derefString(sessionID)
		out.AccountID = derefString(accountID)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AuthTransaction{}, ErrNotFound
		}
		return AuthTransaction{}, fmt.Errorf("cloudserver/store.ConsumeAuthTransaction: %w", err)
	}
	verifier, err := s.enc.Open(sealed)
	if err != nil {
		return AuthTransaction{}, fmt.Errorf("cloudserver/store.ConsumeAuthTransaction: open verifier: %w", err)
	}
	out.PKCEVerifier = string(verifier)
	return out, nil
}

// derefString flattens a nullable text column to "".
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// CSRFRotation is the result of rotating a browser session's CSRF token: the
// new RAW token (returned exactly once — only its hash is stored) plus the
// session's expiry, so the caller can tell the SPA when to re-bootstrap.
type CSRFRotation struct {
	RawCSRFToken string
	ExpiresAt    time.Time
}

// RotateBrowserCSRF replaces the session's CSRF secret and returns the new raw
// token once. It is the E8 bootstrap primitive: the store keeps only csrf_hash,
// so a reload endpoint CANNOT hand back the existing token — it must mint a new
// one. Rotation is a single conditional UPDATE against a live (unrevoked,
// unexpired) session, so a dead cookie can never mint a working CSRF token.
//
// Multi-tab semantics are last-rotation-wins by construction: the previous raw
// token stops validating the moment this returns.
func (s *Store) RotateBrowserCSRF(ctx context.Context, accountID, rawSession string, now time.Time) (CSRFRotation, error) {
	if now.IsZero() {
		now = time.Now()
	}
	raw, err := randToken()
	if err != nil {
		return CSRFRotation{}, fmt.Errorf("cloudserver/store.RotateBrowserCSRF: rand: %w", err)
	}
	out := CSRFRotation{RawCSRFToken: raw}
	err = s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`UPDATE browser_sessions SET csrf_hash = $3
			  WHERE account_id = $1::uuid AND session_hash = $2
			    AND revoked_at IS NULL AND expires_at > $4
			  RETURNING expires_at`,
			accountID, hashSecret(rawSession), hashSecret(raw), now).Scan(&out.ExpiresAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return fmt.Errorf("rotate csrf: %w", e)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return CSRFRotation{}, ErrNotFound
		}
		return CSRFRotation{}, fmt.Errorf("cloudserver/store.RotateBrowserCSRF: %w", err)
	}
	return out, nil
}

// StepUpAuthorization is a minted, not-yet-consumed re-authentication grant.
type StepUpAuthorization struct {
	ID        string
	Action    string
	AuthTime  time.Time
	ExpiresAt time.Time
}

// CreateStepUpAuthorization records a successful re-authentication as a
// one-use, short-lived (≤DefaultStepUpTTL) grant bound to {account, session,
// action}. It is written under tenant context, so the row is RLS-scoped to the
// account from the moment it exists.
func (s *Store) CreateStepUpAuthorization(ctx context.Context, accountID, sessionID, action string, now time.Time) (StepUpAuthorization, error) {
	if now.IsZero() {
		now = time.Now()
	}
	switch action {
	case StepUpActionDeletion, StepUpActionExport, StepUpActionSecurity:
	default:
		return StepUpAuthorization{}, fmt.Errorf("cloudserver/store.CreateStepUpAuthorization: unknown action %q", action)
	}
	if sessionID == "" {
		return StepUpAuthorization{}, fmt.Errorf("cloudserver/store.CreateStepUpAuthorization: empty session id")
	}
	out := StepUpAuthorization{Action: action, AuthTime: now, ExpiresAt: now.Add(DefaultStepUpTTL)}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO step_up_authorizations
			   (account_id, session_id, action, auth_time, expires_at)
			 VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			 RETURNING authz_id::text`,
			accountID, sessionID, action, out.AuthTime, out.ExpiresAt).Scan(&out.ID)
	})
	if err != nil {
		return StepUpAuthorization{}, fmt.Errorf("cloudserver/store.CreateStepUpAuthorization: %w", err)
	}
	return out, nil
}

// consumeStepUpTx claims a step-up authorization INSIDE an existing tenant
// transaction, so consumption and the mutation it guards commit or roll back
// together (a failed mutation must not burn the authorization, and a consumed
// authorization must not permit a second mutation).
//
// Every binding is checked in the WHERE clause — account, session, action,
// unexpired, unconsumed — so a step-up minted for another session, another
// action, or already spent matches zero rows and yields ErrStepUpInvalid.
func consumeStepUpTx(ctx context.Context, tx pgx.Tx, accountID, sessionID, action, authzID string, now time.Time) error {
	if authzID == "" || sessionID == "" {
		return ErrStepUpInvalid
	}
	var claimed string
	e := tx.QueryRow(ctx,
		`UPDATE step_up_authorizations SET consumed_at = $6
		  WHERE account_id = $1::uuid AND authz_id = $2::uuid
		    AND session_id = $3::uuid AND action = $4
		    AND consumed_at IS NULL AND expires_at > $5
		  RETURNING authz_id::text`,
		accountID, authzID, sessionID, action, now, now).Scan(&claimed)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrStepUpInvalid
	}
	if e != nil {
		// A malformed uuid parameter is a client-shaped input, not a server fault:
		// report it as an invalid step-up rather than leaking a driver error.
		if isInvalidUUIDErr(e) {
			return ErrStepUpInvalid
		}
		return fmt.Errorf("consume step-up: %w", e)
	}
	return nil
}

// isInvalidUUIDErr reports whether err is Postgres's invalid-text-representation
// (22P02) — what a non-uuid string cast to uuid produces.
func isInvalidUUIDErr(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "22P02"
	}
	return false
}
