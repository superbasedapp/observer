package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// portalmfa.go is the store seam of the portal's passkey second factor (C2;
// cloud 0131 / 0132; wave 17 lane portal-guardrails; docs/security.md
// PLATRAIL-3). Every statement runs in the caller's account context
// (WithAccount), so row-level security confines it to the caller's own
// passkeys, ceremonies, recovery codes and browser session. The decisions
// (who may enrol, manage, change an org's requirement) are
// internal/cloudserver/portalmfa's; this file only stores and reads.

// Portal second-factor errors.
var (
	// ErrPortalCeremonyInvalid: the ceremony is unknown, consumed, expired,
	// of the other kind, or belongs to another session.
	ErrPortalCeremonyInvalid = errors.New("cloudserver/store: portal passkey ceremony invalid")
	// ErrPortalPasskeyExists: the credential id is already registered.
	ErrPortalPasskeyExists = errors.New("cloudserver/store: that passkey is already registered")
	// ErrPortalPasskeyLimit: portalmfa.MaxActivePasskeys reached.
	ErrPortalPasskeyLimit = errors.New("cloudserver/store: passkey limit reached")
	// ErrPortalPasskeyStale: the passkey was revoked, or its counter moved,
	// since it was read (a concurrent use).
	ErrPortalPasskeyStale = errors.New("cloudserver/store: passkey changed since it was read")
	// ErrRecoveryCodeInvalid: no unused recovery code of the account matches.
	ErrRecoveryCodeInvalid = errors.New("cloudserver/store: recovery code invalid or used")
	// ErrPortalSessionGone: the browser session was revoked meanwhile.
	ErrPortalSessionGone = errors.New("cloudserver/store: browser session revoked")
	// ErrOrgPolicyForbidden: only an org owner or admin may change the
	// second-factor requirement.
	ErrOrgPolicyForbidden = errors.New("cloudserver/store: only an org owner or admin may change the sign-in requirement")
)

// PortalCeremonyKind is a portal ceremony's kind (the 0131 CHECK).
type PortalCeremonyKind string

// The two kinds.
const (
	PortalCeremonyRegister PortalCeremonyKind = "register"
	PortalCeremonyAssert   PortalCeremonyKind = "assert"
)

// PortalPasskey is one passkey as the portal lists it (no key material).
type PortalPasskey struct {
	CredentialID   []byte
	Label          string
	BackupEligible bool
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// PortalSecondFactor is what the portal reads about an account's second
// factor and one of its sessions.
type PortalSecondFactor struct {
	portalmfa.SessionState
	// ActivePasskeys is the account's unrevoked passkey count.
	ActivePasskeys int
	// RecoveryCodesLeft is the account's unused recovery code count.
	RecoveryCodesLeft int
	// AuthTime is the session's fresh primary sign-in time (zero: unknown).
	AuthTime time.Time
}

// PortalSecondFactorState reads the account's enrolment and the session's
// second factor in one statement. ErrNotFound when the session is gone.
func (s *Store) PortalSecondFactorState(ctx context.Context, accountID, sessionID string) (PortalSecondFactor, error) {
	var out PortalSecondFactor
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var method *string
		var amr []string
		var authAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT (SELECT count(*) FROM portal_passkeys p WHERE p.account_id = $1::uuid AND p.revoked_at IS NULL),
			        (SELECT count(*) FROM portal_recovery_codes c WHERE c.account_id = $1::uuid AND c.used_at IS NULL),
			        b.second_factor_method, b.second_factor_amr, b.authenticated_at
			   FROM browser_sessions b
			  WHERE b.account_id = $1::uuid AND b.id = $2::uuid AND b.revoked_at IS NULL`,
			accountID, sessionID).Scan(&out.ActivePasskeys, &out.RecoveryCodesLeft, &method, &amr, &authAt)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out.Enrolled = out.ActivePasskeys > 0
		if method != nil {
			out.Method = portalmfa.Method(*method)
		}
		out.AMR = amr
		if authAt != nil {
			out.AuthTime = authAt.UTC()
		}
		return nil
	})
	if err != nil {
		return PortalSecondFactor{}, fmt.Errorf("cloudserver/store.PortalSecondFactorState: %w", err)
	}
	return out, nil
}

// ListPortalPasskeys returns the account's active passkeys, oldest first.
func (s *Store) ListPortalPasskeys(ctx context.Context, accountID string) ([]PortalPasskey, error) {
	out := []PortalPasskey{}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT credential_id, label, backup_eligible, created_at, last_used_at
			   FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL
			  ORDER BY created_at, credential_id`, accountID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p PortalPasskey
			if err := rows.Scan(&p.CredentialID, &p.Label, &p.BackupEligible, &p.CreatedAt, &p.LastUsedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListPortalPasskeys: %w", err)
	}
	return out, nil
}

// cleanPasskeyLabel trims a label and bounds it.
func cleanPasskeyLabel(label string) string {
	label = strings.TrimSpace(label)
	if !utf8.ValidString(label) {
		return ""
	}
	if utf8.RuneCountInString(label) > portalmfa.MaxLabelRunes {
		label = string([]rune(label)[:portalmfa.MaxLabelRunes])
	}
	return label
}

// BeginPortalPasskeyCeremony stores a challenge for the account's session.
// Expired ceremonies of the account are swept in the same transaction.
func (s *Store) BeginPortalPasskeyCeremony(ctx context.Context, accountID, sessionID, rawCeremony string, kind PortalCeremonyKind, challenge []byte, label string, now time.Time) error {
	if rawCeremony == "" || len(challenge) != staffauth.ChallengeBytes {
		return fmt.Errorf("cloudserver/store.BeginPortalPasskeyCeremony: bad input")
	}
	now = nowOr(now)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM portal_passkey_ceremonies WHERE account_id = $1::uuid AND expires_at <= $2`, accountID, now); err != nil {
			return fmt.Errorf("sweep: %w", err)
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO portal_passkey_ceremonies (ceremony_hash, account_id, session_id, kind, challenge, label, created_at, expires_at)
			 VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8)`,
			hashSecret(rawCeremony), accountID, sessionID, string(kind), challenge, cleanPasskeyLabel(label),
			now, now.Add(portalmfa.CeremonyTTL))
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.BeginPortalPasskeyCeremony: %w", err)
	}
	return nil
}

// PortalCeremony is a consumed ceremony.
type PortalCeremony struct {
	Challenge []byte
	Label     string
}

// ConsumePortalPasskeyCeremony spends a ceremony of kind for the account's
// session. ErrPortalCeremonyInvalid for anything else.
func (s *Store) ConsumePortalPasskeyCeremony(ctx context.Context, accountID, sessionID, rawCeremony string, kind PortalCeremonyKind, now time.Time) (PortalCeremony, error) {
	if rawCeremony == "" {
		return PortalCeremony{}, ErrPortalCeremonyInvalid
	}
	now = nowOr(now)
	var out PortalCeremony
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`UPDATE portal_passkey_ceremonies SET consumed_at = $5
			  WHERE ceremony_hash = $1 AND account_id = $2::uuid AND session_id = $3::uuid AND kind = $4
			    AND consumed_at IS NULL AND expires_at > $5
			  RETURNING challenge, label`,
			hashSecret(rawCeremony), accountID, sessionID, string(kind), now).Scan(&out.Challenge, &out.Label)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrPortalCeremonyInvalid
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrPortalCeremonyInvalid) {
			return PortalCeremony{}, ErrPortalCeremonyInvalid
		}
		return PortalCeremony{}, fmt.Errorf("cloudserver/store.ConsumePortalPasskeyCeremony: %w", err)
	}
	return out, nil
}

// PortalPasskeyIDs returns the credential ids of the account's active
// passkeys (the assertion's allowCredentials, the registration's exclude
// list).
func (s *Store) PortalPasskeyIDs(ctx context.Context, accountID string) ([][]byte, error) {
	ps, err := s.ListPortalPasskeys(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(ps))
	for i, p := range ps {
		out[i] = p.CredentialID
	}
	return out, nil
}

// portalPasskeyLockTx serialises an account's passkey enrolments and
// removals for the rest of the transaction.
func portalPasskeyLockTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	_, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('sbci_portal_passkeys:' || $1::uuid::text, 0))`, accountID)
	return err
}

// markSessionSecondFactorTx records how the session completed its second
// factor. ErrPortalSessionGone when the session was revoked.
func markSessionSecondFactorTx(ctx context.Context, tx pgx.Tx, accountID, sessionID string, method portalmfa.Method, amr []string, now time.Time) error {
	if amr == nil {
		amr = []string{}
	}
	tag, err := tx.Exec(ctx,
		`UPDATE browser_sessions
		    SET second_factor_at = $3, second_factor_method = $4, second_factor_amr = $5
		  WHERE account_id = $1::uuid AND id = $2::uuid AND revoked_at IS NULL`,
		accountID, sessionID, now, string(method), amr)
	if err != nil {
		return fmt.Errorf("mark session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrPortalSessionGone
	}
	return nil
}

// RegisterPortalPasskeyInput is a verified registration.
type RegisterPortalPasskeyInput struct {
	AccountID string
	SessionID string
	Cred      staffauth.NewCredential
	Label     string
	// RecoveryHashes are a fresh batch (portalmfa.HashRecoveryCode), stored
	// only when this is the account's first active passkey.
	RecoveryHashes []string
	Now            time.Time
}

// RegisterPortalPasskeyResult says what the registration did.
type RegisterPortalPasskeyResult struct {
	// First is true when the account had no active passkey: the recovery
	// codes were stored and the session marked as having completed its
	// second factor with this passkey.
	First bool
	// AMR is what the session now carries (First only).
	AMR []string
}

// RegisterPortalPasskey stores a verified passkey. On the account's first
// passkey it also stores the recovery code batch (replacing any older one)
// and marks the session's second factor, all in one transaction.
// ErrPortalPasskeyExists, ErrPortalPasskeyLimit, ErrPortalSessionGone.
func (s *Store) RegisterPortalPasskey(ctx context.Context, in RegisterPortalPasskeyInput) (RegisterPortalPasskeyResult, error) {
	now := nowOr(in.Now)
	var out RegisterPortalPasskeyResult
	err := s.WithAccount(ctx, in.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		if err := portalPasskeyLockTx(ctx, tx, in.AccountID); err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL`, in.AccountID).Scan(&active); err != nil {
			return err
		}
		if active >= portalmfa.MaxActivePasskeys {
			return ErrPortalPasskeyLimit
		}
		transports := in.Cred.Transports
		if transports == nil {
			transports = []string{}
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO portal_passkeys (credential_id, account_id, public_key, sign_count, aaguid, transports, backup_eligible, label, created_at)
			 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9)`,
			in.Cred.ID, in.AccountID, in.Cred.PublicKey, int64(in.Cred.SignCount), nilIfEmpty(in.Cred.AAGUID),
			transports, in.Cred.BackupEligible, cleanPasskeyLabel(in.Label), now)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrPortalPasskeyExists
			}
			return fmt.Errorf("insert passkey: %w", err)
		}
		if active > 0 {
			return nil
		}
		out.First = true
		if err := replaceRecoveryCodesTx(ctx, tx, in.AccountID, in.RecoveryHashes, now); err != nil {
			return err
		}
		out.AMR = portalmfa.AMRFor(portalmfa.MethodPasskey, in.Cred.BackupEligible)
		return markSessionSecondFactorTx(ctx, tx, in.AccountID, in.SessionID, portalmfa.MethodPasskey, out.AMR, now)
	})
	if err != nil {
		for _, e := range []error{ErrPortalPasskeyExists, ErrPortalPasskeyLimit, ErrPortalSessionGone} {
			if errors.Is(err, e) {
				return RegisterPortalPasskeyResult{}, e
			}
		}
		return RegisterPortalPasskeyResult{}, fmt.Errorf("cloudserver/store.RegisterPortalPasskey: %w", err)
	}
	return out, nil
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func replaceRecoveryCodesTx(ctx context.Context, tx pgx.Tx, accountID string, hashes []string, now time.Time) error {
	if len(hashes) != portalmfa.RecoveryCodeCount {
		return fmt.Errorf("recovery codes: want %d hashes, got %d", portalmfa.RecoveryCodeCount, len(hashes))
	}
	if _, err := tx.Exec(ctx, `DELETE FROM portal_recovery_codes WHERE account_id = $1::uuid`, accountID); err != nil {
		return fmt.Errorf("delete old recovery codes: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO portal_recovery_codes (code_hash, account_id, created_at) VALUES ($1, $2::uuid, $3)`,
			h, accountID, now); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return nil
}

// PortalPasskeyForAssertion returns the account's active passkey with the
// credential id, as the verifier needs it. ErrNotFound for any other.
func (s *Store) PortalPasskeyForAssertion(ctx context.Context, accountID string, credentialID []byte) (staffauth.StoredCredential, error) {
	var c staffauth.StoredCredential
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var count int64
		err := tx.QueryRow(ctx,
			`SELECT credential_id, public_key, sign_count FROM portal_passkeys
			  WHERE credential_id = $1 AND account_id = $2::uuid AND revoked_at IS NULL`,
			credentialID, accountID).Scan(&c.ID, &c.PublicKey, &count)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		c.SignCount = uint32(count) //nolint:gosec // G115: the 0131 CHECK bounds it to uint32
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return staffauth.StoredCredential{}, ErrNotFound
		}
		return staffauth.StoredCredential{}, fmt.Errorf("cloudserver/store.PortalPasskeyForAssertion: %w", err)
	}
	c.UserHandle = portalmfa.UserHandle(accountID)
	return c, nil
}

// CompletePortalPasskeyAssertion records a verified assertion: the counter
// moves from stored to presented (compare-and-set, so two concurrent uses of
// one assertion cannot both pass), last_used_at is stamped and the session
// marked with amr, in one transaction. ErrPortalPasskeyStale,
// ErrPortalSessionGone.
func (s *Store) CompletePortalPasskeyAssertion(ctx context.Context, accountID, sessionID string, credentialID []byte, stored, presented uint32, amr []string, now time.Time) error {
	now = nowOr(now)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE portal_passkeys SET sign_count = $4, last_used_at = $5
			  WHERE credential_id = $1 AND account_id = $2::uuid AND revoked_at IS NULL AND sign_count = $3`,
			credentialID, accountID, int64(stored), int64(presented), now)
		if err != nil {
			return fmt.Errorf("update passkey: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrPortalPasskeyStale
		}
		return markSessionSecondFactorTx(ctx, tx, accountID, sessionID, portalmfa.MethodPasskey, amr, now)
	})
	if err != nil {
		for _, e := range []error{ErrPortalPasskeyStale, ErrPortalSessionGone} {
			if errors.Is(err, e) {
				return e
			}
		}
		return fmt.Errorf("cloudserver/store.CompletePortalPasskeyAssertion: %w", err)
	}
	return nil
}

// RedeemPortalRecoveryCode spends one unused recovery code of the account and
// marks the session's second factor as a recovery code (no amr). It returns
// how many codes are left. ErrRecoveryCodeInvalid, ErrPortalSessionGone.
func (s *Store) RedeemPortalRecoveryCode(ctx context.Context, accountID, sessionID, codeHash string, now time.Time) (int, error) {
	now = nowOr(now)
	left := 0
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE portal_recovery_codes SET used_at = $3
			  WHERE code_hash = $1 AND account_id = $2::uuid AND used_at IS NULL`, codeHash, accountID, now)
		if err != nil {
			return fmt.Errorf("redeem: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrRecoveryCodeInvalid
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM portal_recovery_codes WHERE account_id = $1::uuid AND used_at IS NULL`, accountID).Scan(&left); err != nil {
			return err
		}
		return markSessionSecondFactorTx(ctx, tx, accountID, sessionID, portalmfa.MethodRecoveryCode, nil, now)
	})
	if err != nil {
		for _, e := range []error{ErrRecoveryCodeInvalid, ErrPortalSessionGone} {
			if errors.Is(err, e) {
				return 0, e
			}
		}
		return 0, fmt.Errorf("cloudserver/store.RedeemPortalRecoveryCode: %w", err)
	}
	return left, nil
}

// RevokePortalPasskey revokes one of the account's active passkeys. Removing
// the last one turns the second factor off for the account: its recovery
// codes are deleted too. The second-factor mark of every OTHER live browser
// session of the account is cleared in the same transaction (FR-24), so a
// session that proved itself with the revoked passkey is pending again at
// once; keepSessionID (the removing session) keeps its own. It returns the
// active count left. ErrNotFound.
func (s *Store) RevokePortalPasskey(ctx context.Context, accountID, keepSessionID string, credentialID []byte, now time.Time) (int, error) {
	now = nowOr(now)
	left := 0
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if err := portalPasskeyLockTx(ctx, tx, accountID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE portal_passkeys SET revoked_at = $3
			  WHERE credential_id = $1 AND account_id = $2::uuid AND revoked_at IS NULL`, credentialID, accountID, now)
		if err != nil {
			return fmt.Errorf("revoke: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID).Scan(&left); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE browser_sessions
			    SET second_factor_at = NULL, second_factor_method = NULL, second_factor_amr = NULL
			  WHERE account_id = $1::uuid AND id <> $2::uuid AND revoked_at IS NULL AND second_factor_method IS NOT NULL`,
			accountID, keepSessionID); err != nil {
			return fmt.Errorf("clear other sessions: %w", err)
		}
		if left == 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM portal_recovery_codes WHERE account_id = $1::uuid`, accountID); err != nil {
				return fmt.Errorf("delete recovery codes: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("cloudserver/store.RevokePortalPasskey: %w", err)
	}
	return left, nil
}

// ReplacePortalRecoveryCodes stores a new batch of recovery code hashes,
// discarding the old batch. ErrNotFound when the account holds no active
// passkey (codes exist only beside a passkey).
func (s *Store) ReplacePortalRecoveryCodes(ctx context.Context, accountID string, hashes []string, now time.Time) error {
	now = nowOr(now)
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if err := portalPasskeyLockTx(ctx, tx, accountID); err != nil {
			return err
		}
		var active int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM portal_passkeys WHERE account_id = $1::uuid AND revoked_at IS NULL`, accountID).Scan(&active); err != nil {
			return err
		}
		if active == 0 {
			return ErrNotFound
		}
		return replaceRecoveryCodesTx(ctx, tx, accountID, hashes, now)
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("cloudserver/store.ReplacePortalRecoveryCodes: %w", err)
	}
	return nil
}

// OrgSecondFactorRequired reads an org's "require a second factor" setting
// through the caller's membership. ErrNotFound for a non-member.
func (s *Store) OrgSecondFactorRequired(ctx context.Context, accountID, orgID string) (bool, error) {
	var req bool
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := getMyOrgTx(ctx, tx, orgID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT require_second_factor FROM orgs WHERE org_id = $1::uuid`, orgID).Scan(&req)
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, ErrNotFound
		}
		return false, fmt.Errorf("cloudserver/store.OrgSecondFactorRequired: %w", err)
	}
	return req, nil
}

// SetOrgSecondFactorRequired sets an org's requirement; the caller must be
// an owner or admin (ErrOrgPolicyForbidden; the 0048 orgs_admin_update policy
// holds the same). It returns the previous value. ErrNotFound for a
// non-member.
func (s *Store) SetOrgSecondFactorRequired(ctx context.Context, accountID, orgID string, require bool) (bool, error) {
	var prev bool
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		org, err := getMyOrgTx(ctx, tx, orgID)
		if err != nil {
			return err
		}
		if org.ConsoleRole != ConsoleOwner && org.ConsoleRole != ConsoleAdmin {
			return ErrOrgPolicyForbidden
		}
		if err := tx.QueryRow(ctx,
			`SELECT require_second_factor FROM orgs WHERE org_id = $1::uuid FOR UPDATE`, org.OrgID).Scan(&prev); err != nil {
			return fmt.Errorf("lock org: %w", err)
		}
		if prev == require {
			return nil
		}
		_, err = tx.Exec(ctx,
			`UPDATE orgs SET require_second_factor = $2, updated_at = now() WHERE org_id = $1::uuid`, org.OrgID, require)
		return err
	})
	if err != nil {
		for _, e := range []error{ErrNotFound, ErrOrgPolicyForbidden} {
			if errors.Is(err, e) {
				return false, e
			}
		}
		return false, fmt.Errorf("cloudserver/store.SetOrgSecondFactorRequired: %w", err)
	}
	return prev, nil
}
