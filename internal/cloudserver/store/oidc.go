package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// oidc.go is the store seam of the control plane's OIDC issuer (managed-SaaS
// M6.2, cloud migrations 0051-0054; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.4). It is
// the only SQL over the oidc_* tables. Those tables are class S (no RLS), so
// their reads and writes run in WithSystem; the one membership read runs in
// WithAccount, so the org registry's policies (0048) decide what the caller
// is a member of. org_sub_seen is never written here: the 0054 trigger on
// oidc_issued maintains it in the same transaction.

// OIDCStore implements oidcissuer.Store over this Store's role. The serve
// process binds it to sbci_api, whose grants (0052, 0053) are exactly what
// the issuer needs.
type OIDCStore struct{ s *Store }

// OIDC returns the issuer's store seam.
func (s *Store) OIDC() OIDCStore { return OIDCStore{s: s} }

var _ oidcissuer.Store = OIDCStore{}

// errOIDCNotMember ends Member's transaction when the caller holds no
// membership; Member turns it into a zero oidcissuer.Member.
var errOIDCNotMember = errors.New("cloudserver/store: not a member")

// Client implements oidcissuer.Store.
func (o OIDCStore) Client(ctx context.Context, clientID string) (oidcissuer.Client, error) {
	var c oidcissuer.Client
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT client_id, org_id::text, redirect_uris, disabled_at IS NOT NULL
			   FROM oidc_clients WHERE client_id = $1`, clientID).
			Scan(&c.ClientID, &c.OrgID, &c.RedirectURIs, &c.Disabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return oidcissuer.Client{}, oidcissuer.ErrNotFound
	}
	if err != nil {
		return oidcissuer.Client{}, fmt.Errorf("cloudserver/store.OIDCStore.Client: %w", err)
	}
	return c, nil
}

// Member implements oidcissuer.Store. It runs as the caller, so the org row
// is visible only through the caller's own membership; a non-member (or a
// missing org, or a malformed id) is a zero Member.
func (o OIDCStore) Member(ctx context.Context, accountID, orgID string) (oidcissuer.Member, error) {
	var m oidcissuer.Member
	err := o.s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT o.status, o.platform_rail_enabled, o.require_second_factor, a.status,
			        coalesce((SELECT l.subject FROM identity_links l
			                   WHERE l.account_id = a.account_id
			                   ORDER BY (l.provider = 'workos') DESC, l.created_at, l.id
			                   LIMIT 1), '')
			   FROM orgs o
			   JOIN org_members m ON m.org_id = o.org_id AND m.account_id = sbci_current_account()
			   JOIN accounts a ON a.account_id = m.account_id
			  WHERE o.org_id = $1::uuid`, orgID).
			Scan(&m.OrgStatus, &m.RailEnabled, &m.RequireSecondFactor, &m.AccountStatus, &m.Sub)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			// Roll back (a malformed id aborted the transaction).
			return errOIDCNotMember
		}
		if err != nil {
			return err
		}
		// The address claim and its verification flag come from the
		// provider-asserted row (account_verified_emails, A4), read by the one
		// store file allowed to name an address (accountprofile.go), so no
		// statement here pairs identity_links with it
		// (TestStoreSQLNeverJoinsIdentityLinksByEmail).
		if err := setOIDCMemberVerifiedAddress(ctx, tx, accountID, &m); err != nil {
			return err
		}
		m.IsMember = true
		return nil
	})
	if errors.Is(err, errOIDCNotMember) {
		return oidcissuer.Member{}, nil
	}
	if err != nil {
		return oidcissuer.Member{}, fmt.Errorf("cloudserver/store.OIDCStore.Member: %w", err)
	}
	return m, nil
}

// PutCode implements oidcissuer.Store.
func (o OIDCStore) PutCode(ctx context.Context, c oidcissuer.CodeRecord) error {
	amr := c.AMR
	if amr == nil {
		amr = []string{}
	}
	// A zero authentication time (the session's is not known) is stored as
	// NULL, and the token minted from the code then carries no auth_time.
	var authTime *time.Time
	if !c.AuthTime.IsZero() {
		t := c.AuthTime.UTC()
		authTime = &t
	}
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO oidc_codes (code_hash, client_id, org_id, account_id, sub, nonce,
			                         code_challenge, redirect_uri, amr, auth_time, created_at, expires_at)
			 VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10, $11, $12)`,
			c.CodeHash, c.ClientID, c.OrgID, c.AccountID, c.Sub, c.Nonce,
			c.CodeChallenge, c.RedirectURI, amr, authTime, c.CreatedAt, c.ExpiresAt)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.OIDCStore.PutCode: %w", err)
	}
	return nil
}

// ConsumeCode implements oidcissuer.Store: one conditional UPDATE, so of any
// number of concurrent redemptions (on any replica) at most one wins, and an
// expired code is never consumed. A hash no member code carries is tried,
// in the same transaction, against the support codes (oidcsupport.go); the
// two are random 32-byte values, so one hash names at most one row.
func (o OIDCStore) ConsumeCode(ctx context.Context, codeHash string, now time.Time) (oidcissuer.CodeRecord, error) {
	var c oidcissuer.CodeRecord
	var authTime *time.Time
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`UPDATE oidc_codes SET consumed_at = $2
			  WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > $2
			  RETURNING code_hash, client_id, org_id::text, account_id::text, sub, nonce,
			            code_challenge, redirect_uri, amr, auth_time, created_at, expires_at`, codeHash, now).
			Scan(&c.CodeHash, &c.ClientID, &c.OrgID, &c.AccountID, &c.Sub, &c.Nonce,
				&c.CodeChallenge, &c.RedirectURI, &c.AMR, &authTime, &c.CreatedAt, &c.ExpiresAt)
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		sc, err := consumeSupportCode(ctx, tx, codeHash, now)
		if err != nil {
			return err
		}
		c = sc
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return oidcissuer.CodeRecord{}, oidcissuer.ErrNotFound
	}
	if err != nil {
		return oidcissuer.CodeRecord{}, fmt.Errorf("cloudserver/store.OIDCStore.ConsumeCode: %w", err)
	}
	if authTime != nil {
		c.AuthTime = authTime.UTC()
	}
	return c, nil
}

// SigningKeys implements oidcissuer.Store.
func (o OIDCStore) SigningKeys(ctx context.Context) ([]oidcissuer.SigningKey, error) {
	var out []oidcissuer.SigningKey
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT kid, alg, public_jwk, vm_id, status, not_before, not_after
			   FROM oidc_signing_keys WHERE status <> 'retired' ORDER BY kid`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k oidcissuer.SigningKey
			var jwk []byte
			var nb, na *time.Time
			if err := rows.Scan(&k.KID, &k.Alg, &jwk, &k.VMID, &k.Status, &nb, &na); err != nil {
				return err
			}
			if err := json.Unmarshal(jwk, &k.JWK); err != nil {
				return fmt.Errorf("decode public_jwk of %s: %w", k.KID, err)
			}
			if nb != nil {
				k.NotBefore = *nb
			}
			if na != nil {
				k.NotAfter = *na
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OIDCStore.SigningKeys: %w", err)
	}
	return out, nil
}

// StageSigningKeys implements oidcissuer.Store. A kid already registered (in
// any status) is left untouched: a signer restart never demotes or revives a
// key.
func (o OIDCStore) StageSigningKeys(ctx context.Context, vmID string, keys []oidcissuer.PublicKey, now time.Time) error {
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, k := range keys {
			if _, err := oidcissuer.RSAPublicKey(k.JWK); err != nil || k.KID != k.JWK.Kid {
				return fmt.Errorf("key %q is not a usable RS256 signing key", k.KID)
			}
			jwk, err := json.Marshal(k.JWK)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO oidc_signing_keys (kid, public_jwk, vm_id, status, created_at, updated_at)
				 VALUES ($1, $2::jsonb, $3, 'staged', $4, $4)
				 ON CONFLICT DO NOTHING`, k.KID, string(jwk), vmID, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.OIDCStore.StageSigningKeys: %w", err)
	}
	return nil
}

// RecordIssuance implements oidcissuer.Store: the oidc_issued row (whose
// trigger records org_sub_seen) and the oidc_audit_mirror row, one
// transaction. Either insert failing rolls both back, and the issuer then
// returns no token.
func (o OIDCStore) RecordIssuance(ctx context.Context, iss oidcissuer.Issuance) error {
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO oidc_issued (jti, org_id, account_id, sub, client_id, kid, iat, exp)
			 VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8)`,
			iss.JTI, iss.OrgID, iss.AccountID, iss.Sub, iss.ClientID, iss.KID, iss.IssuedAt, iss.ExpiresAt); err != nil {
			return fmt.Errorf("insert oidc_issued: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO oidc_audit_mirror (jti, org_id, payload) VALUES ($1, $2::uuid, $3::jsonb)`,
			iss.JTI, iss.OrgID, string(iss.MirrorPayload)); err != nil {
			return fmt.Errorf("insert oidc_audit_mirror: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.OIDCStore.RecordIssuance: %w", err)
	}
	return nil
}

// InsertOIDCClientTx inserts org's OIDC client inside tx, failing on any
// existing row. The provisioning transaction uses its idempotent form,
// EnsureOIDCClientTx, through RegisterProvisionedOIDCClientTx
// (orgoidcclient.go), so the org and its client commit together (design A7).
func InsertOIDCClientTx(ctx context.Context, tx pgx.Tx, c oidcissuer.Client) error {
	if len(c.RedirectURIs) != 1 {
		return fmt.Errorf("cloudserver/store.InsertOIDCClientTx: want exactly one redirect URI, got %d", len(c.RedirectURIs))
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oidc_clients (client_id, org_id, redirect_uris) VALUES ($1, $2::uuid, $3)`,
		c.ClientID, c.OrgID, c.RedirectURIs); err != nil {
		return fmt.Errorf("cloudserver/store.InsertOIDCClientTx: %w", err)
	}
	return nil
}

// ErrOIDCClientConflict reports that org's OIDC client already exists with
// another redirect URI (or another org under its client id), so ensuring it
// would change a registered client. The issuer matches redirect URIs byte
// for byte; a silent rewrite would move where the org's codes are sent.
var ErrOIDCClientConflict = errors.New("cloudserver/store: the org's OIDC client is registered differently")

// EnsureOIDCClientTx is InsertOIDCClientTx made idempotent: it inserts c
// inside tx unless a row for its client id (or its org) is already there,
// then reads the row back and returns ErrOIDCClientConflict unless it is
// exactly c (same org, same one redirect URI, not disabled). A retried
// provisioning step therefore leaves exactly one client and never rewrites
// one. It needs only SELECT and INSERT on oidc_clients (sbci_api's grant,
// cloud 0052).
func EnsureOIDCClientTx(ctx context.Context, tx pgx.Tx, c oidcissuer.Client) error {
	if len(c.RedirectURIs) != 1 {
		return fmt.Errorf("cloudserver/store.EnsureOIDCClientTx: want exactly one redirect URI, got %d", len(c.RedirectURIs))
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO oidc_clients (client_id, org_id, redirect_uris) VALUES ($1, $2::uuid, $3)
		 ON CONFLICT DO NOTHING`,
		c.ClientID, c.OrgID, c.RedirectURIs); err != nil {
		return fmt.Errorf("cloudserver/store.EnsureOIDCClientTx: %w", err)
	}
	var (
		org      string
		uris     []string
		disabled bool
	)
	// By client id: the CHECK ties a client id to its org, so a conflict on
	// either unique key (client_id, org_id) leaves exactly this row.
	if err := tx.QueryRow(ctx,
		`SELECT org_id::text, redirect_uris, disabled_at IS NOT NULL FROM oidc_clients WHERE client_id = $1`,
		c.ClientID).Scan(&org, &uris, &disabled); err != nil {
		return fmt.Errorf("cloudserver/store.EnsureOIDCClientTx: read back: %w", err)
	}
	if org != c.OrgID || len(uris) != 1 || uris[0] != c.RedirectURIs[0] || disabled {
		return fmt.Errorf("cloudserver/store.EnsureOIDCClientTx(%s): %w", c.ClientID, ErrOIDCClientConflict)
	}
	return nil
}

// RegisterOIDCClient inserts org's OIDC client in a transaction of its own
// (operator backfill for an org provisioned before the hook was wired, and
// tests).
func (s *Store) RegisterOIDCClient(ctx context.Context, c oidcissuer.Client) error {
	return s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return InsertOIDCClientTx(ctx, tx, c)
	})
}

// SetOIDCSigningKeyStatus moves key kid to status `to` along the lifecycle
// oidcissuer.CheckKeyTransition allows. A promotion (staged -> active) sets
// not_before, which oidcissuer.CheckPromotion must accept for lead; the
// status alone decides publication otherwise (retired is never published).
// It is an operator act (sbci_app); it returns
// ErrNotFound when kid is unknown.
func (s *Store) SetOIDCSigningKeyStatus(ctx context.Context, kid, to string, notBefore, now time.Time, lead time.Duration) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var from string
		if err := tx.QueryRow(ctx, `SELECT status FROM oidc_signing_keys WHERE kid = $1 FOR UPDATE`, kid).Scan(&from); err != nil {
			return err
		}
		needsNotBefore, err := oidcissuer.CheckKeyTransition(from, to)
		if err != nil {
			return err
		}
		switch {
		case needsNotBefore:
			if err := oidcissuer.CheckPromotion(notBefore, now, lead); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE oidc_signing_keys SET status = $2, not_before = $3, updated_at = $4 WHERE kid = $1`, kid, to, notBefore, now)
		default:
			_, err = tx.Exec(ctx, `UPDATE oidc_signing_keys SET status = $2, updated_at = $3 WHERE kid = $1`, kid, to, now)
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("cloudserver/store.SetOIDCSigningKeyStatus: %w", err)
	}
	return nil
}

// SweepOIDCCodes deletes codes that expired before now (spent or not) and
// returns how many. Codes live 60 seconds, so this keeps the table tiny and
// leaves no account-linked row behind for long.
func (s *Store) SweepOIDCCodes(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM oidc_codes WHERE expires_at < $1`, now)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM oidc_support_codes WHERE expires_at < $1`, now)
		n += tag.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepOIDCCodes: %w", err)
	}
	return n, nil
}
