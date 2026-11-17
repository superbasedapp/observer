package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// oidcsupport.go is the store seam of the issuer's support path (managed-SaaS
// M7a.2, cloud migrations 0087-0088): the only SQL over oidc_support_codes
// and oidc_support_issued, and the one caller of sbci_support_target.
//
//   - PutSupportCode runs in the STAFF process as sbci_staff (WithStaff) and
//     writes the code and its staff_actions row in one transaction, so a
//     support code never exists without its log entry (audit before act).
//   - ConsumeCode (oidc.go) redeems a support code as well as a member code,
//     as sbci_api; SupportTarget and RecordSupportIssuance run as sbci_api
//     too, in the serve process's token endpoint.

var (
	_ oidcissuer.SupportCodeStore  = StaffOIDCStore{}
	_ oidcissuer.SupportTokenStore = OIDCStore{}
)

// staffSupportReason is the staff_actions reason a support code carries. The
// staff member states no reason of their own at sign-in: the customer's grant
// (in the tenant) carries the reason the access exists.
const staffSupportReason = "support sign-in; access is decided by the organization's own support grant"

// StaffOIDCStore is the staff process's slice of the issuer's store: the
// client lookup and the support code write, both as sbci_staff.
type StaffOIDCStore struct{ s *Store }

// StaffOIDC returns the staff process's issuer seam.
func (s *Store) StaffOIDC() StaffOIDCStore { return StaffOIDCStore{s: s} }

// Client implements oidcissuer.SupportCodeStore: the member path's read,
// as sbci_staff (0087 grants it SELECT on oidc_clients).
func (o StaffOIDCStore) Client(ctx context.Context, clientID string) (oidcissuer.Client, error) {
	var c oidcissuer.Client
	err := o.s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT client_id, org_id::text, redirect_uris, disabled_at IS NOT NULL
			   FROM oidc_clients WHERE client_id = $1`, clientID).
			Scan(&c.ClientID, &c.OrgID, &c.RedirectURIs, &c.Disabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return oidcissuer.Client{}, oidcissuer.ErrNotFound
	}
	if err != nil {
		return oidcissuer.Client{}, fmt.Errorf("cloudserver/store.StaffOIDCStore.Client: %w", err)
	}
	return c, nil
}

// PutSupportCode implements oidcissuer.SupportCodeStore: the support code
// and its staff_actions row (verb support.signin, the org and the client),
// one transaction as sbci_staff.
func (o StaffOIDCStore) PutSupportCode(ctx context.Context, c oidcissuer.CodeRecord) error {
	if !c.Support || c.StaffID == "" || c.AuthTime.IsZero() {
		return errors.New("cloudserver/store.StaffOIDCStore.PutSupportCode: not a support code")
	}
	err := o.s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO oidc_support_codes (code_hash, client_id, org_id, staff_id, nonce, code_challenge,
			                                 redirect_uri, auth_time, created_at, expires_at)
			 VALUES ($1, $2, $3::uuid, $4::uuid, $5, $6, $7, $8, $9, $10)`,
			c.CodeHash, c.ClientID, c.OrgID, c.StaffID, c.Nonce, c.CodeChallenge,
			c.RedirectURI, c.AuthTime.UTC(), c.CreatedAt, c.ExpiresAt); err != nil {
			return err
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: nowOr(c.CreatedAt), actor: staffauth.Actor(c.StaffID), verb: staffauth.VerbSupportSignIn,
			subject: c.StaffID, org: c.OrgID, target: c.ClientID, reason: staffSupportReason, result: "ok",
		})
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.StaffOIDCStore.PutSupportCode: %w", err)
	}
	return nil
}

// consumeSupportCode is ConsumeCode's second statement: the same conditional
// UPDATE over oidc_support_codes, inside ConsumeCode's transaction.
func consumeSupportCode(ctx context.Context, tx pgx.Tx, codeHash string, now time.Time) (oidcissuer.CodeRecord, error) {
	c := oidcissuer.CodeRecord{Support: true}
	err := tx.QueryRow(ctx,
		`UPDATE oidc_support_codes SET consumed_at = $2
		  WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > $2
		  RETURNING code_hash, client_id, org_id::text, staff_id::text, nonce,
		            code_challenge, redirect_uri, auth_time, created_at, expires_at`, codeHash, now).
		Scan(&c.CodeHash, &c.ClientID, &c.OrgID, &c.StaffID, &c.Nonce,
			&c.CodeChallenge, &c.RedirectURI, &c.AuthTime, &c.CreatedAt, &c.ExpiresAt)
	if err != nil {
		return oidcissuer.CodeRecord{}, err
	}
	c.AuthTime = c.AuthTime.UTC()
	return c, nil
}

// SupportTarget implements oidcissuer.SupportTokenStore through the definer
// read sbci_support_target (0088): the staff member's and the org's state,
// nothing else. A malformed id reads as nobody and nowhere.
func (o OIDCStore) SupportTarget(ctx context.Context, staffID, orgID string) (oidcissuer.SupportTarget, error) {
	var t oidcissuer.SupportTarget
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT staff_active, org_status, rail_enabled FROM sbci_support_target($1::uuid, $2::uuid)`, staffID, orgID).
			Scan(&t.StaffActive, &t.OrgStatus, &t.RailEnabled)
	})
	if isInvalidUUIDErr(err) {
		return oidcissuer.SupportTarget{}, nil
	}
	if err != nil {
		return oidcissuer.SupportTarget{}, fmt.Errorf("cloudserver/store.OIDCStore.SupportTarget: %w", err)
	}
	return t, nil
}

// RecordSupportIssuance implements oidcissuer.SupportTokenStore: the
// append-only issued-token row, before the token is returned.
func (o OIDCStore) RecordSupportIssuance(ctx context.Context, iss oidcissuer.SupportIssuance) error {
	err := o.s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO oidc_support_issued (jti, org_id, staff_id, client_id, kid, iat, exp)
			 VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7)`,
			iss.JTI, iss.OrgID, iss.StaffID, iss.ClientID, iss.KID, iss.IssuedAt, iss.ExpiresAt)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.OIDCStore.RecordSupportIssuance: %w", err)
	}
	return nil
}
