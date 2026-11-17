package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// staffcredentials.go holds the operator's passkey management (ruling A2:
// several passkeys per staff member, recovery through the operator CLI
// only) and the login-membership read the cloud processes check at startup
// (ruling A3: the staff login is the only member of sbci_staff). No HTTP
// route reaches the credential methods.

// StaffCredential is one staff passkey as the operator lists it. It carries
// the public half only.
type StaffCredential struct {
	ID         []byte
	Label      string
	Transports []string
	AAGUID     []byte
	SignCount  uint32
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Active reports whether the credential can still sign in.
func (c StaffCredential) Active() bool { return c.RevokedAt == nil }

// ListStaffCredentials returns every passkey of staffID, revoked ones
// included, oldest first; ErrNotFound when the staff member does not exist.
func (s *Store) ListStaffCredentials(ctx context.Context, staffID string) ([]StaffCredential, error) {
	var out []StaffCredential
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := staffUserTx(ctx, tx, staffID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT credential_id, label, transports, aaguid, sign_count, created_at, last_used_at, revoked_at
			   FROM staff_webauthn_credentials WHERE staff_id = $1::uuid
			  ORDER BY created_at, credential_id`, staffID)
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var c StaffCredential
			var count int64
			if err := rows.Scan(&c.ID, &c.Label, &c.Transports, &c.AAGUID, &count, &c.CreatedAt, &c.LastUsedAt, &c.RevokedAt); err != nil {
				return fmt.Errorf("scan credential: %w", err)
			}
			c.SignCount = uint32(count) //nolint:gosec // G115: the column CHECK bounds sign_count to [0, 2^32-1]
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("cloudserver/store.ListStaffCredentials: %w", err)
	}
	return out, nil
}

// RevokeStaffCredential revokes one unrevoked passkey of staffID, ends every
// session it signed in, and logs the revocation with reason, in one
// transaction. ErrNotFound when staffID holds no such unrevoked credential.
// It is the operator's recovery path (observer-cloud staff
// revoke-credential): the staff member then registers a replacement with a
// fresh enrolment code.
func (s *Store) RevokeStaffCredential(ctx context.Context, staffID string, credentialID []byte, reason string, now time.Time) error {
	reason, err := staffauth.ValidateReason(reason)
	if err != nil {
		return fmt.Errorf("cloudserver/store.RevokeStaffCredential: %w", err)
	}
	if len(credentialID) == 0 || len(credentialID) > staffauth.MaxCredentialIDBytes {
		return ErrNotFound
	}
	now = nowOr(now)
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE staff_webauthn_credentials SET revoked_at = $3
			  WHERE credential_id = $1 AND staff_id = $2::uuid AND revoked_at IS NULL`,
			credentialID, staffID, now)
		if err != nil {
			return fmt.Errorf("revoke credential: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		if _, err := tx.Exec(ctx,
			`UPDATE staff_sessions SET revoked_at = $2 WHERE credential_id = $1 AND revoked_at IS NULL`,
			credentialID, now); err != nil {
			return fmt.Errorf("end sessions: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.ActorOperator, verb: staffauth.VerbCredentialRevoked,
			subject: staffID, target: "credential:" + hex.EncodeToString(credentialTag(credentialID)),
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("cloudserver/store.RevokeStaffCredential: %w", err)
	}
	return nil
}

// LoginMemberships is what the login a Store connects as may become: the
// database authority of the process holding it.
type LoginMemberships struct {
	// Login is the session user's name.
	Login string
	// Superuser logins are members of every role.
	Superuser bool
	// Staff, API and Worker report membership (direct or inherited) of
	// sbci_staff, sbci_api and sbci_worker.
	Staff  bool
	API    bool
	Worker bool
}

// LoginMemberships reads the memberships of the login this Store's pool
// connects as. It runs outside any role switch: it asks what the login
// itself may SET ROLE to.
func (s *Store) LoginMemberships(ctx context.Context) (LoginMemberships, error) {
	var m LoginMemberships
	err := s.pool.QueryRow(ctx,
		`SELECT r.rolname, r.rolsuper,
		        pg_has_role(session_user, 'sbci_staff', 'MEMBER'),
		        pg_has_role(session_user, 'sbci_api', 'MEMBER'),
		        pg_has_role(session_user, 'sbci_worker', 'MEMBER')
		   FROM pg_roles r WHERE r.rolname = session_user`).
		Scan(&m.Login, &m.Superuser, &m.Staff, &m.API, &m.Worker)
	if err != nil {
		return LoginMemberships{}, fmt.Errorf("cloudserver/store.LoginMemberships: %w", err)
	}
	return m, nil
}
