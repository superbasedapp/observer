package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// staff.go is the store seam of the staff console (managed-SaaS M6.8; cloud
// migrations 0068-0070, 0076). Every statement runs as sbci_staff through
// WithStaff, the only role granted the staff tables; sbci_api (the customer
// session handlers) holds nothing on them. A staff member is keyed by
// staff_id and authenticated by a WebAuthn credential id; nothing here names
// or stores an email.
//
// WithStaff's `SET LOCAL ROLE sbci_staff` succeeds only for a login that is
// a member of sbci_staff. Since ruling A3 that is the staff login alone
// (sbci_staff_svc, 0076), used by the separate staff process and the
// operator's staff commands; the customer serve login is not a member, so a
// staff method called from serve fails with a permission error.

// RoleStaff is the staff console's role. The staff process constructs its
// Store with it (NewForRole(pool, RoleStaff)), so even a non-staff method
// called there runs as sbci_staff and reaches no customer table; every other
// process reaches it only through WithStaff, and only with a staff login.
const RoleStaff Role = "sbci_staff"

// Staff lifetimes.
const (
	// DefaultStaffEnrolmentTTL is how long an enrolment code lives (design
	// 4.9: 30 minutes).
	DefaultStaffEnrolmentTTL = 30 * time.Minute
	// MaxStaffEnrolmentTTL is the longest a code may live (the
	// staff_enrolments CHECK).
	MaxStaffEnrolmentTTL = time.Hour
	// StaffCeremonyTTL is how long a WebAuthn challenge stays answerable.
	StaffCeremonyTTL = 5 * time.Minute
	// DefaultStaffSessionTTL is a staff session's absolute life.
	DefaultStaffSessionTTL = 8 * time.Hour
	// MaxStaffSessionTTL is the staff_sessions CHECK.
	MaxStaffSessionTTL = 12 * time.Hour
	// DefaultStaffSessionIdleTTL is a staff session's idle window, shorter
	// than the customer portal's (design 3.6).
	DefaultStaffSessionIdleTTL = 30 * time.Minute
	// staffSessionRollInterval coalesces the idle-refresh write.
	staffSessionRollInterval = time.Minute
	// staffActionListMax bounds one read of the action log.
	staffActionListMax = 500
)

// Staff errors.
var (
	// ErrStaffEnrolmentInvalid: the enrolment code is unknown, used, expired,
	// or its staff member is disabled. One error for all four, so a caller
	// learns nothing about which.
	ErrStaffEnrolmentInvalid = errors.New("cloudserver/store: staff enrolment code invalid")
	// ErrStaffCeremonyInvalid: the ceremony is unknown, consumed, expired or
	// of the other kind.
	ErrStaffCeremonyInvalid = errors.New("cloudserver/store: staff ceremony invalid")
	// ErrStaffCredentialExists: the credential id is already registered.
	ErrStaffCredentialExists = errors.New("cloudserver/store: staff credential already registered")
	// ErrStaffCredentialStale: the credential was revoked, its staff member
	// disabled, or its counter moved since it was read (a concurrent use).
	ErrStaffCredentialStale = errors.New("cloudserver/store: staff credential changed since it was read")
	// ErrStaffSessionInvalid: the staff session is unknown, revoked,
	// expired, idle, or its staff member or credential is no longer valid.
	ErrStaffSessionInvalid = errors.New("cloudserver/store: staff session invalid")
)

// WithStaff runs fn in a transaction as sbci_staff, with any tenant context
// cleared. sbci_staff holds grants on the staff tables only, so fn can reach
// nothing else.
func (s *Store) WithStaff(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE sbci_staff`); err != nil {
			return fmt.Errorf("cloudserver/store.WithStaff: set role: %w", err)
		}
		if _, err := tx.Exec(ctx, tenantctx.KindAccount.ClearLocalSQL()); err != nil {
			return fmt.Errorf("cloudserver/store.WithStaff: clear tenant: %w", err)
		}
		return fn(ctx, tx)
	})
}

// StaffUser is a staff member.
type StaffUser struct {
	StaffID     string
	DisplayName string
	Role        staffauth.Role
	Status      string
	CreatedAt   time.Time
}

// EnrolStaffInput is one operator enrolment: a new staff member (StaffID
// empty) or a fresh code for an existing one.
type EnrolStaffInput struct {
	// StaffID names an existing, active staff member; empty creates one
	// from DisplayName and Role.
	StaffID     string
	DisplayName string
	Role        staffauth.Role
	// TTL is the code's life; zero means DefaultStaffEnrolmentTTL, more than
	// MaxStaffEnrolmentTTL is refused.
	TTL time.Duration
	// Reason is logged in staff_actions.
	Reason string
	Now    time.Time
}

// StaffEnrolment is an enrolment's result: the staff member and the RAW
// one-time code, returned once and stored only as a hash.
type StaffEnrolment struct {
	Staff     StaffUser
	RawCode   string
	ExpiresAt time.Time
}

// EnrolStaff creates a staff member (or picks an existing active one) and
// mints a single-use enrolment code for it, logging both in staff_actions,
// in one transaction. It is the operator's path (observer-cloud staff enrol);
// no HTTP route reaches it.
func (s *Store) EnrolStaff(ctx context.Context, in EnrolStaffInput) (StaffEnrolment, error) {
	ttl := in.TTL
	if ttl == 0 {
		ttl = DefaultStaffEnrolmentTTL
	}
	if ttl < 0 || ttl > MaxStaffEnrolmentTTL {
		return StaffEnrolment{}, fmt.Errorf("cloudserver/store.EnrolStaff: ttl %s outside (0, %s]", ttl, MaxStaffEnrolmentTTL)
	}
	reason, err := staffauth.ValidateReason(in.Reason)
	if err != nil {
		return StaffEnrolment{}, fmt.Errorf("cloudserver/store.EnrolStaff: %w", err)
	}
	now := nowOr(in.Now)
	raw, err := randToken()
	if err != nil {
		return StaffEnrolment{}, fmt.Errorf("cloudserver/store.EnrolStaff: rand: %w", err)
	}
	var out StaffEnrolment
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		u, e := enrolTarget(ctx, tx, in, reason, now)
		if e != nil {
			return e
		}
		expires := now.Add(ttl)
		if _, e := tx.Exec(ctx,
			`INSERT INTO staff_enrolments (code_hash, staff_id, created_at, expires_at)
			 VALUES ($1, $2::uuid, $3, $4)`,
			hashSecret(raw), u.StaffID, now, expires); e != nil {
			return fmt.Errorf("insert enrolment: %w", e)
		}
		if e := insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.ActorOperator, verb: staffauth.VerbEnrolmentMinted,
			subject: u.StaffID, reason: reason, result: "ok",
		}); e != nil {
			return e
		}
		out = StaffEnrolment{Staff: u, RawCode: raw, ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return StaffEnrolment{}, fmt.Errorf("cloudserver/store.EnrolStaff: %w", err)
	}
	return out, nil
}

// enrolTarget returns the staff member an enrolment is for, creating it when
// in.StaffID is empty.
func enrolTarget(ctx context.Context, tx pgx.Tx, in EnrolStaffInput, reason string, now time.Time) (StaffUser, error) {
	if in.StaffID != "" {
		u, err := staffUserTx(ctx, tx, in.StaffID)
		if err != nil {
			return StaffUser{}, err
		}
		if u.Status != "active" {
			return StaffUser{}, fmt.Errorf("staff member %s is %s", u.StaffID, u.Status)
		}
		return u, nil
	}
	if _, err := staffauth.ParseRole(string(in.Role)); err != nil {
		return StaffUser{}, err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		return StaffUser{}, errors.New("a display name is required")
	}
	u := StaffUser{DisplayName: name, Role: in.Role, Status: "active"}
	if err := tx.QueryRow(ctx,
		`INSERT INTO staff_users (display_name, staff_role, created_at)
		 VALUES ($1, $2, $3) RETURNING staff_id::text, created_at`,
		name, string(in.Role), now).Scan(&u.StaffID, &u.CreatedAt); err != nil {
		return StaffUser{}, fmt.Errorf("insert staff user: %w", err)
	}
	if err := insertStaffAction(ctx, tx, staffActionRow{
		at: now, actor: staffauth.ActorOperator, verb: staffauth.VerbStaffCreated,
		subject: u.StaffID, detail: map[string]any{"role": string(in.Role)}, reason: reason, result: "ok",
	}); err != nil {
		return StaffUser{}, err
	}
	return u, nil
}

// staffUserTx reads one staff member.
func staffUserTx(ctx context.Context, tx pgx.Tx, staffID string) (StaffUser, error) {
	var u StaffUser
	var role string
	err := tx.QueryRow(ctx,
		`SELECT staff_id::text, display_name, staff_role, status, created_at
		   FROM staff_users WHERE staff_id = $1::uuid`, staffID).
		Scan(&u.StaffID, &u.DisplayName, &role, &u.Status, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return StaffUser{}, ErrNotFound
	}
	if err != nil {
		return StaffUser{}, fmt.Errorf("read staff user: %w", err)
	}
	u.Role = staffauth.Role(role)
	return u, nil
}

// StaffCeremonyKind is a WebAuthn ceremony kind.
type StaffCeremonyKind string

// The two ceremony kinds (the staff_ceremonies.kind CHECK).
const (
	StaffCeremonyRegister StaffCeremonyKind = "register"
	StaffCeremonyAssert   StaffCeremonyKind = "assert"
)

// StaffCeremony is a consumed ceremony: what the finish step verifies
// against.
type StaffCeremony struct {
	Kind      StaffCeremonyKind
	Challenge []byte
	// StaffID and EnrolmentHash are set for a registration only.
	StaffID       string
	EnrolmentHash string
}

// StaffRegistrationStart is what BeginStaffRegistration returns: the staff
// member the code enrols and the credential ids it already holds (excluded
// from the new registration).
type StaffRegistrationStart struct {
	Staff                 StaffUser
	ExistingCredentialIDs [][]byte
}

// BeginStaffRegistration checks the enrolment code (unused, unexpired, its
// staff member active) and records a registration ceremony with challenge,
// bound to the hash of rawCeremony (the ceremony cookie). The code is NOT
// spent here: RegisterStaffCredential spends it with the credential, so the
// code yields at most one credential however many ceremonies it starts. A
// staff member already at staffauth.MaxActivePasskeys is refused here too
// (staffauth.ErrPasskeyLimit, logged), before any ceremony is recorded.
func (s *Store) BeginStaffRegistration(ctx context.Context, rawCode, rawCeremony string, challenge []byte, now time.Time) (StaffRegistrationStart, error) {
	if rawCode == "" || rawCeremony == "" || len(challenge) != staffauth.ChallengeBytes {
		return StaffRegistrationStart{}, ErrStaffEnrolmentInvalid
	}
	now = nowOr(now)
	var out StaffRegistrationStart
	refused := false
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var staffID string
		err := tx.QueryRow(ctx,
			`SELECT e.staff_id::text FROM staff_enrolments e JOIN staff_users u ON u.staff_id = e.staff_id
			  WHERE e.code_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2 AND u.status = 'active'`,
			hashSecret(rawCode), now).Scan(&staffID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStaffEnrolmentInvalid
		}
		if err != nil {
			return fmt.Errorf("read enrolment: %w", err)
		}
		// Refused up front, before the browser ceremony, so the person is
		// told before touching an authenticator; the finish re-checks under
		// the same lock. The refusal commits its log row and starts nothing.
		if refused, err = staffPasskeyCapTx(ctx, tx, staffID, now); err != nil || refused {
			return err
		}
		u, err := staffUserTx(ctx, tx, staffID)
		if err != nil {
			return err
		}
		ids, err := staffCredentialIDsTx(ctx, tx, staffID)
		if err != nil {
			return err
		}
		if err := sweepStaffCeremoniesTx(ctx, tx, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO staff_ceremonies (ceremony_hash, kind, challenge, staff_id, enrolment_hash, created_at, expires_at)
			 VALUES ($1, 'register', $2, $3::uuid, $4, $5, $6)`,
			hashSecret(rawCeremony), challenge, staffID, hashSecret(rawCode), now, now.Add(StaffCeremonyTTL)); err != nil {
			return fmt.Errorf("insert ceremony: %w", err)
		}
		out = StaffRegistrationStart{Staff: u, ExistingCredentialIDs: ids}
		return nil
	})
	if err != nil {
		return StaffRegistrationStart{}, fmt.Errorf("cloudserver/store.BeginStaffRegistration: %w", err)
	}
	if refused {
		return StaffRegistrationStart{}, fmt.Errorf("cloudserver/store.BeginStaffRegistration: %w", staffauth.ErrPasskeyLimit)
	}
	return out, nil
}

// staffPasskeyCapTx applies staffauth.MaxActivePasskeys to one more passkey
// for staffID, inside the caller's transaction. It first takes a
// transaction-scoped advisory lock on the staff member, so two registrations
// racing for the last slot are serialised (an advisory lock needs no UPDATE
// grant, which sbci_staff does not hold on staff_users). When the member is at
// the cap it appends a refused credential.registered row to the action log and
// reports refused: the caller must then commit (the row is the evidence) and
// change nothing else. Existing passkeys over the cap are never touched.
func staffPasskeyCapTx(ctx context.Context, tx pgx.Tx, staffID string, now time.Time) (refused bool, err error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('sbci-staff-passkey:' || $1, 0))`, staffID); err != nil {
		return false, fmt.Errorf("lock staff passkeys: %w", err)
	}
	var active int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM staff_webauthn_credentials WHERE staff_id = $1::uuid AND revoked_at IS NULL`,
		staffID).Scan(&active); err != nil {
		return false, fmt.Errorf("count staff passkeys: %w", err)
	}
	if staffauth.CheckPasskeyCap(active) == nil {
		return false, nil
	}
	if err := insertStaffAction(ctx, tx, staffActionRow{
		at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbCredentialRegistered,
		subject: staffID, target: "passkey-limit",
		reason: fmt.Sprintf("passkey registration refused: %d active passkeys, at most %d", active, staffauth.MaxActivePasskeys),
		result: "refused",
	}); err != nil {
		return false, err
	}
	return true, nil
}

// staffCredentialIDsTx lists a staff member's unrevoked credential ids.
func staffCredentialIDsTx(ctx context.Context, tx pgx.Tx, staffID string) ([][]byte, error) {
	rows, err := tx.Query(ctx,
		`SELECT credential_id FROM staff_webauthn_credentials
		  WHERE staff_id = $1::uuid AND revoked_at IS NULL ORDER BY created_at`, staffID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	ids := [][]byte{}
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	return ids, nil
}

// BeginStaffAssertion records an assertion ceremony with challenge, bound to
// the hash of rawCeremony.
func (s *Store) BeginStaffAssertion(ctx context.Context, rawCeremony string, challenge []byte, now time.Time) error {
	if rawCeremony == "" || len(challenge) != staffauth.ChallengeBytes {
		return fmt.Errorf("cloudserver/store.BeginStaffAssertion: %w", ErrStaffCeremonyInvalid)
	}
	now = nowOr(now)
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := sweepStaffCeremoniesTx(ctx, tx, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO staff_ceremonies (ceremony_hash, kind, challenge, created_at, expires_at)
			 VALUES ($1, 'assert', $2, $3, $4)`,
			hashSecret(rawCeremony), challenge, now, now.Add(StaffCeremonyTTL))
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.BeginStaffAssertion: %w", err)
	}
	return nil
}

// staffCeremonySweepBatch bounds the expired ceremonies one begin removes.
const staffCeremonySweepBatch = 100

// sweepStaffCeremoniesTx deletes a bounded batch of ceremonies that expired
// more than an hour before now. Every begin runs it, so the table stays
// bounded by the begin rate (itself IP rate limited) with no sweeper of its
// own.
func sweepStaffCeremoniesTx(ctx context.Context, tx pgx.Tx, now time.Time) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM staff_ceremonies WHERE ceremony_hash IN (
		   SELECT ceremony_hash FROM staff_ceremonies WHERE expires_at < $1 LIMIT $2)`,
		now.Add(-time.Hour), staffCeremonySweepBatch); err != nil {
		return fmt.Errorf("sweep ceremonies: %w", err)
	}
	return nil
}

// ConsumeStaffCeremony spends the ceremony bound to rawCeremony, once: a
// second call, an expired ceremony or one of the other kind yields
// ErrStaffCeremonyInvalid. It commits on its own, so a failed verification
// afterwards still leaves the challenge spent.
func (s *Store) ConsumeStaffCeremony(ctx context.Context, rawCeremony string, kind StaffCeremonyKind, now time.Time) (StaffCeremony, error) {
	if rawCeremony == "" {
		return StaffCeremony{}, ErrStaffCeremonyInvalid
	}
	now = nowOr(now)
	var out StaffCeremony
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var staffID, enrolment *string
		err := tx.QueryRow(ctx,
			`UPDATE staff_ceremonies SET consumed_at = $3
			  WHERE ceremony_hash = $1 AND kind = $2 AND consumed_at IS NULL AND expires_at > $3
			  RETURNING challenge, staff_id::text, enrolment_hash`,
			hashSecret(rawCeremony), string(kind), now).Scan(&out.Challenge, &staffID, &enrolment)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStaffCeremonyInvalid
		}
		if err != nil {
			return fmt.Errorf("consume ceremony: %w", err)
		}
		out.Kind = kind
		if staffID != nil {
			out.StaffID = *staffID
		}
		if enrolment != nil {
			out.EnrolmentHash = *enrolment
		}
		return nil
	})
	if err != nil {
		return StaffCeremony{}, fmt.Errorf("cloudserver/store.ConsumeStaffCeremony: %w", err)
	}
	return out, nil
}

// RegisterStaffCredential stores a verified credential for a consumed
// registration ceremony and spends its enrolment code, in one transaction:
// a code already spent (or expired, or its staff member disabled since)
// yields ErrStaffEnrolmentInvalid and stores nothing. A staff member who
// already holds staffauth.MaxActivePasskeys unrevoked passkeys is refused with
// staffauth.ErrPasskeyLimit: the refusal is logged (credential.registered,
// result refused) and the code stays unspent.
func (s *Store) RegisterStaffCredential(ctx context.Context, c StaffCeremony, cred staffauth.NewCredential, label string, now time.Time) error {
	if c.Kind != StaffCeremonyRegister || c.StaffID == "" || c.EnrolmentHash == "" {
		return fmt.Errorf("cloudserver/store.RegisterStaffCredential: %w", ErrStaffCeremonyInvalid)
	}
	if len(cred.ID) == 0 || len(cred.ID) > staffauth.MaxCredentialIDBytes || len(cred.PublicKey) == 0 {
		return fmt.Errorf("cloudserver/store.RegisterStaffCredential: credential id or key missing")
	}
	now = nowOr(now)
	transports := cred.Transports
	if transports == nil {
		transports = []string{}
	}
	var aaguid []byte
	if len(cred.AAGUID) == 16 {
		aaguid = cred.AAGUID
	}
	refused := false
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// The cap is checked only for a code that is still spendable, so an
		// invalid code keeps answering ErrStaffEnrolmentInvalid (and logs
		// nothing). A refusal leaves the code unspent: once the operator
		// revokes a passkey, the same unexpired code registers the new one.
		var live bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM staff_enrolments e JOIN staff_users u ON u.staff_id = e.staff_id
			  WHERE e.code_hash = $1 AND e.staff_id = $2::uuid AND u.status = 'active'
			    AND e.used_at IS NULL AND e.expires_at > $3)`,
			c.EnrolmentHash, c.StaffID, now).Scan(&live); err != nil {
			return fmt.Errorf("read enrolment: %w", err)
		}
		if !live {
			return ErrStaffEnrolmentInvalid
		}
		var err error
		if refused, err = staffPasskeyCapTx(ctx, tx, c.StaffID, now); err != nil || refused {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE staff_enrolments e SET used_at = $3
			   FROM staff_users u
			  WHERE e.code_hash = $1 AND e.staff_id = $2::uuid AND u.staff_id = e.staff_id
			    AND u.status = 'active' AND e.used_at IS NULL AND e.expires_at > $3`,
			c.EnrolmentHash, c.StaffID, now)
		if err != nil {
			return fmt.Errorf("spend enrolment: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrStaffEnrolmentInvalid
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO staff_webauthn_credentials
			   (credential_id, staff_id, public_key, sign_count, aaguid, transports, label, created_at)
			 VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8)`,
			cred.ID, c.StaffID, cred.PublicKey, int64(cred.SignCount), aaguid, transports, label, now); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrStaffCredentialExists
			}
			return fmt.Errorf("insert credential: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(c.StaffID), verb: staffauth.VerbCredentialRegistered,
			subject: c.StaffID, target: "credential:" + hex.EncodeToString(credentialTag(cred.ID)),
			reason: "passkey registered with an operator enrolment code", result: "ok",
		})
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RegisterStaffCredential: %w", err)
	}
	if refused {
		return fmt.Errorf("cloudserver/store.RegisterStaffCredential: %w", staffauth.ErrPasskeyLimit)
	}
	return nil
}

// credentialTag is the first 8 bytes of a credential id, enough to tell a
// staff member's passkeys apart in the log.
func credentialTag(id []byte) []byte {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// StaffCredentialForAssertion returns the unrevoked credential with id and
// its active staff member, or ErrNotFound.
func (s *Store) StaffCredentialForAssertion(ctx context.Context, credentialID []byte) (staffauth.StoredCredential, StaffUser, error) {
	if len(credentialID) == 0 || len(credentialID) > staffauth.MaxCredentialIDBytes {
		return staffauth.StoredCredential{}, StaffUser{}, ErrNotFound
	}
	var cred staffauth.StoredCredential
	var u StaffUser
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var count int64
		var role string
		err := tx.QueryRow(ctx,
			`SELECT c.credential_id, c.public_key, c.sign_count,
			        u.staff_id::text, u.display_name, u.staff_role, u.status, u.created_at
			   FROM staff_webauthn_credentials c JOIN staff_users u ON u.staff_id = c.staff_id
			  WHERE c.credential_id = $1 AND c.revoked_at IS NULL AND u.status = 'active'`,
			credentialID).Scan(&cred.ID, &cred.PublicKey, &count, &u.StaffID, &u.DisplayName, &role, &u.Status, &u.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read credential: %w", err)
		}
		cred.SignCount = uint32(count) //nolint:gosec // G115: the column CHECK bounds sign_count to [0, 2^32-1]
		u.Role = staffauth.Role(role)
		cred.UserHandle = staffUserHandle(u.StaffID)
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return staffauth.StoredCredential{}, StaffUser{}, ErrNotFound
		}
		return staffauth.StoredCredential{}, StaffUser{}, fmt.Errorf("cloudserver/store.StaffCredentialForAssertion: %w", err)
	}
	return cred, u, nil
}

// staffUserHandle is the WebAuthn user handle of a staff member: the 16
// bytes of its uuid. A malformed id yields nil.
func staffUserHandle(staffID string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(staffID, "-", ""))
	if err != nil || len(b) != 16 {
		return nil
	}
	return b
}

// StaffUserHandle is the WebAuthn user handle (user.id) the API puts in a
// registration's creation options for staffID: the uuid's 16 bytes.
func StaffUserHandle(staffID string) []byte { return staffUserHandle(staffID) }

// StartStaffSessionInput starts a staff session from a verified assertion.
type StartStaffSessionInput struct {
	StaffID      string
	CredentialID []byte
	// StoredSignCount is the counter read before verification and
	// NewSignCount the asserted one; the caller has applied
	// staffauth.CheckSignCount. The update is conditional on the stored
	// value, so two concurrent uses of one assertion cannot both start a
	// session.
	StoredSignCount uint32
	NewSignCount    uint32
	// PriorRawSession is the staff cookie the browser already held, if any;
	// it is revoked, so a fresh sign-in never leaves an older session (or a
	// planted value) alive.
	PriorRawSession string
	TTL             time.Duration
	IdleTTL         time.Duration
	Now             time.Time
}

// StaffSession is a started staff session: the RAW cookie and CSRF secrets,
// returned once and stored only as hashes.
type StaffSession struct {
	StaffID    string
	Role       staffauth.Role
	RawSession string
	RawCSRF    string
	ExpiresAt  time.Time
}

// StartStaffSession advances the credential's counter, revokes any prior
// session, mints a session and logs it, in one transaction.
func (s *Store) StartStaffSession(ctx context.Context, in StartStaffSessionInput) (StaffSession, error) {
	now := nowOr(in.Now)
	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultStaffSessionTTL
	}
	if ttl > MaxStaffSessionTTL {
		ttl = MaxStaffSessionTTL
	}
	idle := in.IdleTTL
	if idle <= 0 {
		idle = DefaultStaffSessionIdleTTL
	}
	expires := now.Add(ttl)
	idleExpires := now.Add(idle)
	if idleExpires.After(expires) {
		idleExpires = expires
	}
	rawSession, err := randToken()
	if err != nil {
		return StaffSession{}, fmt.Errorf("cloudserver/store.StartStaffSession: rand session: %w", err)
	}
	rawCSRF, err := randToken()
	if err != nil {
		return StaffSession{}, fmt.Errorf("cloudserver/store.StartStaffSession: rand csrf: %w", err)
	}
	var out StaffSession
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var role string
		err := tx.QueryRow(ctx,
			`UPDATE staff_webauthn_credentials c SET sign_count = $4, last_used_at = $5
			   FROM staff_users u
			  WHERE c.credential_id = $1 AND c.staff_id = $2::uuid AND u.staff_id = c.staff_id
			    AND c.revoked_at IS NULL AND u.status = 'active' AND c.sign_count = $3
			  RETURNING u.staff_role`,
			in.CredentialID, in.StaffID, int64(in.StoredSignCount), int64(in.NewSignCount), now).Scan(&role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStaffCredentialStale
		}
		if err != nil {
			return fmt.Errorf("advance counter: %w", err)
		}
		if in.PriorRawSession != "" {
			if _, err := tx.Exec(ctx,
				`UPDATE staff_sessions SET revoked_at = $2 WHERE session_hash = $1 AND revoked_at IS NULL`,
				hashSecret(in.PriorRawSession), now); err != nil {
				return fmt.Errorf("revoke prior session: %w", err)
			}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO staff_sessions
			   (session_hash, staff_id, credential_id, csrf_hash, webauthn_at, created_at, last_seen_at, idle_expires_at, expires_at)
			 VALUES ($1, $2::uuid, $3, $4, $5, $5, $5, $6, $7)`,
			hashSecret(rawSession), in.StaffID, in.CredentialID, hashSecret(rawCSRF), now, idleExpires, expires); err != nil {
			return fmt.Errorf("insert session: %w", err)
		}
		if err := insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(in.StaffID), verb: staffauth.VerbSessionStarted,
			subject: in.StaffID, target: "credential:" + hex.EncodeToString(credentialTag(in.CredentialID)),
			reason: "WebAuthn assertion verified", result: "ok",
		}); err != nil {
			return err
		}
		out = StaffSession{StaffID: in.StaffID, Role: staffauth.Role(role), RawSession: rawSession, RawCSRF: rawCSRF, ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return StaffSession{}, fmt.Errorf("cloudserver/store.StartStaffSession: %w", err)
	}
	return out, nil
}

// StaffPrincipal is the identity behind a valid staff session.
type StaffPrincipal struct {
	StaffID     string
	DisplayName string
	Role        staffauth.Role
	// CSRFHash is the hex SHA-256 of the session's CSRF token.
	CSRFHash string
	// AssertedAt is the time of the WebAuthn assertion that minted the
	// session.
	AssertedAt time.Time
	ExpiresAt  time.Time
}

// IntrospectStaffSession resolves a raw staff cookie: the session must be
// unrevoked, inside both its absolute and idle windows, its staff member
// active and its credential unrevoked. A valid session's idle window rolls
// forward (at most once a minute, never past the absolute expiry).
func (s *Store) IntrospectStaffSession(ctx context.Context, rawSession string, now time.Time, idleTTL time.Duration) (StaffPrincipal, error) {
	if rawSession == "" {
		return StaffPrincipal{}, ErrStaffSessionInvalid
	}
	now = nowOr(now)
	if idleTTL <= 0 {
		idleTTL = DefaultStaffSessionIdleTTL
	}
	var p StaffPrincipal
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var role string
		var lastSeen time.Time
		err := tx.QueryRow(ctx,
			`SELECT s.staff_id::text, u.display_name, u.staff_role, s.csrf_hash, s.webauthn_at, s.expires_at, s.last_seen_at
			   FROM staff_sessions s
			   JOIN staff_users u ON u.staff_id = s.staff_id
			   JOIN staff_webauthn_credentials c ON c.credential_id = s.credential_id
			  WHERE s.session_hash = $1 AND s.revoked_at IS NULL
			    AND s.expires_at > $2 AND s.idle_expires_at > $2
			    AND u.status = 'active' AND c.revoked_at IS NULL`,
			hashSecret(rawSession), now).Scan(&p.StaffID, &p.DisplayName, &role, &p.CSRFHash, &p.AssertedAt, &p.ExpiresAt, &lastSeen)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrStaffSessionInvalid
		}
		if err != nil {
			return fmt.Errorf("read session: %w", err)
		}
		p.Role = staffauth.Role(role)
		if now.Sub(lastSeen) < staffSessionRollInterval {
			return nil
		}
		idleUntil := now.Add(idleTTL)
		if idleUntil.After(p.ExpiresAt) {
			idleUntil = p.ExpiresAt
		}
		if _, err := tx.Exec(ctx,
			`UPDATE staff_sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE session_hash = $1`,
			hashSecret(rawSession), now, idleUntil); err != nil {
			return fmt.Errorf("roll idle window: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrStaffSessionInvalid) {
			return StaffPrincipal{}, ErrStaffSessionInvalid
		}
		return StaffPrincipal{}, fmt.Errorf("cloudserver/store.IntrospectStaffSession: %w", err)
	}
	return p, nil
}

// EndStaffSession revokes the session behind rawSession, which must belong
// to staffID, and logs the sign-out.
func (s *Store) EndStaffSession(ctx context.Context, staffID, rawSession string, now time.Time) error {
	now = nowOr(now)
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE staff_sessions SET revoked_at = $3
			  WHERE session_hash = $1 AND staff_id = $2::uuid AND revoked_at IS NULL`,
			hashSecret(rawSession), staffID, now)
		if err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrStaffSessionInvalid
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbSessionEnded,
			subject: staffID, reason: "signed out", result: "ok",
		})
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.EndStaffSession: %w", err)
	}
	return nil
}

// RecordStaffRefusal logs that a signed-in staff member was refused action
// by the authorization table, with the refusal code as the reason.
func (s *Store) RecordStaffRefusal(ctx context.Context, staffID string, action staffauth.Action, code string, now time.Time) error {
	now = nowOr(now)
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbActionRefused,
			subject: staffID, target: string(action), reason: code, result: "refused",
		})
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RecordStaffRefusal: %w", err)
	}
	return nil
}

// StaffAction is one row of the staff action log.
type StaffAction struct {
	ActionID       string          `json:"action_id"`
	At             time.Time       `json:"at"`
	Actor          string          `json:"actor"`
	Verb           string          `json:"verb"`
	SubjectStaffID string          `json:"subject_staff_id,omitempty"`
	OrgID          string          `json:"org_id,omitempty"`
	Target         string          `json:"target,omitempty"`
	Detail         json.RawMessage `json:"detail,omitempty"`
	Reason         string          `json:"reason"`
	Result         string          `json:"result"`
}

// ListStaffActions returns the newest limit entries of the action log
// (1..500; out of range means 100).
func (s *Store) ListStaffActions(ctx context.Context, limit int) ([]StaffAction, error) {
	if limit <= 0 || limit > staffActionListMax {
		limit = 100
	}
	out := []StaffAction{}
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT action_id::text, at, actor, verb, coalesce(subject_staff_id::text, ''),
			        coalesce(org_id::text, ''), coalesce(target, ''), detail, reason, result
			   FROM staff_actions ORDER BY at DESC, action_id DESC LIMIT $1`, limit)
		if err != nil {
			return fmt.Errorf("list actions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a StaffAction
			var detail []byte
			if err := rows.Scan(&a.ActionID, &a.At, &a.Actor, &a.Verb, &a.SubjectStaffID, &a.OrgID, &a.Target, &detail, &a.Reason, &a.Result); err != nil {
				return fmt.Errorf("scan action: %w", err)
			}
			if len(detail) > 0 {
				a.Detail = detail
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListStaffActions: %w", err)
	}
	return out, nil
}

// staffActionRow is one insert into staff_actions.
type staffActionRow struct {
	at      time.Time
	actor   string
	verb    staffauth.Verb
	subject string
	org     string
	target  string
	detail  any
	reason  string
	result  string
}

// insertStaffAction appends one log row inside the caller's transaction, so
// an action and its log entry commit or roll back together.
func insertStaffAction(ctx context.Context, tx pgx.Tx, r staffActionRow) error {
	if !r.verb.Known() {
		return fmt.Errorf("insert staff action: unknown verb %q", r.verb)
	}
	var detail []byte
	if r.detail != nil {
		b, err := json.Marshal(r.detail)
		if err != nil {
			return fmt.Errorf("insert staff action: detail: %w", err)
		}
		detail = b
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO staff_actions (at, actor, verb, subject_staff_id, org_id, target, detail, reason, result)
		 VALUES ($1, $2, $3, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, NULLIF($6, ''), $7::jsonb, $8, $9)`,
		r.at, r.actor, string(r.verb), r.subject, r.org, r.target, detail, r.reason, r.result); err != nil {
		return fmt.Errorf("insert staff action: %w", err)
	}
	return nil
}

// nowOr returns now, or the wall clock when it is zero.
func nowOr(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now()
	}
	return now
}
