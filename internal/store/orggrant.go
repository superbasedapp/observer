package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Admin-controlled Plane B, the enrolment-grant store seam
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.4; migration
// 082). ONE OWNER: org_enrolment_grant is written exclusively from this
// file, and it is NODE-LOCAL control-plane state pinned out of the org-push
// wire by tests/invariant/privacy_test.go's forbiddenCacheTables.
//
// The grant is the consent boundary the whole feature rests on, so the
// operations here are deliberately few and blunt: write one (replacing any
// prior grant for the same identity), read one, delete one, delete all.
//
// AMENDED in Phase 1b (mini-spec §4.4, review m5). Phase 1a's comment read
// "there is no partial update — widening authority requires a NEW enrolment".
// The second half still holds absolutely and is the invariant that matters.
// The first half no longer does: RenewEnrolmentGrant is the ONE permitted
// partial update, and it is permitted because of what it cannot do. It moves
// ONE clock FORWARD, inside the window the organization already signed for,
// under a guarded monotonic UPDATE. It cannot widen authority, cannot change
// the identity, cannot alter the signature, and cannot extend the grant
// beyond signed_expires_at. Widening authority still requires a whole new
// row, written by a new node-side act.

// EnrolmentGrant is one stored grant. Times are stored RFC3339 and returned
// parsed; an unparseable stored time yields the zero time rather than an
// error, so a hand-edited row can never wedge the daemon (a zero ExpiresAt
// means "no TTL", which internal/govern.Resolve treats as non-expiring).
type EnrolmentGrant struct {
	OrgKey       string
	Generation   int64
	OrgID        string
	OrgName      string
	OrgServerURL string
	KeyPinSHA256 string
	Authority    []string
	ConsentMode  string
	ConsentActor string
	GrantedAt    time.Time
	// ExpiresAt is the WORKING clock. It starts equal to SignedExpiresAt and
	// is moved forward by RenewEnrolmentGrant while the organization keeps
	// authorizing this node.
	ExpiresAt time.Time
	// SignedExpiresAt is the expiry the organization actually SIGNED. It is
	// never modified after the grant is written, so the stored signature
	// keeps verifying against its own row (the evidence property, amendment
	// A1) and the derived renewal TTL can never exceed the signed window.
	SignedExpiresAt time.Time
	// LastRenewedAt is when ExpiresAt was last moved forward, for
	// `observer org grant show`. Zero on a grant that has never renewed.
	LastRenewedAt time.Time
	Signature     string
	ReceiptHash   string
	// ReplacementGeneration orders grant REPLACEMENTS (migration 094, Plane B
	// dual-mode design §5.3 item 5) against each other. It is a wholly
	// separate counter from Generation above (the P0-5 enrolment-IDENTITY
	// fence): Generation names which enrolment epoch this grant belongs to;
	// ReplacementGeneration names how many out-of-band replacements have been
	// accepted for that epoch. 0 means "never replaced" (the grant on file is
	// either the original enrolment grant or has never been superseded).
	// ReplaceEnrolmentGrant is the only writer that advances it.
	ReplacementGeneration int64
}

// WriteEnrolmentGrant stores (or replaces) the grant for one enrolment
// identity. Callers MUST have verified the grant's signature against the
// org policy key ALREADY pinned for this server before calling — see
// cmd/observer/org.go: an unverifiable grant is refused loudly, never stored
// unverified.
func (s *Store) WriteEnrolmentGrant(ctx context.Context, g EnrolmentGrant) error {
	if g.OrgKey == "" {
		return errors.New("store.WriteEnrolmentGrant: org_key is required")
	}
	authority := g.Authority
	if authority == nil {
		authority = []string{}
	}
	raw, err := json.Marshal(authority)
	if err != nil {
		return fmt.Errorf("store.WriteEnrolmentGrant: %w", err)
	}
	// A fresh grant's signed window IS its expiry — this is the one moment
	// the two are, by definition, the same value. Callers may set
	// SignedExpiresAt explicitly (re-writing a row read back from the DB);
	// leaving it zero is the normal enrolment path.
	signedExpiry := g.SignedExpiresAt
	if signedExpiry.IsZero() {
		signedExpiry = g.ExpiresAt
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO org_enrolment_grant
		  (org_key, generation, org_id, org_name, org_server_url, key_pin_sha256,
		   authority_json, consent_mode, consent_actor, granted_at, expires_at,
		   signed_expires_at, last_renewed_at, signature, receipt_hash,
		   replacement_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(org_key) DO UPDATE SET
		   generation     = excluded.generation,
		   org_id         = excluded.org_id,
		   org_name       = excluded.org_name,
		   org_server_url = excluded.org_server_url,
		   key_pin_sha256 = excluded.key_pin_sha256,
		   authority_json = excluded.authority_json,
		   consent_mode   = excluded.consent_mode,
		   consent_actor  = excluded.consent_actor,
		   granted_at     = excluded.granted_at,
		   expires_at     = excluded.expires_at,
		   -- RESET the signed window on re-enrolment (review M1): without
		   -- these two, DO UPDATE would keep the PREVIOUS grant's
		   -- signed_expires_at and the new grant's renewal TTL would be
		   -- derived from the old authorization's window.
		   signed_expires_at = excluded.signed_expires_at,
		   last_renewed_at   = excluded.last_renewed_at,
		   signature      = excluded.signature,
		   receipt_hash   = excluded.receipt_hash,
		   -- A whole new enrolment (this path, not ReplaceEnrolmentGrant)
		   -- resets the replacement counter too: it is a fresh epoch's
		   -- grant, with no replacements yet accepted against it.
		   replacement_generation = excluded.replacement_generation`,
		g.OrgKey, g.Generation, g.OrgID, g.OrgName, g.OrgServerURL, g.KeyPinSHA256,
		string(raw), g.ConsentMode, g.ConsentActor,
		formatGrantTime(g.GrantedAt), formatGrantTime(g.ExpiresAt),
		formatGrantTime(signedExpiry), formatGrantTime(g.LastRenewedAt),
		g.Signature, g.ReceiptHash, g.ReplacementGeneration)
	if err != nil {
		return fmt.Errorf("store.WriteEnrolmentGrant: %w", err)
	}
	return nil
}

// LoadEnrolmentGrant returns the grant for orgKey, or ok=false when this
// machine holds none (the solo / enrolled-but-ungoverned case).
func (s *Store) LoadEnrolmentGrant(ctx context.Context, orgKey string) (EnrolmentGrant, bool, error) {
	return loadEnrolmentGrant(ctx, s.db, orgKey)
}

func loadEnrolmentGrant(ctx context.Context, q querier, orgKey string) (EnrolmentGrant, bool, error) {
	var (
		g                            EnrolmentGrant
		authority                    string
		grantedAt, expiry            string
		signedExpiry, lastRenewedRaw string
	)
	g.OrgKey = orgKey
	err := q.QueryRowContext(ctx, `
		SELECT generation, org_id, org_name, org_server_url, key_pin_sha256,
		       authority_json, consent_mode, consent_actor, granted_at, expires_at,
		       signed_expires_at, last_renewed_at, signature, receipt_hash,
		       replacement_generation
		  FROM org_enrolment_grant WHERE org_key = ?`, orgKey).
		Scan(&g.Generation, &g.OrgID, &g.OrgName, &g.OrgServerURL, &g.KeyPinSHA256,
			&authority, &g.ConsentMode, &g.ConsentActor, &grantedAt, &expiry,
			&signedExpiry, &lastRenewedRaw, &g.Signature, &g.ReceiptHash,
			&g.ReplacementGeneration)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrolmentGrant{}, false, nil
	}
	if err != nil {
		return EnrolmentGrant{}, false, fmt.Errorf("store.LoadEnrolmentGrant: %w", err)
	}
	if authority != "" {
		// A corrupt authority list decodes to nothing rather than erroring:
		// the fail-safe direction for an authority record is LESS authority.
		_ = json.Unmarshal([]byte(authority), &g.Authority)
	}
	g.GrantedAt = parseGrantTime(grantedAt)
	g.ExpiresAt = parseGrantTime(expiry)
	g.SignedExpiresAt = parseGrantTime(signedExpiry)
	g.LastRenewedAt = parseGrantTime(lastRenewedRaw)
	return g, true, nil
}

// RenewEnrolmentGrant moves ONE grant's working expiry forward.
//
// It is the ONLY partial update permitted on this row, and the reason is
// what it cannot do: it moves one clock forward inside a window the
// organization already signed for (the caller derives newExpiry from
// signed_expires_at - granted_at), under a guard that is
//
//   - IDENTITY-SCOPED: org_key AND generation must both match, so a renewal
//     signal that arrives after a re-enrol cannot touch the new grant; and
//   - MONOTONIC: expires_at < ? means a clock skew or a replayed signal can
//     never SHORTEN a grant either.
//
// It cannot widen authority, change the identity, or alter the signature.
// Widening authority still requires a whole new enrolment.
//
// A no-op (nothing matched, or the new expiry was not later) is not an
// error: the caller renews opportunistically on a tick.
func (s *Store) RenewEnrolmentGrant(ctx context.Context, orgKey string, generation int64, newExpiry time.Time) error {
	if orgKey == "" {
		return errors.New("store.RenewEnrolmentGrant: org_key is required")
	}
	if newExpiry.IsZero() {
		return errors.New("store.RenewEnrolmentGrant: a zero expiry would make the grant non-expiring")
	}
	stamp := formatGrantTime(newExpiry)
	_, err := s.db.ExecContext(ctx, `
		UPDATE org_enrolment_grant
		   SET expires_at = ?, last_renewed_at = ?
		 WHERE org_key = ? AND generation = ? AND expires_at < ?`,
		stamp, formatGrantTime(time.Now().UTC()), orgKey, generation, stamp)
	if err != nil {
		return fmt.Errorf("store.RenewEnrolmentGrant: %w", err)
	}
	return nil
}

// ReplaceEnrolmentGrant atomically supersedes the stored grant for
// g.OrgKey with g, the store half of grant replacement (Plane B dual-mode
// design §5.3 item 5, Sol S4). It is applied ONLY when g.ReplacementGeneration
// is STRICTLY GREATER than the replacement_generation currently on file (0
// when no grant is stored yet at all, so the very first replacement always
// applies). Callers — internal/orgclient's accept path — MUST have already
// verified the replacement's signature and its key pin against the pin
// recorded at enrolment before calling; this method enforces ordering only,
// exactly as WriteEnrolmentGrant enforces nothing beyond org_key being set.
//
// applied=false, err=nil means the replacement was REJECTED for being
// non-monotonic (stale, replayed, or arriving out of order) — this is NOT an
// error. The caller keeps the existing grant in force and is expected to log
// the rejection with a named reason, mirroring the codebase's established
// evaluateGrantOffer idiom (internal/orgclient/client.go) for "offered but
// refused" outcomes.
//
// The identity-generation column (`generation`) is DELIBERATELY left
// untouched on every accepted replacement: a replacement supersedes
// authority within the SAME enrolment epoch, it does not start a new one.
// See migration 094's header comment for the full reasoning.
//
// The read-compare-write runs inside one transaction so two racing accept
// calls for the same org_key cannot both pass the monotonic check against a
// value the other has already superseded.
func (s *Store) ReplaceEnrolmentGrant(ctx context.Context, g EnrolmentGrant) (applied bool, err error) {
	if g.OrgKey == "" {
		return false, errors.New("store.ReplaceEnrolmentGrant: org_key is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store.ReplaceEnrolmentGrant: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var current int64
	scanErr := tx.QueryRowContext(ctx,
		`SELECT replacement_generation FROM org_enrolment_grant WHERE org_key = ?`, g.OrgKey).Scan(&current)
	switch {
	case errors.Is(scanErr, sql.ErrNoRows):
		current = 0
	case scanErr != nil:
		return false, fmt.Errorf("store.ReplaceEnrolmentGrant: read current replacement generation: %w", scanErr)
	}
	if g.ReplacementGeneration <= current {
		return false, nil
	}

	authority := g.Authority
	if authority == nil {
		authority = []string{}
	}
	raw, err := json.Marshal(authority)
	if err != nil {
		return false, fmt.Errorf("store.ReplaceEnrolmentGrant: %w", err)
	}
	signedExpiry := g.SignedExpiresAt
	if signedExpiry.IsZero() {
		signedExpiry = g.ExpiresAt
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO org_enrolment_grant
		  (org_key, generation, org_id, org_name, org_server_url, key_pin_sha256,
		   authority_json, consent_mode, consent_actor, granted_at, expires_at,
		   signed_expires_at, last_renewed_at, signature, receipt_hash,
		   replacement_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(org_key) DO UPDATE SET
		   -- generation (the P0-5 enrolment-identity fence) is intentionally
		   -- absent from this SET list: a replacement supersedes authority
		   -- within the CURRENT epoch, it must never touch which epoch a
		   -- grant belongs to.
		   org_id         = excluded.org_id,
		   org_name       = excluded.org_name,
		   org_server_url = excluded.org_server_url,
		   key_pin_sha256 = excluded.key_pin_sha256,
		   authority_json = excluded.authority_json,
		   consent_mode   = excluded.consent_mode,
		   consent_actor  = excluded.consent_actor,
		   granted_at     = excluded.granted_at,
		   expires_at     = excluded.expires_at,
		   signed_expires_at      = excluded.signed_expires_at,
		   last_renewed_at        = excluded.last_renewed_at,
		   signature              = excluded.signature,
		   receipt_hash           = excluded.receipt_hash,
		   replacement_generation = excluded.replacement_generation`,
		g.OrgKey, g.Generation, g.OrgID, g.OrgName, g.OrgServerURL, g.KeyPinSHA256,
		string(raw), g.ConsentMode, g.ConsentActor,
		formatGrantTime(g.GrantedAt), formatGrantTime(g.ExpiresAt),
		formatGrantTime(signedExpiry), formatGrantTime(g.LastRenewedAt),
		g.Signature, g.ReceiptHash, g.ReplacementGeneration)
	if err != nil {
		return false, fmt.Errorf("store.ReplaceEnrolmentGrant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store.ReplaceEnrolmentGrant: commit: %w", err)
	}
	return true, nil
}

// DeleteEnrolmentGrant removes the grant for one identity. Absent is not an
// error (idempotent) — `observer unenroll` must be safe to run twice.
func (s *Store) DeleteEnrolmentGrant(ctx context.Context, orgKey string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_enrolment_grant WHERE org_key = ?`, orgKey); err != nil {
		return fmt.Errorf("store.DeleteEnrolmentGrant: %w", err)
	}
	return nil
}

// DeleteAllEnrolmentGrants removes every grant. Used by the unenrol path
// when the enrolment row is already gone (so no org_key can be derived):
// leaving an orphan grant behind would be the one failure mode that matters,
// since a grant is authority.
func (s *Store) DeleteAllEnrolmentGrants(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_enrolment_grant`); err != nil {
		return fmt.Errorf("store.DeleteAllEnrolmentGrants: %w", err)
	}
	return nil
}

func formatGrantTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseGrantTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
