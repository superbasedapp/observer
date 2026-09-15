package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// dataauthority.go wires the pure internal/dataauthority classifier into the
// session-capture path (CI-P1 Lane B — plan of record
// docs/plans/cloud-intelligence-azure-foundry-plan-of-record-2026-08-30.md
// §3 items 1-2 / §4 / §6). It owns:
//
//   - resolveEnrolment / resolveAuthorityStampFrom: a DYNAMIC, FAIL-CLOSED
//     authority resolver that reads the node's LIVE enrolment state on every
//     call (never snapshotted at Store construction) and turns it into the
//     at-capture stamp UpsertSession writes.
//   - SessionAuthority / EligibleForPersonalCloud: the read API later phases
//     (the personal-cloud enrichment gate) consume.
//
// The sticky/upgrade merge itself (dataauthority.Combine's rule) is applied
// ATOMICALLY inside UpsertSession's single INSERT ... ON CONFLICT statement —
// see the CASE expressions there. A read-modify-write in Go could not be made
// atomic against two concurrent ingests of the same session without an
// explicit write transaction; the existing org_id/user_email COALESCE logic
// already lives in that same statement for the same reason. A table-driven
// test pins the SQL outcome against dataauthority.Combine so the SQL and the
// pure contract can never drift.

// queryRower is the read surface resolveEnrolment needs. Both *sql.DB and
// *sql.Tx satisfy it, so the enrolment read can run standalone (the read API)
// OR inside the session-write transaction (FD2): the capture-time authority
// decision must be atomic with the session UPSERT, and the DSN's
// _txlock=immediate makes a BeginTx hold the write lock from BEGIN, so reading
// enrolment through the tx cannot interleave with a concurrent WriteEnrolment.
type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// resolveEnrolment reads the node's LIVE org-enrolment state directly from the
// org_enrolment singleton (migration 028) on EACH call — deliberately NOT
// snapshotted at Store construction.
//
// This is the cautionary-precedent divergence the plan of record calls out:
// internal/identity.Stamper snapshots org_enrolment ONCE in NewStamper and
// treats every read error as "solo-local / unenrolled" (fail OPEN). This
// resolver must NOT copy either behaviour — (a) a mid-session enrolment change
// must be visible on the very next capture (live read), and (b) any read
// error is UNKNOWN, never personal (fail CLOSED).
//
// Returns (state, determinable). determinable=false means the live enrolment
// state could not be established; the caller stamps UNKNOWN (NULL). Only a
// clean "table present, no enrolment row" read yields a DEFINITIVELY
// unenrolled state — the sole path that produces a personal stamp.
func (s *Store) resolveEnrolment(ctx context.Context) (dataauthority.EnrolmentState, bool) {
	if s == nil || s.db == nil {
		return dataauthority.EnrolmentState{}, false
	}
	return resolveEnrolmentFrom(ctx, s.db)
}

// resolveEnrolmentFrom is the shared body: it reads through any queryRower so
// the same fail-closed logic runs standalone or inside the session-write tx.
func resolveEnrolmentFrom(ctx context.Context, q queryRower) (dataauthority.EnrolmentState, bool) {
	if q == nil {
		return dataauthority.EnrolmentState{}, false
	}
	var orgID string
	err := q.QueryRowContext(ctx,
		`SELECT org_id FROM org_enrolment WHERE id = 1`).Scan(&orgID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// The singleton table exists (migration 028 is far below 096) but
		// holds no row: DEFINITIVELY unenrolled.
		return dataauthority.EnrolmentState{Enrolled: false}, true
	case err != nil:
		// Any other read error — I/O, corruption, or a missing table on a
		// wedged/pre-028 schema — is NOT determinable. Fail closed: UNKNOWN,
		// never personal.
		return dataauthority.EnrolmentState{}, false
	default:
		return dataauthority.EnrolmentState{Enrolled: orgID != ""}, true
	}
}

// resolveAuthorityStampFrom computes the at-capture authority stamp for a
// session being written right now, from the LIVE enrolment state read through
// q. UpsertSession passes its own transaction so the read and the session
// write are atomic (FD2). The two returned values bind directly into
// UpsertSession's INSERT (authority, authority_classifier_version):
//
//	enrolled              -> ("org",      dataauthority.Version)
//	definitively unenrol. -> ("personal", dataauthority.Version)
//	not determinable      -> (nil,        nil)   == UNKNOWN (NULL columns)
//
// On a first capture the INSERT persists this verbatim; on a conflict it is
// the `excluded.authority` the ON CONFLICT CASE reads to apply the sticky /
// upgrade rule. Both returns are `any` so a not-determinable resolve binds
// SQL NULL.
func (s *Store) resolveAuthorityStampFrom(ctx context.Context, q queryRower) (authority any, version any) {
	state, determinable := resolveEnrolmentFrom(ctx, q)
	if !determinable {
		return nil, nil
	}
	c := dataauthority.ClassifyAtCapture(state)
	return string(c.Authority), c.Version
}

// SessionAuthority returns the stored data-authority Classification for
// sessionID. found=false means the session is UNKNOWN for enrichment
// purposes: either the row does not exist, or its authority column is NULL —
// a pre-096 legacy row (never backfilled, by design) or a first capture whose
// live enrolment state could not be determined. A found=false session is
// never eligible for personal cloud enrichment.
func (s *Store) SessionAuthority(ctx context.Context, sessionID string) (dataauthority.Classification, bool, error) {
	var auth sql.NullString
	var ver sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT authority, authority_classifier_version FROM sessions WHERE id = ?`,
		sessionID).Scan(&auth, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return dataauthority.Classification{}, false, nil
	}
	if err != nil {
		return dataauthority.Classification{}, false, fmt.Errorf("store.SessionAuthority: %w", err)
	}
	if !auth.Valid || auth.String == "" {
		// NULL/empty authority == UNKNOWN (ineligible).
		return dataauthority.Classification{}, false, nil
	}
	return dataauthority.Classification{
		Authority: dataauthority.Authority(auth.String),
		Version:   int(ver.Int64),
	}, true, nil
}

// EligibleForPersonalCloud reports whether sessionID's data may be considered
// for personal-cloud-plane enrichment. True ONLY for the personal/eligible
// classification; org, unknown (NULL authority), and missing sessions all
// report false. The eligibility decision itself is delegated to
// dataauthority.Classification.EligibleForPersonalEnrichment so the pure
// contract stays the single source of truth (this method never re-derives it).
func (s *Store) EligibleForPersonalCloud(ctx context.Context, sessionID string) (bool, error) {
	c, found, err := s.SessionAuthority(ctx, sessionID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	return c.EligibleForPersonalEnrichment(), nil
}
