package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// portalconsent.go owns the PORTAL-plane consent state (migration 0014, F9):
// what the signed-in developer chose on the browser consent screen, plus the
// append-only trail of how it changed.
//
// SCOPE — read this before wiring anything else to these tables. These rows are
// browser-surface PREFERENCES. They are NOT the authority for what a node may
// upload: node egress consent is NODE-authoritative (the node holds the grant,
// declares its generation on every upload, and the server validates against the
// structural_grants REGISTRATION, which follows that generation monotonically —
// see RegisterStructuralGrant). Nothing on the upload path reads these tables,
// and nothing here mints or moves accounts.consent_generation. Two different
// consent shapes, one owner each (CLAUDE.md #4).

// PortalConsentChoice is one purpose's stored answer.
type PortalConsentChoice struct {
	Purpose   string    `json:"purpose"`
	Granted   bool      `json:"granted"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PortalConsentEvent is one recorded CHANGE to a choice. Action is "granted" or
// "revoked".
type PortalConsentEvent struct {
	Purpose string    `json:"purpose"`
	Action  string    `json:"action"`
	At      time.Time `json:"at"`
}

// Portal consent event actions (migration 0014's CHECK vocabulary).
const (
	// PortalConsentGranted records a purpose moving to granted.
	PortalConsentGranted = "granted"
	// PortalConsentRevoked records a purpose moving to not-granted.
	PortalConsentRevoked = "revoked"
)

// PortalConsentChoices returns the account's stored choices, purpose-ascending.
// An EMPTY slice means the consent screen has never been completed — the caller
// must render that as "setup has not run", never as "everything declined".
func (s *Store) PortalConsentChoices(ctx context.Context, accountID string) ([]PortalConsentChoice, error) {
	out := []PortalConsentChoice{}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT purpose, granted, updated_at FROM portal_consent_choices
			  WHERE account_id = $1::uuid ORDER BY purpose`, accountID)
		if e != nil {
			return fmt.Errorf("list portal consent choices: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var c PortalConsentChoice
			if e := rows.Scan(&c.Purpose, &c.Granted, &c.UpdatedAt); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.PortalConsentChoices: %w", err)
	}
	return out, nil
}

// SetPortalConsentChoices writes the whole choice set in one transaction and
// appends an event for every purpose whose answer actually CHANGED (including
// its first recorded value). Re-submitting an unchanged set appends nothing, so
// the trail reads as a history of decisions rather than of page loads.
//
// The caller supplies the complete, already-validated set: which purposes exist,
// and which of them are mandatory, is the API layer's vocabulary (it serves the
// screen), not this seam's. Every purpose in the map is written.
func (s *Store) SetPortalConsentChoices(ctx context.Context, accountID string, choices map[string]bool, now time.Time) ([]PortalConsentChoice, error) {
	if now.IsZero() {
		now = time.Now()
	}
	// Deterministic write order: two concurrent submissions for one account then
	// touch the rows in the same sequence and cannot deadlock on each other.
	purposes := make([]string, 0, len(choices))
	for p := range choices {
		purposes = append(purposes, p)
	}
	sort.Strings(purposes)

	var out []PortalConsentChoice
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		out = out[:0]
		// One writer per account at a time. Two submissions racing (two tabs,
		// or a double-click) would otherwise both read the same "before" value
		// and both append the same event to a trail that cannot be corrected.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
			"sbci-portal-consent\x1f"+accountID); e != nil {
			return fmt.Errorf("lock portal consent: %w", e)
		}
		for _, purpose := range purposes {
			granted := choices[purpose]
			// The PREVIOUS value has to be read before the write: RETURNING on
			// an ON CONFLICT DO UPDATE yields the NEW row, so there is no
			// in-statement way to see what the row held. `previous == nil` is a
			// first write, which counts as a change (it is the initial recorded
			// decision).
			var previous *bool
			e := tx.QueryRow(ctx,
				`SELECT granted FROM portal_consent_choices
				  WHERE account_id = $1::uuid AND purpose = $2`,
				accountID, purpose).Scan(&previous)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return fmt.Errorf("read portal consent choice: %w", e)
			}

			var updated time.Time
			if e := tx.QueryRow(ctx,
				`INSERT INTO portal_consent_choices (account_id, purpose, granted, updated_at)
				 VALUES ($1::uuid, $2, $3, $4)
				 ON CONFLICT (account_id, purpose) DO UPDATE SET
				   granted    = EXCLUDED.granted,
				   updated_at = EXCLUDED.updated_at
				 RETURNING updated_at`,
				accountID, purpose, granted, now).Scan(&updated); e != nil {
				return fmt.Errorf("upsert portal consent choice: %w", e)
			}
			out = append(out, PortalConsentChoice{Purpose: purpose, Granted: granted, UpdatedAt: updated})
			if previous != nil && *previous == granted {
				continue // unchanged — nothing to record
			}
			action := PortalConsentRevoked
			if granted {
				action = PortalConsentGranted
			}
			if _, e := tx.Exec(ctx,
				`INSERT INTO portal_consent_events (account_id, purpose, action, at)
				 VALUES ($1::uuid, $2, $3, $4)`,
				accountID, purpose, action, now); e != nil {
				return fmt.Errorf("record portal consent event: %w", e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.SetPortalConsentChoices: %w", err)
	}
	return out, nil
}

// PortalConsentHistory returns the account's change trail, newest first, capped
// at limit (<=0 ⇒ 100). It exists so the trail is readable through the same
// tenant seam that wrote it rather than only by direct SQL.
func (s *Store) PortalConsentHistory(ctx context.Context, accountID string, limit int) ([]PortalConsentEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	out := []PortalConsentEvent{}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT purpose, action, at FROM portal_consent_events
			  WHERE account_id = $1::uuid ORDER BY at DESC, purpose LIMIT $2`,
			accountID, limit)
		if e != nil {
			return fmt.Errorf("list portal consent events: %w", e)
		}
		defer rows.Close()
		for rows.Next() {
			var ev PortalConsentEvent
			if e := rows.Scan(&ev.Purpose, &ev.Action, &ev.At); e != nil {
				return e
			}
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.PortalConsentHistory: %w", err)
	}
	return out, nil
}
