package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// teamallowlist.go is the store seam of the team create allow-list (managed-
// SaaS plan 07 wave 17 lane portal-guardrails; cloud 0130; completion audit
// 2026-11-16 gap 8; L-111 A5; docs/security.md TEAMGATE-1).
//
// While the platform switch SBCI_TEAM_CREATE_ALLOWLIST is on, ProvisionOrg
// (orgs.go) refuses a TEAM create unless sbci_team_create_allowed() answers
// true for the caller: the caller's account id, or the domain of its
// verified email, has an active entry. The entries are written only as
// sbci_staff (WithStaff: the staff console's process, and the operator's
// `observer-cloud staff team-allowlist` verbs), each with a staff_actions row
// in the same transaction. A removal stamps removed_*; nothing is deleted.

// ErrTeamCreateNotAllowed is ProvisionOrg's refusal of a team create by an
// account that is not on the allow-list while the switch is on.
var ErrTeamCreateNotAllowed = errors.New("cloudserver/store: team org creation is by invitation only")

// ErrTeamAllowlistExists is an add of an entry that is already active.
var ErrTeamAllowlistExists = errors.New("cloudserver/store: that allow-list entry already exists")

// teamAllowlistListMax bounds one listing.
const teamAllowlistListMax = 2000

// TeamAllowlistEntry is one team_create_allowlist row.
type TeamAllowlistEntry struct {
	EntryID       string     `json:"entry_id"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	AddedBy       string     `json:"added_by"`
	AddedReason   string     `json:"added_reason"`
	AddedAt       time.Time  `json:"added_at"`
	RemovedAt     *time.Time `json:"removed_at,omitempty"`
	RemovedBy     string     `json:"removed_by,omitempty"`
	RemovedReason string     `json:"removed_reason,omitempty"`
}

// Active reports whether the entry is in force.
func (e TeamAllowlistEntry) Active() bool { return e.RemovedAt == nil }

// enforceTeamCreateAllowlistTx refuses the caller's team create when it is
// not allow-listed. It runs inside the caller's account transaction (the
// definer reads sbci_current_account()).
func enforceTeamCreateAllowlistTx(ctx context.Context, tx pgx.Tx) error {
	ok, err := teamCreateAllowedTx(ctx, tx)
	if err != nil {
		return err
	}
	if !ok {
		return ErrTeamCreateNotAllowed
	}
	return nil
}

func teamCreateAllowedTx(ctx context.Context, tx pgx.Tx) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT sbci_team_create_allowed()`).Scan(&ok); err != nil {
		return false, fmt.Errorf("read team create allow-list: %w", err)
	}
	return ok, nil
}

// TeamCreateAllowed reports whether accountID is on the team create
// allow-list (by account id or verified email domain), as the console shows
// it before a create. It does not read the switch: the caller does.
func (s *Store) TeamCreateAllowed(ctx context.Context, accountID string) (bool, error) {
	var ok bool
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		v, err := teamCreateAllowedTx(ctx, tx)
		ok = v
		return err
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.TeamCreateAllowed: %w", err)
	}
	return ok, nil
}

// ListTeamAllowlist returns the allow-list, active entries first, then the
// removed ones (when includeRemoved), newest first within each. Staff role.
func (s *Store) ListTeamAllowlist(ctx context.Context, includeRemoved bool) ([]TeamAllowlistEntry, error) {
	out := []TeamAllowlistEntry{}
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT entry_id::text, kind, value, added_by, added_reason, added_at,
			        removed_at, coalesce(removed_by, ''), coalesce(removed_reason, '')
			   FROM team_create_allowlist
			  WHERE $1 OR removed_at IS NULL
			  ORDER BY (removed_at IS NULL) DESC, coalesce(removed_at, added_at) DESC, entry_id
			  LIMIT $2`, includeRemoved, teamAllowlistListMax)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e TeamAllowlistEntry
			if err := rows.Scan(&e.EntryID, &e.Kind, &e.Value, &e.AddedBy, &e.AddedReason, &e.AddedAt,
				&e.RemovedAt, &e.RemovedBy, &e.RemovedReason); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListTeamAllowlist: %w", err)
	}
	return out, nil
}

// TeamAllowlistChange is who changes the allow-list and why.
type TeamAllowlistChange struct {
	// StaffID is the staff member; empty for the operator's CLI.
	StaffID string
	Reason  string
	Now     time.Time
}

func (c TeamAllowlistChange) actor() string {
	if c.StaffID == "" {
		return staffauth.ActorOperator
	}
	return staffauth.Actor(c.StaffID)
}

func allowlistTarget(kind, value string) string { return kind + ":" + value }

// AddTeamAllowlistEntry adds an active entry, with a team_allowlist.added
// staff_actions row in the same transaction. ErrTeamAllowlistExists when the
// same entry is already active.
func (s *Store) AddTeamAllowlistEntry(ctx context.Context, e staffauth.AllowlistEntry, c TeamAllowlistChange) (TeamAllowlistEntry, error) {
	e, err := staffauth.ValidateAllowlistEntry(string(e.Kind), e.Value)
	if err != nil {
		return TeamAllowlistEntry{}, fmt.Errorf("cloudserver/store.AddTeamAllowlistEntry: %w", err)
	}
	reason, err := staffauth.ValidateReason(c.Reason)
	if err != nil {
		return TeamAllowlistEntry{}, fmt.Errorf("cloudserver/store.AddTeamAllowlistEntry: %w", err)
	}
	now := nowOr(c.Now).UTC()
	var out TeamAllowlistEntry
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO team_create_allowlist (kind, value, added_by, added_reason, added_at)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING entry_id::text, kind, value, added_by, added_reason, added_at`,
			string(e.Kind), e.Value, c.actor(), reason, now).
			Scan(&out.EntryID, &out.Kind, &out.Value, &out.AddedBy, &out.AddedReason, &out.AddedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrTeamAllowlistExists
			}
			return fmt.Errorf("insert entry: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: c.actor(), verb: staffauth.VerbTeamAllowlistAdded, subject: c.StaffID,
			target: allowlistTarget(out.Kind, out.Value), detail: map[string]string{"entry_id": out.EntryID},
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		return TeamAllowlistEntry{}, fmt.Errorf("cloudserver/store.AddTeamAllowlistEntry: %w", err)
	}
	return out, nil
}

// RemoveTeamAllowlistEntry stamps an active entry removed, with a
// team_allowlist.removed staff_actions row in the same transaction.
// ErrNotFound when no active entry has that id. An account already holding a
// team org keeps it; only a further create is refused.
func (s *Store) RemoveTeamAllowlistEntry(ctx context.Context, entryID string, c TeamAllowlistChange) (TeamAllowlistEntry, error) {
	reason, err := staffauth.ValidateReason(c.Reason)
	if err != nil {
		return TeamAllowlistEntry{}, fmt.Errorf("cloudserver/store.RemoveTeamAllowlistEntry: %w", err)
	}
	now := nowOr(c.Now).UTC()
	var out TeamAllowlistEntry
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`UPDATE team_create_allowlist
			    SET removed_at = $2, removed_by = $3, removed_reason = $4
			  WHERE entry_id = $1::uuid AND removed_at IS NULL
			  RETURNING entry_id::text, kind, value, added_by, added_reason, added_at, removed_at, removed_by, removed_reason`,
			entryID, now, c.actor(), reason).
			Scan(&out.EntryID, &out.Kind, &out.Value, &out.AddedBy, &out.AddedReason, &out.AddedAt,
				&out.RemovedAt, &out.RemovedBy, &out.RemovedReason)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("remove entry: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: c.actor(), verb: staffauth.VerbTeamAllowlistRemoved, subject: c.StaffID,
			target: allowlistTarget(out.Kind, out.Value), detail: map[string]string{"entry_id": out.EntryID},
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		return TeamAllowlistEntry{}, fmt.Errorf("cloudserver/store.RemoveTeamAllowlistEntry: %w", err)
	}
	return out, nil
}
