package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// staffavailability.go is the one writer of availability_inputs (cloud
// migration 0069; design m6.0 4.5 and 4.9): the staff-authored inputs the
// availability envelope (sbo-availability-v1, M6.3) is composed from. Every
// write is logged in staff_actions in the same transaction, with the reason,
// the new value and the value it replaced.

// AvailabilityInputRow is one stored input.
type AvailabilityInputRow struct {
	Section   string          `json:"section"`
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	Reason    string          `json:"reason"`
	Author    string          `json:"author"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ListAvailabilityInputs returns every input, by section and key.
func (s *Store) ListAvailabilityInputs(ctx context.Context) ([]AvailabilityInputRow, error) {
	out := []AvailabilityInputRow{}
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT section, key, value, reason, author, updated_at
			   FROM availability_inputs ORDER BY section, key`)
		if err != nil {
			return fmt.Errorf("list inputs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r AvailabilityInputRow
			var value []byte
			if err := rows.Scan(&r.Section, &r.Key, &value, &r.Reason, &r.Author, &r.UpdatedAt); err != nil {
				return fmt.Errorf("scan input: %w", err)
			}
			r.Value = value
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListAvailabilityInputs: %w", err)
	}
	return out, nil
}

// SetAvailabilityInput writes (inserts or replaces) one input as staff
// member staffID and logs it. in comes from staffauth.ValidateAvailabilityInput
// and reason from staffauth.ValidateReason.
func (s *Store) SetAvailabilityInput(ctx context.Context, staffID string, in staffauth.AvailabilityInput, reason string, now time.Time) error {
	reason, err := staffauth.ValidateReason(reason)
	if err != nil {
		return fmt.Errorf("cloudserver/store.SetAvailabilityInput: %w", err)
	}
	if _, err := staffauth.ParseSection(string(in.Section)); err != nil {
		return fmt.Errorf("cloudserver/store.SetAvailabilityInput: %w", err)
	}
	// The envelope's own rules, before anything is stored (STAFF-8): an
	// input the composer could not carry is refused here, never at issue
	// time. The error wraps availcompose.ErrInvalidInput.
	if err := availcompose.ValidateInput(string(in.Section), in.Key, in.Value); err != nil {
		return fmt.Errorf("cloudserver/store.SetAvailabilityInput: %w", err)
	}
	now = nowOr(now)
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		previous, err := availabilityValueTx(ctx, tx, in.Section, in.Key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO availability_inputs (section, key, value, reason, author, updated_at)
			 VALUES ($1, $2, $3::jsonb, $4, $5, $6)
			 ON CONFLICT (section, key) DO UPDATE
			   SET value = EXCLUDED.value, reason = EXCLUDED.reason,
			       author = EXCLUDED.author, updated_at = EXCLUDED.updated_at`,
			string(in.Section), in.Key, in.Value, reason, staffauth.Actor(staffID), now); err != nil {
			return fmt.Errorf("write input: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbAvailabilitySet,
			subject: staffID, org: availabilityOrg(in.Section, in.Key), target: availabilityTarget(in.Section, in.Key),
			detail: map[string]any{"value": json.RawMessage(in.Value), "previous": previous},
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.SetAvailabilityInput: %w", err)
	}
	return nil
}

// DeleteAvailabilityInput removes one input as staff member staffID and logs
// it; ErrNotFound when there is none.
func (s *Store) DeleteAvailabilityInput(ctx context.Context, staffID string, section staffauth.Section, key, reason string, now time.Time) error {
	reason, err := staffauth.ValidateReason(reason)
	if err != nil {
		return fmt.Errorf("cloudserver/store.DeleteAvailabilityInput: %w", err)
	}
	now = nowOr(now)
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		previous, err := availabilityValueTx(ctx, tx, section, key)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM availability_inputs WHERE section = $1 AND key = $2`, string(section), key); err != nil {
			return fmt.Errorf("delete input: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbAvailabilityDeleted,
			subject: staffID, org: availabilityOrg(section, key), target: availabilityTarget(section, key),
			detail: map[string]any{"previous": previous}, reason: reason, result: "ok",
		})
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("cloudserver/store.DeleteAvailabilityInput: %w", err)
	}
	return nil
}

// availabilityValueTx reads one input's value under a row lock, or
// ErrNotFound.
func availabilityValueTx(ctx context.Context, tx pgx.Tx, section staffauth.Section, key string) (json.RawMessage, error) {
	var value []byte
	err := tx.QueryRow(ctx,
		`SELECT value FROM availability_inputs WHERE section = $1 AND key = $2 FOR UPDATE`,
		string(section), key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return value, nil
}

// availabilityTarget is the staff_actions.target of an input.
func availabilityTarget(section staffauth.Section, key string) string {
	return "availability:" + string(section) + "/" + key
}

// availabilityOrg is the org an input is about, for the log row's org_id: an
// org_controls key that is an org id; "" for the platform-wide row and the
// other sections (the staff console's per-org log view reads org_id).
func availabilityOrg(section staffauth.Section, key string) string {
	if section != staffauth.SectionOrgControls {
		return ""
	}
	id, err := uuid.Parse(key)
	if err != nil {
		return ""
	}
	return id.String()
}

// ErrNoChange means a per-org component toggle would change nothing: the org
// is already in the asked state.
var ErrNoChange = errors.New("cloudserver/store: no change")

// OrgComponentChange is what SetOrgComponentInput wrote.
type OrgComponentChange struct {
	// Previous is the components input value before (nil: no row).
	Previous json.RawMessage
	// Value is the value after (nil: the row was removed).
	Value json.RawMessage
}

// SetOrgComponentInput turns component on or off for org orgID by rewriting
// that component's components input (availcompose.Toggle: a named reach that
// gains or loses the org; the row goes when its list empties), as staff
// member staffID, and logs it with the org's id, in one transaction. The
// toggle is decided on the row as locked inside the transaction (an advisory
// lock on the row's key, so two toggles of the same component for different
// orgs cannot lose one another). ErrNoChange when the org is already in that
// state; an error wrapping availcompose.ErrToggle when the toggle cannot be
// made for one org.
func (s *Store) SetOrgComponentInput(ctx context.Context, staffID, orgID, component string, on bool, reason string, now time.Time) (OrgComponentChange, error) {
	reason, err := staffauth.ValidateReason(reason)
	if err != nil {
		return OrgComponentChange{}, fmt.Errorf("cloudserver/store.SetOrgComponentInput: %w", err)
	}
	now = nowOr(now)
	section := staffauth.SectionComponents
	var out OrgComponentChange
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "sbci-availability-input:"+availabilityTarget(section, component)); err != nil {
			return fmt.Errorf("lock input: %w", err)
		}
		previous, err := availabilityValueTx(ctx, tx, section, component)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		t, err := availcompose.Toggle(component, previous, orgID, on)
		if err != nil {
			return err
		}
		if !t.Changed {
			return ErrNoChange
		}
		out = OrgComponentChange{Previous: previous, Value: t.Value}
		detail := map[string]any{"org": orgID, "on": on, "value": t.Value, "previous": previous}
		row := staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbAvailabilitySet, subject: staffID,
			org: orgID, target: availabilityTarget(section, component), detail: detail, reason: reason, result: "ok",
		}
		if t.Value == nil {
			if _, err := tx.Exec(ctx, `DELETE FROM availability_inputs WHERE section = $1 AND key = $2`, string(section), component); err != nil {
				return fmt.Errorf("delete input: %w", err)
			}
			row.verb = staffauth.VerbAvailabilityDeleted
			return insertStaffAction(ctx, tx, row)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO availability_inputs (section, key, value, reason, author, updated_at)
			 VALUES ($1, $2, $3::jsonb, $4, $5, $6)
			 ON CONFLICT (section, key) DO UPDATE
			   SET value = EXCLUDED.value, reason = EXCLUDED.reason,
			       author = EXCLUDED.author, updated_at = EXCLUDED.updated_at`,
			string(section), component, []byte(t.Value), reason, staffauth.Actor(staffID), now); err != nil {
			return fmt.Errorf("write input: %w", err)
		}
		return insertStaffAction(ctx, tx, row)
	})
	if err != nil {
		if errors.Is(err, ErrNoChange) {
			return OrgComponentChange{}, ErrNoChange
		}
		return OrgComponentChange{}, fmt.Errorf("cloudserver/store.SetOrgComponentInput: %w", err)
	}
	return out, nil
}
