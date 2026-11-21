package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

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
