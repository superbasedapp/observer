package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RetentionPushFloor is the push-cursor view node retention needs to avoid
// deleting telemetry the org server has not yet accepted (T-830, T-839).
//
// Held is true whenever the node holds an enrolment row, whether the org push
// is running ([org_client].enabled = true) or PAUSED (enabled = false, which
// operators use as a pause, as on 2026-08-26): a paused node still owes the
// org every row above the cursor, so retention must not delete them (D-673).
// Held is false only on a node that is not enrolled: there is no org copy to
// wait for, so local-only retention is unchanged byte for byte.
//
// ActionsCursor / SessionsCursor / GuardEventsCursor are the highest
// actions.id, sessions.rowid and guard_events.id the org has acknowledged;
// rows above them must stay (up to the held-data cap the caller applies).
type RetentionPushFloor struct {
	Held bool
	// Paused reports an enrolled node whose org push is switched off. The
	// hold applies all the same; the flag only lets surfaces say why rows
	// are piling up.
	Paused            bool
	ActionsCursor     int64
	SessionsCursor    int64
	GuardEventsCursor int64
}

// LoadRetentionPushFloor reports the retention push floor. orgPushEnabled is
// the caller's [org_client].enabled; it no longer decides whether the floor is
// held (an enrolment row alone does, T-839 / D-673), it only sets Paused.
func (s *Store) LoadRetentionPushFloor(ctx context.Context, orgPushEnabled bool) (RetentionPushFloor, error) {
	enr, err := s.LoadEnrolment(ctx)
	if err != nil {
		return RetentionPushFloor{}, fmt.Errorf("store.LoadRetentionPushFloor: %w", err)
	}
	if enr == nil {
		return RetentionPushFloor{}, nil
	}
	c, err := s.LoadPushCursor(ctx)
	if err != nil {
		return RetentionPushFloor{}, fmt.Errorf("store.LoadRetentionPushFloor: %w", err)
	}
	return RetentionPushFloor{
		Held:              true,
		Paused:            !orgPushEnabled,
		ActionsCursor:     c.Actions,
		SessionsCursor:    c.Sessions,
		GuardEventsCursor: c.GuardEvents,
	}, nil
}

// retentionHoldShedKey is the schema_meta key holding the last time node
// retention released held (unsent) rows because the held data passed
// [observer.retention].held_max_mb (T-839).
const retentionHoldShedKey = "retention_hold_shed"

// RetentionHoldShed records one retention pass that deleted rows the org had
// NOT yet accepted, because the held data passed the cap. It is the evidence
// `observer doctor` turns into a FAIL line: those rows never reached the org.
type RetentionHoldShed struct {
	At          time.Time `json:"at"`
	Actions     int64     `json:"actions"`
	GuardEvents int64     `json:"guard_events"`
	HeldBytes   int64     `json:"held_bytes"`
	CapBytes    int64     `json:"cap_bytes"`
	ShedThrough string    `json:"shed_through"`
}

// RecordRetentionHoldShed persists the latest over-cap shed (latest wins).
func (s *Store) RecordRetentionHoldShed(ctx context.Context, shed RetentionHoldShed) error {
	raw, err := json.Marshal(shed)
	if err != nil {
		return fmt.Errorf("store.RecordRetentionHoldShed: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO schema_meta(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		retentionHoldShedKey, string(raw)); err != nil {
		return fmt.Errorf("store.RecordRetentionHoldShed: %w", err)
	}
	return nil
}

// LoadRetentionHoldShed returns the latest over-cap shed, ok=false when none
// was ever recorded (or the stored value no longer parses).
func (s *Store) LoadRetentionHoldShed(ctx context.Context) (RetentionHoldShed, bool, error) {
	v, err := s.readMeta(ctx, retentionHoldShedKey)
	if err != nil {
		return RetentionHoldShed{}, false, fmt.Errorf("store.LoadRetentionHoldShed: %w", err)
	}
	if v == "" {
		return RetentionHoldShed{}, false, nil
	}
	var shed RetentionHoldShed
	if err := json.Unmarshal([]byte(v), &shed); err != nil {
		return RetentionHoldShed{}, false, nil //nolint:nilerr // an unreadable marker is no evidence, not a doctor failure
	}
	return shed, true, nil
}
