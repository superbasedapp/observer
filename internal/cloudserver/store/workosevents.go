package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The WorkOS lifecycle-event ledger (plan §3 W1 "Lifecycle phase 1", D18). It
// is a dedupe ledger, not an archive: only {event id, event type, received,
// processed} is kept — never the provider's payload, and never an account link
// (migration 0010's header carries the full classification).
//
// Both methods run on the SYSTEM path: intake happens before (and independently
// of) resolving which account, if any, an event concerns.

// WorkOSEventIntake is what taking delivery of an event tells the caller.
//
// The two flags answer two DIFFERENT questions, and conflating them is the bug
// this type exists to prevent (F7):
//
//   - Fresh — did THIS call insert the row? Useful for logging and metrics.
//   - Processed — has the event's handling already COMPLETED (processed_at set)?
//     This, not Fresh, is what decides whether to act: a row recorded by an
//     earlier attempt that then crashed (or whose revocation errored) is
//     `Fresh=false, Processed=false`, and it MUST be re-processed on redelivery.
//     Treating "not fresh" as "already handled" silently drops exactly the
//     deliveries a retry was meant to save.
type WorkOSEventIntake struct {
	Fresh     bool
	Processed bool
}

// RecordWorkOSEvent takes delivery of one provider event and reports its
// PROCESSING state. WorkOS delivers at-least-once, so intake must be idempotent
// (the INSERT ... ON CONFLICT DO NOTHING is the whole guard — no read-then-write
// window) while still leaving a failed attempt retryable.
//
// The insert and the read-back run in ONE transaction, so the state returned is
// the state as of a single consistent point: a concurrent duplicate delivery
// either sees the row unprocessed (and one of the two does the work; the work
// itself is idempotent) or sees it processed (and acknowledges).
func (s *Store) RecordWorkOSEvent(ctx context.Context, eventID, eventType string, now time.Time) (WorkOSEventIntake, error) {
	var out WorkOSEventIntake
	if eventID == "" {
		return out, fmt.Errorf("cloudserver/store.RecordWorkOSEvent: empty event id")
	}
	if eventType == "" {
		return out, fmt.Errorf("cloudserver/store.RecordWorkOSEvent: empty event type")
	}
	if now.IsZero() {
		now = time.Now()
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`INSERT INTO workos_events (event_id, event_type, received_at)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (event_id) DO NOTHING`,
			eventID, eventType, now)
		if e != nil {
			return fmt.Errorf("insert workos event: %w", e)
		}
		out.Fresh = ct.RowsAffected() == 1
		var processedAt *time.Time
		if e := tx.QueryRow(ctx,
			`SELECT processed_at FROM workos_events WHERE event_id = $1`, eventID).Scan(&processedAt); e != nil {
			return fmt.Errorf("read workos event state: %w", e)
		}
		out.Processed = processedAt != nil
		return nil
	})
	if err != nil {
		return WorkOSEventIntake{}, fmt.Errorf("cloudserver/store.RecordWorkOSEvent: %w", err)
	}
	return out, nil
}

// MarkWorkOSEventProcessed stamps processed_at on an already-recorded event. It
// is written only after the phase-1 handling for that event finished, so a row
// left with processed_at NULL is an honest "took delivery, did not complete"
// marker rather than a silent success.
//
// The stamp is write-once (the WHERE clause skips an already-processed row), so
// a concurrent duplicate delivery cannot move the timestamp forward.
func (s *Store) MarkWorkOSEventProcessed(ctx context.Context, eventID string, now time.Time) error {
	if eventID == "" {
		return fmt.Errorf("cloudserver/store.MarkWorkOSEventProcessed: empty event id")
	}
	if now.IsZero() {
		now = time.Now()
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`UPDATE workos_events SET processed_at = $2
			  WHERE event_id = $1 AND processed_at IS NULL`,
			eventID, now)
		if e != nil {
			return fmt.Errorf("mark workos event processed: %w", e)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.MarkWorkOSEventProcessed: %w", err)
	}
	return nil
}

// WorkOSEvent is one recorded intake row, for tests and operator forensics.
type WorkOSEvent struct {
	EventID     string
	EventType   string
	ReceivedAt  time.Time
	ProcessedAt *time.Time
}

// GetWorkOSEvent reads one recorded event, or ErrNotFound.
func (s *Store) GetWorkOSEvent(ctx context.Context, eventID string) (WorkOSEvent, error) {
	var out WorkOSEvent
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT event_id, event_type, received_at, processed_at
			   FROM workos_events WHERE event_id = $1`, eventID).
			Scan(&out.EventID, &out.EventType, &out.ReceivedAt, &out.ProcessedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	if err != nil {
		return WorkOSEvent{}, err
	}
	return out, nil
}
