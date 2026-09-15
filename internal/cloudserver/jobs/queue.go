// Package jobs is the queue abstraction + worker skeleton for the hosted
// cloud-intelligence service (plan §6 CI-P3/CI-P4). This phase implements ONLY
// the Postgres-backed queue (the analysis_jobs table with lease columns IS the
// queue, dequeued through the SECURITY DEFINER lease function) behind a narrow
// Queue interface; the Azure Storage Queue driver is a later swap behind the
// same interface (substrate contract §1). The worker proves the
// lease/reservation/TTL/revalidation semantics with a no-op executor — NO
// Foundry inference (CI-P4 adds that).
package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Queue is the enqueue/lease surface. At-least-once delivery is assumed
// (substrate §6.1); every consumer path is idempotent by design (the lease
// function's FOR UPDATE SKIP LOCKED + the job state machine).
type Queue interface {
	// Enqueue registers a job as available for lease. In the pg driver the job
	// row inserted by the API (state='queued') IS the enqueue, so this is a
	// validating no-op; the Azure driver will push a message carrying the job
	// reference.
	Enqueue(ctx context.Context, jobID string) error

	// Lease leases the next due job for worker, applying a visibility timeout of
	// leaseFor. Returns (nil, nil) when nothing is due.
	Lease(ctx context.Context, worker string, classes []string, leaseFor time.Duration, now time.Time) (*store.LeasedJob, error)
}

// PGQueue is the Postgres table-based queue. It delegates the atomic dequeue to
// the store's SECURITY DEFINER lease primitive.
type PGQueue struct {
	store *store.Store
}

// NewPGQueue returns a Postgres-backed queue over s.
func NewPGQueue(s *store.Store) *PGQueue { return &PGQueue{store: s} }

// Enqueue is a validating no-op: in pg mode the job row is the queue element.
func (q *PGQueue) Enqueue(_ context.Context, jobID string) error {
	if jobID == "" {
		return errors.New("cloudserver/jobs.PGQueue.Enqueue: empty jobID")
	}
	return nil
}

// Lease leases the next due job via the lease function (visibility timeout =
// leaseFor).
func (q *PGQueue) Lease(ctx context.Context, worker string, classes []string, leaseFor time.Duration, now time.Time) (*store.LeasedJob, error) {
	return q.store.LeaseNextJob(ctx, worker, classes, leaseFor, now)
}

var _ Queue = (*PGQueue)(nil)
