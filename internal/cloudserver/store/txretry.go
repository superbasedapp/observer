package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// CLOUD-LOCK-1: a result completion takes several row locks and the account
// advisory lock, so two concurrent transactions can deadlock (40P01) or fail
// serialization (40001). PostgreSQL has already rolled the loser back, so the
// WHOLE transaction can be run again from the start; nothing partial is ever
// retried and no other error class is.

// SQLSTATE codes retryTx treats as transient.
const (
	sqlStateDeadlock      = "40P01"
	sqlStateSerialization = "40001"
)

// txRetryMaxAttempts is the total number of tries (the first plus retries).
const txRetryMaxAttempts = 3

// txRetryBaseBackoff is the first backoff; each retry doubles it, then a
// random factor in [0.5, 1.5) is applied.
const txRetryBaseBackoff = 20 * time.Millisecond

// txRetrier carries the injectable sleeper and jitter source so tests never
// wait on a real clock. The zero value sleeps on the real clock.
type txRetrier struct {
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func() float64 // returns [0,1)
}

func (r txRetrier) wait(ctx context.Context, d time.Duration) error {
	if r.sleep != nil {
		return r.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r txRetrier) rand() float64 {
	if r.jitter != nil {
		return r.jitter()
	}
	return rand.Float64() //nolint:gosec // backoff jitter, not security
}

// isRetryableTxError reports whether err carries SQLSTATE 40P01 or 40001.
func isRetryableTxError(err error) bool {
	var pge *pgconn.PgError
	if !errors.As(err, &pge) {
		return false
	}
	return pge.Code == sqlStateDeadlock || pge.Code == sqlStateSerialization
}

// run calls fn up to txRetryMaxAttempts times, retrying only while it fails
// with a deadlock or serialization error. fn must run one complete
// transaction and reset any captured outputs at its start.
func (r txRetrier) run(ctx context.Context, fn func() error) error {
	var err error
	backoff := txRetryBaseBackoff
	for attempt := 1; attempt <= txRetryMaxAttempts; attempt++ {
		if err = fn(); err == nil || !isRetryableTxError(err) {
			return err
		}
		if attempt == txRetryMaxAttempts {
			break
		}
		d := time.Duration(float64(backoff) * (0.5 + r.rand()))
		if werr := r.wait(ctx, d); werr != nil {
			return fmt.Errorf("cloudserver/store: retry wait: %w", werr)
		}
		backoff *= 2
	}
	return err
}
