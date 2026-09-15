package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidRateLimit is returned when a limiter call has an invalid bucket,
// key, or window. A non-positive limit is the explicit disabled state and does
// not return this error.
var ErrInvalidRateLimit = errors.New("cloudserver/store: invalid rate-limit arguments")

// AllowRateLimit atomically records one hit in the shared PostgreSQL fixed
// window identified by bucket and key. All API replicas calling the same
// database therefore observe one cap rather than one cap per process.
//
// limit <= 0 is disabled and returns an in-process allow without database I/O.
// The operation is performed through the SECURITY DEFINER function, so the API
// role receives EXECUTE but no direct counter-table privileges. It returns
// (allowed, retryAfter, err): a denied request has a positive retryAfter, while
// any database or validation failure returns err separately and must be treated
// as fail-closed by callers.
func (s *Store) AllowRateLimit(ctx context.Context, bucket, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if limit <= 0 {
		return true, 0, nil
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" || len(bucket) > 64 || key == "" || len(key) > 512 {
		return false, 0, ErrInvalidRateLimit
	}
	windowMS := window.Milliseconds()
	if windowMS <= 0 {
		return false, 0, ErrInvalidRateLimit
	}
	keyHash := hashRateLimitKey(bucket, key)

	var (
		allowed    bool
		retryAfter time.Duration
	)
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var retryMS int64
		if err := tx.QueryRow(ctx,
			`SELECT allowed, retry_after_ms
			   FROM sbci_rate_limit($1, $2, $3, $4)`,
			bucket, keyHash, limit, windowMS).Scan(&allowed, &retryMS); err != nil {
			return fmt.Errorf("cloudserver/store.AllowRateLimit: execute counter: %w", err)
		}
		if retryMS < 0 {
			return errors.New("cloudserver/store.AllowRateLimit: negative retry interval")
		}
		if !allowed {
			if retryMS < 1 {
				return errors.New("cloudserver/store.AllowRateLimit: denied without positive retry interval")
			}
			retryAfter = time.Duration(retryMS) * time.Millisecond
		}
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	return allowed, retryAfter, nil
}

// hashRateLimitKey keeps raw IP, device, and account identifiers out of the
// shared operational table. The fixed domain prefix and bucket separator make
// equal raw keys in different dimensions produce different hashes.
func hashRateLimitKey(bucket, key string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("sbci-rate-limit-key/v1\x00"))
	_, _ = h.Write([]byte(bucket))
	_, _ = h.Write([]byte{'\x00'})
	_, _ = h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}
