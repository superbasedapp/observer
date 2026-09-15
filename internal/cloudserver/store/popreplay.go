package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SweepExpiredPoPReplay deletes every expired proof-of-possession jti across
// all tenants (FC3), purely by expires_at, through the SECURITY DEFINER sweep
// primitive (pop_replay is RLS tenant-scoped, so a plain DELETE under WithSystem
// would match no rows). It bounds the replay cache so a holder of a legitimate
// device key cannot grow the database indefinitely with fresh-jti proofs.
// Returns how many rows were deleted. Schedule it periodically (the serve loop
// runs it on a ticker).
func (s *Store) SweepExpiredPoPReplay(ctx context.Context, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var deleted int
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_sweep_expired_pop_replay($1)`, now).Scan(&deleted)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SweepExpiredPoPReplay: %w", err)
	}
	return deleted, nil
}
