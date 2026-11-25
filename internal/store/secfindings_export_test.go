//go:build !sbo_omit_security

package store

import (
	"context"
	"time"
)

// Test-only: production code records finding events through appendSecEvent
// inside the secfindings writers.

// AppendSecFindingEvent records one lifecycle event (finding id may be ""
// for a project-level event such as a baseline set).
func (s *Store) AppendSecFindingEvent(ctx context.Context, findingID, rootHash, kind, detail string, now time.Time) error {
	return appendSecEvent(ctx, s.db, findingID, rootHash, kind, detail, now.UTC().Format(secTime))
}
