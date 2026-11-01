package store

import (
	"context"
	"fmt"
	"time"
)

// HookOccurrence is one stored row of a hook event family: a hook event
// whose id is content-derived (the same session and the same text give the
// same base id), stored under the base id or base#<n>.
type HookOccurrence struct {
	ID string
	At time.Time
}

// HookOccurrences returns the actions rows of sourceFile whose
// source_event_id is base or base#<n>, newest first. It lets a hook tell a
// re-delivery of one event (a second registration firing the same payload,
// a retry) from the same text submitted again later in the session
// (Windows 11 Pro live run, B7). Both arms of the WHERE are ranges on the
// UNIQUE(source_file, source_event_id) index.
func (s *Store) HookOccurrences(ctx context.Context, sourceFile, base string) ([]HookOccurrence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source_event_id, timestamp FROM actions
		WHERE source_file = ? AND (source_event_id = ? OR (source_event_id >= ? AND source_event_id < ?))`,
		sourceFile, base, base+"#", base+"$")
	if err != nil {
		return nil, fmt.Errorf("store.HookOccurrences: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HookOccurrence
	for rows.Next() {
		var id, ts string
		if err := rows.Scan(&id, &ts); err != nil {
			return nil, fmt.Errorf("store.HookOccurrences: %w", err)
		}
		at, _ := parseDBTime(ts)
		out = append(out, HookOccurrence{ID: id, At: at})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.HookOccurrences: %w", err)
	}
	// Newest first; equal times keep the longer (later-numbered) id first.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (out[j].At.After(out[j-1].At) || (out[j].At.Equal(out[j-1].At) && len(out[j].ID) > len(out[j-1].ID))); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}
