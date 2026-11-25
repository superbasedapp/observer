package dashapi

import (
	"time"
)

// CloudRFC3339 renders a time as RFC3339 UTC, or "" for the zero time so the
// handler never emits "0001-01-01…" for an unset stamp.
func CloudRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
