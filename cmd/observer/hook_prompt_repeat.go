package main

import (
	"context"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// promptRedeliveryWindow is how close to the newest stored row of the same
// prompt a delivery must be to count as the same event delivered again.
// Claude Code's UserPromptSubmit payload carries no per-submission id, so
// the two shapes are told apart by time: a second registration of the hook
// (plugin plus settings.json) fires within the same second, while a user
// who types the same prompt again does so after the agent answered.
// Residual: the same text submitted twice within this window is one row.
const promptRedeliveryWindow = 10 * time.Second

// promptOccurrenceID is the source_event_id a prompt event carries (B7,
// Windows 11 Pro live run): the base id when the prompt is new in the
// session; the newest stored row's id when that row is within the window
// (a re-delivery, which the actions upsert then collapses); otherwise a
// fresh base#<n>, so the same prompt typed again is its own row. stored is
// newest first (store.HookOccurrences).
func promptOccurrenceID(base string, stored []store.HookOccurrence, now time.Time, window time.Duration) string {
	if len(stored) == 0 {
		return base
	}
	// A row stamped after now (a clock step) counts as within the window.
	if now.Sub(stored[0].At) <= window {
		return stored[0].ID
	}
	return base + "#" + strconv.Itoa(len(stored)+1)
}

// resolvePromptOccurrence reads the prompt's stored rows and returns its
// id; a failed read keeps the base id (the pre-B7 behaviour: a repeat
// collapses, nothing is lost or doubled).
func resolvePromptOccurrence(ctx context.Context, st *store.Store, sourceFile, base string, now time.Time) string {
	stored, err := st.HookOccurrences(ctx, sourceFile, base)
	if err != nil {
		return base
	}
	return promptOccurrenceID(base, stored, now, promptRedeliveryWindow)
}
