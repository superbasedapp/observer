package main

import (
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudScopeSyncItems keeps a selected-session action from spending allowance
// on other pending sessions. The general sync retains its existing queue order.
func cloudScopeSyncItems(items []store.CloudOutboxItem, sessionID string, out io.Writer) []store.CloudOutboxItem {
	if sessionID == "" {
		return items
	}
	selected := items[:0]
	for _, item := range items {
		if item.SessionID == sessionID {
			selected = append(selected, item)
		}
	}
	fmt.Fprintln(out, "Uploading only the selected session; other queued sessions are unchanged.")
	return selected
}

// cloudScopedSyncError reports a failed selected upload even when the later
// result pull succeeds. General batch sync preserves its partial-success behavior.
func cloudScopedSyncError(sessionID string, err error, failed, reconfirm int) error {
	if sessionID != "" && err == nil && (failed > 0 || reconfirm > 0) {
		return fmt.Errorf("selected session was not uploaded: %d failed, %d need review; check the session's enrichment status", failed, reconfirm)
	}
	return err
}
