package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cleanupInProcessDaemon undoes the process-wide state an in-process
// `observer start` (newStartCmd run on a goroutine) leaves behind once it has
// stopped. A real daemon is its own process, so nothing here outlives it in
// production; a test binary runs every later test in the same process.
//
//   - setDaemonConfigPath: newStartCmd records its --config process-wide.
//   - store.SetUpdatePostureEnv: start publishes the update posture
//     (updateRuntime.PublishPosture). Left set, every later push batch in the
//     binary carries an update_posture row, so a batch with no rows is never
//     Empty() and the cloud-session flush loop ships posture-only envelopes
//     until its batch cap (Pending, coverage rows_pending) instead of
//     stopping.
//
// Call it right after newStartCmd and before registering the cleanup that
// stops the daemon: cleanups run last-in first-out, so this one runs after
// the daemon has returned and can no longer republish.
func cleanupInProcessDaemon(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		setDaemonConfigPath("")
		store.ClearUpdatePostureEnv()
	})
}
