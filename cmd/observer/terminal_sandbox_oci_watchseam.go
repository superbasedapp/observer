package main

import (
	"context"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// terminal_sandbox_oci_watchseam.go is the daemon's hand-off of its watcher
// to the container driver (lane SBX-P3C, gap G27): a run whose tool state is
// projected registers its transcript subtrees as watch roots for the run's
// life through the watcher's one seam (internal/watcher AddProjectionRoot).
// It carries no driver code, so it is built in every build (start.go sets
// it); with no oci driver nothing ever reads it.

// sandboxProjectionWatchFunc registers hostRoot as a watch root of tool's
// adapter whose files are judged at boxRoot and whose events are bound to
// the run (bind: the run id and its workspace), and returns its removal.
type sandboxProjectionWatchFunc func(ctx context.Context, tool, hostRoot, boxRoot string, bind watcher.ProjectionBinding) (func(), error)

// sandboxProjectionWatcher is the daemon watcher's seam; nil outside the
// daemon (a CLI launch has no watcher and leaves the transcripts to the
// daemon's next start, which removes the projection).
var sandboxProjectionWatcher atomic.Pointer[sandboxProjectionWatchFunc]

// setSandboxProjectionWatcher installs the seam (nil clears it).
func setSandboxProjectionWatcher(fn sandboxProjectionWatchFunc) {
	if fn == nil {
		sandboxProjectionWatcher.Store(nil)
		return
	}
	sandboxProjectionWatcher.Store(&fn)
}
