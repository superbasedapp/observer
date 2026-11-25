package invariant

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

const remotenotifyImportPrefix = "github.com/marmutapp/superbased-observer/internal/remotenotify"

// forbiddenRemotenotifyImporters are the capture-path packages that must NEVER
// reach the outbound notification rail — the "no network calls in the
// observer/watcher" invariant (CLAUDE.md; remote-dashboard-access plan §2).
// remotenotify is invoked ONLY from the dashboard/lifecycle layer (the
// termsession session-exit seam wired in cmd); a leaked import here would let
// the watcher or proxy phone out, which this test refuses at build time.
var forbiddenRemotenotifyImporters = []string{
	filepath.Join("..", "..", "internal", "watcher"),
	filepath.Join("..", "..", "internal", "proxy"),
}

// TestRemotenotifyUnreachableFromCapturePaths enforces the boundary: no file
// under internal/watcher or internal/proxy may import internal/remotenotify.
// Textual import scan (build-tag agnostic), mirroring
// TestObsReverseImportBoundary.
func TestRemotenotifyUnreachableFromCapturePaths(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Dirs:      forbiddenRemotenotifyImporters,
		Recursive: true,
		// Test files too: this scan has always covered every .go file
		// under the two trees.
		IncludeTests:   true,
		ForbiddenTrees: []string{remotenotifyImportPrefix},
		Reason:         "the outbound notification rail must never be reachable from the capture path (watcher/proxy); invoke it from the dashboard/lifecycle layer only",
	})
}
