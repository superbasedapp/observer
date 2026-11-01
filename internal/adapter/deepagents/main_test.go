package deepagents

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testhome"
)

// TestMain pins the profile roots (HOME, USERPROFILE, APPDATA, LOCALAPPDATA,
// the XDG dirs) to one process temp home for the whole run (surface-gap
// FU-102): TestIsForeignMountPathAndMirror stages a
// sessions.db mirror under os.UserCacheDir(), which was the developer's real
// ~/.cache/superbased-observer/deepagents-mirror.
func TestMain(m *testing.M) {
	_, cleanup, err := testhome.PinProcess()
	if err != nil {
		os.Exit(2)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
