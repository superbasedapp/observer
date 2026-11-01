package diag

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testhome"
)

// TestMain pins the profile roots (HOME, USERPROFILE, APPDATA, LOCALAPPDATA,
// the XDG dirs) to one process temp home for the whole run (surface-gap
// FU-102). The adapter checks resolve installed tools through the package
// managers, and on the 2026-10-27 Windows sweep 14 tests here (TestRun_*,
// TestCheckAdapter*, TestCheckGovernance_FilterBySubstring) made npm write
// a debug log into the developer's real %LOCALAPPDATA%\npm-cache\_logs.
// Tests that need a specific home pin their own on top with t.Setenv.
func TestMain(m *testing.M) {
	_, cleanup, err := testhome.PinProcess()
	if err != nil {
		os.Exit(2)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
