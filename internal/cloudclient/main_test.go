package cloudclient

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testhome"
)

// TestMain pins the profile roots (HOME, USERPROFILE, APPDATA, LOCALAPPDATA,
// the XDG dirs) to one process temp home for the whole run (surface-gap
// FU-102): a credential-store test took the cloud credential
// coordination lock under os.UserConfigDir(), which was the developer's real
// ~/.config/sbo-cloud-credential-v1/.
func TestMain(m *testing.M) {
	_, cleanup, err := testhome.PinProcess()
	if err != nil {
		os.Exit(2)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}
