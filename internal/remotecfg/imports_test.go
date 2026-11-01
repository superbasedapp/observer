package remotecfg

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsRestrictedToConfigAndRemoteauth pins the module boundary (plan
// section B): the arm/disarm/rotate transaction owner may import ONLY
// internal/config + internal/remoteauth (and internal/fsatomic, the
// owner-only file create, R-160) from the project, never net/http, the
// dashboard or cmd (moving BuildController here would cycle).
func TestImportsRestrictedToConfigAndRemoteauth(t *testing.T) {
	const prefix = "github.com/marmutapp/superbased-observer/"
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"net/http",
			"github.com/fsnotify/fsnotify",
			prefix + "internal/intelligence/dashboard",
		},
		ForbiddenPrefixes: []string{prefix},
		Except:            []string{prefix + "internal/config", prefix + "internal/remoteauth", prefix + "internal/fsatomic"},
		Reason:            "remotecfg may import ONLY internal/config + internal/remoteauth (+ internal/fsatomic for the owner-only secret file)",
	})
}
