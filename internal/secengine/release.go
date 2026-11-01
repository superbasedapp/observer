package secengine

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// Platform is one OS and architecture Observer ships a binary for.
type Platform struct{ OS, Arch string }

// ReleasePlatforms are the platforms every security.engine manifest must
// pin an Opengrep binary for: the five Observer itself ships (npm platform
// packages, PyPI wheels and the VS Code targets).
var ReleasePlatforms = []Platform{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

// CheckReleaseSet is the publish step's gate for a security.engine
// manifest (WINFIX4 audit finding 6): every release platform has an
// Opengrep entry that the manifest does not revoke, so a manifest built
// for one platform never reaches the others. revocation is the publisher's
// explicit statement that the manifest withdraws digests: it is exempt
// from the platform rule and must revoke at least one.
func CheckReleaseSet(m content.Manifest, revocation bool) error {
	if m.Kind != content.Engine {
		return fmt.Errorf("secengine.CheckReleaseSet: kind %q, not %s", m.Kind, content.Engine)
	}
	if revocation {
		if len(m.Revoked) == 0 {
			return fmt.Errorf("secengine.CheckReleaseSet: a revocation manifest revokes nothing")
		}
		return nil
	}
	var missing []string
	for _, p := range ReleasePlatforms {
		found := false
		for _, e := range m.Entries {
			if strings.HasPrefix(e.Name, "opengrep") && e.OS == p.OS && e.Arch == p.Arch && !content.IsRevoked(m, e.SHA256) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, p.OS+"/"+p.Arch)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("secengine.CheckReleaseSet: no Opengrep pin for %s; every release platform needs one unless the manifest is an explicit revocation", strings.Join(missing, ", "))
	}
	return nil
}
