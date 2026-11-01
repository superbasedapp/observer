package ibmbob

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// settingsReadCap bounds the settings.json read; the file is a few hundred
// bytes (hooks + licenseConsent + bobShell.lastRunVersion).
const settingsReadCap = 1 << 20

// readInstallVersion returns the install-level Bob Shell version for the
// store at dbPath (`<home>/.bob/db/bob.db`): the `bobShell.lastRunVersion`
// key of the sibling `<home>/.bob/settings/settings.json`, which Bob
// rewrites on every launch with the running build's version.
//
// It is the best version signal the store offers (tasks.version is NULL on
// every grounded 2.0.6 row), but it names the build that LAST RAN, not the
// one that wrote an old task: operator ruling 2026-10-21 (1) stamps it on
// every session anyway, preferring tasks.version when a build records one.
//
// Only that one key is decoded; the rest of settings.json (hooks, consent)
// is never inspected, and auth-secrets.json (a sibling) is never opened.
// Any read/parse problem yields "".
func readInstallVersion(dbPath string) string {
	settings := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "settings", "settings.json")
	f, err := os.Open(settings) //nolint:gosec // G703: Bob's settings.json beside the watcher-discovered store, read only
	if err != nil {
		return ""
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, settingsReadCap))
	if err != nil {
		return ""
	}
	var doc struct {
		BobShell struct {
			LastRunVersion string `json:"lastRunVersion"`
		} `json:"bobShell"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return strings.TrimSpace(doc.BobShell.LastRunVersion)
}
