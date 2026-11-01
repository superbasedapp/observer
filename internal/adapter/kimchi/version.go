package kimchi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// settingsFile is the harness settings file beside the sessions tree
// (`<agent dir>/settings.json`).
const settingsFile = "settings.json"

// harnessSettings decodes the ONE non-secret field this adapter reads from
// the harness settings: `lastChangelogVersion`, the version of the kimchi
// build that last showed its changelog, i.e. the build the operator is
// running. Declaring only that field is the guard: the file's other keys
// (provider/model defaults, retry knobs, theme) are never decoded, and the
// credential files beside it (config.json, harness/auth.json,
// harness/models.json, org-policy.json) are never opened.
type harnessSettings struct {
	LastChangelogVersion string `json:"lastChangelogVersion"`
}

// installVersion returns the kimchi build version recorded in the settings
// file of the agent dir that owns sessionPath
// (`<agent dir>/sessions/--<slug>--/<ts>_<uuid>.jsonl`). The transcript
// itself carries no version, so this is an INSTALL-level stamp (operator
// ruling 2026-10-21 #1): it names the build the install was running when it
// last wrote the setting, not necessarily the build that wrote an old
// session. Empty when the file is absent, unreadable or malformed — the
// honest "unknown".
func installVersion(sessionPath string) string {
	agentDir := filepath.Dir(filepath.Dir(filepath.Dir(sessionPath)))
	if filepath.Base(filepath.Dir(filepath.Dir(sessionPath))) != "sessions" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(agentDir, settingsFile)) //nolint:gosec // sibling of the watch root, fixed name
	if err != nil {
		return ""
	}
	var s harnessSettings
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	v := strings.TrimSpace(s.LastChangelogVersion)
	if v == "" || len(v) > 64 || strings.ContainsAny(v, " \t\r\n") {
		return ""
	}
	return v
}

// emitToolVersion stamps the session with the install-level version. The
// store write is first-wins-unless-empty, so emitting on every parse is
// idempotent.
func (st *parseState) emitToolVersion(res *adapter.ParseResult) {
	if st.sessionID == "" {
		return
	}
	if v := installVersion(st.path); v != "" {
		res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{SessionID: st.sessionID, Version: v})
	}
}
