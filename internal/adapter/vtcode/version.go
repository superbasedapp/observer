package vtcode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// updateCheckFileName is VT Code's update-check cache: a small non-secret
// JSON (`last_checked_unix_secs`, `latest_version`, `last_seen_version`,
// `release_notes`, ...) written on every launch. Grounded on both OSes
// (0.180.2): `~/.cache/vtcode/last_update_check` (XDG cache) and
// `%APPDATA%\vinhnx\vtcode\cache\last_update_check`.
const updateCheckFileName = "last_update_check"

// versionFileForStateRoot maps a global archive dir (`<state>/sessions`)
// to the same install's update-check cache:
//
//   - Windows: `<APPDATA>\vinhnx\vtcode\state\sessions` →
//     `<APPDATA>\vinhnx\vtcode\cache\last_update_check`.
//   - Linux:   `<home>/.local/state/vtcode/sessions` →
//     `<home>/.cache/vtcode/last_update_check`. An `$XDG_STATE_HOME`
//     root (`<x>/vtcode/sessions`) maps to `$XDG_CACHE_HOME/vtcode/...`
//     when set, else to nothing (no grounded pairing).
func versionFileForStateRoot(root string) string {
	clean := filepath.Clean(root)
	vtDir := filepath.Dir(clean) // <...>/vtcode or <...>/vinhnx/vtcode/state
	switch {
	case strings.EqualFold(filepath.Base(vtDir), "state") &&
		strings.EqualFold(filepath.Base(filepath.Dir(vtDir)), "vtcode"):
		return filepath.Join(filepath.Dir(vtDir), "cache", updateCheckFileName)
	case strings.EqualFold(filepath.Base(vtDir), "vtcode") &&
		strings.EqualFold(filepath.Base(filepath.Dir(vtDir)), "state") &&
		strings.EqualFold(filepath.Base(filepath.Dir(filepath.Dir(vtDir))), ".local"):
		home := filepath.Dir(filepath.Dir(filepath.Dir(vtDir)))
		return filepath.Join(home, ".cache", "vtcode", updateCheckFileName)
	case strings.EqualFold(filepath.Base(vtDir), "vtcode"):
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "vtcode", updateCheckFileName)
		}
	}
	return ""
}

// versionCache memoizes the install-level version per update-check file.
type versionCache struct {
	mu    sync.Mutex
	files map[string]cachedVersion
}

type cachedVersion struct {
	size    int64
	mtime   time.Time
	version string
}

// version returns `last_seen_version` from the update-check file at path
// (the version of the binary that last ran), or "" when absent,
// malformed, or not a bounded semver-ish token. `latest_version` is the
// newest UPSTREAM release, not what is installed, and is never used.
func (c *versionCache) version(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
		return ""
	}
	c.mu.Lock()
	if c.files == nil {
		c.files = map[string]cachedVersion{}
	}
	if f, ok := c.files[path]; ok && f.size == fi.Size() && f.mtime.Equal(fi.ModTime()) {
		c.mu.Unlock()
		return f.version
	}
	c.mu.Unlock()

	v := ""
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // fixed cache file beside a watched archive dir
		var f struct {
			LastSeenVersion string `json:"last_seen_version"`
		}
		if json.Unmarshal(b, &f) == nil && validVersion(f.LastSeenVersion) {
			v = strings.TrimSpace(f.LastSeenVersion)
		}
	}
	c.mu.Lock()
	c.files[path] = cachedVersion{size: fi.Size(), mtime: fi.ModTime(), version: v}
	c.mu.Unlock()
	return v
}

// validVersion accepts a short dotted numeric token ("0.180.2",
// optionally with a -pre/+build suffix).
func validVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 32 || v[0] < '0' || v[0] > '9' || !strings.Contains(v, ".") {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-', r == '+':
		default:
			return false
		}
	}
	return true
}

// stateRootFor picks the archive dir (and so the install) a session
// belongs to: the root its archive was found under, else the archive root
// sharing the longest path prefix with the event log (a WSL workspace
// pairs with the WSL state dir, a /mnt/c one with the Windows one), ties
// going to the first (native) root.
func (a *Adapter) stateRootFor(eventsPath, archiveRoot string) string {
	if archiveRoot != "" {
		return archiveRoot
	}
	best, bestLen := "", -1
	norm := func(p string) string { return strings.ToLower(filepath.ToSlash(filepath.Clean(p))) }
	ev := norm(eventsPath)
	for _, r := range a.roots {
		if isWorkspaceSessionsRoot(r) {
			continue
		}
		n := commonPrefixLen(ev, norm(r))
		if n > bestLen {
			best, bestLen = r, n
		}
	}
	return best
}

// commonPrefixLen returns the length of the longest shared prefix.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
