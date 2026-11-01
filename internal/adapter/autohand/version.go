package autohand

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	npmPackageName = "autohand-cli"
	maxPackageJSON = 256 << 10
)

// npmRoots are the npm global node_modules locations probed under a user home
// (slash-separated, `*` globs one path element).
var npmRoots = []string{
	"AppData/Roaming/npm/node_modules",
	"AppData/Roaming/nvm/*/node_modules",
	".npm-global/lib/node_modules",
	".local/lib/node_modules",
	".bun/install/global/node_modules",
	".nvm/versions/node/*/lib/node_modules",
}

// systemNpmRoots are probed only when the data home is the running process's
// own home.
var systemNpmRoots = []string{
	"/usr/local/lib/node_modules",
	"/usr/lib/node_modules",
	"/opt/homebrew/lib/node_modules",
}

type pkgCacheItem struct {
	mod     time.Time
	size    int64
	version string
}

// readPackageVersion returns the version of an autohand-cli package.json, or
// "" when the file is not that package.
func (a *Adapter) readPackageVersion(path string) string {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxPackageJSON {
		return ""
	}
	a.mu.Lock()
	if c, ok := a.pkgCache[path]; ok && c.mod.Equal(fi.ModTime()) && c.size == fi.Size() {
		a.mu.Unlock()
		return c.version
	}
	a.mu.Unlock()
	f, err := os.Open(path) //nolint:gosec // npm package manifest next to the vendor install
	if err != nil {
		return ""
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxPackageJSON))
	if err != nil {
		return ""
	}
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	version := ""
	if json.Unmarshal(body, &p) == nil && p.Name == npmPackageName && versionPattern.MatchString(strings.TrimSpace(p.Version)) {
		version = strings.TrimSpace(p.Version)
	}
	a.mu.Lock()
	if a.pkgCache == nil {
		a.pkgCache = map[string]pkgCacheItem{}
	}
	a.pkgCache[path] = pkgCacheItem{mod: fi.ModTime(), size: fi.Size(), version: version}
	a.mu.Unlock()
	return version
}

// installedVersion returns the npm-installed autohand-cli version visible from
// the data home's user home (install-level: the version installed NOW). The
// vendor's native builds (curl / irm installer) carry no readable manifest and
// yield "".
func (a *Adapter) installedVersion(dataHome string) string {
	var homes []string
	runtimeHome, _ := os.UserHomeDir()
	if filepath.Base(dataHome) == dataDirName {
		homes = append(homes, filepath.Dir(dataHome))
	} else if runtimeHome != "" {
		homes = append(homes, runtimeHome) // custom AUTOHAND_HOME
	}
	var roots []string
	for _, h := range homes {
		for _, r := range npmRoots {
			roots = append(roots, filepath.Join(h, filepath.FromSlash(r)))
		}
		if runtimeHome != "" && filepath.Clean(h) == filepath.Clean(runtimeHome) {
			for _, r := range systemNpmRoots {
				roots = append(roots, filepath.FromSlash(r))
			}
		}
	}
	for _, r := range roots {
		matches := []string{r}
		if strings.Contains(r, "*") {
			matches, _ = filepath.Glob(r)
			sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		}
		for _, m := range matches {
			if v := a.readPackageVersion(filepath.Join(m, npmPackageName, "package.json")); v != "" {
				return v
			}
		}
	}
	return ""
}

// toolVersion resolves the version of the CLI that ran the session. The
// metadata records none for the terminal client (clientVersion is a HOST's
// env, never autohand's own), so, in order of precision:
//
//  1. an error.log record written during the session (it names the build that
//     ran: cli.version);
//  2. the installed npm package version (install-level);
//  3. the newest error.log record written before the session began (the
//     build last seen running; install-level history).
//
// The vendor's version-check-*.json carries only the latest AVAILABLE release,
// not the running build, so it is deliberately not used.
func (a *Adapter) toolVersion(dataHome string, m metadata, entries []logEntry) string {
	for _, e := range entriesFor(entries, m) {
		if e.Version != "" {
			return e.Version
		}
	}
	if v := a.installedVersion(dataHome); v != "" {
		return v
	}
	created := parseTime(m.CreatedAt)
	if created.IsZero() {
		return ""
	}
	best := ""
	for _, e := range entries {
		if e.Version != "" && !e.When.After(created) {
			best = e.Version
		}
	}
	return best
}

// toolVersionStamp builds the per-session version output, nil when unknown.
func (a *Adapter) toolVersionStamp(sessID, dataHome string, m metadata, entries []logEntry) []models.SessionToolVersion {
	if sessID == "" {
		return nil
	}
	v := a.toolVersion(dataHome, m, entries)
	if v == "" {
		return nil
	}
	return []models.SessionToolVersion{{SessionID: sessID, Version: v}}
}
