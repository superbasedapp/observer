package codebuddy

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CodeBuddy records its version in exactly two on-disk places (grounded
// 2026-10-21, v2.171.0): the per-process start line of its diagnostic log
// (see logs.go, the PER-SESSION source) and the installed npm package's
// package.json (the INSTALL-level source). The transcript carries neither;
// the only `version` field in it is the file-history backup counter.
//
// Operator ruling 2026-10-21: every session is stamped, preferring the
// per-session value. The install-level fallback is the version installed NOW,
// so it can postdate a session recorded under an older release; the stamp is
// still the best recorded fact the machine holds and the first-wins store
// write never overwrites a per-session value arriving later.

// systemNodeModules are the npm global roots outside the user's home, a
// package var so tests can empty it and stay hermetic.
var systemNodeModules = []string{
	"/usr/lib/node_modules",
	"/usr/local/lib/node_modules",
	"/opt/homebrew/lib/node_modules",
}

// packageRel is the package's location under a node_modules directory.
var packageRel = filepath.Join("@tencent-ai", "codebuddy-code", "package.json")

// installVersionCache memoises the package.json probe, per data home.
var installVersionCache = struct {
	sync.Mutex
	m map[string]installVersionEntry
}{m: map[string]installVersionEntry{}}

type installVersionEntry struct {
	version string
	at      time.Time
}

// installVersion returns the version of the installed CodeBuddy npm package
// reachable from the data home's user home, "" when none is found. The result
// is cached for a minute (a parse pass touches it once per file).
func installVersion(home string) string {
	installVersionCache.Lock()
	defer installVersionCache.Unlock()
	if e, ok := installVersionCache.m[home]; ok && time.Since(e.at) < time.Minute {
		return e.version
	}
	v := probeInstallVersion(home)
	installVersionCache.m[home] = installVersionEntry{version: v, at: time.Now()}
	return v
}

func probeInstallVersion(home string) string {
	if home == "" {
		return ""
	}
	user := filepath.Dir(home)
	candidates := []string{
		// Windows npm global prefix (%APPDATA%\npm).
		filepath.Join(user, "AppData", "Roaming", "npm", "node_modules", packageRel),
		// Common per-user prefixes on Linux / macOS.
		filepath.Join(user, ".npm-global", "lib", "node_modules", packageRel),
		filepath.Join(user, ".local", "lib", "node_modules", packageRel),
		filepath.Join(user, "node_modules", packageRel),
	}
	for _, root := range systemNodeModules {
		candidates = append(candidates, filepath.Join(root, packageRel))
	}
	for _, c := range candidates {
		if v := readPackageVersion(c); v != "" {
			return v
		}
	}
	return ""
}

// readPackageVersion reads a package.json's name + version, bounded, and only
// accepts the CodeBuddy package.
func readPackageVersion(path string) string {
	f, err := os.Open(path) //nolint:gosec // fixed package-manager path under the user's home
	if err != nil {
		return ""
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return ""
	}
	var m struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &m) != nil || m.Name != "@tencent-ai/codebuddy-code" {
		return ""
	}
	return versionToken(strings.TrimSpace(m.Version))
}

// toolVersionFor resolves the version to stamp on a session: the logging
// process's own start line first, then the newest start line in the same
// logs, then the installed package.
func toolVersionFor(home string, facts sessionLogFacts) string {
	switch {
	case facts.Version != "":
		return facts.Version
	case facts.InstallVersion != "":
		return facts.InstallVersion
	default:
		return installVersion(home)
	}
}
