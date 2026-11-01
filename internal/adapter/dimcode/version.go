package dimcode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DimCode's store records NO version (no column, no log line, no settings
// key), so the tool version is the INSTALLED build, resolved from the two
// places an install leaves a version on disk (operator ruling 2026-10-21:
// stamp every session, prefer a per-session value when the store has one,
// else fall back to the install-level one):
//
//  1. <dimcode home>/binaries/dimcode-<platform>/<version>/ - the runtime the
//     npm shim downloads on first run (live: WSL 0.5.21). The highest
//     semver-named directory is the one in use.
//  2. the npm package's own package.json (`name: "dimcode"`), where the
//     shim lives (live: Windows, no binaries dir, %APPDATA%\npm\node_modules).
//
// The store root is <home>/.dimcode/v2, so the DimCode home is its parent and
// the user home its grandparent. Only version strings are read; the
// directory names and package.json's name/version are not secrets.

// semverDir matches a version-named directory (0.5.21, 1.2.3-rc.1).
var semverDir = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)

// npmPackageDirs are the npm global install locations, relative to the user
// home, probed for the dimcode package when no binaries dir exists.
var npmPackageDirs = [][]string{
	{"AppData", "Roaming", "npm", "node_modules", "dimcode"},
	{".npm-global", "lib", "node_modules", "dimcode"},
	{".local", "lib", "node_modules", "dimcode"},
	{".bun", "install", "global", "node_modules", "dimcode"},
}

// installVersion resolves the installed DimCode version for the store whose
// directory is root, "" when nothing is found.
func installVersion(root string) string {
	dimHome := filepath.Dir(root)
	if v := binariesVersion(filepath.Join(dimHome, "binaries")); v != "" {
		return v
	}
	userHome := filepath.Dir(dimHome)
	for _, rel := range npmPackageDirs {
		if v := packageVersion(filepath.Join(append([]string{userHome}, rel...)...)); v != "" {
			return v
		}
	}
	return ""
}

// binariesVersion returns the highest version-named directory under any
// binaries/dimcode-<platform>/ directory.
func binariesVersion(binaries string) string {
	platforms, err := os.ReadDir(binaries)
	if err != nil {
		return ""
	}
	best := ""
	for _, p := range platforms {
		if !p.IsDir() || !strings.HasPrefix(p.Name(), "dimcode") {
			continue
		}
		vers, err := os.ReadDir(filepath.Join(binaries, p.Name()))
		if err != nil {
			continue
		}
		for _, v := range vers {
			if v.IsDir() && semverDir.MatchString(v.Name()) && (best == "" || semverLess(best, v.Name())) {
				best = v.Name()
			}
		}
	}
	return best
}

// packageVersion reads name + version from <dir>/package.json and returns the
// version only for the dimcode package itself.
func packageVersion(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // G304: fixed install locations under the user home
	if err != nil {
		return ""
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &pkg) != nil || pkg.Name != "dimcode" || !semverDir.MatchString(pkg.Version) {
		return ""
	}
	return pkg.Version
}

// semverLess reports a < b comparing the numeric major.minor.patch core; the
// pre-release tail only breaks a tie (a release outranks its pre-release).
func semverLess(a, b string) bool {
	ac, at := splitSemver(a)
	bc, bt := splitSemver(b)
	for i := 0; i < 3; i++ {
		if ac[i] != bc[i] {
			return ac[i] < bc[i]
		}
	}
	switch {
	case at == bt:
		return false
	case at == "":
		return false
	case bt == "":
		return true
	}
	return at < bt
}

func splitSemver(v string) ([3]int, string) {
	var core [3]int
	tail := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v, tail = v[:i], v[i:]
	}
	for i, part := range strings.SplitN(v, ".", 3) {
		core[i], _ = strconv.Atoi(part)
	}
	return core, tail
}
