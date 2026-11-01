package autohand

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// sessionsDirName is the vendor's session directory under its data home.
const sessionsDirName = "sessions"

// dataDirName is the vendor's data directory under $HOME on every OS.
const dataDirName = ".autohand"

// rootSpec is one watch root together with the logical OS of the home it
// belongs to ("" when unknown). The OS is what lets the adapter recognise a
// device-synced copy of a session (see foreignCopy).
type rootSpec struct {
	path string
	os   string
}

// defaultRootSpecs returns ~/.autohand/sessions under every cross-mount
// resolved $HOME (Autohand lays its data home out identically on Linux,
// macOS and Windows, so a WSL2 observer reads /mnt/c/Users/<u>/.autohand and a
// Windows observer reads \\wsl.localhost\<distro>\home\<u>\.autohand), plus
// $AUTOHAND_HOME/sessions when the operator moved the vendor's data home
// (AUTOHAND_HOME is read by the vendor at startup; it can only describe the
// running process's own OS). Duplicates and empties are dropped.
func defaultRootSpecs() []rootSpec {
	seen := map[string]bool{}
	var out []rootSpec
	add := func(p, osName string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, rootSpec{path: p, os: osName})
	}
	if h := strings.TrimSpace(os.Getenv("AUTOHAND_HOME")); h != "" {
		add(filepath.Join(h, sessionsDirName), runtimeHomeOS())
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, dataDirName, sessionsDirName), h.OS)
	}
	return out
}

// runtimeHomeOS names the logical OS of the running process's home.
func runtimeHomeOS() string {
	switch runtime.GOOS {
	case "windows":
		return crossmount.OSWindows
	case "darwin":
		return crossmount.OSDarwin
	default:
		return crossmount.OSLinux
	}
}

// rootPaths projects specs onto their paths.
func rootPaths(specs []rootSpec) []string {
	paths := make([]string, 0, len(specs))
	for _, s := range specs {
		paths = append(paths, s.path)
	}
	return paths
}

// homeOSFor returns the logical OS of the watch root that contains path
// (longest matching root wins), or "" when no root with a known OS does.
func (a *Adapter) homeOSFor(path string) string {
	best, bestOS := -1, ""
	clean := filepath.Clean(path)
	for _, s := range a.specs {
		if s.os == "" {
			continue
		}
		root := s.path
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			if len(root) > best {
				best, bestOS = len(root), s.os
			}
		}
	}
	return bestOS
}

// pathFamily classifies a project path by the OS family that could have
// produced it: "windows" for a drive-letter or UNC path, "posix" for an
// absolute slash path, "" otherwise (relative, empty, unrecognisable).
func pathFamily(p string) string {
	p = strings.TrimSpace(p)
	switch {
	case len(p) >= 3 && isASCIILetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		return "windows"
	case strings.HasPrefix(p, `\\`):
		return "windows"
	case strings.HasPrefix(p, "/"):
		return "posix"
	}
	return ""
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// foreignCopy reports whether the session file at path is a device-sync copy
// rather than an original: its project path belongs to the other OS family
// than the home it sits under. Unknown on either side is never foreign.
func (a *Adapter) foreignCopy(path, projectPath string) bool {
	family := pathFamily(projectPath)
	if family == "" {
		return false
	}
	home := a.homeOSFor(path)
	switch home {
	case "":
		return false
	case crossmount.OSWindows:
		return family != "windows"
	default:
		return family != "posix"
	}
}
