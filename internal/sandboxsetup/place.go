package sandboxsetup

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// place.go holds the pure placement rules of a pinned download (plan
// sections 3.2 and 6): where a pin's file goes, with which modes, and
// whether a from_file path may stand in for the download. The cmd-side
// downloader (cmd/observer/sandbox_setup_download.go) does the I/O and
// asks these functions; nothing here touches the filesystem.

// The tools directory's fixed path elements under the XDG data home.
const (
	// ToolsAppDir is Observer's directory under the data home.
	ToolsAppDir = "superbased-observer"
	// ToolsDirName holds every pinned sandbox host tool.
	ToolsDirName = "sandbox-tools"
	// observerStateDir is ~/.observer, which the isolation engine binds into
	// a box: a placed tool never lives under it.
	observerStateDir = ".observer"
)

// The modes of a placed pin.
const (
	// PlacedFileMode is a placed tool's mode: executable by the user, never
	// writable by anyone else.
	PlacedFileMode fs.FileMode = 0o755
	// PlacedDirMode is every directory the downloader creates: the user's
	// only, so no other account can swap the file between placing and use.
	PlacedDirMode fs.FileMode = 0o700
)

// The placement refusals, matched with errors.Is.
var (
	// ErrNoDataHome: neither an absolute XDG_DATA_HOME nor an absolute home
	// directory is known.
	ErrNoDataHome = errors.New("sandboxsetup: no absolute data home")
	// ErrBadPinPath: a pin's id or version is not one safe path element.
	ErrBadPinPath = errors.New("sandboxsetup: the pin's id or version is not a safe path element")
	// ErrPlacementForbidden: the target is relative, or under ~/.observer,
	// or under a path a sandbox binds writable.
	ErrPlacementForbidden = errors.New("sandboxsetup: the placement target is not allowed")
	// ErrFromFileSymlink: a from_file path is a symbolic link.
	ErrFromFileSymlink = errors.New("sandboxsetup: the file is a symbolic link")
	// ErrFromFileNotRegular: a from_file path is not a regular file (a
	// directory, a device, a pipe).
	ErrFromFileNotRegular = errors.New("sandboxsetup: the file is not a regular file")
	// ErrFromFileSize: a from_file path is empty or larger than the pin.
	ErrFromFileSize = errors.New("sandboxsetup: the file's size does not fit the pin")
	// ErrFromFileRelative: a from_file path is not absolute.
	ErrFromFileRelative = errors.New("sandboxsetup: the file path is not absolute")
)

// ToolsRoot is <data home>/superbased-observer/sandbox-tools, where the data
// home is XDG_DATA_HOME when it is set and absolute (the XDG spec ignores a
// relative value) and <home>/.local/share otherwise. getenv is the
// environment lookup (os.Getenv in production).
func ToolsRoot(getenv func(string) string, home string) (string, error) {
	base := ""
	if getenv != nil {
		if x := getenv("XDG_DATA_HOME"); x != "" && filepath.IsAbs(x) {
			base = x
		}
	}
	if base == "" {
		if home == "" || !filepath.IsAbs(home) {
			return "", ErrNoDataHome
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(filepath.Clean(base), ToolsAppDir, ToolsDirName), nil
}

// safeElement reports whether s is one plain path element: non-empty, not
// "." or "..", and only letters, digits, dot, dash and underscore.
func safeElement(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// PinDir is the directory a pin's file is placed in: <root>/<pin id>/<version>.
func PinDir(root string, p Pin) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: root %q", ErrPlacementForbidden, root)
	}
	if !safeElement(p.ID) || !safeElement(p.Version) {
		return "", fmt.Errorf("%w: %q %q", ErrBadPinPath, p.ID, p.Version)
	}
	return filepath.Join(root, p.ID, p.Version), nil
}

// PinPath is the placed file's path: <PinDir>/<pin id>.
func PinPath(root string, p Pin) (string, error) {
	dir, err := PinDir(root, p)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, p.ID), nil
}

// within reports whether path is root or below it (both cleaned).
func within(path, root string) bool {
	if path == root {
		return true
	}
	if !strings.HasSuffix(root, string(filepath.Separator)) {
		root += string(filepath.Separator)
	}
	return strings.HasPrefix(path, root)
}

// CheckPlacement refuses a target that is not absolute, that lies under
// <home>/.observer (the isolation engine binds it into a box), or that lies
// under any of bound, the paths a sandbox binds writable. Empty entries of
// bound are skipped; a relative entry is refused as a misuse.
func CheckPlacement(target, home string, bound []string) error {
	if target == "" || !filepath.IsAbs(target) {
		return fmt.Errorf("%w: %q is not absolute", ErrPlacementForbidden, target)
	}
	t := filepath.Clean(target)
	roots := make([]string, 0, len(bound)+1)
	if home != "" {
		if !filepath.IsAbs(home) {
			return fmt.Errorf("%w: home %q is not absolute", ErrPlacementForbidden, home)
		}
		roots = append(roots, filepath.Join(home, observerStateDir))
	}
	for _, b := range bound {
		if b == "" {
			continue
		}
		if !filepath.IsAbs(b) {
			return fmt.Errorf("%w: bound path %q is not absolute", ErrPlacementForbidden, b)
		}
		roots = append(roots, filepath.Clean(b))
	}
	for _, r := range roots {
		if within(t, r) {
			return fmt.Errorf("%w: %s is under %s", ErrPlacementForbidden, t, r)
		}
	}
	return nil
}

// CheckFromFile judges a from_file path offered in place of the download:
// absolute, a regular file and not a symbolic link (fi must come from an
// Lstat of path), and of a size within the pin's (more than zero bytes, at
// most p.Size). The sha256 is the caller's check, on the bytes it copies.
func CheckFromFile(path string, fi fs.FileInfo, p Pin) error {
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %q", ErrFromFileRelative, path)
	}
	if fi == nil {
		return fmt.Errorf("%w: no file facts for %s", ErrFromFileNotRegular, path)
	}
	m := fi.Mode()
	if m&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrFromFileSymlink, path)
	}
	if !m.IsRegular() {
		return fmt.Errorf("%w: %s", ErrFromFileNotRegular, path)
	}
	if fi.Size() <= 0 || fi.Size() > p.Size {
		return fmt.Errorf("%w: %s is %d bytes, the pin is %d", ErrFromFileSize, path, fi.Size(), p.Size)
	}
	return nil
}
