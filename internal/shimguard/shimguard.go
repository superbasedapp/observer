package shimguard

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// ShimMarker is carried on the second line of every command-wrapping shim. It
// is how a shim recognizes ANOTHER shim while walking PATH for the real
// command, how the observer launchers' resolver skips shims
// (toolresolve.Env.ExcludeMarker), and how the shell-wrap applier recognizes
// files it owns in the shim directory (it never deletes a file that does not
// carry it). internal/shellwrap re-exports it.
const ShimMarker = "SBO-SHELLWRAP-SHIM"

// IsShim reports whether a file's head bytes carry the shim marker.
func IsShim(head []byte) bool {
	return strings.Contains(string(head), ShimMarker)
}

// DefaultShimDir is the observer-owned shim directory under home, in goos's
// path notation (backslashes for "windows", so a WSL daemon can name a
// Windows home's directory).
func DefaultShimDir(goos, home string) string {
	if goos == "windows" {
		return strings.Join([]string{home, ".observer", "shims"}, `\`)
	}
	return path.Join(home, ".observer", "shims")
}

// LookPath is exec.LookPath for callers that want the VENDOR binary: a hit
// that is a command-wrapping shim (it carries ShimMarker) is skipped and the
// PATH walk continues, so a shim named `claude` is never reported as "claude
// is installed" nor run by a caller that sets up its own routing. Launchers
// resolve through internal/toolresolve, which applies the same exclusion;
// this is for the few call sites that use a bare PATH lookup.
func LookPath(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil || !IsShimFile(p) {
		return p, err
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		// A path with a separator makes exec.LookPath check that one file
		// (applying PATHEXT on Windows) instead of walking PATH again.
		c, err := exec.LookPath(filepath.Join(dir, name))
		if err == nil && !IsShimFile(c) {
			return c, nil
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

// IsShimFile reports whether the file at p is a command-wrapping shim: its
// first 512 bytes carry ShimMarker. An unreadable file is not a shim.
func IsShimFile(p string) bool {
	head, err := ReadHead(p, 512)
	return err == nil && IsShim(head)
}

// ReadHead returns up to n leading bytes of the file at p (fewer when the
// file is shorter). It is the one shim-detection read: LookPath's PATH walk
// and the shell-wrap applier's shim-directory scan both use it.
func ReadHead(p string, n int) ([]byte, error) {
	f, err := os.Open(p) /* #nosec G304 -- a binary exec.LookPath itself located on PATH, or a file in the observer-owned shim directory; never request-derived */ //nolint:gosec // G703: a PATH hit or a file in the observer-owned shim directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:got], nil
}
