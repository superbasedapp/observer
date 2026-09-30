package shellwrapsvc

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// LookPath is exec.LookPath for callers that want the VENDOR binary: a hit
// that is a command-wrapping shim (it carries shellwrap.ShimMarker) is
// skipped and the PATH walk continues, so a shim named `claude` is never
// reported as "claude is installed" nor run by a caller that sets up its own
// routing. Launchers resolve through internal/toolresolve, which applies the
// same exclusion; this is for the few call sites that use a bare PATH lookup.
func LookPath(name string) (string, error) {
	p, err := exec.LookPath(name)
	if err != nil || !isShimFile(p) {
		return p, err
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		// A path with a separator makes exec.LookPath check that one file
		// (applying PATHEXT on Windows) instead of walking PATH again.
		c, err := exec.LookPath(filepath.Join(dir, name))
		if err == nil && !isShimFile(c) {
			return c, nil
		}
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

func isShimFile(p string) bool {
	head, err := readHead(p, 512)
	return err == nil && shellwrap.IsShim(head)
}
