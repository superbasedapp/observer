package mirrorbase

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	mu       sync.RWMutex
	override string
)

// Base returns the directory under which per-tool mirror subtrees are
// created (the "<UserCacheDir>/superbased-observer" level). When
// SetBaseForProcess has been called, that directory is returned
// instead and err is always nil.
func Base() (string, error) {
	mu.RLock()
	o := override
	mu.RUnlock()
	if o != "" {
		return o, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "superbased-observer"), nil
}

// SetBaseForProcess redirects every subsequent mirror write for the
// remainder of the process to dir. It exists for single-command
// lifecycles (the one-shot usage report) that must confine all writes
// to a scratch directory; long-lived daemon assemblies must never
// call it. Passing "" restores the default derivation (test use).
func SetBaseForProcess(dir string) {
	mu.Lock()
	override = dir
	mu.Unlock()
}
