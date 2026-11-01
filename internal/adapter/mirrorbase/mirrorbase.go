// Package mirrorbase owns the base directory under which adapters
// stage read-only mirror copies of foreign-mount (e.g. DrvFs) SQLite
// stores that cannot be opened in place. Seven adapters (opencode,
// kilocode, clinecli, devin, kirocli, goose, crush) previously derived
// this base inline from os.UserCacheDir(); this package is the single
// owner (CLAUDE.md rule 4) so an alternate-lifecycle caller — the
// `observer usage` one-shot, whose contract is "nothing is written
// outside a temp directory it deletes" — can redirect every mirror
// write into its own scratch directory with one call.
//
// The daemon/watcher path never calls SetBaseForProcess, so its
// base is the old inline derivation:
// <UserCacheDir>/superbased-observer/<tool>-mirror/<hash>/.
//
// Since T-927 the package also owns the staging itself (Stage): every
// adapter's mirror is built here from an allow-list of the tables it
// queries, never as a byte copy of the vendor file, so credential tables
// that share a store with the conversation (OpenCode `credential`, Kiro
// CLI `auth_kv`, Qoder Work's BYOK and OAuth tables) never leave it. See
// docs/security.md MIRROR-CRED-1.
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
