package hook

import (
	"os"
	"path/filepath"
	"sync"
)

// The hook forensics logs (hook-events.jsonl, cursor-stop-debug.jsonl) live
// in the Observer home of the config the invocation runs under: the
// directory of [observer] db_path, the convention every other node state
// file follows (daemon.log, the delivery credential, the OTLP ingest
// token). Live proof 2026-10-21: they used to land in ~/.observer even when
// --config pointed db_path elsewhere, so a sandboxed or second install
// wrote its forensics into the operator's real home.
//
// The hook package does no config I/O of its own: the `observer hook`
// command installs a resolver (SetStateDirResolver) that is run at most
// once, lazily, on the first log write, so an invocation that writes no
// log pays nothing. With no resolver, or one that returns "", the logs
// fall back to ~/.observer, the default db_path's directory.
var stateDir struct {
	mu       sync.Mutex
	resolve  func() string
	resolved bool
	dir      string
}

// SetStateDirResolver installs how the hook forensics logs find the
// Observer home (the directory of the resolved config's db_path). fn runs
// at most once, on the first log write; nil restores the ~/.observer
// default.
func SetStateDirResolver(fn func() string) {
	stateDir.mu.Lock()
	defer stateDir.mu.Unlock()
	stateDir.resolve = fn
	stateDir.resolved = false
	stateDir.dir = ""
}

// hookStateDir returns the directory the forensics logs are written to,
// "" when neither the resolver nor the user's home answers.
func hookStateDir() string {
	stateDir.mu.Lock()
	if !stateDir.resolved && stateDir.resolve != nil {
		stateDir.dir = stateDir.resolve()
		stateDir.resolved = true
	}
	dir := stateDir.dir
	stateDir.mu.Unlock()
	if dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".observer")
}

// stateFilePath joins name onto hookStateDir, "" when there is no
// directory.
func stateFilePath(name string) string {
	dir := hookStateDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, name)
}
