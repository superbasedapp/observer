package orgclient

import (
	"os"
	"path/filepath"
	"strings"
)

// Once-per-install notices (WINNODE2, section 16c). A routine downgrade
// warning (the OS keychain is unavailable, the machine key is unavailable)
// used to print on every CLI call, and over PowerShell remoting each stderr
// line becomes a red error record even when the command succeeded. The
// warning now prints once per install and state: the state last warned
// about is kept in a small notice marker under <observer dir>/notices. It is
// deliberately NOT a file in a credential store, so writing it says nothing
// about where a credential lives and a read-only command never creates a
// credential-store marker.

// noticeDirName is the notice markers' directory under the observer dir.
const noticeDirName = "notices"

// noticePath is the marker file for key under dir.
func noticePath(dir, key string) string {
	return filepath.Join(dir, noticeDirName, sanitizeNoticeKey(key))
}

// sanitizeNoticeKey keeps a key to a portable file name.
func sanitizeNoticeKey(key string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, key)
}

// noticeFirst reports whether the notice key has not yet been given for
// state on this install, and records state when it has not. An empty dir
// (no observer dir known) always answers true, so the caller falls back to
// its per-process behaviour. A marker that cannot be written still answers
// true: a repeated warning beats a lost one.
func noticeFirst(dir, key, state string) bool {
	if dir == "" {
		return true
	}
	p := noticePath(dir, key)
	if b, err := os.ReadFile(p); err == nil && string(b) == state {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err == nil {
		_ = os.WriteFile(p, []byte(state), 0o600)
	}
	return true
}

// noticeReset forgets the notice key, so its next occurrence is given again.
func noticeReset(dir, key string) {
	if dir == "" {
		return
	}
	_ = os.Remove(noticePath(dir, key))
}
