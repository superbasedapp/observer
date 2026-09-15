//go:build unix

package attachsock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// errLockHeld is returned by acquireListenLock when another process already
// holds the attach listen lock — a live daemon. The unix transport's Listen
// maps it to ErrSocketLiveDaemon. It lives beside its only producer (the flock
// is unix-only; the Windows transport gets its live-daemon guard from
// FILE_FLAG_FIRST_PIPE_INSTANCE instead).
var errLockHeld = errors.New("attachsock: attach listen lock is held by another process")

// listenLock is a HELD advisory (flock) lock on the attach dir's lock file. It
// stays open for the LISTENER's lifetime (A3-5): ListenSocket wraps the
// returned net.Listener so its Close releases the lock. While it is held, a
// competing daemon's non-blocking flock attempt fails — a probe-free, positive
// signal that a live daemon owns the socket, closing the probe-false-negative
// steal window.
type listenLock struct {
	f *os.File
}

// release unlocks and closes the lock file. Safe to call more than once.
func (l *listenLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// acquireListenLock takes a NON-BLOCKING exclusive advisory (flock) lock on
// path, creating it 0600 inside the already-owner-only attach dir. On success
// the lock is HELD (the file stays open) until the returned lock's release runs
// — ListenSocket ties that to the listener's Close (A3-5). If another process
// already holds the lock, errLockHeld is returned WITHOUT blocking, so the
// caller can report a live daemon with no probe at all.
func acquireListenLock(path string) (*listenLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLockHeld
		}
		return nil, fmt.Errorf("flock %q: %w", path, err)
	}
	return &listenLock{f: f}, nil
}
