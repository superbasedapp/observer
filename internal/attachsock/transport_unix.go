//go:build unix

package attachsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// transport_unix.go is the AF_UNIX transport: the original attach channel,
// moved behind the Transport seam unchanged. Security model (A1): the socket's
// PARENT DIRECTORY is 0700, so connect(2) — which requires execute (search)
// permission on the parent dir — is OS-enforced owner-only with NO race
// window, regardless of the socket file's own mode or the process umask.

// unixTransport serves the attach channel over an AF_UNIX socket.
type unixTransport struct{}

// defaultTransport is the unix AF_UNIX transport on this platform.
var defaultTransport Transport = unixTransport{}

// Describe implements Transport.
func (unixTransport) Describe() string { return TransportUnixSocket }

// Supported implements Transport: unix enforces the owner-only model this
// transport relies on (connect(2) needs search permission on the 0700 parent),
// so attach serves here.
func (unixTransport) Supported() bool { return true }

// Endpoint implements Transport: the AF_UNIX socket path under the DB dir. It
// refuses a path at/over UNIX_PATH_MAX with an actionable message rather than
// handing back an endpoint whose bind would fail with a causeless
// "invalid argument" (DI-09).
func (unixTransport) Endpoint(dbPath string) (string, error) {
	path := SocketPath(dbPath)
	if err := checkSocketPathLength(path); err != nil {
		return "", fmt.Errorf("attachsock.Endpoint: %w", err)
	}
	return path, nil
}

// Dial implements Transport: a plain AF_UNIX connect bounded by timeout and
// ctx. The ErrDaemonUnreachable wrapping belongs to the package-level Dial, so
// this returns the raw dial error.
func (unixTransport) Dial(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "unix", endpoint)
}

// lockedListener wraps a net.Listener whose Close ALSO owns the socket-path
// unlink AND releases the held listen lock, so the flock lives exactly as long
// as the listener (A3-5) and the path is removed by — and only by — the holder
// that bound it (F3).
type lockedListener struct {
	net.Listener
	lock      *listenLock
	path      string      // the bound socket path (owned unlink target)
	boundInfo os.FileInfo // stat of the socket we bound, for a SameFile unlink guard
	closeOnce sync.Once
}

// Close closes the underlying listener, unlinks OUR socket path, then releases
// the held listen lock, strictly in that order, exactly once. The ordering is
// load-bearing (F3): releasing the flock BEFORE the unlink would let a
// replacement daemon acquire the lock and bind a NEW socket at the same path,
// which our unlink would then destroy. Removing the path while still holding
// the lock closes that window. The os.SameFile guard is belt-and-braces —
// even under the held lock we only remove the path if it still refers to the
// exact inode we bound (the stdlib's own unlink-on-close is disabled in Listen
// so this is the single unlink site).
func (l *lockedListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() {
		if l.path != "" && l.boundInfo != nil {
			if cur, statErr := os.Stat(l.path); statErr == nil && os.SameFile(l.boundInfo, cur) {
				_ = os.Remove(l.path)
			}
		}
		l.lock.release()
	})
	return err
}

// Listen implements Transport: it creates the owner-only attach socket at
// endpoint. The parent directory is created (and, if pre-existing and looser,
// tightened to) 0700; the socket itself is additionally chmod 0600
// (belt-and-braces). Before binding we refuse to steal an endpoint a LIVE
// daemon is serving (A9): an existing socket is probe-dialed and only unlinked
// when the dial fails (stale). A non-socket file at the path is never removed.
func (t unixTransport) Listen(endpoint string) (net.Listener, error) {
	// Fail EARLY and actionably (DI-09): a path at/over the 108-byte
	// UNIX_PATH_MAX would otherwise reach net.Listen and fail with a bare
	// "bind: invalid argument", which names no cause and no fix. Any operator
	// with a deep $HOME or a relocated [observer].db_path can hit this.
	if err := checkSocketPathLength(endpoint); err != nil {
		return nil, fmt.Errorf("attachsock.ListenSocket: %w", err)
	}
	dir := filepath.Dir(endpoint)
	// Create the parent 0700. MkdirAll won't tighten an existing looser dir, so
	// we stat + chmod it below to guarantee owner-only search permission.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("attachsock.ListenSocket: create attach dir %q: %w", dir, err)
	}
	dfi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("attachsock.ListenSocket: stat attach dir %q: %w", dir, err)
	}
	if !dfi.IsDir() {
		return nil, fmt.Errorf("attachsock.ListenSocket: attach path parent %q is not a directory", dir)
	}
	if perm := dfi.Mode().Perm(); perm != 0o700 {
		// A pre-existing dir may be looser (e.g. the DB dir shared with other
		// state). Tighten it to owner-only so connect() is owner-enforced.
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("attachsock.ListenSocket: tighten attach dir %q perms (%o→0700): %w", dir, perm, err)
		}
	}

	// A3-5/A6/A9: acquire the listen lock and HOLD it for the listener's
	// lifetime. A NON-BLOCKING flock is the primary live-daemon detector — if
	// another daemon holds it, we bail with ErrSocketLiveDaemon BEFORE any
	// probe/unlink, removing the probe-false-negative steal window (a daemon
	// whose accept loop is momentarily wedged would fail the probe-dial yet
	// still hold the lock). Once acquired the lock also serializes the
	// stat→probe→remove→listen sequence against a second local daemon.
	lock, lerr := acquireListenLock(filepath.Join(dir, "attach.lock"))
	if lerr != nil {
		if errors.Is(lerr, errLockHeld) {
			return nil, fmt.Errorf("attachsock.ListenSocket: %w at %q", ErrSocketLiveDaemon, endpoint)
		}
		return nil, fmt.Errorf("attachsock.ListenSocket: acquire listen lock: %w", lerr)
	}
	// The lock is HELD from here. Release it on every error path below; on
	// success the returned lockedListener's Close releases it (A3-5).
	listening := false
	defer func() {
		if !listening {
			lock.release()
		}
	}()

	if fi, err := os.Stat(endpoint); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("attachsock.ListenSocket: refusing to remove non-socket file %q", endpoint)
		}
		// Secondary stale check (A9): the held lock already excludes a live
		// local daemon, but a probe-dial that unexpectedly succeeds means
		// something else is serving the path — bail rather than steal. Only
		// unlink when the dial fails (stale socket from a crashed daemon).
		if c, derr := net.DialTimeout("unix", endpoint, 500*time.Millisecond); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("attachsock.ListenSocket: %w at %q", ErrSocketLiveDaemon, endpoint)
		}
		if err := os.Remove(endpoint); err != nil {
			return nil, fmt.Errorf("attachsock.ListenSocket: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("attachsock.ListenSocket: stat %q: %w", endpoint, err)
	}
	ln, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("attachsock.ListenSocket: listen: %w", err)
	}
	// Take ownership of the unlink: the stdlib's default unlink-on-close would
	// remove whatever file sits at the path at Close time, UNORDERED against
	// our flock release — a replacement daemon's freshly-bound socket could be
	// the casualty (F3). lockedListener.Close does the unlink itself, ordered
	// before the lock release and inode-guarded.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(endpoint, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(endpoint)
		return nil, fmt.Errorf("attachsock.ListenSocket: chmod: %w", err)
	}
	// Record the bound socket's identity for the SameFile unlink guard in Close.
	boundInfo, _ := os.Stat(endpoint)
	listening = true
	return &lockedListener{Listener: ln, lock: lock, path: endpoint, boundInfo: boundInfo}, nil
}
