//go:build unix

package listenhandover

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Supported reports whether this OS can pass a listening socket across a
// re-exec (execve keeps every descriptor without close-on-exec).
func Supported() bool { return true }

// keepOnExec clears close-on-exec on f, so execve passes it on, and
// returns its descriptor number. It reaches the descriptor through
// SyscallConn, never f.Fd(), which would switch the socket (shared with
// the listener it was duplicated from) to blocking mode.
func keepOnExec(f *os.File) (int, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	fd, ferr := -1, error(nil)
	if err := rc.Control(func(d uintptr) {
		fd = int(d)
		_, ferr = unix.FcntlInt(d, unix.F_SETFD, 0)
	}); err != nil {
		return 0, err
	}
	return fd, ferr
}

// inheritedFile opens the descriptor fd a re-exec passed on, marking it
// close-on-exec at once. nil when fd is not open.
func inheritedFile(fd int) *os.File {
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return nil
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "observer-proxy-listener-"+strconv.Itoa(fd))
}
