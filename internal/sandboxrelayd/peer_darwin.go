//go:build darwin

package sandboxrelayd

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// PeerSameUser checks the peer credentials of a unix-socket connection on
// macOS (LOCAL_PEERCRED, the xucred of the connecting process): only a
// process of this user may speak on a relay socket, as on Linux. The macOS
// sandbox drivers (lane SBX-P5) serve the relay on a unix socket exactly as
// bwrap does; this check is built from Apple's documentation and is
// register item MAC-5 until a Mac runs it. The struct's version is checked
// before its uid (CheckXucred, lane SBX-P3B).
func PeerSameUser(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("sandboxrelayd: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) //nolint:gosec // G115: a socket descriptor
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	return CheckXucred(cred.Version, cred.Uid, os.Getuid())
}
