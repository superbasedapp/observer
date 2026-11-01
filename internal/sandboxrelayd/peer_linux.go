//go:build linux

package sandboxrelayd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// PeerSameUser checks the peer credentials of a unix-socket connection
// (SO_PEERCRED): only a process of this user may speak on a relay socket
// (the hardened channel, sandbox plan section 5.2 and M4). The socket's own
// directory is already 0700; this is the second check.
func PeerSameUser(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("sandboxrelayd: not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) //nolint:gosec // G115: a socket descriptor
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != os.Getuid() {
		return fmt.Errorf("sandboxrelayd: peer uid %d is not this user", cred.Uid)
	}
	return nil
}
