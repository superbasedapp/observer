//go:build linux

package signerd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// PeerCredUID returns the uid of the process at the other end of a unix
// socket connection (SO_PEERCRED: the kernel's record from connect time, not
// anything the peer says).
func PeerCredUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("signerd.PeerCredUID: not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("signerd.PeerCredUID: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return -1, fmt.Errorf("signerd.PeerCredUID: %w", err)
	}
	if credErr != nil {
		return -1, fmt.Errorf("signerd.PeerCredUID: %w", credErr)
	}
	return int(cred.Uid), nil
}

// ListenUnix listens on the unix socket at path. A stale socket file left by
// a previous run is removed; any other file at path is refused. The socket is
// made 0660 (the serve user reaches it through the shared group; SO_PEERCRED
// is still checked on every connection).
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("signerd.ListenUnix: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("signerd.ListenUnix: remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("signerd.ListenUnix: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("signerd.ListenUnix: chmod: %w", err)
	}
	return ln, nil
}
