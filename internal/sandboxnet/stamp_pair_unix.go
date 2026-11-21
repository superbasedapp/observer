//go:build unix

package sandboxnet

import (
	"net"
	"os"
	"syscall"
)

// stampConnPair returns the two ends of a connected unix socket pair for a
// StampHop connection (tracker row F-010, audit N3-A4). Unlike net.Pipe,
// each end supports CloseWrite, so a box client that half-closes after its
// request still reads the response, as it does through the raw pipe. Both
// descriptors are close-on-exec, made under syscall.ForkLock, so no child
// the helper starts (the box among them) inherits either end.
func stampConnPair() (box, home net.Conn, err error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, os.NewSyscallError("socketpair", err)
	}
	box, err = fdConn(fds[0], "sandboxnet-stamp-box")
	if err != nil {
		_ = syscall.Close(fds[1])
		return nil, nil, err
	}
	home, err = fdConn(fds[1], "sandboxnet-stamp-home")
	if err != nil {
		_ = box.Close()
		return nil, nil, err
	}
	return box, home, nil
}

// fdConn wraps fd as a net.Conn; fd itself is closed (FileConn holds its
// own duplicate).
func fdConn(fd int, name string) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), name)
	c, err := net.FileConn(f)
	_ = f.Close()
	return c, err
}
