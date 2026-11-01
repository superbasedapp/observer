//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_vsock_linux.go is the guest's AF_VSOCK listener
// (golang.org/x/sys/unix, no new module): a non-blocking socket wrapped in
// an os.File, so Accept, reads, writes and deadlines go through Go's
// poller. Only the host (CID 2) may connect.

// vsockAddr is a vsock endpoint.
type vsockAddr struct{ cid, port uint32 }

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string {
	return strconv.FormatUint(uint64(a.cid), 10) + ":" + strconv.FormatUint(uint64(a.port), 10)
}

// vsockListener is one listening port.
type vsockListener struct {
	f    *os.File
	port uint32
}

// vmListenVsock listens on port for any CID.
func vmListenVsock(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Listen(fd, 8); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &vsockListener{f: os.NewFile(uintptr(fd), "vsock-listener"), port: port}, nil //nolint:gosec // G115: a descriptor number
}

func (l *vsockListener) Accept() (net.Conn, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var sa unix.Sockaddr
	var aerr error
	err = rc.Read(func(fd uintptr) bool {
		nfd, sa, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC) //nolint:gosec // G115: a descriptor number
		return !errors.Is(aerr, syscall.EAGAIN)
	})
	if err != nil {
		return nil, err
	}
	if aerr != nil {
		return nil, aerr
	}
	remote := vsockAddr{}
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		remote = vsockAddr{cid: vm.CID, port: vm.Port}
	}
	return &vsockConn{File: os.NewFile(uintptr(nfd), "vsock"), local: vsockAddr{cid: unix.VMADDR_CID_ANY, port: l.port}, remote: remote}, nil //nolint:gosec // G115: a descriptor number
}

func (l *vsockListener) Close() error   { return l.f.Close() }
func (l *vsockListener) Addr() net.Addr { return vsockAddr{cid: unix.VMADDR_CID_ANY, port: l.port} }

// SetDeadline bounds Accept.
func (l *vsockListener) SetDeadline(t time.Time) error { return l.f.SetReadDeadline(t) }

// vsockConn is one accepted connection.
type vsockConn struct {
	*os.File
	local, remote vsockAddr
}

func (c *vsockConn) LocalAddr() net.Addr  { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr { return c.remote }

// CloseWrite half-closes (relayBridge uses it).
func (c *vsockConn) CloseWrite() error {
	rc, err := c.File.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = unix.Shutdown(int(fd), unix.SHUT_WR) }); err != nil { //nolint:gosec // G115: a descriptor number
		return err
	}
	return serr
}

// vmPeerIsHost accepts only a connection from the host (CID 2): a process
// inside the VM connecting to its own listener comes from the guest's CID
// or the local CID.
func vmPeerIsHost(c net.Conn) bool {
	vc, ok := c.(*vsockConn)
	return ok && vc.remote.cid == sandboxvm.HostCID
}
