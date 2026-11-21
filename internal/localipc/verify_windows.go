//go:build windows

package localipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
)

// verifyServer resolves the pipe's server process
// (GetNamedPipeServerProcessId), reads its token user and applies
// identityAllowed. Every lookup failure refuses: a server this client
// cannot identify is not trusted with a request.
func verifyServer(conn net.Conn) error {
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("%w: the pipe connection exposes no handle", ErrServerUnverified)
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(h.Fd()), &pid); err != nil {
		return fmt.Errorf("%w: GetNamedPipeServerProcessId: %w", ErrServerUnverified, err)
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("%w: open the server process %d: %w", ErrServerUnverified, pid, err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return fmt.Errorf("%w: open the server's token: %w", ErrServerUnverified, err)
	}
	defer func() { _ = tok.Close() }()
	server, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: read the server's token user: %w", ErrServerUnverified, err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: read this process's token user: %w", ErrServerUnverified, err)
	}
	return identityAllowed(server.User.Sid.String(), self.User.Sid.String())
}
