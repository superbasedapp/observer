//go:build windows

package sandboxrelayd

import (
	"net"

	"golang.org/x/sys/windows"
)

// PeerSameUser checks the client of a named-pipe connection (the daemon's
// relay link endpoint, internal/localipc): the client process's token user
// must be this process's user. The pipe's own owner-only DACL already
// refuses other users; this is the second check, the Windows analogue of
// SO_PEERCRED. Any other connection is refused. The decision is
// PeerIdentity.SameUser (peer_check.go, tested with fakes); this file is
// only its Windows I/O.
func PeerSameUser(c net.Conn) error {
	return windowsPeerIdentity.SameUser(c)
}

// windowsPeerIdentity reads the facts through the Win32 API. go-winio's
// pipe connections expose Fd().
var windowsPeerIdentity = PeerIdentity{
	Handle: func(c net.Conn) (uintptr, bool) {
		f, ok := c.(interface{ Fd() uintptr })
		if !ok {
			return 0, false
		}
		return f.Fd(), true
	},
	ClientPID: func(h uintptr) (uint32, error) {
		var pid uint32
		err := windows.GetNamedPipeClientProcessId(windows.Handle(h), &pid)
		return pid, err
	},
	ProcessUser: func(pid uint32) (string, error) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", err
		}
		defer func() { _ = windows.CloseHandle(h) }()
		var tok windows.Token
		if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
			return "", err
		}
		defer func() { _ = tok.Close() }()
		u, err := tok.GetTokenUser()
		if err != nil {
			return "", err
		}
		return u.User.Sid.String(), nil
	},
	Self: func() (string, error) {
		me, err := currentUser()
		if err != nil {
			return "", err
		}
		return me.String(), nil
	},
}
