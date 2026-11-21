package localipc

import "net"

// PeerPID returns the process id of the client at the other end of an
// accepted attach-channel connection: SO_PEERCRED on Linux, LOCAL_PEERPID on
// macOS, GetNamedPipeClientProcessId on Windows. ok is false when the
// platform has no lookup or the lookup fails; callers treat that as "caller
// not identified", never as a particular process (lane cli-2: who started a
// launch).
func PeerPID(conn net.Conn) (pid int, ok bool) {
	if conn == nil {
		return 0, false
	}
	return peerPID(conn)
}
