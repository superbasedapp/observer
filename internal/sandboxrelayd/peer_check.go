package sandboxrelayd

import (
	"errors"
	"fmt"
	"net"
)

// PeerIdentity is the I/O the Windows named-pipe peer check reads
// (peer_windows.go), injected so the decision itself runs with fakes on any
// host (SBX-P6 audit item 8). Every field is required.
type PeerIdentity struct {
	// Handle is the named-pipe handle behind a connection; false when the
	// connection is not a named pipe.
	Handle func(c net.Conn) (uintptr, bool)
	// ClientPID is the pipe client's process id.
	ClientPID func(h uintptr) (uint32, error)
	// ProcessUser is a process's token user SID, in string form.
	ProcessUser func(pid uint32) (string, error)
	// Self is this process's token user SID, in string form.
	Self func() (string, error)
}

// SameUser checks the client of a named-pipe connection: c must be a named
// pipe whose client process runs as this process's user. Any failure to
// read a fact refuses the connection.
func (p PeerIdentity) SameUser(c net.Conn) error {
	if p.Handle == nil || p.ClientPID == nil || p.ProcessUser == nil || p.Self == nil {
		return errors.New("sandboxrelayd: no peer identity reader")
	}
	h, ok := p.Handle(c)
	if !ok {
		return errors.New("sandboxrelayd: not a named pipe")
	}
	pid, err := p.ClientPID(h)
	if err != nil {
		return fmt.Errorf("sandboxrelayd: pipe client: %w", err)
	}
	user, err := p.ProcessUser(pid)
	if err != nil {
		return fmt.Errorf("sandboxrelayd: pipe client process: %w", err)
	}
	me, err := p.Self()
	if err != nil {
		return fmt.Errorf("sandboxrelayd: this process's user: %w", err)
	}
	if user == "" || user != me {
		return errors.New("sandboxrelayd: the pipe client is not this user")
	}
	return nil
}

// XucredVersion is Apple's XUCRED_VERSION, the only struct version a
// LOCAL_PEERCRED xucred may carry: `#define XUCRED_VERSION 0` in
// <sys/ucred.h> (macOS SDK). golang.org/x/sys/unix has the field
// (unix.Xucred.Version) but not the constant, so it is defined here.
const XucredVersion uint32 = 0

// CheckXucred is the macOS peer check over the xucred's fields (lane
// SBX-P3B, register item MAC-5): a struct whose version is not
// XucredVersion is refused before its uid is trusted (its layout is then not
// the one the uid was read from), and the uid must be self. Pure, so it is
// tested on every OS; peer_darwin.go reads the struct.
func CheckXucred(version, uid uint32, self int) error {
	if version != XucredVersion {
		return fmt.Errorf("sandboxrelayd: peer credential version %d is not XUCRED_VERSION %d", version, XucredVersion)
	}
	if self < 0 || uint64(uid) != uint64(self) {
		return fmt.Errorf("sandboxrelayd: peer uid %d is not this user", uid)
	}
	return nil
}
