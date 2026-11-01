package sandboxrelayd

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// pipeConn stands in for a named-pipe connection (go-winio's pipe types
// expose Fd()).
type pipeConn struct {
	net.Conn
	fd uintptr
}

func (p pipeConn) Fd() uintptr { return p.fd }

// fakeIdentity is a PeerIdentity over a table: handle 7 belongs to pid 70,
// whose user is userOf[70].
func fakeIdentity(userOf map[uint32]string, me string) PeerIdentity {
	return PeerIdentity{
		Handle: func(c net.Conn) (uintptr, bool) {
			f, ok := c.(interface{ Fd() uintptr })
			if !ok {
				return 0, false
			}
			return f.Fd(), true
		},
		ClientPID: func(h uintptr) (uint32, error) {
			if h == 0 {
				return 0, errors.New("no client")
			}
			return uint32(h) * 10, nil
		},
		ProcessUser: func(pid uint32) (string, error) {
			u, ok := userOf[pid]
			if !ok {
				return "", errors.New("access denied")
			}
			return u, nil
		},
		Self: func() (string, error) { return me, nil },
	}
}

// TestPeerSameUserDecision is the Windows PeerSameUser decision with fakes
// (SBX-P6 audit item 8): the same user passes; another user, a vanished
// client, a connection that is not a pipe, or an unreadable fact refuses.
func TestPeerSameUserDecision(t *testing.T) {
	t.Parallel()
	me := "S-1-5-21-1-2-3-1001"
	id := fakeIdentity(map[uint32]string{70: me, 80: "S-1-5-21-1-2-3-1002", 90: ""}, me)
	if err := id.SameUser(pipeConn{fd: 7}); err != nil {
		t.Fatalf("the same user was refused: %v", err)
	}
	for name, c := range map[string]struct {
		conn net.Conn
		want string
	}{
		"another user":          {pipeConn{fd: 8}, "not this user"},
		"an unnamed token user": {pipeConn{fd: 9}, "not this user"},
		"no client process":     {pipeConn{fd: 0}, "pipe client"},
		"an unreadable process": {pipeConn{fd: 5}, "pipe client process"},
		"not a named pipe":      {&net.TCPConn{}, "not a named pipe"},
	} {
		if err := id.SameUser(c.conn); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	broken := id
	broken.Self = func() (string, error) { return "", errors.New("no token") }
	if err := broken.SameUser(pipeConn{fd: 7}); err == nil {
		t.Error("an unreadable own user passed")
	}
	if err := (PeerIdentity{}).SameUser(pipeConn{fd: 7}); err == nil {
		t.Error("an empty identity reader passed")
	}
}

// TestCheckXucred (lane SBX-P3B, MAC-5): the macOS peer check refuses a
// xucred whose version is not XUCRED_VERSION before it trusts the uid, and
// refuses another user's uid. Pure, so it runs on every OS.
func TestCheckXucred(t *testing.T) {
	cases := []struct {
		name    string
		version uint32
		uid     uint32
		self    int
		ok      bool
	}{
		{"this user, current version", XucredVersion, 501, 501, true},
		{"another user", XucredVersion, 502, 501, false},
		{"wrong version, right uid", XucredVersion + 1, 501, 501, false},
		{"wrong version, root", 7, 0, 0, false},
		{"no self uid", XucredVersion, 0, -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckXucred(tc.version, tc.uid, tc.self); (err == nil) != tc.ok {
				t.Fatalf("CheckXucred(%d, %d, %d) = %v, want ok %v", tc.version, tc.uid, tc.self, err, tc.ok)
			}
		})
	}
	if XucredVersion != 0 {
		t.Fatal("XUCRED_VERSION is 0 in <sys/ucred.h>")
	}
}
