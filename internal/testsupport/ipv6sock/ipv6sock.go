package ipv6sock

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
)

// errOpened stops the probe dial in its Control hook: socket() succeeded.
var errOpened = errors.New("ipv6sock: AF_INET6 socket opened")

var (
	once  sync.Once
	avail bool
	why   error
)

// Available reports whether this host can open an AF_INET6 socket. It probes
// once per process with a dial of [::1] that its own Control hook stops
// after socket() and before connect(), the point where netguard checks an
// address, so nothing is sent. When the answer is no, err is the socket()
// error (EAFNOSUPPORT). Any other outcome counts as available: only a host
// that cannot make the socket at all is excused.
func Available() (ok bool, err error) {
	once.Do(func() {
		d := net.Dialer{Control: func(string, string, syscall.RawConn) error { return errOpened }}
		_, derr := d.Dial("tcp6", "[::1]:9")
		avail, why = probeResult(derr)
	})
	return avail, why
}

// probeResult reads the probe dial's error: EAFNOSUPPORT means no IPv6
// sockets; anything else (the Control hook's stop, or a later error) means
// a socket was made.
func probeResult(err error) (bool, error) {
	if errors.Is(err, syscall.EAFNOSUPPORT) {
		return false, err
	}
	return true, nil
}

// MustHave skips t when this host cannot open an IPv6 socket at all, with a
// message that says so and why the case needs one.
func MustHave(t testing.TB) {
	t.Helper()
	if ok, err := Available(); !ok {
		t.Skipf("this host cannot open an IPv6 socket (%v): an IPv6 dial fails at socket() "+
			"before netguard's Control hook can refuse it, so this case is tested only where IPv6 exists", err)
	}
}
