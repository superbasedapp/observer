package ipv6sock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestProbeResult: only EAFNOSUPPORT, however wrapped, means no IPv6
// sockets; the Control hook's own stop and every other error mean a socket
// was made.
func TestProbeResult(t *testing.T) {
	sockErr := &net.OpError{Op: "dial", Net: "tcp6", Err: os.NewSyscallError("socket", syscall.EAFNOSUPPORT)}
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"socket: address family not supported", sockErr, false},
		{"wrapped again", fmt.Errorf("deliver: %w", sockErr), false},
		{"the Control hook stopped it after socket()", &net.OpError{Op: "dial", Err: errOpened}, true},
		{"connect refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, true},
		{"address not available (IPv6 without ::1)", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)}, true},
		{"no error", nil, true},
	} {
		got, err := probeResult(c.err)
		if got != c.want {
			t.Errorf("%s: available = %v, want %v", c.name, got, c.want)
		}
		if !got && !errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Errorf("%s: reason %v does not carry EAFNOSUPPORT", c.name, err)
		}
	}
}

// TestAvailableAgreesWithTheKernel: the live probe says yes exactly when
// this host can make an AF_INET6 socket, checked the other way: by
// listening on an IPv6 wildcard.
func TestAvailableAgreesWithTheKernel(t *testing.T) {
	ok, err := Available()
	l, lerr := net.Listen("tcp6", "[::]:0")
	if lerr == nil {
		_ = l.Close()
	}
	if errors.Is(lerr, syscall.EAFNOSUPPORT) == ok {
		t.Fatalf("Available() = %v (%v), but listening on [::]:0 gave %v", ok, err, lerr)
	}
}
