package netpolicy

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrDialRefused is the sentinel every dial-time refusal wraps, so a caller
// can distinguish "the policy refused this address" from a network error
// with errors.Is without parsing the message.
var ErrDialRefused = errors.New("netpolicy: dial refused")

// DialPolicy is the set of address classes one upstream may reach. The zero
// value is the strictest policy (public only). It is comparable, so a caller
// may key a per-policy connection pool on it.
type DialPolicy struct {
	// AllowLoopback admits 127.0.0.0/8 and ::1.
	AllowLoopback bool
	// AllowPrivate admits RFC 1918, CGNAT and ULA space.
	AllowPrivate bool
}

// Allows reports whether the policy permits one address class. ClassForbidden
// has no policy that admits it, by construction.
func (p DialPolicy) Allows(c NetworkClass) bool {
	switch c {
	case ClassPublic:
		return true
	case ClassLoopback:
		return p.AllowLoopback
	case ClassPrivate:
		return p.AllowPrivate
	default:
		return false
	}
}

// CheckIP applies the policy to one resolved address. host is carried only
// for the error text.
func (p DialPolicy) CheckIP(host string, ip net.IP) error {
	class := ClassifyIP(ip)
	if p.Allows(class) {
		return nil
	}
	switch class {
	case ClassLoopback, ClassPrivate:
		return fmt.Errorf("%w: %s address %s (%s) is outside this upstream's allowed network classes", ErrDialRefused, class, ip, host)
	default:
		return fmt.Errorf("%w: %s (%s): link-local, metadata, multicast and unspecified addresses are never permitted", ErrDialRefused, ip, host)
	}
}

// CheckDialAddress applies the policy to a "host:port" dial address whose host
// is the IP LITERAL the resolver produced. This is the security boundary: it
// runs after DNS, per resolved address. An address whose host is not an IP
// literal fails closed - the dialer contract guarantees a literal here, so
// anything else means an assumption broke.
func (p DialPolicy) CheckDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable dial address %q", ErrDialRefused, address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: dial address %q is not an IP literal", ErrDialRefused, host)
	}
	return p.CheckIP(host, ip)
}

// CheckDialNetwork refuses a non-TCP dial outright.
func CheckDialNetwork(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	default:
		return fmt.Errorf("%w: refusing non-TCP network %q", ErrDialRefused, network)
	}
}

// Control returns the net.Dialer.Control hook enforcing the policy: the
// network check, then the resolved-address check.
func (p DialPolicy) Control() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		if err := CheckDialNetwork(network); err != nil {
			return err
		}
		return p.CheckDialAddress(address)
	}
}
