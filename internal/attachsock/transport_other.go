//go:build !unix && !windows

package attachsock

import (
	"context"
	"net"
	"time"
)

// transport_other.go is the honest no-transport fallback for platforms that
// have neither AF_UNIX-with-directory-permissions nor Windows named pipes
// (plan9, js/wasm, wasip1). It exists so the tree cross-compiles everywhere;
// every method fails with ErrUnsupported rather than pretending to serve, and
// Supported() is false so callers refuse the surface upstream with honest copy.

// unsupportedTransport serves nothing.
type unsupportedTransport struct{}

// defaultTransport is the no-op transport on this platform.
var defaultTransport Transport = unsupportedTransport{}

// Describe implements Transport.
func (unsupportedTransport) Describe() string { return TransportNone }

// Supported implements Transport: no attach channel exists here.
func (unsupportedTransport) Supported() bool { return false }

// Endpoint implements Transport: there is no endpoint to name.
func (unsupportedTransport) Endpoint(string) (string, error) { return "", ErrUnsupported }

// Listen implements Transport: nothing to listen on.
func (unsupportedTransport) Listen(string) (net.Listener, error) { return nil, ErrUnsupported }

// Dial implements Transport: nothing to dial.
func (unsupportedTransport) Dial(context.Context, string, time.Duration) (net.Conn, error) {
	return nil, ErrUnsupported
}
