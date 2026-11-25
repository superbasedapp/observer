package attachsock

import (
	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// transport.go re-exports the few names of the attach channel's OS transport
// that callers still reach through this package. The transport itself moved
// to core internal/localipc (lane MP-L1K, T-715) because the MCP relay's IPC
// rides the same owner-only socket / named-pipe model; new code uses
// localipc directly. The protocol, server and client in this package are
// unchanged and stay in the terminals component.

// TransportUnixSocket is localipc.TransportUnixSocket, the name
// DefaultTransport().Describe() reports for the AF_UNIX transport.
const TransportUnixSocket = localipc.TransportUnixSocket

// DefaultTransport is localipc.DefaultTransport.
func DefaultTransport() localipc.Transport { return localipc.DefaultTransport() }

// SocketPath is localipc.SocketPath.
func SocketPath(dbPath string) string { return localipc.SocketPath(dbPath) }
