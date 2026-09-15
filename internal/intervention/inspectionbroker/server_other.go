//go:build !linux

package inspectionbroker

import (
	"context"
	"net"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

// Server is unavailable on non-Linux systems.
type Server struct {
	TargetUID     int
	IOTimeout     time.Duration
	AuthorizePeer func(context.Context, Peer) error
	Inspect       func(context.Context, int) (intervention.Identity, error)
}

// Serve reports ErrUnavailable on non-Linux systems.
func (Server) Serve(context.Context, *net.UnixListener) error { return ErrUnavailable }
