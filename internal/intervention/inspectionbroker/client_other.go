//go:build !linux

package inspectionbroker

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

// Client is unavailable on operating systems without Linux SO_PEERCRED and
// procfs identity support.
type Client struct {
	SocketPath string
	TargetUID  int
	Timeout    time.Duration
}

// Inspect reports ErrUnavailable on non-Linux systems.
func (Client) Inspect(context.Context, int, int64, string) (intervention.Identity, error) {
	return intervention.Identity{}, ErrUnavailable
}
