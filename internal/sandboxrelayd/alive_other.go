//go:build !unix && !windows

package sandboxrelayd

import "fmt"

// holdAlive is not offered off unix (the relay ships only where bwrap runs).
func holdAlive(string, string) (func(), error) {
	return nil, fmt.Errorf("sandboxrelayd.HoldRun: %w", errAliveNotOffered)
}

// probeAlive knows nothing off unix: the record decides.
func probeAlive(string) helperState { return helperUnknown }

// dropAlive has nothing to drop off unix.
func dropAlive(string) {}
