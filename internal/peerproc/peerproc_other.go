//go:build !linux && !windows && !darwin

package peerproc

import (
	"context"
	"net/netip"
)

const supported = false

func find(context.Context, netip.AddrPort, netip.AddrPort, map[int]string) (Peer, error) {
	return Peer{SocketUID: -1}, ErrUnsupported
}

func startToken(int) (string, bool) { return "", false }

func ancestors(int) []int { return nil }

// envMarker reads no other process's environment on this platform.
func envMarker([]int, []string) (string, bool) { return "", false }
