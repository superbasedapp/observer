//go:build !linux

package signerd

import "net"

// PeerCredUID is unavailable off Linux: it always fails, so a Server with no
// injected PeerUID refuses every peer.
func PeerCredUID(net.Conn) (int, error) { return -1, ErrPeerCredUnsupported }

// ListenUnix refuses to start the signer off Linux: without SO_PEERCRED it
// cannot tell which process is asking for a signature.
func ListenUnix(string) (net.Listener, error) { return nil, ErrPeerCredUnsupported }
