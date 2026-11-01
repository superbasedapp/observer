//go:build !linux && !darwin && !windows

package sandboxrelayd

import (
	"errors"
	"net"
)

// PeerSameUser has no peer-credential read here (Linux and macOS have one),
// so every other platform refuses the connection.
func PeerSameUser(net.Conn) error {
	return errors.New("sandboxrelayd: peer credentials are checked on Linux and macOS only")
}
