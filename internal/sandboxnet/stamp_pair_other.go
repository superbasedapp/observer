//go:build !unix

package sandboxnet

import "net"

// stampConnPair returns an in-memory pair where unix socket pairs are not
// available. The stamping hop runs only in the Linux host helper, so this
// keeps the package building elsewhere; net.Pipe has no CloseWrite (audit
// N3-A4).
func stampConnPair() (box, home net.Conn, err error) {
	box, home = net.Pipe()
	return box, home, nil
}
