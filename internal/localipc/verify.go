package localipc

import (
	"errors"
	"fmt"
	"net"
)

// verify.go is the client's check of WHO serves an endpoint (security
// ledger ATT-1, client precondition): the Windows pipe name is predictable
// in a namespace every local account can create names in, so a client must
// confirm the pipe is served by its own user (or SYSTEM) before it sends a
// request. A unix socket lives in the owner-only 0700 directory, which only
// this user can create the socket in, so it needs no extra check.

// ErrServerUnverified is wrapped by VerifyServer when the process serving
// the endpoint is not this user's (nor SYSTEM's), or cannot be identified.
var ErrServerUnverified = errors.New("localipc: the endpoint's server is not this user's observer daemon")

// localSystemSID is the well-known SID of LocalSystem.
const localSystemSID = "S-1-5-18"

// VerifyServer reports an error wrapping ErrServerUnverified unless conn's
// server runs as this user (or SYSTEM). It is a no-op where the transport's
// own permissions already guarantee that (unix).
func VerifyServer(conn net.Conn) error { return verifyServer(conn) }

// identityAllowed is the pure rule: the server's user SID must equal the
// client's own, or be LocalSystem. An empty SID never matches.
func identityAllowed(serverSID, selfSID string) error {
	switch {
	case serverSID == "" || selfSID == "":
		return fmt.Errorf("%w: the user of one side is unknown", ErrServerUnverified)
	case serverSID == selfSID, serverSID == localSystemSID:
		return nil
	default:
		return fmt.Errorf("%w: it runs as %s", ErrServerUnverified, serverSID)
	}
}
