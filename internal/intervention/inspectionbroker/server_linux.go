//go:build linux

package inspectionbroker

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

const acceptPollInterval = 250 * time.Millisecond

// Server serves bounded identity reads for one configured operating-system
// user. AuthorizePeer must independently bind Peer to the trusted, installed
// controller process; a matching UID alone is never sufficient.
type Server struct {
	TargetUID int
	IOTimeout time.Duration
	// AuthorizePeer is called before target inspection and again immediately
	// before a successful response, fencing controller replacement.
	AuthorizePeer func(context.Context, Peer) error
	// Inspect defaults to intervention.Inspect. An override is intended for
	// deterministic tests of target identity changes.
	Inspect func(context.Context, int) (intervention.Identity, error)

	effectiveUID func() int
}

// Serve accepts one request per connection until ctx is canceled. The caller
// creates and owns listener and its root-owned filesystem path.
func (server Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	if ctx == nil || listener == nil || server.TargetUID < 0 || server.AuthorizePeer == nil {
		return ErrInvalidRequest
	}
	effectiveUID := os.Geteuid
	if server.effectiveUID != nil {
		effectiveUID = server.effectiveUID
	}
	if effectiveUID() != 0 {
		return ErrUnauthorized
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		deadline := time.Now().Add(acceptPollInterval)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := listener.SetDeadline(deadline); err != nil {
			return ErrUnavailable
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			return ErrUnavailable
		}
		server.serveConnection(ctx, connection)
	}
}

func (server Server) serveConnection(ctx context.Context, connection *net.UnixConn) {
	defer func() { _ = connection.Close() }()
	deadline := boundedDeadline(ctx, server.IOTimeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return
	}
	requestContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	peer, err := unixPeer(connection)
	if err != nil {
		return
	}
	var request inspectRequest
	if err := readFrame(connection, &request); err != nil {
		server.writeError(connection, "", codeInvalidRequest)
		return
	}
	if !validRequest(request) {
		server.writeError(connection, request.Nonce, codeInvalidRequest)
		return
	}
	if peer.UID != server.TargetUID || server.AuthorizePeer(requestContext, peer) != nil {
		server.writeError(connection, request.Nonce, codeUnauthorized)
		return
	}
	inspect := intervention.Inspect
	if server.Inspect != nil {
		inspect = server.Inspect
	}
	before, err := inspect(requestContext, request.PID)
	if err != nil {
		server.writeError(connection, request.Nonce, codeInspectionUnavailable)
		return
	}
	if !identityMatchesRequest(before, request, server.TargetUID) {
		server.writeError(connection, request.Nonce, codeIdentityMismatch)
		return
	}
	after, err := inspect(requestContext, request.PID)
	if err != nil {
		server.writeError(connection, request.Nonce, codeInspectionUnavailable)
		return
	}
	if before != after || !identityMatchesRequest(after, request, server.TargetUID) {
		server.writeError(connection, request.Nonce, codeIdentityMismatch)
		return
	}
	if requestContext.Err() != nil {
		return
	}
	if server.AuthorizePeer(requestContext, peer) != nil {
		server.writeError(connection, request.Nonce, codeUnauthorized)
		return
	}
	_ = writeFrame(connection, inspectResponse{
		Version: wireVersion, Kind: kindResult, Nonce: request.Nonce, Identity: &after,
	})
}

func (server Server) writeError(connection *net.UnixConn, nonce, code string) {
	_ = writeFrame(connection, inspectResponse{
		Version: wireVersion, Kind: kindResult, Nonce: nonce, Error: code,
	})
}

func identityMatchesRequest(identity intervention.Identity, request inspectRequest, targetUID int) bool {
	return validIdentity(identity) && identity.PID == request.PID &&
		identity.StartTicks == request.StartTicks && identity.BootID == request.BootID &&
		identity.UID == targetUID
}
