//go:build linux

package inspectionbroker

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intervention"
)

const acceptPollInterval = 250 * time.Millisecond

// maxConcurrentConnections bounds how many accepted connections this Server
// serves at once. Each one may fork a subprocess (the production
// AuthorizePeer shells out to systemctl show) and read /proc for the
// requested target, so an unbounded goroutine-per-connection accept loop
// would let a burst of local connections exhaust process/file-descriptor
// limits; a small bound keeps that cost capped while still letting requests
// run in parallel instead of serially queueing behind acceptPollInterval.
const maxConcurrentConnections = 8

// Server serves bounded identity reads for one configured operating-system
// user. AuthorizePeer must independently bind Peer to the trusted, installed
// controller process; a matching UID alone is never sufficient.
type Server struct {
	TargetUID int
	IOTimeout time.Duration
	// AuthorizePeer is called exactly once per request, immediately before a
	// successful response, fencing controller replacement across the whole
	// request window: target inspection (which can take real wall-clock
	// time — two /proc reads bracketing a stability check) runs first, so a
	// controller that stopped being the trusted, installed process during
	// that window is still caught before anything is disclosed.
	//
	// It is deliberately NOT also called before target inspection any more
	// (removed by INT-1 to stop forking systemctl-show twice per request).
	// That is a real behavior change, not a free one: a same-UID peer that
	// is NOT the legitimate controller previously got refused with zero
	// /proc work; now it drives two full Inspect passes on every request
	// before this single call refuses it. That is a bounded self-DoS shape
	// (capped by maxConcurrentConnections and IOTimeout, like any other
	// request here) — never a disclosure risk, since nothing is written to
	// the connection until this call succeeds. No cheap pre-inspect gate
	// (e.g. a short-TTL cache of the last authorized controller pid/uid)
	// exists to avoid that extra work; adding one is future work, not done
	// here, because a cached "authorized" verdict is itself a window a
	// controller replacement could ride through undetected.
	AuthorizePeer func(context.Context, Peer) error
	// Inspect defaults to intervention.Inspect. An override is intended for
	// deterministic tests of target identity changes.
	Inspect func(context.Context, int) (intervention.Identity, error)

	effectiveUID func() int
}

// Serve accepts one request per connection until ctx is canceled. The caller
// creates and owns listener and its root-owned filesystem path. Accepted
// connections are served concurrently, bounded by maxConcurrentConnections:
// a slow or malicious peer's request (bounded by IOTimeout regardless) can
// no longer stall every other queued connection behind it, but a burst of
// connections still can't spawn unbounded goroutines/subprocesses. Serve
// waits for every in-flight connection to finish before returning, so a
// caller that cancels ctx never has an orphaned goroutine still holding the
// listener's root-owned socket.
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
	semaphore := make(chan struct{}, maxConcurrentConnections)
	var inFlight sync.WaitGroup
	defer inFlight.Wait()
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
		select {
		case semaphore <- struct{}{}:
			inFlight.Add(1)
			go func() {
				defer inFlight.Done()
				defer func() { <-semaphore }()
				server.serveConnection(ctx, connection)
			}()
		case <-ctx.Done():
			_ = connection.Close()
			return nil
		}
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
	if peer.UID != server.TargetUID {
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
