package cloudgateway

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudclient"
)

// connect.go is the connect request on the BOOTSTRAP lane (Getting started
// v2, shared contract A): `observer connect` with no server address asks the
// cloud for a browser approval that signs this machine in and picks where its
// data goes, then polls until the person answers.
//
// Ungated by design, like sign-in: the user's own typed `observer connect`
// (or the dashboard / VS Code button that runs it) is the authorization (R2
// disposition F10). The create call sends the device public key and a short
// description of the machine (name, OS, architecture, Observer version, an
// optional team slug); the poll sends only a proof of possession. No session
// data. Never called by a daemon loop. Ledger row ONB-5 in docs/security.md.

// Re-exported so callers classify poll outcomes without importing the lane.
var (
	// ErrConnectRequestGone: the request expired or is unknown; start over.
	ErrConnectRequestGone = cloudclient.ErrConnectRequestGone
	// ErrConnectUnsupported: the cloud has no connect requests yet.
	ErrConnectUnsupported = cloudclient.ErrConnectUnsupported
	// ErrConnectSlowDown: the poll was rate-limited; wait longer.
	ErrConnectSlowDown = cloudclient.ErrConnectSlowDown
)

// IsProofRejected reports whether err is the cloud refusing this machine's
// proof of its key (re-exported from the lane, like the errors above). The
// lane already re-sends once on the server's clock, so a refusal that
// remains means a clock far off or a key the request was not made with.
func IsProofRejected(err error) bool { return cloudclient.IsProofRejected(err) }

// ConnectRequestInput, ConnectRequest, ConnectStatus and ConnectTarget are
// the lane's plain result types, re-exported for the same reason.
type (
	ConnectRequestInput = cloudclient.ConnectRequestInput
	ConnectRequest      = cloudclient.ConnectRequest
	ConnectStatus       = cloudclient.ConnectStatus
	ConnectTarget       = cloudclient.ConnectTarget
)

// BootstrapConnectStart creates a connect request for this machine's device
// key (POST /v1/connect/requests). Needs no consent grant.
func (g *Gateway) BootstrapConnectStart(ctx context.Context, in ConnectRequestInput) (ConnectRequest, error) {
	c, err := g.network()
	if err != nil {
		return ConnectRequest{}, err
	}
	return c.CreateConnectRequest(ctx, in)
}

// BootstrapConnectPoll reads the request's state (GET
// /v1/connect/requests/{id}); an approved answer completes device sign-in.
// Needs no consent grant.
func (g *Gateway) BootstrapConnectPoll(ctx context.Context, requestID string) (ConnectStatus, error) {
	c, err := g.network()
	if err != nil {
		return ConnectStatus{}, err
	}
	return c.PollConnectRequest(ctx, requestID)
}

// AttachProof is the device proof an attach grant rides with, re-exported so
// callers never import the lane.
type AttachProof = attachgrant.Proof

// BootstrapAttachProof signs the device proof for an attach grant the
// approved poll handed over (cloudclient.AttachProof): the device key over
// the grant and the node key being enrolled. Local only: no network call and
// no consent grant (the person's own Connect approval is the authorization).
func (g *Gateway) BootstrapAttachProof(grant, agentPublicKey string) (AttachProof, error) {
	c, err := g.network()
	if err != nil {
		return AttachProof{}, err
	}
	return c.AttachProof(grant, agentPublicKey)
}
