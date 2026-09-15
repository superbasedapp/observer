package api

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// headerPoP is the request header carrying the compact proof-of-possession
// string. Must match internal/cloudclient's private headerPoP constant — the
// two are the client and server ends of the same wire contract.
const headerPoP = "SBO-PoP"

// PoPRequest is the input to a PoPVerifier.Verify call, built by the
// authenticate middleware from one authenticated HTTP request.
type PoPRequest struct {
	// ProofHeader is the raw SBO-PoP header value.
	ProofHeader string
	// Method is the observed HTTP method.
	Method string
	// URL is the absolute external URL the server reconstructs for this
	// request (scheme + externalBaseURL host + path — see Server.externalBaseURL).
	// Never derived from client-controllable headers (Host, X-Forwarded-*).
	URL string
	// Body is the request body (used for the write-method body digest).
	Body []byte
	// AccessToken is the raw bearer token presented on this request; its hash
	// is bound into the proof (ath claim).
	AccessToken string
	// DevicePublicKey is the raw Ed25519 public key registered for the
	// introspected token's device.
	DevicePublicKey ed25519.PublicKey
	// Now is the reference time for the iat clock window.
	Now time.Time
	// MaxAge bounds how far in the past iat may be.
	MaxAge time.Duration
	// MaxSkew bounds how far in the future iat may be (clock skew tolerance).
	MaxSkew time.Duration
}

// PoPResult is what a successful PoPVerifier.Verify hands back to the
// middleware for jti replay recording.
type PoPResult struct {
	JTI       string
	JTIExpiry time.Time
}

// PoPVerifier authenticates a proof-of-possession header against a request.
// The middleware and jti-replay plumbing are format-agnostic; only this
// interface's implementation knows the wire shape.
type PoPVerifier interface {
	Verify(req PoPRequest) (PoPResult, error)
}

// ErrPoP wraps every proof-of-possession failure this package returns.
var ErrPoP = errors.New("cloudserver/api: proof-of-possession failed")

// CloudPoPVerifier implements PoPVerifier using the shared internal/cloudpop
// JWS-compact proof format — the SAME format internal/cloudclient mints via
// cloudpop.Create. This is the production verifier; there is no other format.
type CloudPoPVerifier struct{}

// Verify implements PoPVerifier.
func (CloudPoPVerifier) Verify(req PoPRequest) (PoPResult, error) {
	if req.ProofHeader == "" {
		return PoPResult{}, fmt.Errorf("%w: missing %s header", ErrPoP, headerPoP)
	}
	if len(req.DevicePublicKey) != ed25519.PublicKeySize {
		return PoPResult{}, fmt.Errorf("%w: registered device key is %d bytes, want %d", ErrPoP, len(req.DevicePublicKey), ed25519.PublicKeySize)
	}

	// The store's registered-device Thumbprint (internal/cloudserver/store)
	// hashes the raw public key bytes directly; cloudpop's Thumbprint is the
	// RFC 7638 hash of the canonical JWK JSON — a different preimage. Rather
	// than compare against the store's field, recompute the RFC 7638
	// thumbprint fresh from the registered raw public key so the comparison
	// is apples-to-apples against what the proof's embedded JWK carries.
	expectedThumbprint := cloudpop.Thumbprint(req.DevicePublicKey)

	v, err := cloudpop.Verify(req.ProofHeader, cloudpop.VerifyParams{
		ExpectedMethod:          req.Method,
		ExpectedURL:             req.URL,
		ExpectedThumbprint:      expectedThumbprint,
		ExpectedAccessTokenHash: cloudpop.HashAccessToken(req.AccessToken),
		Now:                     req.Now,
		MaxAge:                  req.MaxAge,
		MaxSkew:                 req.MaxSkew,
		Body:                    req.Body,
	})
	if err != nil {
		return PoPResult{}, fmt.Errorf("%w: %w", ErrPoP, err)
	}

	return PoPResult{
		JTI:       v.JTI,
		JTIExpiry: v.IssuedAt.Add(req.MaxAge),
	}, nil
}

var _ PoPVerifier = CloudPoPVerifier{}
