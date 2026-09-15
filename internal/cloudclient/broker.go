package cloudclient

import (
	"context"
	"errors"
	"fmt"
)

// CloudIdentityBroker is the WorkOS seam. It yields a currently-valid WorkOS
// access token, refreshing through WorkOS as needed — WorkOS is the sole
// refresh authority (amendment §3.3). Two implementations ship: WorkOSBroker
// (production PKCE, workosbroker.go) and StubBroker (dev/test, below).
type CloudIdentityBroker interface {
	// AccessToken returns a currently-valid WorkOS access token. Implementations
	// must refresh (through WorkOS) when the cached token is near expiry, and
	// return an error the client will NOT retry (identity failures are not
	// transport failures).
	AccessToken(ctx context.Context) (string, error)
}

// ErrNoIdentity is returned by a broker with no usable session (the user has
// not completed WorkOS login). Callers surface it as "run `observer cloud
// login`".
var ErrNoIdentity = errors.New("cloudclient: no WorkOS identity available")

// StubBroker is the in-lane dev/test broker. It returns a fixed token, or a
// configured error, and records how many times it was asked (so tests can
// assert refresh behaviour). It performs no network I/O.
type StubBroker struct {
	// Token is returned by AccessToken when Err is nil.
	Token string
	// Err, when non-nil, is returned instead of Token.
	Err error
	// Calls counts AccessToken invocations.
	Calls int
}

// AccessToken implements CloudIdentityBroker.
func (b *StubBroker) AccessToken(ctx context.Context) (string, error) {
	b.Calls++
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("cloudclient.StubBroker: %w", err)
	}
	if b.Err != nil {
		return "", b.Err
	}
	if b.Token == "" {
		return "", ErrNoIdentity
	}
	return b.Token, nil
}
