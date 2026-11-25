package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Identity is the validated result of a broker token: a stable provider +
// subject the server links to an account, plus optional display claims.
type Identity struct {
	Provider string
	Subject  string
	Email    string // optional, display-only
}

// ErrInvalidToken indicates the broker token failed validation.
var ErrInvalidToken = errors.New("cloudserver/identity: invalid broker token")

// Verifier validates a broker access token. Implementations must reject
// expired, malformed, wrong-audience, or wrong-issuer tokens.
type Verifier interface {
	// Verify validates the raw broker access token and returns the identity, or
	// ErrInvalidToken. It must not have side effects.
	Verify(ctx context.Context, rawToken string) (Identity, error)
	// Provider is the identity-link provider label these tokens resolve under
	// (e.g. "workos" or "dev"). It namespaces the (provider, subject) key so a
	// dev-auth subject can never collide with a production WorkOS subject.
	Provider() string
}

// DevAuthVerifier is the SBCI_DEV_AUTH=1 stub, mirroring the org server's
// --dev-auth precedent. It accepts a token of the form "dev:<subject>" (or
// "dev:<subject>:<email>") and treats the subject as authenticated. It is
// ENABLED ONLY when the operator sets the flag; production must swap in the
// WorkOS verifier.
type DevAuthVerifier struct{}

// NewDevAuth returns the dev-auth stub verifier.
func NewDevAuth() *DevAuthVerifier { return &DevAuthVerifier{} }

// Provider returns "dev".
func (*DevAuthVerifier) Provider() string { return "dev" }

// Verify accepts "dev:<subject>[:<email>]".
func (*DevAuthVerifier) Verify(_ context.Context, rawToken string) (Identity, error) {
	const prefix = "dev:"
	if !strings.HasPrefix(rawToken, prefix) {
		return Identity{}, fmt.Errorf("%w: dev-auth expects a dev:<subject> token", ErrInvalidToken)
	}
	rest := strings.TrimPrefix(rawToken, prefix)
	parts := strings.SplitN(rest, ":", 2)
	subject := strings.TrimSpace(parts[0])
	if subject == "" {
		return Identity{}, fmt.Errorf("%w: empty dev-auth subject", ErrInvalidToken)
	}
	id := Identity{Provider: "dev", Subject: subject}
	if len(parts) == 2 {
		id.Email = strings.TrimSpace(parts[1])
	}
	return id, nil
}

// workosNotConfigured is the placeholder for the production adapter (plan
// §4(a)/Sol SD7). It fails closed so a misconfigured production deployment can
// never silently accept tokens.
type workosNotConfigured struct{}

// NewWorkOSPlaceholder returns a Verifier that always fails closed until the
// real WorkOS adapter lands after the operator spike.
func NewWorkOSPlaceholder() Verifier { return workosNotConfigured{} }

func (workosNotConfigured) Provider() string { return "workos" }

func (workosNotConfigured) Verify(context.Context, string) (Identity, error) {
	return Identity{}, fmt.Errorf("%w: production WorkOS verifier is blocked on the operator spike (plan §4a)", ErrInvalidToken)
}
