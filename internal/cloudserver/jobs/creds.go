package jobs

import "context"

// CredentialSource is the pre-approval boundary seam (plan §2.1): it returns the
// provider API key for a route, or ok=false when ABSENT. The production worker's
// credential is simply not provisioned until the Modified-Abuse-Monitoring
// approval + ContentLogging=false state exists — the gate is credential
// ABSENCE, not a request attribute, so no client-assertable "synthetic" class
// can bypass it. An absent credential parks the job provider_policy_unverified
// WITHOUT any provider call.
type CredentialSource interface {
	ProviderKey(ctx context.Context, routeID string) (key string, ok bool, err error)
}

// AbsentCredentials is the fail-closed default: no key for any route. This is
// the production posture pre-approval (substrate §6.3), and the worker's default
// when none is injected.
type AbsentCredentials struct{}

// ProviderKey always reports absent.
func (AbsentCredentials) ProviderKey(context.Context, string) (string, bool, error) {
	return "", false, nil
}

// StaticCredentials returns a fixed key for every route (post-approval / tests /
// the operator-only non-production proving path). An empty Key reports absent.
type StaticCredentials struct{ Key string }

// ProviderKey returns the fixed key, ok=false when it is empty.
func (c StaticCredentials) ProviderKey(context.Context, string) (string, bool, error) {
	return c.Key, c.Key != "", nil
}
