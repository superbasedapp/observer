package jobs

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// CredentialSource is the pre-approval boundary seam (plan §2.1): it returns the
// provider API key for a RESOLVED route, or ok=false when ABSENT. The production
// worker's credential is simply not provisioned until the provider posture the
// route needs is in place: the gate is credential ABSENCE, not a request
// attribute, so no client-assertable "synthetic" class can bypass it. An absent
// credential parks the job provider_policy_unverified WITHOUT any provider call.
//
// It is handed the whole resolved route snapshot (not just its id) so a source
// can answer per provider: a key provisioned for one provider family is never
// handed to a route that speaks another family's dialect.
type CredentialSource interface {
	ProviderKey(ctx context.Context, route store.RouteInfo) (key string, ok bool, err error)
}

// AbsentCredentials is the fail-closed default: no key for any route. This is
// the production posture pre-approval (substrate §6.3), and the worker's default
// when none is injected.
type AbsentCredentials struct{}

// ProviderKey always reports absent.
func (AbsentCredentials) ProviderKey(context.Context, store.RouteInfo) (string, bool, error) {
	return "", false, nil
}

// StaticCredentials returns a fixed key for every route (tests and the
// operator-only non-production proving path). An empty Key reports absent.
type StaticCredentials struct{ Key string }

// ProviderKey returns the fixed key, ok=false when it is empty.
func (c StaticCredentials) ProviderKey(context.Context, store.RouteInfo) (string, bool, error) {
	return c.Key, c.Key != "", nil
}

// FamilyCredentials holds at most one key per provider family and answers for a
// route by the family of the route's dialect (inference.SpecFor). A route whose
// dialect is unknown, or whose family has no key, is ABSENT, so a deployment
// configured with only an Anthropic key can never call a Foundry route, and
// vice versa. This is the production credential source.
type FamilyCredentials struct {
	Keys map[inference.Family]string
}

// ProviderKey returns the key of the route's dialect family, ok=false when the
// dialect is unknown or that family has no key.
func (c FamilyCredentials) ProviderKey(_ context.Context, route store.RouteInfo) (string, bool, error) {
	spec, ok := inference.SpecFor(route.Dialect)
	if !ok {
		return "", false, nil
	}
	k := c.Keys[spec.Family]
	return k, k != "", nil
}
