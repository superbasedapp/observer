package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// orgoidcclient.go registers a new org as a client of the platform OIDC
// issuer (managed-SaaS plan 07 wave 15 lane platform-signin, CPSIGN-9;
// design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md A7
// and 4.1). The client is control-plane data, so it is written by the
// control plane, in the provisioning transaction, together with the org: it
// exists from the moment the org does, long before the tenant is created and
// the org turns active (the issuer's org-active rule refuses an authorize
// until then), and a provisioning that rolls back leaves no client behind.
//
// The client is the public one design A7 names: id "org:<org id>", no
// secret, PKCE S256, one exact redirect URI
// https://<slug>.<tenant domain>/auth/oidc/callback, the path of the tenant
// rail's callback (internal/orgserver/auth DefaultOIDCRedirectPath, mirrored
// as oidcissuer.TenantCallbackPath). The tenant domain is the API process's
// SBCI_TENANT_DOMAIN (api.Options.TenantDomain); the org host's
// [platform].host_base must equal it, so the org rail's redirect URI (its
// external URL https://<slug>.<host_base> plus the callback path) is byte
// for byte the registered one.
//
// The call site is ProvisionOrg (orgs.go), after the org_slugs insert:
//
//	if err := RegisterProvisionedOIDCClientTx(ctx, tx, orgID, in.Slug, in.TenantDomain); err != nil {
//		return fmt.Errorf("register oidc client: %w", err)
//	}
//
// with ProvisionOrgInput.TenantDomain set by the console's create route from
// api.Server's tenant domain (landed at the wave 15 merge, L-123).

// RegisterProvisionedOIDCClientTx registers org orgID's platform OIDC client
// inside the provisioning transaction tx, for the org served at slug under
// tenantDomain. It is idempotent: a retried provisioning step finds the same
// client and writes nothing (EnsureOIDCClientTx); a client already
// registered with another redirect URI is ErrOIDCClientConflict.
//
// An empty tenantDomain registers nothing and returns nil: a deployment with
// no tenant domain (a single-host dev or staging cloud) has no tenant
// dashboard for anybody to sign in to, and the console shows no tenant host
// either (portal_orgs.go tenantHost). The org can be registered later with
// RegisterOIDCClient once a domain exists.
func RegisterProvisionedOIDCClientTx(ctx context.Context, tx pgx.Tx, orgID, slug, tenantDomain string) error {
	if strings.TrimSpace(tenantDomain) == "" {
		return nil
	}
	c, err := oidcissuer.ClientForOrg(orgID, slug, tenantDomain)
	if err != nil {
		return fmt.Errorf("cloudserver/store.RegisterProvisionedOIDCClientTx: %w", err)
	}
	if err := EnsureOIDCClientTx(ctx, tx, c); err != nil {
		return fmt.Errorf("cloudserver/store.RegisterProvisionedOIDCClientTx: %w", err)
	}
	return nil
}
