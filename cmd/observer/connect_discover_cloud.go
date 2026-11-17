//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// connect_discover_cloud.go is the discovery seam pair in a build with Cloud
// Intelligence: GET /v1/orgs and POST /v1/orgs/personal:ensure through the
// consent gateway's Bootstrap family (design decision D-IND-2; ledger row
// IND-2). No consent source is passed: the user's own `observer connect` is
// the authorization, as for sign-in (R2 F10), and a nil source keeps every
// feature send fail-closed. The base URL resolves exactly as `observer cloud
// login` resolves it (--base-url, then the environment, then [cloud].base_url,
// then the built-in default), so discovery asks the estate the user signed in
// to.

func defaultConnectDiscovery() connectDiscovery {
	return connectDiscovery{
		listOrgs: func(ctx context.Context, o connectCloudOpts) (cloudcontract.DeviceOrgList, error) {
			gw, err := openConnectGateway(o)
			if err != nil {
				return cloudcontract.DeviceOrgList{}, err
			}
			return gw.BootstrapListOrgs(ctx)
		},
		ensurePersonal: func(ctx context.Context, o connectCloudOpts) (cloudcontract.EnsurePersonalOrgResponse, error) {
			gw, err := openConnectGateway(o)
			if err != nil {
				return cloudcontract.EnsurePersonalOrgResponse{}, err
			}
			return gw.BootstrapEnsurePersonalOrg(ctx)
		},
	}
}

// openConnectGateway opens the bootstrap-only gateway for discovery.
func openConnectGateway(o connectCloudOpts) (*cloudgateway.Gateway, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: o.configPath})
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return openCloudGateway(cfg, resolveCloudBaseURL(o.baseURL, cfg), o.devToken, nil, nil)
}
