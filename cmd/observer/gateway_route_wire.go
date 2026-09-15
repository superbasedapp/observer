package main

import (
	"log/slog"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/proxy"
)

// virtualKeySource is the production proxy.VirtualKeySource (P5a Sol S2,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2.3): a
// LAZY adapter over the node's orgclient BearerStore third slot
// (Save/LoadVirtualKey). It defers OpenBearerStore — and therefore the OS
// keychain probe — until the first LoadVirtualKey call, so a solo-local
// install that never routes through the org AI Gateway pays no keychain cost
// and touches no keychain-unavailable sentinel. The proxy consults
// LoadVirtualKey only when an org-route is installed (SetOrgGatewayRoute in
// orgModeGateway) AND a request resolves to Gateway Mode, so on the common
// path this adapter is never opened at all.
//
// Constructing the adapter is free; it satisfies proxy.VirtualKeySource
// (orgclient never imported by internal/proxy — bound here, the same seam
// pattern as CostComputer/Admitter). The daemon-side orgclient (start.go)
// writes the same keychain slot via SaveVirtualKey under the same
// service+dir, so what the daemon provisions is exactly what this reads.
type virtualKeySource struct {
	service string
	dir     string
	logger  *slog.Logger

	once sync.Once
	bs   orgclient.BearerStore
}

// newVirtualKeySource builds the lazy production virtual-key source. It never
// touches the keychain until LoadVirtualKey is first called.
func newVirtualKeySource(cfg config.Config, dir string, logger *slog.Logger) *virtualKeySource {
	return &virtualKeySource{service: cfg.OrgClient.KeychainID, dir: dir, logger: logger}
}

// LoadVirtualKey implements proxy.VirtualKeySource. Opens the BearerStore on
// first use, then returns the stored virtual key + the routing generation it
// was minted under. An orgclient.ErrNoSecret (Gateway Mode not provisioned)
// propagates as a non-nil error, which the proxy translates into a
// fail-closed 502 rather than forwarding the developer's own credential.
func (v *virtualKeySource) LoadVirtualKey() (string, uint64, error) {
	v.once.Do(func() {
		v.bs = orgclient.OpenBearerStore(v.service, v.dir, v.logger)
	})
	return v.bs.LoadVirtualKey()
}

// applyOrgRouteBootstrap installs the node-local [proxy.org_route] bootstrap
// (P5a) onto the proxy's routing snapshot at startup via SetOrgGatewayRoute.
// The zero value (mode == "") is fully inert — no call is made, so an install
// with no [proxy.org_route] section gets byte-identical proxy behavior
// (TestOrgRoute_InertByDefault). config.Load already validated the shape
// (validateProxyOrgRoute), so a failure here is unexpected and non-fatal: the
// previously-live (inert) snapshot keeps serving and the daemon logs it,
// rather than refusing to start over a routing-config edit.
//
// An org-published gateway.providers MODE body supersedes this bootstrap hot
// at runtime through the SAME one-snapshot seam (the gateway.providers policy
// accept path also calls SetOrgGatewayRoute) — node-local config layer and
// org layer, one live routing generation, exactly the two-source-one-table
// pattern [proxy.upstreams] already uses with SetLaneTable.
func applyOrgRouteBootstrap(p *proxy.Proxy, cfg config.Config, logger *slog.Logger) {
	r := cfg.Proxy.OrgRoute
	if r.Mode == "" {
		return
	}
	if err := p.SetOrgGatewayRouteWithFallback(r.Mode, r.Primary, r.Fallbacks, r.TerminalPolicy, r.DirectFallbackCustodyAck); err != nil {
		logger.Warn("proxy: [proxy.org_route] bootstrap rejected — org route stays inert",
			"mode", r.Mode, "primary", r.Primary, "err", err)
		return
	}
	logger.Info("proxy: org AI Gateway route installed from [proxy.org_route]",
		"mode", r.Mode, "primary", r.Primary, "fallbacks", len(r.Fallbacks),
		"terminal", r.TerminalPolicy, "generation", p.RoutingGeneration())
}
