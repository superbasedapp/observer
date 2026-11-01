package diag

import (
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// proxyclientauth.go: the doctor row of the proxy client token (OSH-R-009,
// docs/plans/proxy-client-auth-2026-10-30.md). It reads the config and the
// persisted routes only; the daemon's start log names every fact that held
// enforcement off (launcher-routed tools and sandboxed terminals as well).

const proxyClientAuthCheckName = "proxy.client_auth"

// checkProxyClientAuth reports the client-auth posture of this node's proxy.
func checkProxyClientAuth(homeDir string, cfg config.Config) Check {
	return proxyClientAuthCheck(cfg, cfg.Proxy.Port, proxyroute.InspectRoutes(homeDir))
}

// proxyClientAuthCheck builds the row from already read facts.
func proxyClientAuthCheck(cfg config.Config, port int, routes []proxyroute.RouteStatus) Check {
	c := Check{Name: proxyClientAuthCheckName, Status: StatusOK}
	if !cfg.Proxy.ClientAuthWanted() {
		c.Message = "client authentication is off (the default): any local process that is not a browser can use the proxy"
		return c
	}
	var plain, token []string
	for _, st := range routes {
		if st.State != proxyroute.RouteOurs || st.Port != port {
			continue
		}
		if st.ClientAuth {
			token = append(token, st.Tool)
		} else {
			plain = append(plain, st.Tool)
		}
	}
	sort.Strings(plain)
	sort.Strings(token)
	for _, t := range token {
		c.Details = append(c.Details, t+": route carries the client token")
	}
	for _, t := range plain {
		c.Details = append(c.Details, t+": route is in the plain form (run `observer init` to rewrite it)")
	}
	if !cfg.Proxy.RequireClientAuth {
		c.Message = fmt.Sprintf("client token routes are on and not required: %d route(s) carry the token, %d plain; set [proxy].require_client_auth once every route and session carries it", len(token), len(plain))
		return c
	}
	if len(plain) > 0 {
		c.Status = StatusWarn
		c.Message = fmt.Sprintf("client authentication is required but %d route(s) are still plain, so the daemon keeps serving every local client", len(plain))
		return c
	}
	c.Message = "client authentication is required and every config route carries the token; the daemon's start log says whether launcher-routed tools or sandboxed terminals still hold it off"
	return c
}
