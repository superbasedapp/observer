package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

func TestProxyClientAuthCheck(t *testing.T) {
	t.Parallel()
	routes := []proxyroute.RouteStatus{
		{Tool: "claude-code", State: proxyroute.RouteOurs, Port: 8820, ClientAuth: true},
		{Tool: "kimi-code", State: proxyroute.RouteOurs, Port: 8820},
		{Tool: "codex", State: proxyroute.RouteOurs, Port: 9999},
	}
	cfg := func(routes, require bool) config.Config {
		c := config.Config{}
		c.Proxy.ClientAuthRoutes, c.Proxy.RequireClientAuth = routes, require
		return c
	}
	for _, c := range []struct {
		name   string
		cfg    config.Config
		routes []proxyroute.RouteStatus
		status Status
		want   string
	}{
		{"off", cfg(false, false), routes, StatusOK, "off"},
		{"routes on, not required", cfg(true, false), routes, StatusOK, "1 route(s) carry the token, 1 plain"},
		{"required, a plain route", cfg(false, true), routes, StatusWarn, "still plain"},
		{"required, every route tokened", cfg(true, true), routes[:1], StatusOK, "every config route carries the token"},
	} {
		got := proxyClientAuthCheck(c.cfg, 8820, c.routes)
		if got.Status != c.status || !strings.Contains(got.Message, c.want) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}
