package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/remedy"
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

// TestProxyClientAuthRemediations: a plain route links to Set up (its
// command is spelled in the detail), and a token-capable node that does not
// require the token yet links to Settings > Proxy.
func TestProxyClientAuthRemediations(t *testing.T) {
	t.Parallel()
	routes := []proxyroute.RouteStatus{
		{Tool: "claude-code", State: proxyroute.RouteOurs, Port: 8820, ClientAuth: true},
		{Tool: "kimi-code", State: proxyroute.RouteOurs, Port: 8820},
	}
	notRequired := config.Config{}
	notRequired.Proxy.ClientAuthRoutes = true
	c := proxyClientAuthCheck(notRequired, 8820, routes)
	assertSpelled(t, c, remedy.Init, remedy.OpenSettings)
	if !strings.Contains(c.Message, "Settings > Proxy") {
		t.Errorf("message does not name the control: %q", c.Message)
	}

	required := config.Config{}
	required.Proxy.RequireClientAuth = true
	c = proxyClientAuthCheck(required, 8820, routes)
	assertSpelled(t, c, remedy.Init)
	for _, r := range c.Remediations {
		if r.Action == remedy.OpenSettings {
			t.Errorf("already required: no Settings link expected, got %+v", c.Remediations)
		}
	}

	allTokened := proxyClientAuthCheck(required, 8820, routes[:1])
	if len(allTokened.Remediations) != 0 {
		t.Errorf("healthy check carries remediations %+v", allTokened.Remediations)
	}
}
