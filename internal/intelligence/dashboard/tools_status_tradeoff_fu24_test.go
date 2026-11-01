package dashboard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestWiringRouteTradeoff pins FU-24: the route step carries the registry's
// CC-11 trade-off sentence for the consent, and a tool with none carries
// none.
func TestWiringRouteTradeoff(t *testing.T) {
	cc := wiringFor("claude-code", nil)
	if cc == nil || cc.Route.Tradeoff != integration.RouteTradeoff("claude-code") || !strings.Contains(cc.Route.Tradeoff, "Remote Control") {
		t.Fatalf("claude-code route wiring = %+v, want the Remote Control trade-off", cc)
	}
	if cx := wiringFor("codex", nil); cx == nil || cx.Route.Tradeoff != "" {
		t.Errorf("codex route wiring = %+v, want no trade-off", cx)
	}
}
