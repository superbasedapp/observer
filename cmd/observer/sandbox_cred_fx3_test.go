//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// TestHomeRelayAlwaysGetsASentinel (FX3 item 5, live finding F-L3P4-4): a
// home_relay run's box gets a sentinel in its tool's key variable whoever
// serves the key at home, so Claude Code starts instead of printing "Not
// logged in". The org gateway route serves with no stored key (it replaces
// every credential header with the org's virtual key); a routing key pool
// does not (it only rotates keys a request already carries), so a pool
// alone is refused at setup with words that say so, not left to the box.
func TestHomeRelayAlwaysGetsASentinel(t *testing.T) {
	t.Run("org route, no stored key", func(t *testing.T) {
		obs, _ := credEnvForTest(t, true)
		credOtherHomeRelay = func() bool { return true }
		plan := credPlan(obs, "run-fx3-org")
		if err := credSetup(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		env := map[string]string{}
		credEnv(plan, env)
		if !sandboxcred.IsSentinel(env["ANTHROPIC_API_KEY"]) {
			t.Fatalf("the box got no sentinel: %v", env)
		}
	})
	t.Run("key pool alone", func(t *testing.T) {
		obs, _ := credEnvForTest(t, true)
		credKeyPoolSet = func() bool { return true }
		err := credSetup(context.Background(), credPlan(obs, "run-fx3-pool"))
		if err == nil || !strings.Contains(err.Error(), "custody_unsatisfiable") || !strings.Contains(err.Error(), "key pool does not serve home_relay") {
			t.Fatalf("a pool-only home_relay: %v", err)
		}
	})
	t.Run("the driver's rule", func(t *testing.T) {
		var pool, route config.Config
		pool.Routing.KeyPool = map[string][]string{"anthropic": {"k1", "k2"}}
		route.Proxy.OrgRoute.Mode = "gateway"
		if homeRelayServedAtHome(pool) || !homeRelayServedAtHome(route) {
			t.Fatal("homeRelayServedAtHome")
		}
	})
}
