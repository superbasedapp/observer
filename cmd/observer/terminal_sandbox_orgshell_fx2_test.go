//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestOrgShellDailyQuotaHook (FX2 fix round 1): the generic consent code
// reads the org row's daily quota only through the registration's
// dailyQuota hook; the hook answers the verified body's value while the
// row is offered, and 0 otherwise. A vendor without the hook answers 0.
func TestOrgShellDailyQuotaHook(t *testing.T) {
	var c config.TerminalSandboxHostedConfig
	c.OpenShellOrg.Published.DailyBoxMinutesPerMember = 480
	if got := hostedVendorDailyQuota(sandboxremote.VendorOpenShellOrg, c); got != 0 {
		t.Fatalf("a row not offered answered %d", got)
	}
	c.OpenShellOrg.Published.Offered = true
	if got := hostedVendorDailyQuota(sandboxremote.VendorOpenShellOrg, c); got != 480 {
		t.Fatalf("the offered row answered %d", got)
	}
	if got := hostedVendorDailyQuota(sandboxremote.VendorE2B, c); got != 0 {
		t.Fatalf("a vendor without the hook answered %d", got)
	}
}
