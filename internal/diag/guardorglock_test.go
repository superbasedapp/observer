package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestCheckGuardOrgLock walks guardOrgLockRows: one row per lock state, and
// every overridden setting named in the details.
func TestCheckGuardOrgLock(t *testing.T) {
	cases := []struct {
		name    string
		lock    config.GuardOrgLock
		want    Status
		message string
		details int
	}{
		{"no lock", config.GuardOrgLock{}, StatusOK, "no org lock", 0},
		{"tampered", config.GuardOrgLock{State: "tampered", Detail: "org lock missing"}, StatusFail, "does not verify", 0},
		{
			"managed with overrides",
			config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true, Overridden: []string{"guard.enabled: local false, organization floor true", "guard.mode: local off, organization floor enforce"}},
			StatusWarn, "overridden by organization policy", 2,
		},
		{
			// T-881: values a governance pin replaced are overrides too, so
			// the check no longer says "no local setting is below it".
			"managed with pinned overrides only",
			config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true, Pinned: []string{"guard.enabled: local false, organization pin true", "guard.mode: local observe, organization pin enforce"}},
			StatusWarn, "overridden by organization policy", 2,
		},
		{
			"managed with pinned and floored overrides",
			config.GuardOrgLock{
				State: "valid", TenancyKnown: true, Managed: true,
				Pinned:     []string{"guard.enabled: local false, organization pin true"},
				Overridden: []string{"guard.prompt.enabled: local false, organization floor true"},
			},
			StatusWarn, "overridden by organization policy", 2,
		},
		{"managed, nothing below the floor", config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true}, StatusOK, "managed node", 0},
		{"individual", config.GuardOrgLock{State: "valid", TenancyKnown: true}, StatusOK, "individual node", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			cfg.Guard.Lock = tc.lock
			c := checkGuardOrgLock(cfg)
			if c.Status != tc.want || !strings.Contains(c.Message, tc.message) || len(c.Details) != tc.details {
				t.Fatalf("check = %+v, want status %v message containing %q with %d details", c, tc.want, tc.message, tc.details)
			}
		})
	}
}
