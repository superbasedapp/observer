package main

import (
	"strings"
	"testing"
	"time"
)

// TestResolveBillingTimings is W16-D5's configuration: the past_due grace
// in whole days and the waitlist retry floor as a duration, each defaulting
// when unset, each refused outside its range, and both reaching the
// resolved host-API configuration.
func TestResolveBillingTimings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		env       map[string]string
		grace     time.Duration
		floor     time.Duration
		wantErrOn string
	}{
		{name: "unset: the defaults", env: map[string]string{}},
		{name: "a 14-day grace", env: map[string]string{envPastDueGraceDays: "14"}, grace: 14 * 24 * time.Hour},
		{name: "a 7-day grace and a 20m floor", env: map[string]string{envPastDueGraceDays: "7", envWaitlistRetryFloor: "20m"}, grace: 7 * 24 * time.Hour, floor: 20 * time.Minute},
		{name: "zero days", env: map[string]string{envPastDueGraceDays: "0"}, wantErrOn: envPastDueGraceDays},
		{name: "too many days", env: map[string]string{envPastDueGraceDays: "91"}, wantErrOn: envPastDueGraceDays},
		{name: "days not a number", env: map[string]string{envPastDueGraceDays: "two weeks"}, wantErrOn: envPastDueGraceDays},
		{name: "floor not a duration", env: map[string]string{envWaitlistRetryFloor: "15"}, wantErrOn: envWaitlistRetryFloor},
		{name: "floor too short", env: map[string]string{envWaitlistRetryFloor: "30s"}, wantErrOn: envWaitlistRetryFloor},
		{name: "floor past the cap", env: map[string]string{envWaitlistRetryFloor: "2h"}, wantErrOn: envWaitlistRetryFloor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{
				envHostAPIHostsFile: "/etc/sbci/hosts.json", envHostAPICAFile: "/etc/sbci/ca.pem",
				envHostAPICertFile: "/etc/sbci/client.pem", envHostAPIKeyFile: "/etc/sbci/client.key",
			}
			for k, v := range tc.env {
				env[k] = v
			}
			cfg, enabled, err := resolveHostAPIWorkerConfig(envMap(env))
			if tc.wantErrOn != "" {
				if err == nil || enabled || !strings.Contains(err.Error(), tc.wantErrOn) {
					t.Fatalf("err = %v, enabled = %v; want an error naming %s", err, enabled, tc.wantErrOn)
				}
				return
			}
			if err != nil || !enabled || cfg.pastDueGrace != tc.grace || cfg.waitlistFloor != tc.floor {
				t.Fatalf("cfg = %+v, enabled %v, err %v; want grace %s floor %s", cfg, enabled, err, tc.grace, tc.floor)
			}
		})
	}
}
