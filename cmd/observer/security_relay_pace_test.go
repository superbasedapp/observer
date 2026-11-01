//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"testing"
	"time"
)

// TestDepsRelayIntervalFor (SECP-26, lane LEFT-SHARED): the scan paces to
// half the relay's per-node budget when the relay sends one, and to half the
// default (2 s, as before) when it does not (an older server).
func TestDepsRelayIntervalFor(t *testing.T) {
	cases := []struct {
		perMinute int
		want      time.Duration
	}{
		{0, 2 * time.Second},
		{60, 2 * time.Second},
		{20, 6 * time.Second},
		{10, 12 * time.Second},
		{3, time.Minute},
		{1, 2 * time.Minute},
		{600, 200 * time.Millisecond},
	}
	for _, c := range cases {
		if got := depsRelayIntervalFor(c.perMinute); got != c.want {
			t.Errorf("perMinute %d: %v, want %v", c.perMinute, got, c.want)
		}
	}
	saved := depsRelayPerMinute
	defer func() { depsRelayPerMinute = saved }()
	depsRelayPerMinute = func() int { return 20 }
	if depsRelayInterval() != 6*time.Second {
		t.Fatalf("a relay that lowered its rate to 20 a minute: %v", depsRelayInterval())
	}
}
