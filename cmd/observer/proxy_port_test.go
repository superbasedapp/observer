package main

import "testing"

// TestEffectiveProxyPort pins U-05: the port the daemon binds and the port the
// dashboard reports (sidebar footer, Setup route writers) come from one rule,
// so `observer start --port N` is reported as N, not [proxy].port.
func TestEffectiveProxyPort(t *testing.T) {
	cases := []struct {
		name             string
		configured, flag int
		want             int
	}{
		{"no override uses config", 8820, 0, 8820},
		{"override wins", 8820, 18820, 18820},
		{"negative override ignored", 8820, -1, 8820},
		{"zero config with override", 0, 18820, 18820},
	}
	for _, c := range cases {
		if got := effectiveProxyPort(c.configured, c.flag); got != c.want {
			t.Errorf("%s: effectiveProxyPort(%d, %d) = %d, want %d", c.name, c.configured, c.flag, got, c.want)
		}
	}
}
