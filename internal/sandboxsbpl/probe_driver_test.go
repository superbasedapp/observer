package sandboxsbpl

import (
	"strings"
	"testing"
)

// TestProbeDriverRow pins the seatbelt_driver row (lane SBX-UPD, register
// MAC-10): sandbox-exec (and the empty default) walk on; the declared
// fallback mxc-exec-mac is refused fallback_driver_unavailable before
// anything on the host is read, naming the pinned package; an unknown
// driver is refused.
func TestProbeDriverRow(t *testing.T) {
	for _, tc := range []struct {
		driver, verdict, rule string
	}{
		{"", VerdictAvailable, "P4 sandbox-exec"},
		{DriverSandboxExec, VerdictAvailable, "P4 sandbox-exec"},
		{FallbackDriver, VerdictFallbackDriverUnavailable, "P2b driver"},
		{"bogus", VerdictDisabledByConfig, "P2b driver"},
	} {
		env := goodEnv()
		reads := 0
		ver, stat := env.OSVersion, env.StatExec
		env.OSVersion = func() (string, error) { reads++; return ver() }
		env.StatExec = func(p string) (ExecFacts, error) { reads++; return stat(p) }
		env.Driver = tc.driver
		r := Probe(env)
		if r.Verdict.Code != tc.verdict || r.Rule != tc.rule {
			t.Fatalf("driver %q: %s at %s (%s)", tc.driver, r.Verdict.Code, r.Rule, r.Verdict.Reason)
		}
		if tc.verdict != VerdictAvailable && reads != 0 {
			t.Fatalf("driver %q read the host %d times before refusing", tc.driver, reads)
		}
	}
	if !strings.Contains(FallbackRefusal, FallbackPackage) || !strings.Contains(FallbackRefusal, "MAC-10") || len(FallbackBinarySHA256) != 64 {
		t.Fatalf("the refusal or the pin facts are incomplete: %q", FallbackRefusal)
	}
}
