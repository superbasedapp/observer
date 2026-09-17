package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// TestOTLPIngressPostureCheck is the NODE-OTLP-1 doctor-WARN pin: the one
// posture that must be reported is an OPENED receiver bound non-loopback,
// because the node has no receiver-token option and that flag also turns off
// the Host-header guard. Every other combination is OK — including
// allow_non_loopback set while the receiver is never opened at all, which is
// inert config, not a live exposure.
func TestOTLPIngressPostureCheck(t *testing.T) {
	cfgWith := func(otelEnabled, obsEnabled, allowNonLoopback bool) config.Config {
		var c config.Config
		c.Ingest.OTel.Enabled = otelEnabled
		c.Ingest.OTel.AllowNonLoopback = allowNonLoopback
		c.Ingest.OTel.GRPCAddr = "0.0.0.0:4317"
		c.Ingest.OTel.HTTPAddr = "0.0.0.0:4318"
		c.Observability.Enabled = obsEnabled
		return c
	}

	for _, tc := range []struct {
		name string
		cfg  config.Config
		want diag.Status
	}{
		{"receiver never opened", cfgWith(false, false, false), diag.StatusOK},
		{"receiver never opened, flag set anyway", cfgWith(false, false, true), diag.StatusOK},
		{"otel on, loopback", cfgWith(true, false, false), diag.StatusOK},
		{"observability on, loopback", cfgWith(false, true, false), diag.StatusOK},
		{"otel on, non-loopback", cfgWith(true, false, true), diag.StatusWarn},
		{"observability on, non-loopback", cfgWith(false, true, true), diag.StatusWarn},
		{"both on, non-loopback", cfgWith(true, true, true), diag.StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := otlpIngressPostureCheck(tc.cfg)
			if got.Status != tc.want {
				t.Fatalf("status = %v, want %v (message %q)", got.Status, tc.want, got.Message)
			}
			if got.Name != "otlp.ingress" {
				t.Errorf("name = %q, want otlp.ingress", got.Name)
			}
			if tc.want == diag.StatusWarn {
				// The WARN must SAY that nothing authenticates the listener —
				// a warning that only says "non-loopback" leaves the operator
				// guessing whether a token is protecting it.
				joined := strings.Join(append([]string{got.Message}, got.Details...), "\n")
				if !strings.Contains(joined, "no token") && !strings.Contains(joined, "NO authentication") {
					t.Errorf("warn text never says the listener is unauthenticated:\n%s", joined)
				}
			}
		})
	}
}
