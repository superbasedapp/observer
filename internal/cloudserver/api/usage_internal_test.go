package api

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestSessionMetricsJSONUsage pins the stored session snapshot (D-866): every
// snapshot carries the resolved usage_status, and an unmeasured session stores
// NO token or cost keys, so no later reader sees "0 tokens / $0". A legacy
// envelope (no field) with all-zero figures resolves to not_measured.
func TestSessionMetricsJSONUsage(t *testing.T) {
	usageKeys := []string{"tokens_in", "tokens_out", "cache_read", "cost_usd"}
	cases := []struct {
		name       string
		metrics    cloudcontract.MetricsBlock
		wantStatus string
		wantFigs   bool
	}{
		{"new node not measured", cloudcontract.MetricsBlock{UsageStatus: cloudcontract.UsageNotMeasured}, "not_measured", false},
		{"new node measured zero", cloudcontract.MetricsBlock{UsageStatus: cloudcontract.UsageMeasured}, "measured", true},
		{"legacy with figures", cloudcontract.MetricsBlock{TokensIn: 10, TokensOut: 5, CostUSD: 0.01}, "measured", true},
		{"legacy all zero", cloudcontract.MetricsBlock{}, "not_measured", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(sessionMetricsJSON(cloudcontract.Envelope{Metrics: tc.metrics}), &m); err != nil {
				t.Fatalf("decode snapshot: %v", err)
			}
			if m["usage_status"] != tc.wantStatus {
				t.Fatalf("usage_status = %v, want %q", m["usage_status"], tc.wantStatus)
			}
			for _, k := range usageKeys {
				if _, ok := m[k]; ok != tc.wantFigs {
					t.Fatalf("key %q present=%v, want %v (snapshot %v)", k, ok, tc.wantFigs, m)
				}
			}
			if _, ok := m["error_rate"]; !ok {
				t.Fatal("error_rate must stay in every snapshot")
			}
		})
	}
}
