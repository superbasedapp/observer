package jobs

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestUsageHonestMetrics pins the digest fold (D-866): every snapshot leaves
// with a resolved usage_status, an unmeasured one loses its token and cost
// keys (including a legacy all-zero snapshot stored before the field), and the
// stored map is never mutated.
func TestUsageHonestMetrics(t *testing.T) {
	usageKeys := []string{"tokens_in", "tokens_out", "cache_read", "cost_usd"}
	cases := []struct {
		name       string
		in         map[string]any
		wantStatus string
		wantFigs   bool
	}{
		{"new not measured", map[string]any{"usage_status": "not_measured", "error_rate": 0.0}, "not_measured", false},
		{"new measured zero", map[string]any{"usage_status": "measured", "tokens_in": 0.0, "tokens_out": 0.0, "cache_read": 0.0, "cost_usd": 0.0}, "measured", true},
		{"legacy with figures", map[string]any{"tokens_in": 10.0, "tokens_out": 5.0, "cache_read": 1.0, "cost_usd": 0.01}, "measured", true},
		{"legacy all zero", map[string]any{"tokens_in": 0.0, "tokens_out": 0.0, "cache_read": 0.0, "cost_usd": 0.0, "error_rate": 0.1}, "not_measured", false},
		{"unknown status falls back to figures", map[string]any{"usage_status": "partial", "tokens_in": 3.0}, "measured", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(tc.in)
			out := usageHonestMetrics(tc.in)
			if out["usage_status"] != tc.wantStatus {
				t.Fatalf("usage_status = %v, want %q", out["usage_status"], tc.wantStatus)
			}
			for _, k := range usageKeys {
				_, has := out[k]
				if !tc.wantFigs && has {
					t.Fatalf("unmeasured snapshot kept %q: %v", k, out)
				}
			}
			if len(tc.in) != before {
				t.Fatal("usageHonestMetrics mutated the stored snapshot")
			}
		})
	}
	if usageHonestMetrics(nil) != nil {
		t.Fatal("a nil snapshot must stay nil")
	}
}

// TestBuildDigestEvidenceUsageHonest pins that the digest evidence handed to
// the model goes through the usage fold.
func TestBuildDigestEvidenceUsageHonest(t *testing.T) {
	ev := buildDigestEvidence("cp-1", time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),
		[]store.DigestSessionRow{{CloudSessionID: "cs-1", Title: "t", Metrics: map[string]any{"tokens_in": 0.0, "cost_usd": 0.0}}})
	m := ev.Sessions[0].Metrics
	if m["usage_status"] != "not_measured" {
		t.Fatalf("usage_status = %v, want not_measured", m["usage_status"])
	}
	if _, ok := m["cost_usd"]; ok {
		t.Fatalf("unmeasured session kept cost_usd: %v", m)
	}
}

// TestPromptsExplainUnmeasuredUsage pins that both model prompts tell the
// model an unmeasured session's usage is unknown, not zero.
func TestPromptsExplainUnmeasuredUsage(t *testing.T) {
	for name, p := range map[string]string{"luna": lunaSystemPrompt, "digest": digestSystemPrompt} {
		if !strings.Contains(p, `"usage_status" is "not_measured"`) || !strings.Contains(p, "UNKNOWN, not zero") {
			t.Fatalf("%s system prompt does not explain not_measured usage", name)
		}
	}
}
