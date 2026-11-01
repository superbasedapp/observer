//go:build !sbo_omit_cloud_intelligence

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCloudUsagePresence pins that presence is read from the captured rows
// (D-866): a hooks-only session with actions but no token rows is "not
// captured", a session with rows is captured even when they total zero.
func TestCloudUsagePresence(t *testing.T) {
	cases := []struct {
		name string
		m    store.CloudSessionMetrics
		want cloudevidence.UsagePresence
	}{
		{"no rows at all", store.CloudSessionMetrics{ErrorRate: 0.1}, cloudevidence.UsageNotCaptured},
		{"rows totalling zero", store.CloudSessionMetrics{RecordedRows: 2, Turns: []store.CloudTokenTurn{{}, {}}}, cloudevidence.UsageCaptured},
		{"rows with tokens", store.CloudSessionMetrics{RecordedRows: 1, TokensIn: 10, Turns: []store.CloudTokenTurn{{Input: 10}}}, cloudevidence.UsageCaptured},
		{"legacy proxy turns only", store.CloudSessionMetrics{ProxyTurns: []store.CloudTokenTurn{{}}}, cloudevidence.UsageCaptured},
		{"sums without a row count", store.CloudSessionMetrics{TokensOut: 3}, cloudevidence.UsageCaptured},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cloudUsagePresence(tc.m); got != tc.want {
				t.Fatalf("cloudUsagePresence = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCloudMetricsCarriesUsagePresence pins that the metrics mapping hands the
// presence statement to the builder, so the D-866 hooks-only session uploads
// usage_status "not_measured" instead of a free session.
func TestCloudMetricsCarriesUsagePresence(t *testing.T) {
	got := cloudMetrics(store.CloudSessionFacts{ActionCount: 4}, nil)
	if got.Usage != cloudevidence.UsageNotCaptured {
		t.Fatalf("hooks-only session Usage = %v, want UsageNotCaptured", got.Usage)
	}
}

// TestCloudPrintEnvelopeSummaryUsage pins the preview summary: an unmeasured
// session reads "not measured", never "tokens in 0 / cost $0.0000".
func TestCloudPrintEnvelopeSummaryUsage(t *testing.T) {
	cases := []struct {
		name    string
		metrics cloudcontract.MetricsBlock
		want    string
		notWant string
	}{
		{"not measured", cloudcontract.MetricsBlock{UsageStatus: cloudcontract.UsageNotMeasured}, "tokens and cost not measured", "cost $"},
		{"measured zero", cloudcontract.MetricsBlock{UsageStatus: cloudcontract.UsageMeasured}, "tokens in 0 / out 0", "not measured"},
		{"measured figures", cloudcontract.MetricsBlock{TokensIn: 12, TokensOut: 3}, "tokens in 12 / out 3", "not measured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			cloudPrintEnvelopeSummary(&buf, cloudEnvelopeResult{Envelope: &cloudcontract.Envelope{Metrics: tc.metrics}})
			out := buf.String()
			if !strings.Contains(out, tc.want) || strings.Contains(out, tc.notWant) {
				t.Fatalf("summary %q: want %q, not %q", out, tc.want, tc.notWant)
			}
		})
	}
}
