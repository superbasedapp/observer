package cloudcontract

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestMetricsUsageStatusValidate pins the usage_status schema rules (D-866):
// the closed vocabulary, and that "not_measured" never rides with figures.
func TestMetricsUsageStatusValidate(t *testing.T) {
	cases := []struct {
		name    string
		metrics MetricsBlock
		wantErr bool
	}{
		{"absent with figures", MetricsBlock{TokensIn: 10}, false},
		{"absent all zero", MetricsBlock{}, false},
		{"measured with figures", MetricsBlock{TokensIn: 10, UsageStatus: UsageMeasured}, false},
		{"measured all zero", MetricsBlock{UsageStatus: UsageMeasured}, false},
		{"not measured all zero", MetricsBlock{UsageStatus: UsageNotMeasured}, false},
		{"not measured with tokens", MetricsBlock{TokensOut: 1, UsageStatus: UsageNotMeasured}, true},
		{"not measured with cache read", MetricsBlock{CacheReadTokens: 1, UsageStatus: UsageNotMeasured}, true},
		{"not measured with cost", MetricsBlock{CostUSD: 0.01, UsageStatus: UsageNotMeasured}, true},
		{"unknown status", MetricsBlock{UsageStatus: "partial"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnvelope()
			env.Metrics = tc.metrics
			err := env.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestMetricsResolvedUsage pins the ONE reading every consumer uses: an
// explicit status wins; an absent one (an older node) is measured only when a
// figure is non-zero, and all-zero resolves to not_measured (conservative).
func TestMetricsResolvedUsage(t *testing.T) {
	cases := []struct {
		name    string
		metrics MetricsBlock
		want    UsageStatus
	}{
		{"explicit not measured", MetricsBlock{UsageStatus: UsageNotMeasured}, UsageNotMeasured},
		{"explicit measured zero", MetricsBlock{UsageStatus: UsageMeasured}, UsageMeasured},
		{"legacy tokens in", MetricsBlock{TokensIn: 1}, UsageMeasured},
		{"legacy tokens out", MetricsBlock{TokensOut: 1}, UsageMeasured},
		{"legacy cache read", MetricsBlock{CacheReadTokens: 1}, UsageMeasured},
		{"legacy cost only", MetricsBlock{CostUSD: 0.5}, UsageMeasured},
		{"legacy all zero", MetricsBlock{ErrorRate: 0.2}, UsageNotMeasured},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.metrics.ResolvedUsage(); got != tc.want {
				t.Fatalf("ResolvedUsage() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUsageStatusWireShape pins the additive wire shape: absent status keeps
// the pre-D-866 bytes (no key at all), a set status serializes as the last
// metrics key, and a hosted re-decode of either reproduces the evidence digest
// (the admission check in internal/cloudserver/api/jobs.go).
func TestUsageStatusWireShape(t *testing.T) {
	for _, status := range []UsageStatus{"", UsageMeasured, UsageNotMeasured} {
		t.Run(string(status), func(t *testing.T) {
			env := validEnvelope()
			env.Metrics = MetricsBlock{DeterministicScore: 50, UsageStatus: status}
			cd, err := EvidenceContentDigest(env)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			env.EvidenceContentDigest = cd
			raw, err := UploadBytes(env)
			if err != nil {
				t.Fatalf("upload bytes: %v", err)
			}
			hasKey := bytes.Contains(raw, []byte(`"usage_status"`))
			if hasKey != (status != "") {
				t.Fatalf("usage_status key present=%v for status %q", hasKey, status)
			}
			var decoded Envelope
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded.Metrics.UsageStatus != status {
				t.Fatalf("decoded status %q, want %q", decoded.Metrics.UsageStatus, status)
			}
			re, err := EvidenceContentDigest(decoded)
			if err != nil || re != cd {
				t.Fatalf("re-decoded digest %q (err %v), want %q", re, err, cd)
			}
		})
	}
}

// TestUsageStatusOldDecoderRejects documents WHY the hosted server must roll
// before the node: a server built before this field decodes the envelope into
// a struct without it, so its digest recompute drops the key and no longer
// matches the embedded digest (422 digest_mismatch). The node therefore emits
// the field only where the figures alone cannot answer, keeping every
// measured, non-zero envelope byte-identical to what an older server accepts.
func TestUsageStatusOldDecoderRejects(t *testing.T) {
	env := validEnvelope()
	env.Metrics = MetricsBlock{UsageStatus: UsageNotMeasured}
	cd, err := EvidenceContentDigest(env)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	oldView := env
	oldView.Metrics.UsageStatus = "" // what a decoder without the field keeps
	old, err := EvidenceContentDigest(oldView)
	if err != nil {
		t.Fatalf("old digest: %v", err)
	}
	if old == cd {
		t.Fatal("an older decoder would reproduce the digest; the roll-order note is stale")
	}
}
