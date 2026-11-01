package cloudevidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// TestBuildEnvelopeUsageStatus walks usageStatusRules one row per case (D-866):
// the status comes from the caller's data-presence statement, and the field is
// emitted only where the figures alone cannot answer.
func TestBuildEnvelopeUsageStatus(t *testing.T) {
	zero := MetricsInput{DeterministicScore: 40}
	nonZero := MetricsInput{TokensIn: 500, TokensOut: 300, CacheReadTokens: 100, CostUSD: 0.01, DeterministicScore: 75}
	costOnly := MetricsInput{CostUSD: 0.02}
	cases := []struct {
		name     string
		metrics  MetricsInput
		presence UsagePresence
		want     cloudcontract.UsageStatus
	}{
		{"not captured", zero, UsageNotCaptured, cloudcontract.UsageNotMeasured},
		{"captured all zero", zero, UsageCaptured, cloudcontract.UsageMeasured},
		{"captured non-zero", nonZero, UsageCaptured, ""},
		{"captured cost only", costOnly, UsageCaptured, ""},
		{"unspecified non-zero", nonZero, UsageUnspecified, ""},
		{"unspecified all zero", zero, UsageUnspecified, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Metrics = tc.metrics
			in.Metrics.Usage = tc.presence
			env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
			if err != nil {
				t.Fatalf("BuildEnvelope: %v", err)
			}
			if env.Metrics.UsageStatus != tc.want {
				t.Fatalf("usage_status = %q, want %q", env.Metrics.UsageStatus, tc.want)
			}
		})
	}
}

// TestBuildEnvelopeNotCapturedWithFiguresRefused pins that a caller cannot
// claim "not captured" while handing over figures: the contract refuses the
// contradiction rather than uploading numbers it says were never measured.
func TestBuildEnvelopeNotCapturedWithFiguresRefused(t *testing.T) {
	in := baseInput()
	in.Metrics.Usage = UsageNotCaptured
	if _, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts()); err == nil {
		t.Fatal("BuildEnvelope accepted not-captured usage with non-zero figures")
	}
}

// TestUsageStatusPreviewEqualsUpload pins the two-digest truth for the new
// field: the preview bytes carry it, both digests cover it (changing it changes
// both), and a hosted re-decode of the bytes reproduces the evidence digest,
// which is exactly the admission check a current server runs.
func TestUsageStatusPreviewEqualsUpload(t *testing.T) {
	in := baseInput()
	in.Metrics = MetricsInput{DeterministicScore: 40, Usage: UsageNotCaptured}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	raw, digests, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"usage_status": "not_measured"`)) {
		t.Fatalf("preview bytes do not show usage_status:\n%s", raw)
	}
	var decoded cloudcontract.Envelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("server-side Validate: %v", err)
	}
	re, err := cloudcontract.EvidenceContentDigest(decoded)
	if err != nil || re != digests.EvidenceContent || decoded.EvidenceContentDigest != re {
		t.Fatalf("server recompute %q (err %v), embedded %q, want %q", re, err, decoded.EvidenceContentDigest, digests.EvidenceContent)
	}
	if cloudcontract.UploadDigest(raw) != digests.Upload {
		t.Fatal("upload digest does not cover the previewed bytes")
	}

	measured := *env
	measured.Metrics.UsageStatus = cloudcontract.UsageMeasured
	measured.EvidenceContentDigest = ""
	_, d2, err := Serialize(&measured)
	if err != nil {
		t.Fatalf("Serialize measured: %v", err)
	}
	if d2.EvidenceContent == digests.EvidenceContent || d2.Upload == digests.Upload {
		t.Fatal("usage_status is not covered by both digests")
	}
}

// TestLegacyEnvelopeStillDecodes pins the old-node direction: a golden
// envelope serialized before usage_status existed decodes, validates and
// reproduces its own evidence digest on a current server, and its non-zero
// figures resolve to measured.
func TestLegacyEnvelopeStillDecodes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "codex_structural.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	raw = bytes.TrimRight(raw, "\n")
	if bytes.Contains(raw, []byte("usage_status")) {
		t.Fatal("golden already carries usage_status; it no longer models an old node")
	}
	var env cloudcontract.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	re, err := cloudcontract.EvidenceContentDigest(env)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if env.EvidenceContentDigest != "" && re != env.EvidenceContentDigest {
		t.Fatalf("legacy digest %q, recomputed %q", env.EvidenceContentDigest, re)
	}
	if got := env.Metrics.ResolvedUsage(); got != cloudcontract.UsageMeasured {
		t.Fatalf("legacy non-zero envelope resolved to %q", got)
	}
}
