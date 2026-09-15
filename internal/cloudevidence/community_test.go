package cloudevidence

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

func communityInput() CommunityInput {
	return CommunityInput{
		CohortKey:     "global",
		MetricID:      "sessions_per_active_day",
		MetricVersion: 1,
		WindowID:      "2026-09",
		Value:         4.5,
	}
}

// TestBuildCommunityContribution pins the composition: schema version
// stamped from the constant, digest set and internally consistent, and the
// contribution validates.
func TestBuildCommunityContribution(t *testing.T) {
	t.Parallel()
	c, err := BuildCommunityContribution(communityInput())
	if err != nil {
		t.Fatalf("BuildCommunityContribution: %v", err)
	}
	if c.SchemaVersion != cloudcontract.CommunityContributionSchemaVersion {
		t.Errorf("schema version = %q", c.SchemaVersion)
	}
	if c.CohortKey != "global" || c.MetricID != "sessions_per_active_day" ||
		c.MetricVersion != 1 || c.WindowID != "2026-09" || c.Value != 4.5 {
		t.Errorf("unexpected contribution: %+v", c)
	}
	if c.Digest == "" {
		t.Fatal("Digest was not set")
	}
	// Recomputing the digest over the same content (digest cleared) must equal
	// the stamped value — the digest is non-self-referential.
	recomputed, err := cloudcontract.CommunityDigest(c)
	if err != nil {
		t.Fatalf("CommunityDigest: %v", err)
	}
	if recomputed != c.Digest {
		t.Errorf("recomputed digest %q != stamped digest %q", recomputed, c.Digest)
	}
}

// TestBuildCommunityContributionRejects walks the refusals: Validate's bounds
// surface through the builder unchanged.
func TestBuildCommunityContributionRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*CommunityInput)
		wantErr string
	}{
		{"empty cohort key", func(in *CommunityInput) { in.CohortKey = "" }, "cohort_key is required"},
		{"empty metric id", func(in *CommunityInput) { in.MetricID = "" }, "metric_id is required"},
		{"zero metric version", func(in *CommunityInput) { in.MetricVersion = 0 }, "metric_version must be positive"},
		{"negative metric version", func(in *CommunityInput) { in.MetricVersion = -1 }, "metric_version must be positive"},
		{"bad window", func(in *CommunityInput) { in.WindowID = "2026/09" }, "is not 'YYYY-MM'"},
		{"empty window", func(in *CommunityInput) { in.WindowID = "" }, "is not 'YYYY-MM'"},
		{"negative value", func(in *CommunityInput) { in.Value = -1 }, "must be non-negative"},
		{"NaN value", func(in *CommunityInput) { in.Value = math.NaN() }, "must be finite"},
		{"Inf value", func(in *CommunityInput) { in.Value = math.Inf(1) }, "must be finite"},
		{"value over the sanity ceiling", func(in *CommunityInput) { in.Value = cloudcontract.MaxContributionValue + 1 }, "sanity ceiling"},
		{"cohort key too long", func(in *CommunityInput) {
			in.CohortKey = strings.Repeat("c", cloudcontract.MaxCohortKeyBytes+1)
		}, "exceeds"},
		{"metric id too long", func(in *CommunityInput) {
			in.MetricID = strings.Repeat("m", cloudcontract.MaxMetricIDBytes+1)
		}, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := communityInput()
			tc.mutate(&in)
			_, err := BuildCommunityContribution(in)
			if err == nil {
				t.Fatalf("BuildCommunityContribution() = nil error, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildCommunityContribution() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestSerializeCommunityIsTheOneSerializer pins that the digest returned
// alongside the bytes is exactly the digest a recipient recomputes from those
// bytes — the property that makes preview, digest, and upload one artifact.
func TestSerializeCommunityIsTheOneSerializer(t *testing.T) {
	t.Parallel()
	c, err := BuildCommunityContribution(communityInput())
	if err != nil {
		t.Fatalf("BuildCommunityContribution: %v", err)
	}
	final, digest, err := SerializeCommunity(c)
	if err != nil {
		t.Fatalf("SerializeCommunity: %v", err)
	}
	if !bytes.Contains(final, []byte(digest)) {
		t.Fatal("the returned digest is not embedded in the returned bytes")
	}
	// A pre-stamped contribution must serialize identically — the serializer
	// clears the field before digesting, so a stale digest can never poison
	// the value.
	poisoned := c
	poisoned.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	final2, digest2, err := SerializeCommunity(poisoned)
	if err != nil {
		t.Fatalf("SerializeCommunity(poisoned): %v", err)
	}
	if digest2 != digest || !bytes.Equal(final2, final) {
		t.Errorf("a stale Digest field changed the output: %q vs %q", digest2, digest)
	}
}

// TestSerializeCommunityRoundTrips pins that the serialized bytes parse back
// as valid JSON carrying the exact wire fields plus the embedded digest, and
// that recomputing the digest from the round-tripped struct still matches.
func TestSerializeCommunityRoundTrips(t *testing.T) {
	t.Parallel()
	c, err := BuildCommunityContribution(communityInput())
	if err != nil {
		t.Fatalf("BuildCommunityContribution: %v", err)
	}
	final, digest, err := SerializeCommunity(c)
	if err != nil {
		t.Fatalf("SerializeCommunity: %v", err)
	}
	var parsed cloudcontract.CommunityContribution
	if err := json.Unmarshal(final, &parsed); err != nil {
		t.Fatalf("Unmarshal(final): %v", err)
	}
	if parsed.Digest != digest {
		t.Errorf("parsed digest = %q, want %q", parsed.Digest, digest)
	}
	if parsed.CohortKey != c.CohortKey || parsed.MetricID != c.MetricID ||
		parsed.MetricVersion != c.MetricVersion || parsed.WindowID != c.WindowID || parsed.Value != c.Value {
		t.Errorf("round-tripped contribution = %+v, want the fields of %+v", parsed, c)
	}
	recomputed, err := cloudcontract.CommunityDigest(parsed)
	if err != nil {
		t.Fatalf("CommunityDigest(parsed): %v", err)
	}
	if recomputed != digest {
		t.Errorf("recomputed digest from round-tripped struct = %q, want %q", recomputed, digest)
	}
}

// TestSerializeCommunityRejectsInvalidContribution pins that an invalid
// contribution never produces bytes.
func TestSerializeCommunityRejectsInvalidContribution(t *testing.T) {
	t.Parallel()
	bad := cloudcontract.CommunityContribution{} // zero value: fails every bound
	if _, _, err := SerializeCommunity(bad); err == nil {
		t.Fatal("SerializeCommunity(zero value) = nil error, want a refusal")
	}
}
