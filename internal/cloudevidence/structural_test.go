package cloudevidence

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

func structuralInput() StructuralDayInput {
	return StructuralDayInput{
		Period:          "2026-09-01",
		Revision:        1,
		SourceWatermark: "2026-09-01T21:14:02Z",
		SessionCount:    6,
		ActionCount:     301,
		ToolMix: []StructuralMixInput{
			{Key: "codex", Count: 2},
			{Key: "claude-code", Count: 4},
		},
		ModelFamilyMix: []StructuralMixInput{
			{Key: "gpt-5", Count: 2},
			{Key: "claude-sonnet", Count: 4},
		},
		TokensIn:                 90_000,
		TokensOut:                6_100,
		CacheReadTokens:          500_000,
		CostUSD:                  1.75,
		SessionsWithOutcomes:     1,
		SessionsWithVerification: 5,
	}
}

const testTZ = "Europe/Berlin"

// TestBuildStructuralSnapshot pins the composition: rule versions stamped from
// constants (not caller input), Active derived, bands derived, mixes sorted.
func TestBuildStructuralSnapshot(t *testing.T) {
	t.Parallel()
	snap, err := BuildStructuralSnapshot(structuralInput(), StructuralBuildOptions{DeclaredTimezone: testTZ})
	if err != nil {
		t.Fatalf("BuildStructuralSnapshot: %v", err)
	}
	if snap.SchemaVersion != cloudcontract.StructuralSnapshotSchemaVersion {
		t.Errorf("schema version = %q", snap.SchemaVersion)
	}
	if snap.PeriodRuleVersion != StructuralPeriodRuleV1 || snap.TimezoneRuleVersion != StructuralTimezoneRuleV1 {
		t.Errorf("rule versions = %d/%d, want %d/%d", snap.PeriodRuleVersion, snap.TimezoneRuleVersion,
			StructuralPeriodRuleV1, StructuralTimezoneRuleV1)
	}
	if !snap.Active {
		t.Error("a 6-session window must be active")
	}
	if snap.DeclaredTimezone != testTZ {
		t.Errorf("declared timezone = %q", snap.DeclaredTimezone)
	}
	// 5/6 ≈ 0.83 -> high; 1/6 ≈ 0.17 -> low.
	if snap.VerificationCoverageBand != cloudcontract.CoverageBandHigh {
		t.Errorf("verification band = %q, want high", snap.VerificationCoverageBand)
	}
	if snap.OutcomeEvidenceBand != cloudcontract.CoverageBandLow {
		t.Errorf("outcome band = %q, want low", snap.OutcomeEvidenceBand)
	}
	want := []cloudcontract.StructuralMixEntry{{Key: "claude-code", Count: 4}, {Key: "codex", Count: 2}}
	if len(snap.ToolMix) != len(want) {
		t.Fatalf("tool mix = %v, want %v", snap.ToolMix, want)
	}
	for i := range want {
		if snap.ToolMix[i] != want[i] {
			t.Errorf("tool mix[%d] = %v, want %v", i, snap.ToolMix[i], want[i])
		}
	}
}

// TestBuildStructuralSnapshotMixOrderIndependence is the determinism property
// that matters in practice: SQLite may return GROUP BY rows in any order, and
// the same window must still digest identically. The builder's merge+sort is
// what guarantees it.
func TestBuildStructuralSnapshotMixOrderIndependence(t *testing.T) {
	t.Parallel()
	a := structuralInput()
	b := structuralInput()
	// Same facts, different row order, and one split across duplicate keys.
	b.ToolMix = []StructuralMixInput{
		{Key: "claude-code", Count: 1},
		{Key: "codex", Count: 2},
		{Key: "claude-code", Count: 3}, // merges to 4
	}
	b.ModelFamilyMix = []StructuralMixInput{
		{Key: "claude-sonnet", Count: 4},
		{Key: "gpt-5", Count: 2},
	}

	sa, err := BuildStructuralSnapshot(a, StructuralBuildOptions{DeclaredTimezone: testTZ})
	if err != nil {
		t.Fatalf("build a: %v", err)
	}
	sb, err := BuildStructuralSnapshot(b, StructuralBuildOptions{DeclaredTimezone: testTZ})
	if err != nil {
		t.Fatalf("build b: %v", err)
	}
	ba, da, err := SerializeStructural(sa)
	if err != nil {
		t.Fatalf("serialize a: %v", err)
	}
	bb, db, err := SerializeStructural(sb)
	if err != nil {
		t.Fatalf("serialize b: %v", err)
	}
	if !bytes.Equal(ba, bb) {
		t.Errorf("row order changed the canonical bytes:\n%s\n---\n%s", ba, bb)
	}
	if da != db {
		t.Errorf("row order changed the digest: %q vs %q", da, db)
	}
}

// TestCoverageBandFor is the band table.
func TestCoverageBandFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		num, den int
		want     cloudcontract.CoverageBand
	}{
		{0, 0, cloudcontract.CoverageBandNone},   // empty window
		{0, 10, cloudcontract.CoverageBandNone},  // nothing covered
		{5, 0, cloudcontract.CoverageBandNone},   // nonsensical denominator
		{-1, 10, cloudcontract.CoverageBandNone}, // defensive
		{1, 10, cloudcontract.CoverageBandLow},   // 0.10
		{3, 10, cloudcontract.CoverageBandLow},   // 0.30, just under 1/3
		{1, 3, cloudcontract.CoverageBandMedium}, // exactly 1/3 -> medium
		{5, 10, cloudcontract.CoverageBandMedium},
		{6, 10, cloudcontract.CoverageBandMedium}, // 0.60, just under 2/3
		{2, 3, cloudcontract.CoverageBandHigh},    // exactly 2/3 -> high
		{9, 10, cloudcontract.CoverageBandHigh},
		{10, 10, cloudcontract.CoverageBandHigh},
	}
	for _, tc := range cases {
		if got := CoverageBandFor(tc.num, tc.den); got != tc.want {
			t.Errorf("CoverageBandFor(%d, %d) = %q, want %q", tc.num, tc.den, got, tc.want)
		}
	}
}

// TestBuildStructuralSnapshotFoldsUnrepresentableKeys pins the fold-not-fail
// choice: a malformed local tool string costs the developer a category label,
// never the whole window's insights — and the counts still sum correctly.
func TestBuildStructuralSnapshotFoldsUnrepresentableKeys(t *testing.T) {
	t.Parallel()
	in := structuralInput()
	in.SessionCount = 3
	in.ActionCount = 3
	in.SessionsWithOutcomes = 0
	in.SessionsWithVerification = 0
	in.ToolMix = []StructuralMixInput{
		{Key: "codex", Count: 1},
		{Key: "/home/dev/weird-tool", Count: 1}, // path-shaped: folds
		{Key: "another bad key", Count: 1},      // whitespace: folds, merges with the above
	}
	in.ModelFamilyMix = []StructuralMixInput{{Key: "gpt-5", Count: 3}}

	snap, err := BuildStructuralSnapshot(in, StructuralBuildOptions{DeclaredTimezone: testTZ})
	if err != nil {
		t.Fatalf("BuildStructuralSnapshot: %v", err)
	}
	got := map[string]int{}
	total := 0
	for _, e := range snap.ToolMix {
		got[e.Key] = e.Count
		total += e.Count
	}
	if got["codex"] != 1 {
		t.Errorf("codex count = %d, want 1", got["codex"])
	}
	if got[StructuralUnclassifiedKey] != 2 {
		t.Errorf("%s count = %d, want 2 (both malformed keys merged)", StructuralUnclassifiedKey, got[StructuralUnclassifiedKey])
	}
	if total != in.SessionCount {
		t.Errorf("mix counts sum to %d, want the session count %d — folding must not lose counts", total, in.SessionCount)
	}
	// Whatever else happened, no path fragment reached the bytes.
	final, _, err := SerializeStructural(snap)
	if err != nil {
		t.Fatalf("SerializeStructural: %v", err)
	}
	if bytes.Contains(final, []byte("/home/dev")) {
		t.Errorf("a path fragment reached the canonical bytes:\n%s", final)
	}
}

// TestBuildStructuralSnapshotRejects walks the refusals.
func TestBuildStructuralSnapshotRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*StructuralDayInput)
		tz      string
		wantErr string
	}{
		{"missing timezone", func(*StructuralDayInput) {}, "", "declared timezone is required"},
		{"negative session count", func(in *StructuralDayInput) { in.SessionCount = -1 }, testTZ, "negative"},
		{"revision zero", func(in *StructuralDayInput) { in.Revision = 0 }, testTZ, "revision"},
		{"bad period", func(in *StructuralDayInput) { in.Period = "01/09/2026" }, testTZ, "period"},
		{"empty window carrying aggregates", func(in *StructuralDayInput) {
			in.SessionCount = 0
			in.ToolMix, in.ModelFamilyMix = nil, nil
			in.SessionsWithOutcomes, in.SessionsWithVerification = 0, 0
			// ActionCount and the sums stay non-zero: an inconsistent DTO.
		}, testTZ, "carries aggregates"},
		{"coverage over denominator", func(in *StructuralDayInput) {
			in.SessionsWithVerification = in.SessionCount + 1
		}, testTZ, "exceeds session_count"},
		{"too many distinct keys", func(in *StructuralDayInput) {
			in.ToolMix = nil
			for i := 0; i <= cloudcontract.MaxStructuralMixEntries; i++ {
				in.ToolMix = append(in.ToolMix, StructuralMixInput{Key: "t" + itoa(i), Count: 1})
			}
		}, testTZ, "exceeds max"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := structuralInput()
			tc.mutate(&in)
			_, err := BuildStructuralSnapshot(in, StructuralBuildOptions{DeclaredTimezone: tc.tz})
			if err == nil {
				t.Fatalf("BuildStructuralSnapshot() = nil error, want one mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("BuildStructuralSnapshot() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestBuildStructuralSnapshotEmptyWindow pins that a genuinely empty day builds
// a valid "nothing happened" snapshot rather than an error.
func TestBuildStructuralSnapshotEmptyWindow(t *testing.T) {
	t.Parallel()
	snap, err := BuildStructuralSnapshot(StructuralDayInput{
		Period:   "2026-09-02",
		Revision: 1,
	}, StructuralBuildOptions{DeclaredTimezone: "UTC"})
	if err != nil {
		t.Fatalf("BuildStructuralSnapshot: %v", err)
	}
	if snap.Active {
		t.Error("an empty window must not report active")
	}
	if snap.VerificationCoverageBand != cloudcontract.CoverageBandNone ||
		snap.OutcomeEvidenceBand != cloudcontract.CoverageBandNone {
		t.Errorf("empty window bands = %q/%q, want none/none", snap.VerificationCoverageBand, snap.OutcomeEvidenceBand)
	}
	if _, _, err := SerializeStructural(snap); err != nil {
		t.Fatalf("SerializeStructural(empty): %v", err)
	}
}

// TestSerializeStructuralIsTheOneSerializer pins that the digest returned
// alongside the bytes is exactly the digest a recipient recomputes from those
// bytes — the property that makes preview, digest, and upload one artifact.
func TestSerializeStructuralIsTheOneSerializer(t *testing.T) {
	t.Parallel()
	snap, err := BuildStructuralSnapshot(structuralInput(), StructuralBuildOptions{DeclaredTimezone: testTZ})
	if err != nil {
		t.Fatalf("BuildStructuralSnapshot: %v", err)
	}
	final, digest, err := SerializeStructural(snap)
	if err != nil {
		t.Fatalf("SerializeStructural: %v", err)
	}
	if !bytes.Contains(final, []byte(digest)) {
		t.Fatal("the returned digest is not embedded in the returned bytes")
	}
	// A pre-stamped snapshot must serialize identically — the serializer clears
	// the field before digesting, so a stale digest can never poison the value.
	poisoned := snap
	poisoned.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	final2, digest2, err := SerializeStructural(poisoned)
	if err != nil {
		t.Fatalf("SerializeStructural(poisoned): %v", err)
	}
	if digest2 != digest || !bytes.Equal(final2, final) {
		t.Errorf("a stale Digest field changed the output: %q vs %q", digest2, digest)
	}
}

// itoa is a tiny helper so the test file needs no strconv import for one call.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
