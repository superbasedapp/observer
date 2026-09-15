package cloudcontract

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// validSnapshot returns a snapshot that passes Validate, for tests to perturb.
func validSnapshot() StructuralSnapshot {
	return StructuralSnapshot{
		SchemaVersion:       StructuralSnapshotSchemaVersion,
		Period:              "2026-09-01",
		PeriodRuleVersion:   1,
		TimezoneRuleVersion: 1,
		DeclaredTimezone:    "Europe/Berlin",
		Revision:            2,
		SourceWatermark:     "2026-09-01T23:41:07Z",
		Active:              true,
		SessionCount:        9,
		ActionCount:         412,
		ToolMix: []StructuralMixEntry{
			{Key: "claude-code", Count: 5},
			{Key: "codex", Count: 4},
		},
		ModelFamilyMix: []StructuralMixEntry{
			{Key: "claude-sonnet", Count: 5},
			{Key: "gpt-5", Count: 4},
		},
		TokensIn:                 120_000,
		TokensOut:                8_400,
		CacheReadTokens:          980_000,
		CostUSD:                  3.25,
		VerificationCoverageBand: CoverageBandHigh,
		OutcomeEvidenceBand:      CoverageBandLow,
		CoverageDenominators: StructuralCoverageDenominators{
			SessionsWithOutcomes:     2,
			SessionsWithVerification: 7,
		},
	}
}

// TestStructuralSerializationIsDeterministic pins the property the whole
// idempotency model rests on: two structurally-equal snapshots produce
// byte-identical output and therefore an identical digest. If this ever fails,
// a replay-ack becomes a false "different window" rejection.
func TestStructuralSerializationIsDeterministic(t *testing.T) {
	t.Parallel()
	a, b := validSnapshot(), validSnapshot()

	for i := 0; i < 32; i++ { // repeat: a map anywhere in the type would show up as flapping
		ba, err := StructuralUploadBytes(a)
		if err != nil {
			t.Fatalf("StructuralUploadBytes(a): %v", err)
		}
		bb, err := StructuralUploadBytes(b)
		if err != nil {
			t.Fatalf("StructuralUploadBytes(b): %v", err)
		}
		if !bytes.Equal(ba, bb) {
			t.Fatalf("iteration %d: equal snapshots serialized differently:\n%s\n---\n%s", i, ba, bb)
		}
	}

	da, err := StructuralDigest(a)
	if err != nil {
		t.Fatalf("StructuralDigest(a): %v", err)
	}
	db, err := StructuralDigest(b)
	if err != nil {
		t.Fatalf("StructuralDigest(b): %v", err)
	}
	if da != db {
		t.Errorf("equal snapshots digested differently: %q vs %q", da, db)
	}
	if !strings.HasPrefix(da, "sha256:") {
		t.Errorf("digest %q lacks the sha256: prefix", da)
	}
}

// TestStructuralDigestIsNonSelfReferential pins the digest discipline: the
// preimage never contains the digest field, so the digest cannot cover itself,
// and stamping a digest onto a snapshot does not change what that snapshot
// digests to. That is what lets a server recompute the digest from the bytes it
// received rather than trusting the value the client declared.
func TestStructuralDigestIsNonSelfReferential(t *testing.T) {
	t.Parallel()
	s := validSnapshot()

	pre, err := StructuralPreimage(s)
	if err != nil {
		t.Fatalf("StructuralPreimage: %v", err)
	}
	if bytes.Contains(pre, []byte(`"digest"`)) {
		t.Fatalf("the preimage contains a digest field — the digest would cover itself:\n%s", pre)
	}

	d, err := StructuralDigest(s)
	if err != nil {
		t.Fatalf("StructuralDigest: %v", err)
	}
	// Stamp it and re-derive: the value must be stable.
	s.Digest = d
	again, err := StructuralDigest(s)
	if err != nil {
		t.Fatalf("StructuralDigest(stamped): %v", err)
	}
	if again != d {
		t.Errorf("digest changed after stamping: %q -> %q", d, again)
	}

	// The upload bytes DO carry the digest (that is what the server recomputes
	// against), and clearing it again reproduces the preimage exactly.
	final, err := StructuralUploadBytes(s)
	if err != nil {
		t.Fatalf("StructuralUploadBytes: %v", err)
	}
	if !bytes.Contains(final, []byte(d)) {
		t.Errorf("upload bytes do not embed the digest — the server has nothing to recompute against")
	}
	var round StructuralSnapshot
	if err := json.Unmarshal(final, &round); err != nil {
		t.Fatalf("upload bytes are not valid JSON: %v", err)
	}
	roundPre, err := StructuralPreimage(round)
	if err != nil {
		t.Fatalf("StructuralPreimage(round): %v", err)
	}
	if !bytes.Equal(roundPre, pre) {
		t.Errorf("a server recomputing from the received bytes would get a different preimage:\n%s\n---\n%s", roundPre, pre)
	}
}

// TestStructuralSnapshotHasNoContentFields pins the "inexpressible, not merely
// validated away" claim: the canonical serialization's key set is a fixed,
// enumerated list with no path, excerpt, project, session, or free-text field
// anywhere in it. A future field that could carry content fails this test at
// the moment it is added, rather than at review time.
func TestStructuralSnapshotHasNoContentFields(t *testing.T) {
	t.Parallel()
	snap := validSnapshot()
	d, err := StructuralDigest(snap)
	if err != nil {
		t.Fatalf("StructuralDigest: %v", err)
	}
	snap.Digest = d // the wire form always carries it; omitempty drops it otherwise
	final, err := StructuralUploadBytes(snap)
	if err != nil {
		t.Fatalf("StructuralUploadBytes: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(final, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]bool{
		"schema_version": true, "period": true, "period_rule_version": true,
		"timezone_rule_version": true, "declared_timezone": true, "revision": true,
		"source_watermark": true, "active": true, "session_count": true,
		"action_count": true, "tool_mix": true, "model_family_mix": true,
		"tokens_in": true, "tokens_out": true, "cache_read_tokens": true,
		"cost_usd": true, "verification_coverage_band": true,
		"outcome_evidence_band": true, "coverage_denominators": true, "digest": true,
	}
	for k := range generic {
		if !want[k] {
			t.Errorf("unexpected top-level field %q on the structural snapshot — every field here leaves "+
				"the machine, so a new one is a disclosure decision, not a refactor", k)
		}
	}
	for k := range want {
		if _, ok := generic[k]; !ok {
			t.Errorf("field %q disappeared from the canonical serialization", k)
		}
	}
}

// TestStructuralSnapshotValidate walks the bounds one violation at a time.
func TestStructuralSnapshotValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(*StructuralSnapshot)
		wantErr string
	}{
		{"valid", func(*StructuralSnapshot) {}, ""},
		{"wrong schema version", func(s *StructuralSnapshot) { s.SchemaVersion = "structural_insights.v9" }, "schema_version"},
		{"empty period", func(s *StructuralSnapshot) { s.Period = "" }, "period is empty"},
		{"period not a day", func(s *StructuralSnapshot) { s.Period = "2026-09-01T00:00:00Z" }, "period"},
		{"period rule zero", func(s *StructuralSnapshot) { s.PeriodRuleVersion = 0 }, "period_rule_version"},
		{"timezone rule zero", func(s *StructuralSnapshot) { s.TimezoneRuleVersion = 0 }, "timezone_rule_version"},
		{"empty timezone", func(s *StructuralSnapshot) { s.DeclaredTimezone = "" }, "declared_timezone is empty"},
		{"overlong timezone", func(s *StructuralSnapshot) {
			s.DeclaredTimezone = strings.Repeat("z", MaxDeclaredTimezoneBytes+1)
		}, "exceeds max"},
		{"revision zero", func(s *StructuralSnapshot) { s.Revision = 0 }, "revision"},
		{"watermark not RFC3339", func(s *StructuralSnapshot) { s.SourceWatermark = "yesterday" }, "source_watermark"},
		{"active without watermark", func(s *StructuralSnapshot) { s.SourceWatermark = "" }, "must carry a source_watermark"},
		{"negative tokens", func(s *StructuralSnapshot) { s.TokensIn = -1 }, "negative token count"},
		{"negative cost", func(s *StructuralSnapshot) { s.CostUSD = -0.01 }, "negative"},
		{"unsorted mix", func(s *StructuralSnapshot) {
			s.ToolMix = []StructuralMixEntry{{Key: "codex", Count: 4}, {Key: "claude-code", Count: 5}}
		}, "strictly key-ascending"},
		{"duplicate mix key", func(s *StructuralSnapshot) {
			s.ToolMix = []StructuralMixEntry{{Key: "codex", Count: 4}, {Key: "codex", Count: 5}}
		}, "strictly key-ascending"},
		{"path-shaped mix key", func(s *StructuralSnapshot) {
			s.ToolMix = []StructuralMixEntry{{Key: "src/main.go", Count: 1}}
		}, "category-slug charset"},
		{"zero-count mix entry", func(s *StructuralSnapshot) {
			s.ToolMix = []StructuralMixEntry{{Key: "codex", Count: 0}}
		}, "is not positive"},
		{"too many mix entries", func(s *StructuralSnapshot) {
			s.ToolMix = make([]StructuralMixEntry, MaxStructuralMixEntries+1)
		}, "exceeds max"},
		{"unknown band", func(s *StructuralSnapshot) { s.OutcomeEvidenceBand = "excellent" }, "outcome_evidence_band"},
		{"numerator over denominator", func(s *StructuralSnapshot) {
			s.CoverageDenominators.SessionsWithVerification = s.SessionCount + 1
		}, "exceeds session_count"},
		{"active contradicts session count", func(s *StructuralSnapshot) { s.Active = false }, "active"},
		{"inactive carrying aggregates", func(s *StructuralSnapshot) {
			s.Active = false
			s.SessionCount = 0
			s.SourceWatermark = ""
			s.CoverageDenominators = StructuralCoverageDenominators{}
			s.ToolMix, s.ModelFamilyMix = nil, nil
			// ActionCount/token sums deliberately left non-zero.
		}, "inactive window must carry no aggregates"},
		{"digest without prefix", func(s *StructuralSnapshot) { s.Digest = "deadbeef" }, "missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSnapshot()
			tc.mutate(&s)
			err := s.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidInactiveSnapshot pins that a zero-activity window is a legal
// snapshot, not an error: a day with no eligible sessions still gets a truthful
// "nothing happened" record rather than a gap the server has to guess about.
func TestValidInactiveSnapshot(t *testing.T) {
	t.Parallel()
	s := StructuralSnapshot{
		SchemaVersion:            StructuralSnapshotSchemaVersion,
		Period:                   "2026-09-02",
		PeriodRuleVersion:        1,
		TimezoneRuleVersion:      1,
		DeclaredTimezone:         "UTC",
		Revision:                 1,
		VerificationCoverageBand: CoverageBandNone,
		OutcomeEvidenceBand:      CoverageBandNone,
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("an empty window must be a valid snapshot: %v", err)
	}
}

// TestNormalizeMixKey pins the key rule — in particular that no filesystem
// path, URL, or Windows drive reference can be SPELLED as a mix key, which is
// what makes "a path leaked into the mix" structurally impossible rather than
// merely unlikely.
func TestNormalizeMixKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string // "" means expect an error
	}{
		{"plain tool", "claude-code", "claude-code"},
		{"family", "gpt-5", "gpt-5"},
		{"dotted", "kilo-code.cli", "kilo-code.cli"},
		{"empty", "", ""},
		{"unix path", "/home/dev/secret", ""},
		{"relative path", "src/main.go", ""},
		{"windows path", `C:\Users\dev`, ""},
		{"url", "https://example.com", ""},
		{"whitespace", "my tool", ""},
		{"newline", "tool\nname", ""},
		{"ansi escape", "tool\x1b[31m", ""},
		{"bidi override", "tool\u202e", ""},
		{"overlong", strings.Repeat("t", MaxStructuralMixKeyBytes+1), ""},
		{"non-ascii prose", "modèle-français", ""},
		{"quote", `tool"name`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeMixKey("k", tc.in)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("NormalizeMixKey(%q) = %q, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeMixKey(%q) = %v, want %q", tc.in, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("NormalizeMixKey(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCoverageBandVocabularyIsClosed pins the band vocabulary.
func TestCoverageBandVocabularyIsClosed(t *testing.T) {
	t.Parallel()
	for _, b := range AllCoverageBands() {
		if !b.Valid() {
			t.Errorf("%q is in AllCoverageBands but reports invalid", b)
		}
	}
	for _, b := range []CoverageBand{"", "partial", "NONE", "very-high"} {
		if b.Valid() {
			t.Errorf("%q must not be a valid coverage band", b)
		}
	}
}
