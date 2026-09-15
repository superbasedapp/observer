package cloudcontract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// activityMixCompatEnvelope is a minimal VALID envelope used by the additive-
// field compatibility pins below.
func activityMixCompatEnvelope() Envelope {
	return Envelope{
		SchemaVersion:   EnvelopeSchemaVersion,
		CloudSessionID:  "cs-compat-1",
		CloudProjectID:  "cp-compat-1",
		Tool:            "codex",
		ModelFamily:     "gpt-5.6",
		StartedAtBucket: "2026-09-06T10:00:00Z",
		DurationSeconds: 600,
		Metrics:         MetricsBlock{TokensIn: 10, TokensOut: 5},
		Actions:         []Action{{Ref: "a0", Kind: "read", Category: "go", Status: "ok"}},
		Milestones:      []Milestone{{Ref: "m1", Kind: "first_edit", ElapsedSeconds: 30}},
		Outcomes:        Outcomes{TestsRun: 1, TestsPassed: 1, Build: "passed"},
		DisclosurePurposes: []Purpose{
			PurposeStructuralInsights,
		},
		ScrubberVersion: "scrub.v1",
		Authority: dataauthority.Classification{
			Authority: dataauthority.AuthorityPersonal,
			Version:   dataauthority.Version,
		},
	}
}

// TestActivityMixIsAdditiveBothDirections pins the F4 compatibility contract for
// the `activity_mix` field, which was added WITHOUT bumping
// EnvelopeSchemaVersion because it is `omitempty` and purely additive.
//
// WHAT THIS PROTECTS. The two-digest protocol makes the server recompute the
// digest over the bytes it received; a peer that DROPS an unknown field on
// unmarshal and re-serializes would compute a different digest and reject the
// upload with 422 digest_mismatch — terminal on the node. So both directions
// must hold on the CURRENT contract:
//
//   - an envelope WITHOUT activity_mix (what an older node builds) is valid and
//     round-trips through this contract with an unchanged digest;
//   - an envelope WITH activity_mix round-trips with an unchanged digest.
//
// The rollout constraint this implies — SERVER BEFORE NODE — is documented in
// docs/cloud-intelligence.md ("What the envelope carries"), because no test can
// pin the behaviour of a server binary that predates the field.
func TestActivityMixIsAdditiveBothDirections(t *testing.T) {
	for _, tc := range []struct {
		name string
		mix  []StructuralMixEntry
	}{
		{"without activity_mix", nil},
		{"with activity_mix", []StructuralMixEntry{{Key: "edit", Count: 3}, {Key: "run", Count: 9}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := activityMixCompatEnvelope()
			env.ActivityMix = tc.mix
			if err := env.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			ecd, err := EvidenceContentDigest(env)
			if err != nil {
				t.Fatalf("EvidenceContentDigest: %v", err)
			}
			env.EvidenceContentDigest = ecd
			b, err := UploadBytes(env)
			if err != nil {
				t.Fatalf("UploadBytes: %v", err)
			}
			up := UploadDigest(b)

			// The field is omitempty: an envelope without a mix must not even
			// carry the key, so its bytes are byte-identical to what a build
			// predating the field produced.
			if tc.mix == nil && strings.Contains(string(b), "activity_mix") {
				t.Fatalf("an empty mix serialized the key anyway:\n%s", b)
			}
			if tc.mix != nil && !strings.Contains(string(b), "activity_mix") {
				t.Fatalf("a populated mix did not serialize:\n%s", b)
			}

			// Round-trip through this contract's own Envelope: the digest must
			// survive unmarshal + re-serialize. A peer that dropped the field
			// would fail exactly here.
			var back Envelope
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := back.Validate(); err != nil {
				t.Fatalf("round-tripped envelope is invalid: %v", err)
			}
			if len(back.ActivityMix) != len(tc.mix) {
				t.Fatalf("activity_mix lost on round trip: got %+v, want %+v", back.ActivityMix, tc.mix)
			}
			rb, err := UploadBytes(back)
			if err != nil {
				t.Fatalf("UploadBytes(round-trip): %v", err)
			}
			if got := UploadDigest(rb); got != up {
				t.Fatalf("upload digest changed on round trip:\n got %s\nwant %s\n--- bytes ---\n%s", got, up, rb)
			}
			backECD, err := EvidenceContentDigest(back)
			if err != nil {
				t.Fatalf("EvidenceContentDigest(round-trip): %v", err)
			}
			if backECD != ecd {
				t.Fatalf("evidence-content digest changed on round trip: got %s, want %s", backECD, ecd)
			}
		})
	}
}

// TestActivityMixDropRegeneratesADifferentDigest is the NEGATIVE control that
// gives the test above its meaning: dropping the field (what an older peer does
// with an unknown key) really does change the digest — which is exactly the
// 422 digest_mismatch a node would see against a server that predates it.
func TestActivityMixDropRegeneratesADifferentDigest(t *testing.T) {
	env := activityMixCompatEnvelope()
	env.ActivityMix = []StructuralMixEntry{{Key: "edit", Count: 3}}
	withBytes, err := UploadBytes(env)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	env.ActivityMix = nil
	withoutBytes, err := UploadBytes(env)
	if err != nil {
		t.Fatalf("UploadBytes: %v", err)
	}
	if UploadDigest(withBytes) == UploadDigest(withoutBytes) {
		t.Fatal("dropping activity_mix left the digest unchanged — the compat pin above would be vacuous")
	}
}
