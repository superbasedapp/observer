package cloudevidence

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Sentinel values seeded into a maximal fixture. None may survive into the
// serialized envelope: raw paths become category/hash, secrets are scrubbed,
// and file contents / env values / auth headers are never envelope fields at
// all.
const (
	sentinelAbsPath      = "/home/user/secret-project/internal/auth/keys.go"
	sentinelWinPath      = `C:\Users\dev\project\secret.go`
	sentinelSecretKey    = "sk-liveSECRETvalue0123456789abcd"
	sentinelBearer       = "Bearer abcdef1234567890TOKEN"
	sentinelAWSKey       = "AKIAIOSFODNN7EXAMPLE"
	sentinelEnvAssign    = "OPENAI_API_KEY=sk-anotherLIVEsecret0123456789"
	sentinelFileContents = "-----BEGIN PRIVATE KEY-----MIIEv..."
)

// maximalFixture returns an envelope built with every optional field populated
// and sentinels seeded where a naive builder might leak them.
func maximalFixture(t *testing.T) *cloudcontract.Envelope {
	t.Helper()
	rating := 7
	in := SessionInput{
		CloudSessionID:  "cs-max-9f2a",
		CloudProjectID:  "cp-max-4b7e",
		Tool:            "claude-code",
		ModelFamily:     "claude-opus-4-8",
		StartedAtBucket: "2026-08-27T09:00:00Z",
		DurationSeconds: 3600,
		Metrics: MetricsInput{
			TokensIn: 9000, TokensOut: 4000, CacheReadTokens: 2000,
			CostUSD: 0.42, DeterministicScore: 88,
			RedundancyRatio: 0.2, ErrorRate: 0.1,
			ExplorationEfficiency: 0.6, ContinuityScore: 0.7,
		},
		Actions: []ActionInput{
			{Ref: "a1", Kind: "read", Path: sentinelAbsPath, Status: "ok"},
			{Ref: "a2", Kind: "edit", Path: sentinelWinPath, Status: "error"},
			// A file-contents blob placed in a structural (path) field must be
			// reduced to a category + salted hash — the envelope has NO field
			// that carries raw file contents or command output at all. (Note:
			// excerpt scrubbing is best-effort; this sentinel targets the
			// builder's structural guarantee, not arbitrary excerpt content.)
			{Ref: "a3", Kind: "read", Path: sentinelFileContents, Status: "ok"},
		},
		Milestones: []MilestoneInput{{Ref: "m1", Kind: "first_edit", ElapsedSeconds: 300}},
		Outcomes:   OutcomesInput{TestsRun: 5, TestsPassed: 4, Build: "passed"},
		UserFeedback: &UserFeedbackInput{
			Rating: &rating,
			Note:   "note with a leaked " + sentinelSecretKey + " token",
		},
		// Excerpts carry KNOWN secret shapes the scrubber redacts.
		Excerpts: []ExcerptInput{
			{Source: "task_excerpt", Text: "authenticate with " + sentinelBearer},
			{Source: "final_summary", Text: "used " + sentinelAWSKey + " and " + sentinelEnvAssign},
		},
		Authority: personalAuthority(),
	}
	opts := BuildOptions{
		Scrubber:        scrub.New(),
		ScrubberVersion: "scrub-v1",
		GrantedPurposes: []cloudcontract.Purpose{
			cloudcontract.PurposeStructuralInsights,
			cloudcontract.PurposeContextEnrichment,
		},
		PathCorrelation:     true,
		PathSalt:            []byte("account-salt-max"),
		IncludeUserFeedback: true,
	}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	return env
}

// TestForbiddenFieldSentinel walks every string leaf of the serialized JSON
// and asserts no raw path, secret, auth header, env value, or file-content
// sentinel survived.
func TestForbiddenFieldSentinel(t *testing.T) {
	env := maximalFixture(t)
	b, _, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !json.Valid(b) {
		t.Fatalf("serialized envelope is not valid JSON")
	}

	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	leaves := collectStrings(decoded)

	forbidden := []string{
		sentinelAbsPath,
		sentinelWinPath,
		"secret-project", // any fragment of the raw path
		sentinelSecretKey,
		sentinelBearer,
		sentinelAWSKey,
		"sk-anotherLIVEsecret0123456789",
		sentinelFileContents,
		"BEGIN PRIVATE KEY",
	}
	for _, leaf := range leaves {
		for _, bad := range forbidden {
			if strings.Contains(leaf, bad) {
				t.Errorf("forbidden sentinel %q leaked into serialized field value %q", bad, leaf)
			}
		}
	}

	// Positive controls: scrubbing ran (marker present) and paths became
	// categories + hashes.
	joined := strings.Join(leaves, "\n")
	if !strings.Contains(joined, scrub.Redacted) {
		t.Errorf("expected %q marker somewhere (proof scrubbing ran)", scrub.Redacted)
	}
	if env.Actions[0].Category != "go" || env.Actions[0].PathHash == "" {
		t.Errorf("path was not reduced to category+hash: %+v", env.Actions[0])
	}
}

// collectStrings returns every string leaf (and map key) in an unmarshaled
// JSON value.
func collectStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case map[string]any:
		for k, child := range t {
			out = append(out, k)
			out = append(out, collectStrings(child)...)
		}
	case []any:
		for _, child := range t {
			out = append(out, collectStrings(child)...)
		}
	}
	return out
}

// TestScrubIntegrationPreview proves the literal preview shows post-scrub
// content: a seeded secret in an excerpt is redacted in the bytes a user
// confirms.
func TestScrubIntegrationPreview(t *testing.T) {
	in := baseInput()
	in.Excerpts = []ExcerptInput{
		{Source: "task_excerpt", Text: "please use api_key=sk-SUPERSECRETvalue0123456789 for auth"},
	}
	opts := structuralOpts()
	opts.GrantedPurposes = append(opts.GrantedPurposes, cloudcontract.PurposeContextEnrichment)

	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Context) != 1 {
		t.Fatalf("expected one excerpt")
	}
	if strings.Contains(env.Context[0].Text, "sk-SUPERSECRETvalue0123456789") {
		t.Fatalf("secret not scrubbed in built excerpt: %q", env.Context[0].Text)
	}
	if !strings.Contains(env.Context[0].Text, scrub.Redacted) {
		t.Fatalf("expected redaction marker in excerpt: %q", env.Context[0].Text)
	}

	b, _, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if strings.Contains(string(b), "SUPERSECRETvalue") {
		t.Fatalf("secret survived into the preview/upload bytes")
	}
}
