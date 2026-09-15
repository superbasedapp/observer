package cloudevidence

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func personalAuthority() dataauthority.Classification {
	return dataauthority.Classification{Authority: dataauthority.AuthorityPersonal, Version: dataauthority.Version}
}

// baseInput returns a minimal, valid structural-only session input.
func baseInput() SessionInput {
	return SessionInput{
		CloudSessionID:  "cs-abc123",
		CloudProjectID:  "cp-def456",
		Tool:            "codex",
		ModelFamily:     "gpt-5.6",
		StartedAtBucket: "2026-08-27T10:00:00Z",
		DurationSeconds: 600,
		Metrics: MetricsInput{
			TokensIn: 500, TokensOut: 300, CacheReadTokens: 100,
			CostUSD: 0.01, DeterministicScore: 75,
			RedundancyRatio: 0.1, ErrorRate: 0.0,
			ExplorationEfficiency: 0.7, ContinuityScore: 0.85,
		},
		Actions: []ActionInput{
			{Ref: "a1", Kind: "read_file", Path: "internal/foo/bar.go", Status: "ok"},
			{Ref: "a2", Kind: "edit_file", Path: "internal/foo/bar.go", Status: "ok"},
		},
		Milestones: []MilestoneInput{{Ref: "m1", Kind: "first_edit", ElapsedSeconds: 90}},
		Outcomes:   OutcomesInput{TestsRun: 3, TestsPassed: 3, Build: "passed"},
		Authority:  personalAuthority(),
	}
}

func structuralOpts() BuildOptions {
	return BuildOptions{
		Scrubber:        scrub.New(),
		ScrubberVersion: "scrub-v1",
		GrantedPurposes: []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights},
	}
}

func TestBuildEnvelopeRefusesIneligibleAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth dataauthority.Classification
	}{
		{"org", dataauthority.Classification{Authority: dataauthority.AuthorityOrg, Version: dataauthority.Version}},
		{"unknown", dataauthority.Classification{Authority: "unknown", Version: dataauthority.Version}},
		{"zero", dataauthority.Classification{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Authority = tc.auth
			if _, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts()); err == nil {
				t.Fatalf("expected refusal for %s authority", tc.name)
			}
		})
	}
}

func TestBuildEnvelopeRejectsBadCloudIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*SessionInput)
	}{
		{"path-like session", func(s *SessionInput) { s.CloudSessionID = "/home/u/proj" }},
		{"backslash project", func(s *SessionInput) { s.CloudProjectID = `C:\Users\x` }},
		{"dotdot", func(s *SessionInput) { s.CloudSessionID = "../secret" }},
		{"pk-like", func(s *SessionInput) { s.CloudSessionID = "12345" }},
		{"empty", func(s *SessionInput) { s.CloudProjectID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.set(&in)
			if _, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts()); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestBuildEnvelopePathDefaultsToCategoryNoHash(t *testing.T) {
	env, err := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Actions) != 2 {
		t.Fatalf("got %d actions", len(env.Actions))
	}
	for _, a := range env.Actions {
		if a.Category != "go" {
			t.Errorf("category = %q, want go", a.Category)
		}
		if a.PathHash != "" {
			t.Errorf("path hash present without grant: %q", a.PathHash)
		}
	}
}

// TestBuildEnvelopeClampsOverlongCategory pins the robustness fix: an action
// category that is command-shaped (a codex target is a shell command, not a
// file, so path.Ext yields a long punctuation-laden tail) or explicitly
// over-long is bucketed to "other" instead of overflowing the contract's
// MaxShortLabelBytes and failing the whole envelope (which would also leak a
// command fragment). Regression for the live "actions[N].category is 143 bytes"
// enrichment failure.
func TestBuildEnvelopeClampsOverlongCategory(t *testing.T) {
	in := baseInput()
	in.Actions = []ActionInput{
		{Ref: "a1", Kind: "run", Category: strings.Repeat("x", cloudcontract.MaxShortLabelBytes+50), Status: "ok"},
		{Ref: "a2", Kind: "run", Path: "notes/build.log.output.tailthatislongerthansixteenchars", Status: "ok"},
	}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope must not fail on an over-long/command-shaped category: %v", err)
	}
	for i, a := range env.Actions {
		if a.Category != "other" {
			t.Errorf("action[%d] category = %q, want other", i, a.Category)
		}
	}
}

// TestBuildEnvelopeDefaultsEmptyModelFamily pins that a session with no captured
// model still builds: an empty model_family is defaulted to "unknown" rather
// than failing the contract's required, bounded field. Regression for the live
// "model_family is empty" enrichment failure on claude-code sessions.
func TestBuildEnvelopeDefaultsEmptyModelFamily(t *testing.T) {
	in := baseInput()
	in.ModelFamily = ""
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope must not fail on an empty model family: %v", err)
	}
	if env.ModelFamily != "unknown" {
		t.Errorf("empty model family = %q, want unknown", env.ModelFamily)
	}
}

func TestBuildEnvelopePathHashUnderGrant(t *testing.T) {
	opts := structuralOpts()
	opts.PathCorrelation = true
	opts.PathSalt = []byte("account-salt")
	env, err := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	// Same path in both actions ⇒ identical, non-empty, prefixed hashes.
	if env.Actions[0].PathHash == "" || !strings.HasPrefix(env.Actions[0].PathHash, "sha256:") {
		t.Fatalf("expected sha256: path hash, got %q", env.Actions[0].PathHash)
	}
	if env.Actions[0].PathHash != env.Actions[1].PathHash {
		t.Errorf("same path produced different hashes")
	}
	// A different salt changes the hash.
	opts.PathSalt = []byte("other-salt")
	env2, _ := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, opts)
	if env2.Actions[0].PathHash == env.Actions[0].PathHash {
		t.Errorf("different salt did not change the hash")
	}
	// The raw path never appears.
	b, _, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if bytes.Contains(b, []byte("internal/foo/bar.go")) {
		t.Errorf("raw path leaked into serialized envelope")
	}
}

func TestBuildEnvelopeExcerptGating(t *testing.T) {
	in := baseInput()
	in.Excerpts = []ExcerptInput{{Source: "task_excerpt", Text: "do the thing"}}

	// Without the context purpose: excerpts dropped.
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Context) != 0 {
		t.Errorf("excerpts included without context grant")
	}

	// With the context purpose: excerpts included, capped, source labelled.
	opts := structuralOpts()
	opts.GrantedPurposes = append(opts.GrantedPurposes, cloudcontract.PurposeContextEnrichment)
	env, err = BuildEnvelope(in, cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Context) != 1 || env.Context[0].Source != "task_excerpt" {
		t.Fatalf("expected one labelled excerpt, got %+v", env.Context)
	}
	if env.Context[0].LengthCapBytes != cloudcontract.MaxExcerptBytes {
		t.Errorf("cap = %d, want default %d", env.Context[0].LengthCapBytes, cloudcontract.MaxExcerptBytes)
	}
}

func TestBuildEnvelopeUserFeedbackGating(t *testing.T) {
	rating := 9
	in := baseInput()
	in.UserFeedback = &UserFeedbackInput{Rating: &rating, Note: "great run"}

	// Not named ⇒ absent.
	env, _ := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if env.UserFeedback != nil {
		t.Errorf("user feedback present without IncludeUserFeedback")
	}

	// Named ⇒ present and scrubbed.
	opts := structuralOpts()
	opts.IncludeUserFeedback = true
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if env.UserFeedback == nil || env.UserFeedback.Rating == nil || *env.UserFeedback.Rating != 9 {
		t.Fatalf("expected rating 9, got %+v", env.UserFeedback)
	}
}

func TestBuildEnvelopeOverflowSummarized(t *testing.T) {
	in := baseInput()
	in.Actions = make([]ActionInput, cloudcontract.MaxActions+5)
	for i := range in.Actions {
		in.Actions[i] = ActionInput{Ref: "a", Kind: "read", Path: "x.go", Status: "ok"}
	}
	in.Milestones = make([]MilestoneInput, cloudcontract.MaxMilestones+2)
	for i := range in.Milestones {
		in.Milestones[i] = MilestoneInput{Ref: "m", Kind: "step", ElapsedSeconds: i}
	}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Actions) != cloudcontract.MaxActions {
		t.Errorf("actions not capped: %d", len(env.Actions))
	}
	if env.Overflow == nil || env.Overflow.ActionsOmitted != 5 || env.Overflow.MilestonesOmitted != 2 {
		t.Fatalf("overflow not summarized: %+v", env.Overflow)
	}
}

func TestBuildEnvelopeDisclosureSortedDeduped(t *testing.T) {
	opts := structuralOpts()
	opts.GrantedPurposes = []cloudcontract.Purpose{
		cloudcontract.PurposeStructuralInsights,
		cloudcontract.PurposeContextEnrichment,
		cloudcontract.PurposeStructuralInsights, // dup
	}
	env, err := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, opts)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.DisclosurePurposes) != 2 {
		t.Fatalf("expected 2 deduped purposes, got %v", env.DisclosurePurposes)
	}
	if env.DisclosurePurposes[0] > env.DisclosurePurposes[1] {
		t.Errorf("disclosure purposes not sorted: %v", env.DisclosurePurposes)
	}
}

func TestSerializePreviewEqualsUpload(t *testing.T) {
	env, err := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	b1, d1, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	b2, d2, err := Serialize(env)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("Serialize not deterministic")
	}
	if d1 != d2 {
		t.Fatalf("digests not deterministic: %+v vs %+v", d1, d2)
	}
	// The upload digest is over exactly these bytes.
	if d1.Upload != cloudcontract.UploadDigest(b1) {
		t.Errorf("upload digest does not match bytes")
	}
	// Serialize must not mutate the caller's envelope.
	if env.EvidenceContentDigest != "" || env.UploadDigest != "" {
		t.Errorf("Serialize mutated the caller's envelope")
	}
	// Building twice from equal input yields equal bytes.
	env2, _ := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	b3, _, _ := Serialize(env2)
	if !bytes.Equal(b1, b3) {
		t.Errorf("equal inputs produced different bytes")
	}
}

func TestSerializeRebuildDigestCoherence(t *testing.T) {
	// consent/rebuild coherence: a rebuilt identical envelope reproduces the
	// same upload digest; a local edit changes it (⇒ reconfirmation_required).
	env, _ := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	_, d1, _ := Serialize(env)

	rebuilt, _ := BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
	_, d2, _ := Serialize(rebuilt)
	if d1 != d2 {
		t.Fatalf("rebuild produced different digests: %+v vs %+v", d1, d2)
	}

	edited := baseInput()
	edited.Metrics.TokensIn += 1
	e3, _ := BuildEnvelope(edited, cloudcontract.PlanePersonal, structuralOpts())
	_, d3, _ := Serialize(e3)
	if d3.Upload == d1.Upload || d3.EvidenceContent == d1.EvidenceContent {
		t.Errorf("an edit did not change the digests")
	}
}

// TestOverflowCountsAgainstTheTruePopulation pins the honest omission count for
// a PRE-SAMPLED action list (F6). The store now strides across the whole session
// in SQL and hands the builder ~MaxActions rows, so the builder can no longer
// infer "how many were omitted" from the slice it was given — it is told the
// population, and reports the remainder against that.
func TestOverflowCountsAgainstTheTruePopulation(t *testing.T) {
	in := baseInput()
	in.Actions = make([]ActionInput, 100)
	for i := range in.Actions {
		in.Actions[i] = ActionInput{Ref: "a" + refIndex(i*300), Kind: "read", Path: "x.go", Status: "ok"}
	}
	in.ActionsTotal = 30000

	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Actions) != 100 {
		t.Fatalf("kept %d actions, want the 100 handed in", len(env.Actions))
	}
	if env.Overflow == nil || env.Overflow.ActionsOmitted != 29900 {
		t.Fatalf("overflow = %+v, want actions_omitted 29900", env.Overflow)
	}
}

// TestOverflowFallsBackToTheSliceLength keeps the un-sampled caller honest: with
// no declared population, the slice IS the population.
func TestOverflowFallsBackToTheSliceLength(t *testing.T) {
	in := baseInput()
	in.Actions = make([]ActionInput, cloudcontract.MaxActions+7)
	for i := range in.Actions {
		in.Actions[i] = ActionInput{Ref: "a" + refIndex(i), Kind: "read", Path: "x.go", Status: "ok"}
	}
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if env.Overflow == nil || env.Overflow.ActionsOmitted != 7 {
		t.Fatalf("overflow = %+v, want actions_omitted 7", env.Overflow)
	}
	if len(env.Actions) != cloudcontract.MaxActions {
		t.Fatalf("kept %d actions, want MaxActions", len(env.Actions))
	}
}

// TestActionsTotalBelowSliceLengthIsIgnored: a caller that under-reports the
// population must not produce a NEGATIVE omission count.
func TestActionsTotalBelowSliceLengthIsIgnored(t *testing.T) {
	in := baseInput()
	in.ActionsTotal = 1
	env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if env.Overflow != nil {
		t.Fatalf("overflow = %+v, want none", env.Overflow)
	}
}

// TestBuildEnvelopeContextAdmissionTable pins admitExcerpts row by row (the
// 2026-09-16 title-only lane): the excerpt purpose admits everything, the
// narrowed first-prompt class under the structural purpose admits exactly the
// one first_user_prompt excerpt, and a bare structural grant admits nothing.
func TestBuildEnvelopeContextAdmissionTable(t *testing.T) {
	excerpts := []ExcerptInput{
		{Source: SourceUserPrompt, Text: "a later prompt", CapBytes: ExcerptCapBytes},
		{Source: SourceFirstUserPrompt, Text: "fix the flaky login test", CapBytes: ExcerptCapBytes},
		{Source: SourceFinalAssistantMessage, Text: "done, tests green", CapBytes: ExcerptCapBytes},
	}
	cases := []struct {
		name        string
		purposes    []cloudcontract.Purpose
		classes     []cloudcontract.FieldClass
		wantSources []string
	}{
		{
			name:        "excerpt purpose admits the whole selection",
			purposes:    []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights, cloudcontract.PurposeContextEnrichment},
			wantSources: []string{SourceUserPrompt, SourceFirstUserPrompt, SourceFinalAssistantMessage},
		},
		{
			name:        "structural purpose plus the first-prompt class admits only the first prompt",
			purposes:    []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights},
			classes:     []cloudcontract.FieldClass{cloudcontract.FieldClassStructuralMetrics, cloudcontract.FieldClassFirstUserPrompt},
			wantSources: []string{SourceFirstUserPrompt},
		},
		{
			name:     "structural purpose alone admits nothing",
			purposes: []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights},
			classes:  []cloudcontract.FieldClass{cloudcontract.FieldClassStructuralMetrics},
		},
		{
			name:     "first-prompt class but no first prompt selected admits nothing",
			purposes: []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights},
			classes:  []cloudcontract.FieldClass{cloudcontract.FieldClassFirstUserPrompt},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Excerpts = excerpts
			if tc.name == "first-prompt class but no first prompt selected admits nothing" {
				in.Excerpts = excerpts[2:]
			}
			env, err := BuildEnvelope(in, cloudcontract.PlanePersonal, BuildOptions{
				Scrubber:            scrub.New(),
				ScrubberVersion:     "scrub.v1",
				GrantedPurposes:     tc.purposes,
				GrantedFieldClasses: tc.classes,
			})
			if err != nil {
				t.Fatalf("BuildEnvelope: %v", err)
			}
			var got []string
			for _, c := range env.Context {
				got = append(got, c.Source)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantSources, ",") {
				t.Fatalf("context sources = %v, want %v", got, tc.wantSources)
			}
			if len(tc.wantSources) == 1 && !env.ContextIsFirstPromptOnly() {
				t.Fatalf("a lone first-prompt context must satisfy ContextIsFirstPromptOnly")
			}
			if len(tc.wantSources) > 1 && env.ContextIsFirstPromptOnly() {
				t.Fatalf("a wider context must not satisfy ContextIsFirstPromptOnly")
			}
		})
	}
}
