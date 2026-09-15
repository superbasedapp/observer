package cloudevidence

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// goldenCase pairs a hand-authored fixture with its golden file. Regenerate
// goldens with `UPDATE_GOLDEN=1 go test ./internal/cloudevidence/...`.
type goldenCase struct {
	name  string
	build func() (*cloudcontract.Envelope, error)
}

func goldenCases() []goldenCase {
	return []goldenCase{
		{
			name: "codex_structural",
			build: func() (*cloudcontract.Envelope, error) {
				return BuildEnvelope(baseInput(), cloudcontract.PlanePersonal, structuralOpts())
			},
		},
		{
			name: "claudecode_context_paths_feedback",
			build: func() (*cloudcontract.Envelope, error) {
				rating := 8
				in := SessionInput{
					CloudSessionID:  "cs-cc-1001",
					CloudProjectID:  "cp-cc-2002",
					Tool:            "claude-code",
					ModelFamily:     "claude-opus-4-8",
					StartedAtBucket: "2026-08-27T11:00:00Z",
					DurationSeconds: 2400,
					Metrics: MetricsInput{
						TokensIn: 12000, TokensOut: 5000, CacheReadTokens: 3000,
						CostUSD: 0.55, DeterministicScore: 91,
						RedundancyRatio: 0.08, ErrorRate: 0.02,
						ExplorationEfficiency: 0.82, ContinuityScore: 0.93,
					},
					Actions: []ActionInput{
						{Ref: "a1", Kind: "read_file", Path: "cmd/observer/main.go", Status: "ok"},
						{Ref: "a2", Kind: "edit_file", Path: "internal/proxy/proxy.go", Status: "ok"},
						{Ref: "a3", Kind: "run_command", Path: "Makefile", Status: "ok"},
					},
					Milestones: []MilestoneInput{
						{Ref: "m1", Kind: "first_edit", ElapsedSeconds: 200},
						{Ref: "m2", Kind: "tests_green", ElapsedSeconds: 1900},
					},
					Outcomes: OutcomesInput{TestsRun: 12, TestsPassed: 12, Build: "passed"},
					UserFeedback: &UserFeedbackInput{
						Rating: &rating,
						Note:   "clean refactor",
					},
					Excerpts: []ExcerptInput{
						{Source: "task_excerpt", Text: "wire the retry-safe device auth flow"},
						{Source: "final_summary", Text: "implemented and tested the exchange", CapBytes: 256},
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
					PathSalt:            []byte("golden-account-salt"),
					IncludeUserFeedback: true,
				}
				return BuildEnvelope(in, cloudcontract.PlanePersonal, opts)
			},
		},
		{
			name: "cursor_overflow",
			build: func() (*cloudcontract.Envelope, error) {
				in := baseInput()
				in.Tool = "cursor"
				in.CloudSessionID = "cs-cur-777"
				in.CloudProjectID = "cp-cur-888"
				// Distinct refs + a kind that only appears at the very END, so
				// the golden pins the STRIDED sampling: head truncation would
				// drop "a600" and every "edit_file" from the bytes. The last
				// action carries an OFF-VOCABULARY kind, so the golden also
				// pins that an action's kind is normalized on the way out (A2)
				// — the bytes must read "unclassified", never "payroll.csv".
				in.Actions = make([]ActionInput, cloudcontract.MaxActions+345)
				for i := range in.Actions {
					kind := "read_file"
					if i > len(in.Actions)-20 {
						kind = "edit_file"
					}
					if i == len(in.Actions)-1 {
						kind = "payroll.csv"
					}
					in.Actions[i] = ActionInput{
						Ref: fmt.Sprintf("a%d", i), Kind: kind, Path: "x.ts", Status: "ok",
					}
				}
				// Real action kinds (the allow-list's members) plus one hostile
				// key, so the golden pins BOTH halves of the mix rule: known
				// kinds survive as themselves, anything else folds into
				// "unclassified" with its count intact.
				in.ActivityMix = []ActivityMixInput{
					{Kind: "read_file", Count: 582},
					{Kind: "edit_file", Count: 19},
					{Kind: "a path/like key", Count: 3},
				}
				return BuildEnvelope(in, cloudcontract.PlanePersonal, structuralOpts())
			},
		},
	}
}

func TestGoldenEnvelopes(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDEN") != ""
	for _, gc := range goldenCases() {
		t.Run(gc.name, func(t *testing.T) {
			env, err := gc.build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			got, digests, err := Serialize(env)
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			// A golden should never carry a self-referential upload digest
			// inside its bytes.
			if bytes.Contains(got, []byte(digests.Upload)) {
				t.Fatalf("upload digest leaked into golden bytes")
			}
			goldenPath := filepath.Join("testdata", gc.name+".golden.json")
			if update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatalf("mkdir testdata: %v", err)
				}
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s (run UPDATE_GOLDEN=1 to create): %v", goldenPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("serialized envelope differs from golden %s\n--- got ---\n%s", goldenPath, got)
			}
		})
	}
}
