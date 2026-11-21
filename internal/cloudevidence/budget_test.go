package cloudevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// longSession is a session large enough that the default settings produce an
// envelope well over a free-tier-sized budget: a full 256-action sample and
// twenty long prompts.
func longSession() (SessionInput, SessionTexts) {
	in := baseInput()
	in.Actions = nil
	for i := 0; i < 600; i++ {
		in.Actions = append(in.Actions, ActionInput{
			Ref: fmt.Sprintf("a%d", i+1), Kind: []string{"read_file", "edit_file", "run_command"}[i%3],
			Path: fmt.Sprintf("internal/pkg%d/file%d.go", i%17, i), Status: "ok",
		})
	}
	in.ActionsTotal = len(in.Actions)
	var prompts []string
	for i := 0; i < 20; i++ {
		prompts = append(prompts, fmt.Sprintf("request %d: ", i)+strings.Repeat("refactor the storage layer and keep the tests green ", 30))
	}
	texts := SessionTexts{
		UserPrompts:       prompts,
		AssistantMessages: []string{strings.Repeat("done with the change ", 60)},
		Errors:            []string{"permission denied", "no such file or directory", "exit status 1"},
	}
	return in, texts
}

// buildUnder is the node's build path transposed (cmd/observer/cloud.go
// buildPlaneEnvelope): the settings decide the action SAMPLE size and the
// excerpt selection, then BuildEnvelope and the one Serialize.
func buildUnder(in SessionInput, texts SessionTexts) BuildFunc {
	return func(s cloudcontract.EvidenceSettings) ([]byte, error) {
		cur := in
		cur.Actions = strideSample(in.Actions, s.ActionSummaries)
		if s.ActionSummaries == 0 {
			cur.Actions = nil
		}
		cur.Excerpts = SelectExcerptsWithSettings(texts, ExcerptSelection{
			UserMessages: s.UserMessages, AssistantMessages: s.AssistantMessages,
			FailureClasses: s.FailureClasses, Bytes: s.ExcerptBytes,
		})
		opts := structuralOpts()
		opts.GrantedPurposes = append(opts.GrantedPurposes, cloudcontract.PurposeContextEnrichment)
		env, err := BuildEnvelope(cur, cloudcontract.PlanePersonal, opts)
		if err != nil {
			return nil, err
		}
		b, _, err := Serialize(env)
		return b, err
	}
}

// TestFitToBudgetOverBudgetSessionYieldsValidSmallerEnvelope is the R-AI1
// acceptance test: a session over its evidence budget is stepped down to a
// smaller envelope that is WHOLE - it parses, validates and passes the
// evidence-content digest recompute - never a cut of the original bytes.
func TestFitToBudgetOverBudgetSessionYieldsValidSmallerEnvelope(t *testing.T) {
	in, texts := longSession()
	build := buildUnder(in, texts)
	base := cloudcontract.DefaultEvidenceSettings()

	full, err := build(base)
	if err != nil {
		t.Fatalf("full build: %v", err)
	}
	fullTokens := cloudcontract.EstimateEvidenceTokens(len(full))
	budget := fullTokens / 3
	if budget < 1000 {
		t.Fatalf("fixture too small to bind: full envelope is only %d tokens", fullTokens)
	}

	fit, err := FitToBudget(base, budget, build)
	if err != nil {
		t.Fatalf("FitToBudget: %v", err)
	}
	if !fit.SteppedDown || fit.Rung == "" {
		t.Fatalf("expected a step-down, got %+v", fit.Rung)
	}
	if fit.EstimatedTokens > budget || len(fit.Bytes) >= len(full) {
		t.Fatalf("fitted envelope %d bytes (%d tokens) is not within budget %d / smaller than %d bytes",
			len(fit.Bytes), fit.EstimatedTokens, budget, len(full))
	}
	if string(fit.Bytes) == string(full[:min(len(full), len(fit.Bytes))]) {
		t.Fatal("fitted bytes are a prefix of the full envelope: the JSON was cut, not rebuilt")
	}
	var env cloudcontract.Envelope
	if err := json.Unmarshal(fit.Bytes, &env); err != nil {
		t.Fatalf("fitted envelope is not valid JSON: %v", err)
	}
	if err := env.Validate(); err != nil {
		t.Fatalf("fitted envelope does not validate: %v", err)
	}
	recomputed, err := cloudcontract.EvidenceContentDigest(env)
	if err != nil || recomputed != env.EvidenceContentDigest {
		t.Fatalf("fitted envelope's content digest does not recompute (%v): %q vs %q", err, recomputed, env.EvidenceContentDigest)
	}
	// The fitted settings reproduce the fitted bytes: a caller that freezes
	// them on its receipt rebuilds the same envelope at send time.
	again, err := build(fit.Settings)
	if err != nil || string(again) != string(fit.Bytes) {
		t.Fatalf("rebuild under the fitted settings differs (%v)", err)
	}
	// Actions are cut before prompts: the fitted rung keeps more prompts than
	// it keeps of the default action sample, proportionally.
	if fit.Settings.ActionSummaries >= base.ActionSummaries {
		t.Errorf("action sample not reduced: %d", fit.Settings.ActionSummaries)
	}
	if env.Overflow == nil || env.Overflow.ActionsOmitted == 0 {
		t.Errorf("the whole-session action count must survive the smaller sample as an overflow count")
	}
}

func TestFitToBudgetNoBudgetAndUnderBudgetAreUnstepped(t *testing.T) {
	in, texts := longSession()
	build := buildUnder(in, texts)
	base := cloudcontract.DefaultEvidenceSettings()
	full, err := build(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, budget := range []int{0, -5, cloudcontract.EstimateEvidenceTokens(len(full))} {
		fit, err := FitToBudget(base, budget, build)
		if err != nil {
			t.Fatalf("budget %d: %v", budget, err)
		}
		if fit.SteppedDown || string(fit.Bytes) != string(full) || fit.Settings != base {
			t.Fatalf("budget %d: stepped down although the base fits", budget)
		}
	}
}

func TestFitToBudgetFloorOverBudgetRefuses(t *testing.T) {
	in, texts := longSession()
	_, err := FitToBudget(cloudcontract.DefaultEvidenceSettings(), 10, buildUnder(in, texts))
	if !errors.Is(err, ErrEvidenceOverBudget) {
		t.Fatalf("want ErrEvidenceOverBudget, got %v", err)
	}
}

func TestFitToBudgetBuildErrorStopsTheWalk(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	_, err := FitToBudget(cloudcontract.DefaultEvidenceSettings(), 1000, func(cloudcontract.EvidenceSettings) ([]byte, error) {
		calls++
		if calls == 1 {
			return make([]byte, 100000), nil
		}
		return nil, boom
	})
	if !errors.Is(err, boom) || calls != 2 {
		t.Fatalf("want the build error after 2 calls, got %v after %d", err, calls)
	}
	if _, err := FitToBudget(cloudcontract.EvidenceSettings{}, 1000, nil); err == nil {
		t.Fatal("an invalid base must be refused")
	}
}

// TestBudgetLadderNeverRaisesAndNeverGrows pins the ladder's two properties:
// no step asks for more than the base, and each field is non-increasing down
// the table, so a later step never builds a larger envelope.
func TestBudgetLadderNeverRaisesAndNeverGrows(t *testing.T) {
	small := cloudcontract.EvidenceSettings{
		Version: cloudcontract.EvidenceSettingsVersion, UserMessages: 2, AssistantMessages: 0,
		FailureClasses: 1, ActionSummaries: 10, ExcerptBytes: 200, Milestones: true, Outcomes: false,
	}
	for _, base := range []cloudcontract.EvidenceSettings{cloudcontract.DefaultEvidenceSettings(), small} {
		steps := BudgetLadder(base)
		if len(steps) == 0 {
			t.Fatal("empty ladder")
		}
		for i, st := range steps {
			s := st.Settings
			if err := s.Validate(); err != nil {
				t.Fatalf("%s: %v", st.Rung, err)
			}
			if s.UserMessages > base.UserMessages || s.AssistantMessages > base.AssistantMessages ||
				s.FailureClasses > base.FailureClasses || s.ActionSummaries > base.ActionSummaries ||
				s.ExcerptBytes > base.ExcerptBytes || s.Milestones != base.Milestones || s.Outcomes != base.Outcomes {
				t.Fatalf("%s raises a setting above the base: %+v vs %+v", st.Rung, s, base)
			}
			if i == 0 {
				continue
			}
			p := steps[i-1].Settings
			if p == s {
				t.Fatalf("%s duplicates the previous step", st.Rung)
			}
			if s.UserMessages > p.UserMessages || s.AssistantMessages > p.AssistantMessages ||
				s.FailureClasses > p.FailureClasses || s.ActionSummaries > p.ActionSummaries || s.ExcerptBytes > p.ExcerptBytes {
				t.Fatalf("%s grows a setting over %s", st.Rung, steps[i-1].Rung)
			}
		}
		last := steps[len(steps)-1].Settings
		if last.ActionSummaries != 0 || last.FailureClasses != 0 || last.UserMessages > 1 {
			t.Fatalf("the floor must carry at most one prompt and no actions: %+v", last)
		}
	}
}

func TestEstimateEvidenceTokens(t *testing.T) {
	for _, tc := range []struct{ bytes, want int }{
		{0, 0}, {-1, 0}, {1, 1}, {1000, 323}, {1001, 324}, {12383, 4000}, {12384, 4001},
	} {
		if got := cloudcontract.EstimateEvidenceTokens(tc.bytes); got != tc.want {
			t.Errorf("EstimateEvidenceTokens(%d) = %d, want %d", tc.bytes, got, tc.want)
		}
	}
	if !cloudcontract.EvidenceFitsBudget(1<<30, 0) || cloudcontract.EvidenceFitsBudget(12384, 4000) || !cloudcontract.EvidenceFitsBudget(12383, 4000) {
		t.Fatal("EvidenceFitsBudget boundary")
	}
}
