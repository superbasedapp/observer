//go:build !sbo_omit_benchmark

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/procgroup"
)

// benchmark_score.go is the scoring adapter (plan §3.4). It owns the
// benchmark-only `tests_pass` scorer (runs the task's test command in the
// attempt workspace) directly. Every other scorer reuses the obs-eval registry
// through an injected evalScoreFn — the eval import itself lives ONLY in
// obs_wire.go (the sanctioned internal/obs wiring seam; the reverse-import
// boundary in tests/invariant/obs_boundary_test.go forbids it anywhere else),
// so benchmark_score.go stays obs-free and the feature stays separable.

const defaultTestsTimeoutSec = 300

// benchmarkScorer implements attemptScorer. evalScore is the obs-eval bridge
// (nil ⇒ registry scorers unavailable, e.g. a no_obs build); judgeModel names
// the judge model for an llm_judge score row's provenance.
type benchmarkScorer struct {
	evalScore  evalScoreFn
	judgeModel string
}

// Score dispatches on the task's declared scorer (a data lookup, not a
// tool-name business branch): tests_pass runs the workspace command; every
// other scorer shapes a sample and calls the reused registry via evalScore.
func (s benchmarkScorer) Score(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	switch in.Task.Success.Scorer {
	case "tests_pass":
		return s.scoreTestsPass(ctx, in)
	case "contains_all":
		return s.scoreContainsAll(in)
	default:
		return s.scoreViaRegistry(ctx, in)
	}
}

// scoreContainsAll passes only when the extracted final answer contains EVERY
// declared substring (case-insensitive). It is the echo-proof scorer (#1):
// declaring multiple discriminating tokens that a correct answer must contain
// but the prompt does not makes a bare prompt echo unable to pass. An empty
// answer yields no score (⇒ scorer_unavailable), never a silent pass.
func (s benchmarkScorer) scoreContainsAll(in scoreInput) ([]benchmark.ScoreRecord, error) {
	answer := strings.TrimSpace(in.FinalAnswer)
	if answer == "" {
		return nil, nil
	}
	lower := strings.ToLower(answer)
	var missing []string
	for _, v := range in.Task.Success.Values {
		if !strings.Contains(lower, strings.ToLower(v)) {
			missing = append(missing, v)
		}
	}
	rec := benchmark.ScoreRecord{AttemptID: in.AttemptID, RunID: in.RunID, Scorer: "contains_all"}
	if len(missing) == 0 {
		rec.Passed = true
		rec.Score = 1
		rec.Rationale = "answer contains all required tokens"
	} else {
		rec.Rationale = truncateForRow("answer missing required tokens: "+strings.Join(missing, ", "), 500)
	}
	return []benchmark.ScoreRecord{rec}, nil
}

// scoreTestsPass runs the task's test command in the attempt workspace under its
// own timeout + process-group kill (plan §3.4). Exit 0 ⇒ pass.
func (s benchmarkScorer) scoreTestsPass(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	cmd := in.Task.Success.Cmd
	if strings.TrimSpace(cmd) == "" {
		return nil, nil // no command → scorer_unavailable
	}
	timeout := in.Task.Success.TimeoutSec
	if timeout <= 0 {
		timeout = defaultTestsTimeoutSec
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	c := exec.CommandContext(runCtx, "sh", "-c", cmd)
	c.Dir = in.WorkspaceDir
	procgroup.Set(c)
	c.Cancel = func() error { return killProcGroup(c) }
	runErr := c.Run()

	rec := benchmark.ScoreRecord{AttemptID: in.AttemptID, RunID: in.RunID, Scorer: "tests_pass"}
	if runErr == nil {
		rec.Passed = true
		rec.Score = 1
		rec.Rationale = "test command exit 0"
	} else {
		rec.Rationale = "test command failed: " + truncateForRow(runErr.Error(), 200)
		if runCtx.Err() == context.DeadlineExceeded {
			rec.Rationale = fmt.Sprintf("test command timed out after %ds", timeout)
		}
	}
	return []benchmark.ScoreRecord{rec}, nil
}

// scoreViaRegistry shapes a sample from the extracted final answer and scores it
// with a reused registry scorer via evalScore. Text scorers with no recoverable
// answer, an unbuildable scorer, or a nil bridge return no score (⇒
// scorer_unavailable) — never a silent pass.
func (s benchmarkScorer) scoreViaRegistry(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	if s.evalScore == nil || strings.TrimSpace(in.FinalAnswer) == "" {
		return nil, nil
	}
	success := in.Task.Success
	scorer, params, input, output, reference := shapeEvalParams(in)
	score, passed, rationale, available, err := s.evalScore(ctx, scorer, params, input, output, reference)
	if err != nil {
		return nil, fmt.Errorf("benchmark score %q: %w", success.Scorer, err)
	}
	if !available {
		return nil, nil
	}
	rec := benchmark.ScoreRecord{
		AttemptID: in.AttemptID, RunID: in.RunID, Scorer: success.Scorer,
		Score: score, Passed: passed, Rationale: truncateForRow(rationale, 500),
	}
	if success.Scorer == "llm_judge" {
		rec.JudgeModel = s.judgeModel
		rec.RubricHash = hashString(success.Rubric)
	}
	return []benchmark.ScoreRecord{rec}, nil
}

// shapeEvalParams is the Sample-shaping adapter: it maps a benchmark scoreInput
// to the registry's (scorer, params, input, output, reference) — plain values,
// no eval types. The extracted final answer is the output; the task's
// value/pattern become the reference/params; llm_judge renders the rubric.
func shapeEvalParams(in scoreInput) (scorer string, params map[string]string, input, output, reference string) {
	success := in.Task.Success
	params = map[string]string{}
	switch success.Scorer {
	case "contains", "icontains", "exact_match":
		params["value"] = success.Value
	case "regex_match":
		params["pattern"] = success.Pattern
	case "llm_judge":
		params["prompt"] = buildJudgePrompt(success.Rubric)
		if success.Threshold > 0 {
			params["threshold"] = strconv.FormatFloat(success.Threshold, 'f', -1, 64)
		}
	}
	return success.Scorer, params, in.Task.Prompt, in.FinalAnswer, success.Value
}

// buildJudgePrompt renders a rubric into the eval judge prompt template. The
// judge is asked for a structured {"score":0..1,"rationale":...} reply.
func buildJudgePrompt(rubric string) string {
	return "You are grading an AI coding assistant's answer against a rubric.\n\n" +
		"Rubric:\n" + rubric + "\n\n" +
		"Answer to grade:\n{{output}}\n\n" +
		`Reply ONLY with JSON: {"score": <0..1>, "rationale": "<short reason>"}.`
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x", sum[:8])
}

func truncateForRow(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
