//go:build !sbo_omit_judge_client

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

func TestAlignmentJudgeForOff(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"default off", &config.Config{Projects: config.ProjectsConfig{AlignmentJudge: "off"}}},
		{"unset", &config.Config{}},
		{"unrecognized value", &config.Config{Projects: config.ProjectsConfig{AlignmentJudge: "sometimes"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j, model, hosting, reason := alignmentJudgeFor(c.cfg)
			if j != nil {
				t.Fatalf("expected a nil judge, got %v", j)
			}
			if model != "" {
				t.Fatalf("expected an empty model, got %q", model)
			}
			if hosting != "off" {
				t.Fatalf("hosting = %q, want \"off\"", hosting)
			}
			if reason == "" {
				t.Fatal("expected a non-empty reason for a disabled judge")
			}
		})
	}
}

func TestAlignmentJudgeForNoModelConfigured(t *testing.T) {
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		// Observability.Judge.Model left empty on purpose.
	}
	j, _, hosting, reason := alignmentJudgeFor(cfg)
	if j != nil {
		t.Fatalf("expected a nil judge when no model is configured, got %v", j)
	}
	if hosting != "off" {
		t.Fatalf("hosting = %q, want \"off\"", hosting)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason when no model is configured")
	}
}

func TestAlignmentJudgeForLoopbackSkipsEgressScrub(t *testing.T) {
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		Observability: config.ObservabilityConfig{
			Judge: config.ObservabilityJudgeConfig{
				Model:   "llama3",
				BaseURL: "http://127.0.0.1:11434/v1",
			},
		},
	}
	j, model, hosting, reason := alignmentJudgeFor(cfg)
	if j == nil {
		t.Fatalf("expected a non-nil judge, got reason %q", reason)
	}
	if model != "llama3" {
		t.Fatalf("model = %q, want \"llama3\"", model)
	}
	if hosting != "local" {
		t.Fatalf("hosting = %q, want \"local\"", hosting)
	}
	adapter, ok := j.(alignmentJudgeAdapter)
	if !ok {
		t.Fatalf("judge is not an alignmentJudgeAdapter: %T", j)
	}
	if adapter.client.EgressScrubbed() || adapter.client.MaxPromptBytes() != 0 {
		t.Fatal("a loopback judge must NOT be wrapped with egress scrub (zero overhead for a no-egress judge)")
	}
}

func TestAlignmentJudgeForRemoteAppliesEgressScrub(t *testing.T) {
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		Observability: config.ObservabilityConfig{
			Judge: config.ObservabilityJudgeConfig{
				Model: "some/hosted-model",
				// BaseURL left empty -> defaults to the OpenRouter
				// aggregator, which is NOT loopback.
			},
		},
	}
	j, model, hosting, reason := alignmentJudgeFor(cfg)
	if j == nil {
		t.Fatalf("expected a non-nil judge, got reason %q", reason)
	}
	if model != "some/hosted-model" {
		t.Fatalf("model = %q, want \"some/hosted-model\"", model)
	}
	if hosting == "local" || hosting == "off" {
		t.Fatalf("hosting = %q, want a remote bucket (not local/off)", hosting)
	}
	adapter, ok := j.(alignmentJudgeAdapter)
	if !ok {
		t.Fatalf("judge is not an alignmentJudgeAdapter: %T", j)
	}
	if !adapter.client.EgressScrubbed() {
		t.Fatal("a remote judge must be wrapped with a secret-redacting scrubber")
	}
	if adapter.client.MaxPromptBytes() != judgeMaxPromptBytes {
		t.Fatalf("maxPromptBytes = %d, want %d", adapter.client.MaxPromptBytes(), judgeMaxPromptBytes)
	}
}

func TestAlignmentJudgeForEvalOverrideWins(t *testing.T) {
	// [observability.eval] judge_model, when set, wins over an EMPTY
	// [observability.judge] model — the same resolveJudgeConfig
	// precedence obsBuildJudge/obsBuildAdmissionJudge already rely on.
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		Observability: config.ObservabilityConfig{
			Eval: config.ObservabilityEvalConfig{JudgeModel: "eval-override-model"},
		},
	}
	j, model, _, reason := alignmentJudgeFor(cfg)
	if j == nil {
		t.Fatalf("expected a non-nil judge via the eval override, got reason %q", reason)
	}
	if model != "eval-override-model" {
		t.Fatalf("model = %q, want \"eval-override-model\"", model)
	}
}

// TestAlignmentJudgeAdapterAllowInput pins JUDGE-1's decision table as
// actually wired into alignmentJudgeAdapter, via a REMOTE (non-loopback)
// judge built through alignmentJudgeFor — the shape a managed node with a
// third-party judge endpoint has today.
func TestAlignmentJudgeAdapterAllowInput(t *testing.T) {
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		Observability: config.ObservabilityConfig{
			Judge: config.ObservabilityJudgeConfig{
				Model: "some/hosted-model",
				// BaseURL empty -> defaults to the OpenRouter aggregator,
				// which is remote (not loopback).
			},
		},
	}
	j, _, hosting, reason := alignmentJudgeFor(cfg)
	if j == nil {
		t.Fatalf("expected a non-nil judge, got reason %q", reason)
	}
	if hosting == "local" || hosting == "off" {
		t.Fatalf("hosting = %q, want a remote bucket for this test to be meaningful", hosting)
	}
	if _, ok := j.(alignmentJudgeAdapter); !ok {
		t.Fatalf("judge is not an alignmentJudgeAdapter: %T", j)
	}
	gate, ok := j.(alignment.EgressGate)
	if !ok {
		t.Fatalf("alignmentJudgeAdapter must implement alignment.EgressGate")
	}

	cases := []struct {
		name      string
		authority string
		wantOK    bool
	}{
		{"personal authority over a remote judge: allowed", "personal", true},
		{"org authority over a remote judge: refused", "org", false},
		{"unclassified (empty) authority over a remote judge: refused (fail-closed, treated as unknown/org)", "", false},
		{"unrecognized authority string over a remote judge: refused (treated as unknown)", "something-else", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := gate.AllowInput(alignment.Input{Authority: c.authority})
			if ok != c.wantOK {
				t.Fatalf("AllowInput(Authority=%q) ok = %v, reason=%q, want ok=%v", c.authority, ok, reason, c.wantOK)
			}
			if !ok && reason == "" {
				t.Fatal("a refusal must carry a non-empty operator-facing reason")
			}
		})
	}
}

// TestAlignmentJudgeAdapterAllowInputLoopback pins that a LOOPBACK judge
// allows org-authority input — the model never leaves the machine, so
// there is no third party to consent.
func TestAlignmentJudgeAdapterAllowInputLoopback(t *testing.T) {
	cfg := &config.Config{
		Projects: config.ProjectsConfig{AlignmentJudge: "obs_judge"},
		Observability: config.ObservabilityConfig{
			Judge: config.ObservabilityJudgeConfig{
				Model:   "llama3",
				BaseURL: "http://127.0.0.1:11434/v1",
			},
		},
	}
	j, _, hosting, reason := alignmentJudgeFor(cfg)
	if j == nil {
		t.Fatalf("expected a non-nil judge, got reason %q", reason)
	}
	if hosting != "local" {
		t.Fatalf("hosting = %q, want \"local\"", hosting)
	}
	gate, ok := j.(alignment.EgressGate)
	if !ok {
		t.Fatalf("alignmentJudgeAdapter must implement alignment.EgressGate")
	}
	if ok, refuseReason := gate.AllowInput(alignment.Input{Authority: "org"}); !ok {
		t.Fatalf("org-authority input over a loopback judge should be allowed, got refused: %q", refuseReason)
	}
}

// TestAlignmentJudgeAdapterNoNetworkCalls guards the "never make network
// calls" requirement for this test file itself: it exercises only the
// wiring/selection logic and never calls .Judge() on the returned
// adapter, which is the ONLY method that would attempt an HTTP request.
// It parses this file and fails on any call of a method named Judge, so a
// future edit that adds a live .Judge() call fails here instead of reaching
// the network.
func TestAlignmentJudgeAdapterNoNetworkCalls(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "alignment_wire_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Judge" {
				t.Errorf("%s calls .Judge(): the alignment wiring tests must stay offline", fset.Position(call.Pos()))
			}
		}
		return true
	})
}
