package cloudevidence

import (
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// Evidence budget fitting (managed-SaaS ruling R-AI1; the S-3 spike's
// "Data budget" section). A tier caps how much of a session is sent, in
// evidence tokens (cloudcontract.EstimateEvidenceTokens). The budget is met
// by STEPPING DOWN the builder's own evidence settings and rebuilding, never
// by cutting the serialized JSON: a cut envelope would fail Validate and the
// two-digest protocol, while every rung of the ladder below is an envelope
// the builder produces whole.

// budgetRung is one row of the step-down ladder: the CEILING each evidence
// setting may take on that rung. Rungs are ordered richest first and every
// field is non-increasing down the table, so a later rung never yields a
// larger envelope than an earlier one.
//
// Cut order (S-3): the action sample shrinks first, the excerpt size next,
// the developer's prompts last. activity_mix still counts every action of the
// session whatever the sample size, while the prompts are the only record of
// intent.
type budgetRung struct {
	name              string
	userMessages      int
	assistantMessages int
	failureClasses    int
	actionSummaries   int
	excerptBytes      int
}

// budgetLadder is the S-3 ladder (spikes/s3/build.go), L0 the default
// settings and L10 the floor: one prompt of 128 bytes, no action sample, no
// failure classes. A function, not a package variable, so the table is never
// shared mutable state.
func budgetLadder() []budgetRung {
	return []budgetRung{
		{"L0", 15, 1, 3, 256, 1024},
		{"L1", 15, 1, 3, 128, 1024},
		{"L2", 12, 1, 3, 96, 768},
		{"L3", 10, 1, 3, 64, 512},
		{"L4", 8, 1, 3, 48, 384},
		{"L5", 6, 1, 3, 32, 256},
		{"L6", 4, 1, 3, 24, 256},
		{"L7", 3, 0, 3, 16, 192},
		{"L8", 2, 0, 2, 12, 128},
		{"L9", 1, 0, 2, 8, 128},
		{"L10", 1, 0, 0, 0, 128},
	}
}

// BudgetStep is one step of the ladder applied to a base: the rung's name
// and the settings it yields.
type BudgetStep struct {
	Rung     string
	Settings cloudcontract.EvidenceSettings
}

// BudgetLadder returns the step-down sequence for base: each rung's ceilings
// applied to base (min per field), so a step never asks for MORE than the
// developer's own settings allow. Milestones and Outcomes are the base's
// (they are small and fixed-size). Consecutive steps that yield identical
// settings are collapsed, so no envelope is built twice. The first step is
// base clamped to L0, which equals base whenever base is within the default.
func BudgetLadder(base cloudcontract.EvidenceSettings) []BudgetStep {
	var out []BudgetStep
	for _, r := range budgetLadder() {
		s := base
		s.UserMessages = min(s.UserMessages, r.userMessages)
		s.AssistantMessages = min(s.AssistantMessages, r.assistantMessages)
		s.FailureClasses = min(s.FailureClasses, r.failureClasses)
		s.ActionSummaries = min(s.ActionSummaries, r.actionSummaries)
		s.ExcerptBytes = max(cloudcontract.MinEvidenceExcerptBytes, min(s.ExcerptBytes, r.excerptBytes))
		if n := len(out); n > 0 && out[n-1].Settings == s {
			continue
		}
		out = append(out, BudgetStep{Rung: r.name, Settings: s})
	}
	return out
}

// ErrEvidenceOverBudget is returned when even the ladder's floor does not fit
// the budget. The caller must not send the session: nothing it can build is
// small enough.
var ErrEvidenceOverBudget = errors.New("cloudevidence: session evidence exceeds the budget at every step")

// BudgetFit is the outcome of FitToBudget.
type BudgetFit struct {
	// Settings are the evidence settings the fitted envelope was built with.
	// A caller freezes THESE on its consent receipt, so a send-time rebuild
	// reproduces the same bytes.
	Settings cloudcontract.EvidenceSettings
	// Bytes is the serialized envelope that fits.
	Bytes []byte
	// Rung names the ladder step that fitted ("" when the unstepped build
	// already fit).
	Rung string
	// EstimatedTokens is cloudcontract.EstimateEvidenceTokens(len(Bytes)).
	EstimatedTokens int
	// SteppedDown reports whether any step-down was needed.
	SteppedDown bool
}

// BuildFunc builds and serializes one envelope under the given settings. It
// is the caller's whole build path (store read, excerpt selection,
// BuildEnvelope, Serialize), injected so this package stays pure.
type BuildFunc func(cloudcontract.EvidenceSettings) ([]byte, error)

// FitToBudget walks BudgetLadder(base) top-down and returns the first
// envelope whose estimated evidence tokens fit budgetTokens. A non-positive
// budget means "no budget": the base build is returned unstepped. The base is
// validated first, and a build error stops the walk (it is never treated as
// "too big").
func FitToBudget(base cloudcontract.EvidenceSettings, budgetTokens int, build BuildFunc) (BudgetFit, error) {
	if err := base.Validate(); err != nil {
		return BudgetFit{}, fmt.Errorf("cloudevidence.FitToBudget: %w", err)
	}
	if build == nil {
		return BudgetFit{}, errors.New("cloudevidence.FitToBudget: nil build function")
	}
	first, err := build(base)
	if err != nil {
		return BudgetFit{}, fmt.Errorf("cloudevidence.FitToBudget: %w", err)
	}
	if cloudcontract.EvidenceFitsBudget(len(first), budgetTokens) {
		return BudgetFit{Settings: base, Bytes: first, EstimatedTokens: cloudcontract.EstimateEvidenceTokens(len(first))}, nil
	}
	smallest := len(first)
	for _, step := range BudgetLadder(base) {
		if step.Settings == base {
			continue // already built above
		}
		b, err := build(step.Settings)
		if err != nil {
			return BudgetFit{}, fmt.Errorf("cloudevidence.FitToBudget: rung %s: %w", step.Rung, err)
		}
		if cloudcontract.EvidenceFitsBudget(len(b), budgetTokens) {
			return BudgetFit{
				Settings: step.Settings, Bytes: b, Rung: step.Rung,
				EstimatedTokens: cloudcontract.EstimateEvidenceTokens(len(b)), SteppedDown: true,
			}, nil
		}
		smallest = min(smallest, len(b))
	}
	return BudgetFit{}, fmt.Errorf("%w: smallest envelope %d bytes (about %d tokens) against a budget of %d tokens",
		ErrEvidenceOverBudget, smallest, cloudcontract.EstimateEvidenceTokens(smallest), budgetTokens)
}
