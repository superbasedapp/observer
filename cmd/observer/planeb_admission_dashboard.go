package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// planeb_admission_dashboard.go is the node Security page's "Organization
// prompt judge" card (lane adm-p2): GET /api/guard/prompt/judge, read-only,
// composed from the SAME planeBStatusFacts `observer guard status` prints,
// so the card and the CLI can never disagree. It says whether the judge is
// on here (and the first reason it is not), strict or not, what a prompt-gate
// hook does when the daemon cannot answer, the last day's J-801 counts, the
// consent sentence, and the named residuals in plain words. Nothing in it is
// prompt text.

// promptJudgeResiduals are the judge's known limits, in the developer's
// words (docs/guard.md "Org prompt admission judge", docs/security.md ADM-3,
// ADM-4, ADM-5). One row per residual, in the order the card lists them.
var promptJudgeResiduals = []string{
	"On a tool loop only the newest prompt you typed is judged; the coding agent sends the earlier turns, and they are not judged again.",
	"An instruction split between your typed prompt and an attached file or reminder is judged in two parts, so it can pass where the joined text might not.",
	"A prompt with a detected secret is never sent to the judge; this machine decides it with the organization's secret rule instead.",
	"Not covered: tools with neither a prompt-gate hook nor a proxy route, third-party provider lanes on the proxy, and compressed (gzip) request bodies.",
	"Another program running as you can keep this machine's judge busy, and a busy judge counts as one that could not answer.",
}

// promptJudgeView is the card's body.
type promptJudgeView struct {
	Available bool `json:"available"`
	// Active is true when the judge runs on this machine; OffReason is the
	// first reason it does not (the planeBOffReasons table).
	Active    bool   `json:"active"`
	OffReason string `json:"off_reason,omitempty"`
	// Managed, HoldsEnforce and Accepted are the three local facts the
	// lane needs before a policy is even read.
	Managed      bool `json:"managed"`
	HoldsEnforce bool `json:"holds_enforce"`
	Accepted     bool `json:"accepted"`
	HavePolicy   bool `json:"have_policy"`
	// Version / Scope / Mode / Strict / NodeLane describe the cached signed
	// policy (absent when none is cached).
	Version  int64  `json:"version,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Strict   bool   `json:"strict"`
	NodeLane bool   `json:"node_lane"`
	// Enforced is true when an enforce policy actually refuses here
	// (planeb.admission is in preauthorize_enforce); otherwise it flags.
	Enforced   bool   `json:"enforced"`
	JudgeRoute string `json:"judge_route,omitempty"`
	// EngineLinked is false on a build without the admission engine.
	EngineLinked bool `json:"engine_linked"`
	// FailClosed is true when a prompt-gate hook that cannot reach the
	// daemon refuses the prompt; Unreachable says it in words.
	FailClosed  bool   `json:"fail_closed"`
	Unreachable string `json:"unreachable,omitempty"`
	// BudgetMS is the node lane's judge budget for the cached policy.
	BudgetMS int64 `json:"budget_ms,omitempty"`
	// Counts are the last 24 hours of J-801 rows by decision.
	Counts map[string]int `json:"counts"`
	// Lines are the `observer guard status` lines, verbatim.
	Lines []string `json:"lines"`
	// Disclosure is the consent sentence (orgenrol.PromptJudgeDisclosure),
	// shown on a managed machine only.
	Disclosure string   `json:"disclosure,omitempty"`
	Residuals  []string `json:"residuals"`
}

// buildPromptJudgeView maps the facts onto the card.
func buildPromptJudgeView(f planeBStatusFacts) promptJudgeView {
	active, failClosed := promptJudgeStateFromFacts(f)
	v := promptJudgeView{
		Available:    true,
		Active:       active,
		OffReason:    planeBOffReasonFor(f),
		Managed:      f.Managed,
		HoldsEnforce: f.HoldsEnforce,
		Accepted:     f.Accepted,
		HavePolicy:   f.HavePolicy,
		EngineLinked: f.EngineLinked,
		FailClosed:   failClosed,
		Counts:       map[string]int{},
		Lines:        planeBGuardStatusLines(f),
		Residuals:    promptJudgeResiduals,
	}
	for k, n := range f.Counts {
		v.Counts[k] = n
	}
	if f.HavePolicy {
		v.Version, v.Scope, v.Mode = f.Version, string(f.Spec.Scope), f.Spec.Admission.Mode.String()
		v.Strict, v.NodeLane = f.Spec.Admission.Strict, f.Spec.NodeLane
		v.Enforced = planebadmission.Enforces(f.Spec) && f.Preauthorized
		v.BudgetMS = planebadmission.NodeLaneJudgeBudget(f.Spec).Milliseconds()
	}
	if active {
		v.JudgeRoute = planeBJudgeRoute(f)
		v.Unreachable = planeBUnreachableText(f)
	}
	if f.Managed {
		v.Disclosure = "Your organization may let " + orgenrol.PromptJudgeDisclosure + "."
	}
	return v
}

// promptJudgeStatusSeam builds the dashapi.Options.PromptJudgeStatus func for
// the daemon: configPath is re-read on every call (like the CLI) so the card
// reflects the file, database is the daemon's own handle.
func promptJudgeStatusSeam(configPath string, database *sql.DB) func(ctx context.Context) (any, error) {
	return func(ctx context.Context) (any, error) {
		if database == nil {
			return nil, errors.New("promptJudgeStatus: no database")
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return nil, fmt.Errorf("promptJudgeStatus: load config: %w", err)
		}
		return buildPromptJudgeView(loadPlaneBStatusFacts(ctx, cfg, store.New(database), time.Now().UTC())), nil
	}
}
