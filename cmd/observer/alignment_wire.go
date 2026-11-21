//go:build !sbo_omit_judge_client

package main

import (
	"context"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/intelligence/alignment"
)

// alignmentJudgeAdapter adapts the host's generic chatCompletionsJudge to
// alignment.Judge (the §3.6 "J" tier's own interface) — the same "bind a
// model here" pattern obsAdmissionJudge already uses for admission's
// JudgeClient (obs_wire.go). It additionally implements
// alignment.EgressGate (JUDGE-1, docs/security.md): baseURL and orgPinned
// are captured once at construction (alignmentJudgeFor runs once per
// process, not per grading call) and combined with the PER-CALL
// alignment.Input.Authority — the only fact that changes from one grading
// call to the next — inside AllowInput.
type alignmentJudgeAdapter struct {
	client chatCompletionsJudge
	model  string
	// baseURL is the resolved judge endpoint (after the OpenRouter
	// default is applied) — fed to dataauthority.JudgeEgressAllowed's
	// loopback test in AllowInput.
	baseURL string
	// orgPinned records whether the org itself authored/approved this
	// exact judge configuration (JUDGE-1's escape hatch alongside
	// loopback). Hardcoded false today: alignmentJudgeFor has no live
	// signal for this yet — [observability.judge].use_org_relay is NOT a
	// safe proxy here, because this adapter (unlike
	// obsBuildJudge/obsBuildAdmissionJudge) does not actually implement
	// relay routing, so treating UseOrgRelay=true as "org-pinned" would
	// let org-authority content reach the OpenRouter default instead of
	// the org's own relay — the opposite of what org-pinned is meant to
	// assert. Wiring a real signal (e.g. internal/policyfam/nodegov's
	// readEffectivePins() over "observability.judge.*", or giving this
	// adapter genuine relay support first) is a documented follow-up.
	orgPinned bool
}

func (j alignmentJudgeAdapter) Judge(ctx context.Context, prompt string) (string, error) {
	return j.client.Complete(ctx, j.model, prompt)
}

// AllowInput implements alignment.EgressGate (JUDGE-1, docs/security.md).
// in.Authority is populated by the caller from the prompt's session's
// stored dataauthority classification. An empty string means either the
// session has no classification yet, or the caller failed to look one up
// (e.g. store.LoadPromptChainInput's SessionAuthority read errored or
// found nothing) — dataauthority's own convention is that an unknown
// authority is treated exactly like AuthorityOrg (see
// EligibleForOrgEnrichment's doc comment: "an unknown authority ... is
// refused too"). This gate follows that same convention rather than
// fail-open: an empty in.Authority is passed through to
// JudgeEgressAllowed as dataauthority.Authority(""), which its own
// decision table already treats as "AuthorityOrg or unknown" — allowed
// only over loopback or an org-pinned config, refused otherwise. This
// closes the pre-JUDGE-1-hardening gap where an un-classified or
// lookup-failed call site shipped content to any remote judge
// unconditionally.
func (j alignmentJudgeAdapter) AllowInput(in alignment.Input) (bool, string) {
	return dataauthority.JudgeEgressAllowed(dataauthority.Authority(in.Authority), j.baseURL, j.orgPinned)
}

// alignmentJudgeFor returns the configured §3.6 "J" tier judge for cfg, or
// nil with a human-readable reason when it cannot be built:
//
//   - [projects].alignment_judge != "obs_judge" (default "off"): the
//     operator has not opted into judge-tier grading at all.
//   - [observability.judge] (with [observability.eval]'s override applied,
//     the same resolveJudgeConfig precedence obsBuildJudge/
//     obsBuildAdmissionJudge use) has no model configured: there is
//     nothing to reuse.
//
// When a judge IS configured, the base URL decides hosting exactly the
// way it does for the eval/admission judges (judgeHostingLabel): a
// loopback base_url is treated as no-egress and sent unmodified; anything
// else gets secureJudgeEgress's guardrails (secret-redact + payload cap)
// applied before a single byte leaves the node, because §4 W5a requires
// "the adapter applies withEgressScrub exactly as the eval/admission
// adapters do whenever the base URL is not loopback."
func alignmentJudgeFor(cfg *config.Config) (j alignment.Judge, model string, hosting string, reason string) {
	if cfg == nil || cfg.Projects.AlignmentJudge != "obs_judge" {
		return nil, "", "off", `alignment judge disabled ([projects].alignment_judge is not "obs_judge")`
	}

	jc := resolveJudgeConfig(cfg.Observability.Judge, config.ObservabilityJudgeConfig{
		Model:     cfg.Observability.Eval.JudgeModel,
		BaseURL:   cfg.Observability.Eval.JudgeBaseURL,
		APIKeyEnv: cfg.Observability.Eval.JudgeAPIKeyEnv,
	})
	if jc.Model == "" {
		return nil, "", "off", "the judge configured under [observability] has no model set"
	}

	baseURL := jc.BaseURL
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}
	keyEnv := jc.APIKeyEnv
	if keyEnv == "" {
		keyEnv = "OPENROUTER_API_KEY"
	}

	hosting = judgeHostingLabel(baseURL, jc.Model)
	client := secureJudgeEgress(
		newConfiguredJudge(baseURL, os.Getenv(keyEnv), jc),
		hosting,
	)
	return alignmentJudgeAdapter{client: client, model: jc.Model, baseURL: baseURL}, jc.Model, hosting, ""
}
