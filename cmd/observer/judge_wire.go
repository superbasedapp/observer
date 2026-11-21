//go:build !sbo_omit_judge_client

package main

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/judgeclient"
)

// judge_wire.go binds the judge client component (internal/judgeclient) to
// the short package-main names the obs and alignment wiring use. It carries no
// build tag: the alignment judge tier and the obs judges share one client, and
// neither the client nor these bindings import internal/obs (modular packaging
// phase PB, D-408).

// chatCompletionsJudge is the judge client.
type chatCompletionsJudge = judgeclient.Client

// judgeMaxPromptBytes caps the prompt sent to a remote judge.
const judgeMaxPromptBytes = judgeclient.RemoteMaxPromptBytes

// newConfiguredJudge is judgeclient.New with the resolved [observability.judge]
// tuning applied: the reply cap and local context hint (WithTuning) and the
// request profile + reasoning effort (WithRequestProfile, L-02). Every judge
// wiring point builds its client here so a new judge key reaches all of them.
func newConfiguredJudge(baseURL, hv string, jc config.ObservabilityJudgeConfig) chatCompletionsJudge {
	return judgeclient.New(baseURL, hv).
		WithTuning(jc.MaxTokens, jc.NumCtx).
		WithRequestProfile(jc.RequestProfile, jc.ReasoningEffort)
}

// judgeDefaultTimeout is judgeclient.DefaultTimeout (L-20).
func judgeDefaultTimeout(baseURL string) time.Duration {
	return judgeclient.DefaultTimeout(baseURL)
}

// secureJudgeEgress is judgeclient.SecureEgress.
func secureJudgeEgress(c chatCompletionsJudge, hosting string) chatCompletionsJudge {
	return judgeclient.SecureEgress(c, hosting)
}

// resolveJudgeConfig is judgeclient.ResolveConfig.
func resolveJudgeConfig(shared, override config.ObservabilityJudgeConfig) config.ObservabilityJudgeConfig {
	return judgeclient.ResolveConfig(shared, override)
}

// judgeHostingLabel is judgeclient.HostingLabel.
func judgeHostingLabel(baseURL, model string) string {
	return judgeclient.HostingLabel(baseURL, model)
}
