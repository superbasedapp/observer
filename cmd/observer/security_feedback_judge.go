//go:build !sbo_omit_security && !sbo_omit_judge_client

package main

import (
	"context"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// security_feedback_judge.go builds the explain flow's judge from the
// shared [observability.judge] block (with [observability.eval]'s override,
// the precedence every judge uses), through the one judge client
// (judge_wire.go). A remote judge gets secureJudgeEgress (secret redaction
// and the payload cap); a loopback judge is sent the prompt unmodified. Nil
// when no model is configured: the flow then says so and sends nothing.
func securityExplainJudgeFor(cfg config.Config) *securityExplainJudge {
	jc := resolveJudgeConfig(cfg.Observability.Judge, config.ObservabilityJudgeConfig{
		Model:     cfg.Observability.Eval.JudgeModel,
		BaseURL:   cfg.Observability.Eval.JudgeBaseURL,
		APIKeyEnv: cfg.Observability.Eval.JudgeAPIKeyEnv,
	})
	if jc.Model == "" {
		return nil
	}
	baseURL := jc.BaseURL
	if baseURL == "" {
		baseURL = "https://openrouter.ai/api/v1"
	}
	keyEnv := jc.APIKeyEnv
	if keyEnv == "" {
		keyEnv = "OPENROUTER_API_KEY"
	}
	hosting := judgeHostingLabel(baseURL, jc.Model)
	client := secureJudgeEgress(newChatCompletionsJudge(baseURL, os.Getenv(keyEnv)).WithTuning(jc.MaxTokens, jc.NumCtx), hosting)
	model := jc.Model
	return &securityExplainJudge{
		complete: func(ctx context.Context, prompt string) (string, error) { return client.Complete(ctx, model, prompt) },
		baseURL:  baseURL, model: model, hosting: hosting,
	}
}
