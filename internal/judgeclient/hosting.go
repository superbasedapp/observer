package judgeclient

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// RemoteMaxPromptBytes caps the prompt sent to a REMOTE judge (admission spec
// §5 payload ceiling). 32 KiB comfortably fits a policy rubric + a user
// message while bounding what leaves the node.
const RemoteMaxPromptBytes = 32 << 10

// SecureEgress applies the remote-judge egress guardrails - secret redact
// (scrub) + payload cap - to a judge client when the judge is NOT loopback-
// local (admission spec §5), so no raw secret ever leaves to a hosted judge. A
// local (loopback) or off judge carries no egress risk, so its prompt is sent
// unmodified (zero overhead).
func SecureEgress(c Client, hosting string) Client {
	if hosting == "local" || hosting == "off" {
		return c
	}
	return c.WithEgressScrub(scrub.New().String, RemoteMaxPromptBytes)
}

// ResolveConfig applies a per-feature override onto the shared
// [observability.judge] block field-by-field (override wins where set). This is
// the Q4 "shared block + overrides" decision (admission review 2026-07-05).
func ResolveConfig(shared, override config.ObservabilityJudgeConfig) config.ObservabilityJudgeConfig {
	out := shared
	if override.Model != "" {
		out.Model = override.Model
	}
	if override.BaseURL != "" {
		out.BaseURL = override.BaseURL
	}
	if override.APIKeyEnv != "" {
		out.APIKeyEnv = override.APIKeyEnv
	}
	if override.TimeoutMS != 0 {
		out.TimeoutMS = override.TimeoutMS
	}
	if override.MaxTokens != 0 {
		out.MaxTokens = override.MaxTokens
	}
	if override.NumCtx != 0 {
		out.NumCtx = override.NumCtx
	}
	if override.RequestProfile != "" {
		out.RequestProfile = override.RequestProfile
	}
	if override.ReasoningEffort != "" {
		out.ReasoningEffort = override.ReasoningEffort
	}
	if override.UseOrgRelay {
		out.UseOrgRelay = true
	}
	return out
}

// HostingLabel derives the hosting bucket from the resolved base URL - a
// capability read, not a config field (CLAUDE.md rule #3). Used only for the
// verdict record + status display.
func HostingLabel(baseURL, model string) string {
	if model == "" {
		return "off"
	}
	u := strings.ToLower(baseURL)
	switch {
	case u == "": // empty → the OpenRouter default
		return "aggregator"
	case dataauthority.IsLoopbackJudgeEndpoint(baseURL): // exact host parse, never a substring (JUDGE-1 round 4)
		return "local"
	case strings.Contains(u, "openrouter.ai"):
		return "aggregator"
	case strings.Contains(u, "openai.com"), strings.Contains(u, "anthropic.com"), strings.Contains(u, "googleapis.com"):
		return "provider"
	default:
		return "private"
	}
}
