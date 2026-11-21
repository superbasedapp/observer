package judgeclient

import (
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

// Request profiles: how a judge request is shaped on the wire. The profile is
// a capability of the judge model, resolved here at the client boundary from
// the [observability.judge] request_profile key, or (auto) from the model id
// by the reasoningFamilies table. Nothing past this file branches on a
// provider or a model name (CLAUDE.md rule 3).
const (
	// ProfileAuto resolves the profile from the model id (the default).
	ProfileAuto = "auto"
	// ProfileChat sends max_tokens and temperature 0: what every
	// OpenAI-compatible chat model and local server accepts.
	ProfileChat = "chat"
	// ProfileReasoning sends max_completion_tokens, no temperature and a
	// reasoning effort: what OpenAI's GPT-5 and o-series models require (they
	// refuse max_tokens and any temperature but the default, L-02).
	ProfileReasoning = "reasoning"
)

// ValidProfile reports whether p is a request_profile value config accepts
// ("" means auto).
func ValidProfile(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", ProfileAuto, ProfileChat, ProfileReasoning:
		return true
	}
	return false
}

// reasoningMinReplyTokens is the reply cap a reasoning-profile request uses
// when config sets no max_tokens. On a reasoning model the cap also covers
// the hidden reasoning tokens, so the chat default (512) can be spent before
// any verdict text is written; 2048 leaves room at a low effort.
const reasoningMinReplyTokens = 2048

// familyRule is one row of the auto-profile table: a bare model id starting
// with prefix gets profile, and (for the reasoning profile) effort as its
// default reasoning effort ("" sends none).
type familyRule struct {
	prefix  string
	profile string
	effort  string
}

// reasoningFamilies is walked top-down; the first matching prefix wins, so a
// more specific prefix sits above a shorter one. It matches a BARE model id
// (as OpenAI's own API takes it). A routed id with a provider prefix
// ("openai/gpt-5-nano" on OpenRouter or a LiteLLM proxy) is left on the chat
// profile: those services translate max_tokens and drop an unsupported
// temperature themselves. A model this table does not know is set with
// request_profile = "reasoning" (for example an Azure deployment name).
var reasoningFamilies = []familyRule{
	{prefix: "gpt-5-chat", profile: ProfileChat},                    // the non-reasoning GPT-5 chat alias
	{prefix: "gpt-5.", profile: ProfileReasoning, effort: "low"},    // gpt-5.1 and later: no "minimal"
	{prefix: "gpt-5", profile: ProfileReasoning, effort: "minimal"}, // gpt-5, -mini, -nano
	{prefix: "o1-mini", profile: ProfileReasoning},                  // takes no reasoning_effort
	{prefix: "o1-preview", profile: ProfileReasoning},               // takes no reasoning_effort
	{prefix: "o1", profile: ProfileReasoning, effort: "low"},
	{prefix: "o3", profile: ProfileReasoning, effort: "low"},
	{prefix: "o4", profile: ProfileReasoning, effort: "low"},
}

// requestShape is the resolved wire shape for one judge call.
type requestShape struct {
	maxTokensParam string
	temperatureOff bool
	effort         string
	minReplyTokens int
}

// resolveShape resolves the configured profile (and effort override) against
// a model id into the wire shape. Pure.
func resolveShape(profile, effort, model string) requestShape {
	p := strings.ToLower(strings.TrimSpace(profile))
	defEffort := ""
	if p == "" || p == ProfileAuto {
		p = ProfileChat
		id := strings.ToLower(strings.TrimSpace(model))
		if !strings.Contains(id, "/") {
			for _, r := range reasoningFamilies {
				if strings.HasPrefix(id, r.prefix) {
					p, defEffort = r.profile, r.effort
					break
				}
			}
		}
	}
	if p != ProfileReasoning {
		return requestShape{maxTokensParam: llmwire.ParamMaxTokens}
	}
	if e := strings.TrimSpace(effort); e != "" {
		defEffort = e
	}
	return requestShape{
		maxTokensParam: llmwire.ParamMaxCompletionTokens,
		temperatureOff: true,
		effort:         defEffort,
		minReplyTokens: reasoningMinReplyTokens,
	}
}

// Default per-call judge timeouts, by where the judge runs (L-20). A loopback
// judge keeps the admission budget of 1.5 s (a request waits for its verdict).
// A hosted judge needs a TLS handshake, the provider's queue and, on a
// reasoning model, its thinking: the live run (2026-11-20) measured 1-4 s per
// gpt-5-nano verdict at minimal effort, and the first call of a process pays
// the connection set-up on top, which ended at 1.5 s on every first call. 8 s
// covers that with room while still bounding the wait; timeout_ms overrides
// either.
const (
	localJudgeTimeout  = 1500 * time.Millisecond
	remoteJudgeTimeout = 8 * time.Second
)

// DefaultTimeout is the judge call timeout used when config sets no
// timeout_ms: localJudgeTimeout for a loopback base URL, remoteJudgeTimeout
// for any other (an empty base URL is the hosted OpenRouter default).
func DefaultTimeout(baseURL string) time.Duration {
	if baseURL != "" && IsLoopbackURL(baseURL) {
		return localJudgeTimeout
	}
	return remoteJudgeTimeout
}
