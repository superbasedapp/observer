package judgeclient

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

// Request profiles: how a judge request is shaped on the wire. The
// model-family table and the shape it resolves live in internal/llmwire
// (shape.go), the one owner shared with the org server's provider client;
// these names re-export it so judge callers and config are unchanged. The
// profile is resolved at the client boundary from the [observability.judge]
// request_profile key, or (auto) from the model id. Nothing past
// buildRequest branches on a provider or a model name (CLAUDE.md rule 3).
const (
	// ProfileAuto resolves the profile from the model id (the default).
	ProfileAuto = llmwire.ProfileAuto
	// ProfileChat sends max_tokens and temperature 0: what every
	// OpenAI-compatible chat model and local server accepts.
	ProfileChat = llmwire.ProfileChat
	// ProfileReasoning sends max_completion_tokens, no temperature and a
	// reasoning effort: what OpenAI's GPT-5 and o-series models require (they
	// refuse max_tokens and any temperature but the default, L-02).
	ProfileReasoning = llmwire.ProfileReasoning
)

// ValidProfile reports whether p is a request_profile value config accepts
// ("" means auto).
func ValidProfile(p string) bool { return llmwire.ValidProfile(p) }

// resolveShape resolves the configured profile (and effort override) against
// a model id into the wire shape (llmwire.ResolveShape). Pure.
func resolveShape(profile, effort, model string) llmwire.Shape {
	return llmwire.ResolveShape(profile, effort, model)
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
