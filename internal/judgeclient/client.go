package judgeclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

// Client calls an OpenAI-compatible /chat/completions endpoint (OpenRouter by
// default) for a single LLM-as-judge turn and returns the reply text. It is the
// ONE judge implementation behind the obs eval and admission judges (wired in
// cmd/observer/obs_wire.go) and the Projects alignment judge tier (wired in
// cmd/observer/alignment_wire.go). It imports no internal/obs package, so the
// alignment tier needs no Plane A code. It makes an outbound call only when a
// configured judge is invoked.
//
// The request is tagged for downstream attribution: the X-SBO-Eval header and
// the OpenRouter X-Title carry "superbased-observer eval" so the judge spend
// can be told apart from app traffic (plan §15 Q4 — full proxy-routed cost
// capture + sbo.eval spend-exclusion is the documented follow-up).
//
// hv is the Authorization header value's credential portion, sourced from an
// env var by the caller (never written to config or disk).
type Client struct {
	baseURL string
	hv      string
	httpc   *http.Client
	// scrubPrompt, when set, redacts secrets from the prompt BEFORE it is
	// sent upstream so raw secrets never egress to a hosted judge (admission
	// spec §5). Set only for a REMOTE judge (hosting != local) at the wiring
	// point; nil for a loopback judge (no egress, no overhead). Injected as a
	// func so this generic client keeps no internal/scrub import.
	scrubPrompt func(string) string
	// maxPromptBytes caps the prompt sent upstream (0 = uncapped) — a payload
	// ceiling for a remote judge (admission spec §5).
	maxPromptBytes int
	// maxTokens caps the judge REPLY length (0 = omit the field, provider
	// default). The reply is only a short JSON verdict, so a tight cap bounds
	// latency + cost. Defaulted by New; overridable from config via
	// WithTuning.
	maxTokens int
	// numCtx, when >0 AND the judge is loopback-local, is passed through as an
	// Ollama-style context-window hint. It is NEVER sent to a remote judge (a
	// hosted OpenAI-compatible API rejects unknown fields). 0 = omit.
	numCtx int
	// retries is the number of ADDITIONAL attempts on a retryable failure
	// (transport error, request timeout, or 5xx) beyond the first. 0 = a
	// single attempt.
	retries int
	// local marks a loopback/no-egress judge (Ollama-style). When true the
	// credential may be empty (a local host needs no API key) and an
	// Ollama-style num_ctx hint may be passed through. Derived from the base
	// URL at construction — hosting is URL-derived throughout this codebase
	// (there is no hosting= config field; HostingLabel uses the same test).
	local bool
}

const (
	// defaultJudgeMaxTokens caps the judge reply by default — a {"score",
	// "rationale"} verdict fits comfortably; this stops a chatty model from
	// streaming an unbounded reply and bounds hosted-judge cost.
	defaultJudgeMaxTokens = 512
	// defaultJudgeRetries is the default number of ADDITIONAL attempts on a
	// retryable failure (so one automatic retry).
	defaultJudgeRetries = 1
	// judgeRetryBackoff is the pause between judge attempts (context-bounded).
	judgeRetryBackoff = 400 * time.Millisecond
	// judgeMaxResponseBytes caps the upstream body read.
	judgeMaxResponseBytes = 1 << 20
	// judgeSystemPrompt is the fixed judge instruction.
	judgeSystemPrompt = "You are a strict evaluation judge. Reply with a JSON object {\"score\": <0..1>, \"rationale\": <short>} and nothing else."
)

// New returns a judge client for baseURL with credential hv (the
// Authorization header value's credential portion, read from an env var by the
// caller, never from disk).
func New(baseURL, hv string) Client {
	base := strings.TrimRight(baseURL, "/")
	return Client{
		baseURL:   base,
		hv:        hv,
		httpc:     &http.Client{Timeout: 60 * time.Second},
		maxTokens: defaultJudgeMaxTokens,
		retries:   defaultJudgeRetries,
		local:     IsLoopbackURL(base),
	}
}

// WithTuning overrides the reply cap and the (local-only) context-window hint
// from config; a zero/negative value leaves the constructor default untouched.
// It is the config seam for [observability.judge] max_tokens / num_ctx — the
// wiring point applies it after New. Returns
// a copy (value receiver), matching WithEgressScrub's builder style.
func (j Client) WithTuning(maxTokens, numCtx int) Client {
	if maxTokens > 0 {
		j.maxTokens = maxTokens
	}
	if numCtx > 0 {
		j.numCtx = numCtx
	}
	return j
}

// IsLoopbackURL reports whether a base URL points at the loopback
// interface — the "local" hosting bucket this codebase derives from the URL
// (HostingLabel uses the same test; there is no hosting= config field). A
// loopback judge is treated as no-egress: its credential may be empty and an
// Ollama-style num_ctx hint may be passed through.
//
// The actual grammar (exact-host allow-list, not a substring test) lives in
// internal/dataauthority.IsLoopbackJudgeEndpoint — the JUDGE-1 egress gate's
// pure copy — so there is exactly one owner of "is this endpoint local"
// shared by the live client here and the egress-gate decision there. This
// wrapper keeps the client's callers on one short name.
func IsLoopbackURL(baseURL string) bool {
	return dataauthority.IsLoopbackJudgeEndpoint(baseURL)
}

// WithEgressScrub returns a copy of the judge that caps and secret-redacts the
// prompt before sending — applied for a REMOTE judge so raw secrets never
// leave to a hosted judge (admission spec §5). scrub may be nil (cap only).
func (j Client) WithEgressScrub(scrub func(string) string, maxBytes int) Client {
	j.scrubPrompt = scrub
	j.maxPromptBytes = maxBytes
	return j
}

// Complete sends one judge turn for model and returns the reply text.
func (j Client) Complete(ctx context.Context, model, prompt string) (string, error) {
	// A loopback/local judge (Ollama-style) needs no API key — only a remote
	// judge requires a credential (admission spec §5 / gap-audit §5.3).
	if j.hv == "" && !j.local {
		return "", fmt.Errorf("judge credential is empty - set the env var named by [observability.eval] judge_api_key_env (default OPENROUTER_API_KEY), or point base_url at a loopback host for a local no-key judge")
	}
	if model == "" {
		return "", fmt.Errorf("judge model is empty - set [observability.eval] judge_model or the scorer's model= param")
	}
	// Egress guardrails for a REMOTE judge (admission spec §5): cap the
	// payload, then redact secrets so no raw secret leaves to a hosted judge.
	// Both are no-ops for a loopback/local judge (fields unset at wiring).
	if j.maxPromptBytes > 0 && len(prompt) > j.maxPromptBytes {
		prompt = prompt[:j.maxPromptBytes] + "\n…[truncated]"
	}
	if j.scrubPrompt != nil {
		prompt = j.scrubPrompt(prompt)
	}
	req := llmwire.Request{
		Model:       model,
		System:      judgeSystemPrompt,
		Messages:    []llmwire.Message{{Role: llmwire.RoleUser, Content: prompt}},
		MaxTokens:   j.maxTokens,
		Temperature: new(float64),
	}
	// num_ctx is an Ollama-specific knob: only a local host understands it, and
	// only a local host tolerates an unknown field (a hosted API would 400), so
	// it is gated on local.
	if j.local && j.numCtx > 0 {
		req.NumCtx = j.numCtx
	}

	// A transport error or 5xx is retried up to j.retries additional times with
	// a short backoff (gap-audit §5.3); a 4xx returns at once. The context
	// bounds every attempt and each backoff sleep.
	cl, err := llmwire.NewClient(j.httpc,
		llmwire.WithRetry(llmwire.RetryPolicy{
			Retries: j.retries,
			On:      llmwire.RetryTransport | llmwire.RetryServerError,
			Backoff: judgeRetryBackoff,
		}),
		llmwire.WithMaxResponseBytes(judgeMaxResponseBytes),
		llmwire.WithHeaders(map[string]string{
			"X-SBO-Eval": "true",                     // attribution marker (plan §15 Q4)
			"X-Title":    "superbased-observer eval", // OpenRouter etiquette
		}),
		llmwire.WithRawErrors(),
	)
	if err != nil {
		return "", fmt.Errorf("judge: %w", err)
	}
	out, err := cl.Complete(ctx, j.baseURL, j.hv, req)
	var se *llmwire.StatusError
	var te *llmwire.TransportError
	switch {
	case errors.As(err, &se):
		return "", fmt.Errorf("judge: upstream %d: %s", se.StatusCode, truncateJudge(se.Body, 300))
	case errors.As(err, &te):
		return "", fmt.Errorf("judge: request: %w", te.Err)
	case errors.Is(err, llmwire.ErrNoChoices):
		return "", fmt.Errorf("judge: empty choices in response")
	case errors.Is(err, llmwire.ErrDecode):
		return "", fmt.Errorf("judge: decode response: %s", strings.TrimPrefix(err.Error(), llmwire.ErrDecode.Error()+": "))
	case err != nil:
		return "", fmt.Errorf("judge: %w", err)
	}
	return out.Content, nil
}

func truncateJudge(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// EgressScrubbed reports whether a secret-redacting prompt scrub is set (the
// remote-judge guardrail SecureEgress applies).
func (j Client) EgressScrubbed() bool { return j.scrubPrompt != nil }

// MaxPromptBytes returns the prompt cap (0 = uncapped).
func (j Client) MaxPromptBytes() int { return j.maxPromptBytes }

// Local reports whether the client targets a loopback (no-egress) judge.
func (j Client) Local() bool { return j.local }
