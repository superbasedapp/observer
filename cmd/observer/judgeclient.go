//go:build !no_obs

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// chatCompletionsJudge calls an OpenAI-compatible /chat/completions endpoint
// (OpenRouter by default) for a single LLM-as-judge turn and returns the reply
// text. It is the host's implementation detail behind the obs eval.JudgeClient
// (wired in obs_wire.go) — kept in its own file with NO internal/obs import so
// it stays generic and the reverse-import boundary holds (only obs_wire.go may
// import obs). This is the SINGLE outbound network call in the whole eval
// subsystem; it runs only for an explicitly-invoked `observer eval run`.
//
// The request is tagged for downstream attribution: the X-SBO-Eval header and
// the OpenRouter X-Title carry "superbased-observer eval" so the judge spend
// can be told apart from app traffic (plan §15 Q4 — full proxy-routed cost
// capture + sbo.eval spend-exclusion is the documented follow-up).
//
// hv is the Authorization header value's credential portion, sourced from an
// env var by the caller (never written to config or disk).
type chatCompletionsJudge struct {
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
	// latency + cost. Defaulted by newChatCompletionsJudge; overridable from
	// config via withTuning.
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
	// (there is no hosting= config field; judgeHostingLabel uses the same test).
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
)

func newChatCompletionsJudge(baseURL, hv string) chatCompletionsJudge {
	base := strings.TrimRight(baseURL, "/")
	return chatCompletionsJudge{
		baseURL:   base,
		hv:        hv,
		httpc:     &http.Client{Timeout: 60 * time.Second},
		maxTokens: defaultJudgeMaxTokens,
		retries:   defaultJudgeRetries,
		local:     isLoopbackJudgeURL(base),
	}
}

// withTuning overrides the reply cap and the (local-only) context-window hint
// from config; a zero/negative value leaves the constructor default untouched.
// It is the config seam for [observability.judge] max_tokens / num_ctx — the
// wiring point (obs_wire.go) applies it after newChatCompletionsJudge. Returns
// a copy (value receiver), matching withEgressScrub's builder style.
func (j chatCompletionsJudge) withTuning(maxTokens, numCtx int) chatCompletionsJudge {
	if maxTokens > 0 {
		j.maxTokens = maxTokens
	}
	if numCtx > 0 {
		j.numCtx = numCtx
	}
	return j
}

// isLoopbackJudgeURL reports whether a base URL points at the loopback
// interface — the "local" hosting bucket this codebase derives from the URL
// (judgeHostingLabel uses the same test; there is no hosting= config field). A
// loopback judge is treated as no-egress: its credential may be empty and an
// Ollama-style num_ctx hint may be passed through.
//
// The actual grammar (exact-host allow-list, not a substring test) lives in
// internal/dataauthority.IsLoopbackJudgeEndpoint — the JUDGE-1 egress gate's
// pure copy — so there is exactly one owner of "is this endpoint local"
// shared by the live client here and the egress-gate decision there. This
// binding-layer wrapper exists only so call sites in this package keep their
// short, unqualified name.
func isLoopbackJudgeURL(baseURL string) bool {
	return dataauthority.IsLoopbackJudgeEndpoint(baseURL)
}

// withEgressScrub returns a copy of the judge that caps and secret-redacts the
// prompt before sending — applied for a REMOTE judge so raw secrets never
// leave to a hosted judge (admission spec §5). scrub may be nil (cap only).
func (j chatCompletionsJudge) withEgressScrub(scrub func(string) string, maxBytes int) chatCompletionsJudge {
	j.scrubPrompt = scrub
	j.maxPromptBytes = maxBytes
	return j
}

func (j chatCompletionsJudge) complete(ctx context.Context, model, prompt string) (string, error) {
	// A loopback/local judge (Ollama-style) needs no API key — only a remote
	// judge requires a credential (admission spec §5 / gap-audit §5.3).
	if j.hv == "" && !j.local {
		return "", fmt.Errorf("judge credential is empty — set the env var named by [observability.eval] judge_api_key_env (default OPENROUTER_API_KEY), or point base_url at a loopback host for a local no-key judge")
	}
	if model == "" {
		return "", fmt.Errorf("judge model is empty — set [observability.eval] judge_model or the scorer's model= param")
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
	reqBody := map[string]any{
		"model":       model,
		"temperature": 0,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a strict evaluation judge. Reply with a JSON object {\"score\": <0..1>, \"rationale\": <short>} and nothing else."},
			{"role": "user", "content": prompt},
		},
	}
	if j.maxTokens > 0 {
		reqBody["max_tokens"] = j.maxTokens
	}
	// num_ctx is an Ollama-specific knob: only a local host understands it, and
	// only a local host tolerates an unknown field (a hosted API would 400), so
	// it is gated on local.
	if j.local && j.numCtx > 0 {
		reqBody["num_ctx"] = j.numCtx
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("judge: marshal: %w", err)
	}

	body, status, err := j.doWithRetry(ctx, raw)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("judge: upstream %d: %s", status, truncateJudge(string(body), 300))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("judge: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("judge: empty choices in response")
	}
	return parsed.Choices[0].Message.Content, nil
}

// doWithRetry posts the marshalled judge body, retrying on a retryable failure
// — a transport error, a request timeout, or a 5xx upstream — up to j.retries
// additional attempts with a short backoff between them (gap-audit §5.3: the
// single Do() had no resilience to a transient blip). A 4xx is returned
// immediately (a bad request will not fix itself on retry). The context bounds
// every attempt AND each backoff sleep, so a cancelled/expired context ends the
// loop promptly. Returns the (capped) response body + status of the final
// attempt, or the last transport error.
func (j chatCompletionsJudge) doWithRetry(ctx context.Context, raw []byte) ([]byte, int, error) {
	attempts := j.retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, fmt.Errorf("judge: request: %w", ctx.Err())
			case <-time.After(judgeRetryBackoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.baseURL+"/chat/completions", bytes.NewReader(raw))
		if err != nil {
			return nil, 0, fmt.Errorf("judge: new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if j.hv != "" { // a loopback/local judge may run keyless
			req.Header.Set("Authorization", "Bearer "+j.hv)
		}
		req.Header.Set("X-SBO-Eval", "true")                  // attribution marker (plan §15 Q4)
		req.Header.Set("X-Title", "superbased-observer eval") // OpenRouter etiquette

		resp, err := j.httpc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("judge: request: %w", err)
			continue // transport error / timeout — retryable
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 && attempt < attempts-1 {
			lastErr = fmt.Errorf("judge: upstream %d: %s", resp.StatusCode, truncateJudge(string(body), 300))
			continue // 5xx — retryable
		}
		return body, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

func truncateJudge(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
