// Package llmwire is the one OpenAI-compatible inference wire client shared by
// the cloud and org planes (plan 06 section 17.2, work package E1.1). It
// speaks the "openai_compatible" dialect: POST {base}/chat/completions with an
// Authorization header, as served by OVH AI Endpoints (gpt-oss-20b), vLLM, and
// every other server that copies the OpenAI chat-completions shape.
//
// The package has a pure core and one thin transport seam:
//
//   - wire.go, usage.go and errors.go are pure: request and response types,
//     the dialect encoder and decoder, prompt-cache and reasoning-token
//     accounting, and the HTTP-status classification table. They import no
//     net/http, database/sql or fsnotify.
//   - transport.go is the only file that does HTTP. Its Client wraps an
//     *http.Client the caller supplies; production callers build it with
//     internal/netguard (the one SSRF-guarded outbound client). The package
//     never constructs a client of its own and refuses a nil one, so a
//     customer-influenced base URL can never reach an unguarded dialer.
//
// Token accounting follows the OpenAI convention: completion_tokens already
// includes reasoning tokens (they are billed as output), so Usage keeps
// ReasoningTokens as an informational subset, never an addend. Prompt tokens
// include cached prompt tokens when the server reports them.
//
// Testing: testdata/ai_endpoints_chat_completions.synthetic.json is a
// SYNTHETIC fixture written from the public OpenAI chat-completions response
// shape, not a recording of a live call. When M0.3 records a real AI
// Endpoints response it is dropped beside it as
// ai_endpoints_chat_completions.recorded.json and the contract test picks it
// up automatically.
package llmwire
