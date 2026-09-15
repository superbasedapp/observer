package cloudcontract

// vocabulary.go owns the CLOSED LABEL VOCABULARIES that both ends of the lane
// have to agree on: the node's evidence builder, which may only ever emit a
// member of one of these sets, and the hosted prompt builder, which has to tell
// the model what the labels mean.
//
// WHY THEY LIVE HERE (the N5 fix). The failure classes and the MCP family
// labels were declared in internal/cloudevidence and then RESTATED in prose in
// internal/cloudserver/jobs/luna.go. Two copies of a closed vocabulary is a
// drift generator: adding a class on the node silently leaves the model reading
// a stale list, and the model then has no way to interpret a label it was never
// shown. The tag taxonomy already solved this by rendering the prompt from
// tagtaxonomy.Standard(); these two sets now follow the same rule. cloudcontract
// is the one package BOTH sides already import, and it is pure, so it is where a
// shared vocabulary belongs.
//
// Every list here is ORDERED and returned as a COPY, so a caller cannot mutate
// the vocabulary and the rendered prompt is byte-stable across builds.

// Failure-class labels. A context excerpt whose source is "error_class" (or
// "error_class_last") carries EXACTLY one of these strings — optionally followed
// by an " x<count>" occurrence count — and never any part of a recorded failure
// message. See internal/cloudevidence/excerpts.go for the matching rules.
const (
	// ErrorClassExitCodeNonzero is a command that exited non-zero with no more
	// specific cause recognized.
	ErrorClassExitCodeNonzero = "exit_code_nonzero"
	// ErrorClassTimeout is a deadline/timeout expiry.
	ErrorClassTimeout = "timeout"
	// ErrorClassFileNotFound is a missing file or directory.
	ErrorClassFileNotFound = "file_not_found"
	// ErrorClassPermissionDenied is a permission/authorization refusal.
	ErrorClassPermissionDenied = "permission_denied"
	// ErrorClassFileTooLarge is a size refusal (a read that exceeded a cap).
	ErrorClassFileTooLarge = "file_too_large"
	// ErrorClassSyntaxError is a parse/compile failure.
	ErrorClassSyntaxError = "syntax_error"
	// ErrorClassTestFailure is a failing test/assertion.
	ErrorClassTestFailure = "test_failure"
	// ErrorClassNetworkError is a transport/DNS/connection failure.
	ErrorClassNetworkError = "network_error"
	// ErrorClassRateLimited is a rate-limit or quota refusal.
	ErrorClassRateLimited = "rate_limited"
)

// errorClasses is the closed, ordered failure-class vocabulary.
var errorClasses = []string{
	ErrorClassExitCodeNonzero,
	ErrorClassTimeout,
	ErrorClassFileNotFound,
	ErrorClassPermissionDenied,
	ErrorClassFileTooLarge,
	ErrorClassSyntaxError,
	ErrorClassTestFailure,
	ErrorClassNetworkError,
	ErrorClassRateLimited,
}

// ErrorClasses returns the closed failure-class vocabulary, in a stable order.
// The node emits only these labels; the hosted prompt explains only these
// labels. Both read this function so neither can drift from the other.
func ErrorClasses() []string {
	return append([]string(nil), errorClasses...)
}

// MCP server-family labels. The server SEGMENT of an MCP tool name is whatever
// the developer wrote in their own config (routinely a filename or a project
// codename), so it is never echoed: an action's category is one of these fixed
// family labels.
//
// They are CONSTANTS rather than literals in the node's mapping table because
// the mapping table's OUTPUTS and this vocabulary must be the same strings.
// Spelling them independently on each side is how "sentry → observability"
// quietly becomes "sentry → monitoring" — a label the hosted prompt never
// explains and the model has no way to read (A10).
const (
	MCPFamilyObserver      = "observer"
	MCPFamilyGitHub        = "github"
	MCPFamilyBrowser       = "browser"
	MCPFamilyPlaywright    = "playwright"
	MCPFamilyCloudflare    = "cloudflare"
	MCPFamilyFilesystem    = "filesystem"
	MCPFamilyDB            = "db"
	MCPFamilyTracker       = "tracker"
	MCPFamilyChat          = "chat"
	MCPFamilyDocs          = "docs"
	MCPFamilyObservability = "observability"
	MCPFamilyInfra         = "infra"
	MCPFamilyGit           = "git"
	MCPFamilyFetch         = "fetch"
	MCPFamilyMemory        = "memory"
	MCPFamilyTime          = "time"
)

// mcpFamilyLabels is the closed, ordered MCP server-family vocabulary.
// MCPFamilyFallback is the honest bucket for a server we do not know.
var mcpFamilyLabels = []string{
	MCPFamilyObserver, MCPFamilyGitHub, MCPFamilyBrowser, MCPFamilyPlaywright, MCPFamilyCloudflare,
	MCPFamilyFilesystem, MCPFamilyDB, MCPFamilyTracker, MCPFamilyChat, MCPFamilyDocs,
	MCPFamilyObservability, MCPFamilyInfra, MCPFamilyGit, MCPFamilyFetch, MCPFamilyMemory, MCPFamilyTime,
	MCPFamilyFallback,
}

// MCPFamilyFallback is the label an MCP call to an UNKNOWN server carries. It
// is honest ("an MCP call to some server") and, being a fixed string, cannot
// carry a user-authored server id.
const MCPFamilyFallback = "mcp"

// MCPFamilyLabels returns the closed MCP server-family vocabulary, in a stable
// order, with MCPFamilyFallback last.
func MCPFamilyLabels() []string {
	return append([]string(nil), mcpFamilyLabels...)
}

// Model-family labels. An envelope's `model_family` is one of these, never the
// local model string.
//
// WHY A CLOSED SET (A2). The local model string is not ours: it is whatever the
// tool recorded, which on a custom endpoint, a local Ollama tag, or a gateway
// alias is a developer-authored name ("acme-internal-llm-v3"). Shipping it
// verbatim under a field called "model_family" uploads a user string on the
// STRUCTURAL lane, which promises to upload none. A family label answers the
// only question the field is for — which model lineage ran — without carrying a
// byte the developer wrote.
const (
	ModelFamilyClaude   = "claude"
	ModelFamilyGPT      = "gpt"
	ModelFamilyOSeries  = "o-series"
	ModelFamilyGemini   = "gemini"
	ModelFamilyGemma    = "gemma"
	ModelFamilyLlama    = "llama"
	ModelFamilyQwen     = "qwen"
	ModelFamilyMistral  = "mistral"
	ModelFamilyDeepSeek = "deepseek"
	ModelFamilyGrok     = "grok"
	ModelFamilyPhi      = "phi"
	ModelFamilyKimi     = "kimi"
	ModelFamilyGLM      = "glm"
	ModelFamilyMiniMax  = "minimax"
	ModelFamilyNova     = "nova"
	ModelFamilyCohere   = "cohere"
	ModelFamilyGranite  = "granite"
	ModelFamilyFalcon   = "falcon"
	ModelFamilyYi       = "yi"
	// ModelFamilyUnknown is the honest bucket for a model this table does not
	// recognize — including a session that recorded no model at all.
	ModelFamilyUnknown = "unknown"
)

// modelFamilyLabels is the closed, ordered model-family vocabulary, with
// ModelFamilyUnknown last.
var modelFamilyLabels = []string{
	ModelFamilyClaude, ModelFamilyGPT, ModelFamilyOSeries, ModelFamilyGemini, ModelFamilyGemma,
	ModelFamilyLlama, ModelFamilyQwen, ModelFamilyMistral, ModelFamilyDeepSeek, ModelFamilyGrok,
	ModelFamilyPhi, ModelFamilyKimi, ModelFamilyGLM, ModelFamilyMiniMax, ModelFamilyNova,
	ModelFamilyCohere, ModelFamilyGranite, ModelFamilyFalcon, ModelFamilyYi,
	ModelFamilyUnknown,
}

// ModelFamilyLabels returns the closed model-family vocabulary, in a stable
// order, with ModelFamilyUnknown last.
func ModelFamilyLabels() []string {
	return append([]string(nil), modelFamilyLabels...)
}

// Context-excerpt source labels the node's selector emits and the hosted
// service dispatches on. Defined HERE (not in cloudevidence) because the
// server needs the one label that carries a consent meaning of its own:
// ExcerptSourceFirstUserPrompt is the single excerpt the narrowed
// first_user_prompt_excerpt field class authorizes under the STRUCTURAL
// purpose - every other source needs bounded_context_enrichment.
const (
	// ExcerptSourceFirstUserPrompt is the session's first real user prompt.
	ExcerptSourceFirstUserPrompt = "first_user_prompt"
	// ExcerptSourceUserPrompt is a later user prompt sampled across the session.
	ExcerptSourceUserPrompt = "user_prompt"
	// ExcerptSourceFinalAssistantMessage is the last assistant message.
	ExcerptSourceFinalAssistantMessage = "final_assistant_message"
	// ExcerptSourceErrorClass / ExcerptSourceErrorClassLast carry a closed
	// failure-class label plus a count, never message text.
	ExcerptSourceErrorClass     = "error_class"
	ExcerptSourceErrorClassLast = "error_class_last"
)
