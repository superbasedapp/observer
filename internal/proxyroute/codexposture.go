package proxyroute

import "strings"

// codexposture.go - does codex's SELECTED model provider actually reach the
// observer proxy? (post-Agent-Access backlog item 14.)
//
// Codex routes per model provider. The route observer writes
// (model_provider = "openai-observer" + its base_url, or the top-level
// openai_base_url that overrides the BUILT-IN openai provider) only captures
// a turn when the provider codex selects is one of those. A provider that
// resolves its own endpoint - the built-in amazon-bedrock provider, which
// signs requests with AWS SigV4 and sends them to Bedrock, or any provider
// whose base_url is some other host - leaves the proxy entirely: its turns
// are captured from codex's session log only, never proxy-exact.
//
// Grounding (2026-09-27): the codex config reference
// (learn.chatgpt.com/docs/config-file/config-reference) documents
// openai_base_url as the override "for the built-in OpenAI provider",
// model_providers.<id>.base_url for custom providers, and the built-in
// amazon-bedrock provider as configured by aws.profile / aws.region with no
// base_url; the codex app-server README documents Bedrock's AWS credential
// and region requests plus the Bedrock destination.

// CodexBuiltinOpenAI is codex's built-in OpenAI provider id (the default
// when model_provider is unset). openai_base_url overrides its endpoint.
const CodexBuiltinOpenAI = "openai"

// CodexBuiltinBedrock is codex's built-in Amazon Bedrock provider id.
const CodexBuiltinBedrock = "amazon-bedrock"

// The other built-in provider ids codex ships (vendor source
// codex-rs/model-provider-info/src/lib.rs, built_in_model_providers,
// re-grounded 2026-10-25 for surface-gap review CX-9). None has a base_url
// in the user's config, so each falls to a bypassing row; the ids only let
// the explanation say where the turns go.
const (
	// CodexBuiltinBedrockRuntime is the Amazon Bedrock Runtime provider: the
	// same SigV4-signed AWS path as amazon-bedrock.
	CodexBuiltinBedrockRuntime = "amazon-bedrock-runtime"
	// CodexBuiltinGCP is the Google Cloud Vertex AI provider.
	CodexBuiltinGCP = "gcp"
	// CodexBuiltinOllama and CodexBuiltinLMStudio are the local OSS
	// providers (localhost:11434 and localhost:1234).
	CodexBuiltinOllama   = "ollama"
	CodexBuiltinLMStudio = "lmstudio"
)

// CodexPosture classifies where codex's selected provider sends turns.
type CodexPosture string

const (
	// CodexPostureProxy: the selected provider routes to an observer proxy,
	// so turns are proxy-exact.
	CodexPostureProxy CodexPosture = "proxy"
	// CodexPostureUnrouted: the built-in openai provider with no base URL
	// override. Only an `observer codex` launch routes it; a plain `codex`
	// run goes direct.
	CodexPostureUnrouted CodexPosture = "unrouted"
	// CodexPostureBedrock: the built-in amazon-bedrock provider. Turns go
	// SigV4-signed to AWS; no base URL observer can own.
	CodexPostureBedrock CodexPosture = "bedrock"
	// CodexPostureDirect: the selected provider names a base URL that is not
	// an observer proxy.
	CodexPostureDirect CodexPosture = "direct"
	// CodexPostureSelfResolved: a provider with no base URL that is neither
	// openai nor amazon-bedrock - one codex resolves itself (e.g. a local
	// OSS provider). It does not reach the observer proxy.
	CodexPostureSelfResolved CodexPosture = "self_resolved"
)

// Bypasses reports whether turns under this posture never reach the
// observer proxy even when codex is launched through `observer codex`.
func (p CodexPosture) Bypasses() bool {
	switch p {
	case CodexPostureBedrock, CodexPostureDirect, CodexPostureSelfResolved:
		return true
	}
	return false
}

// CodexProviderInput is the routing-relevant slice of an EFFECTIVE codex
// configuration (base config.toml with any profile overlay already applied).
type CodexProviderInput struct {
	// Provider is model_provider; "" means codex's default (openai).
	Provider string
	// ProviderBaseURL is model_providers.<Provider>.base_url, "" when unset.
	ProviderBaseURL string
	// OpenAIBaseURL is the top-level openai_base_url, "" when unset.
	OpenAIBaseURL string
}

// codexPostureRule is one row of the ordered classification table.
type codexPostureRule struct {
	name    string
	match   func(in CodexProviderInput) bool
	posture CodexPosture
}

func isBuiltinOpenAI(in CodexProviderInput) bool {
	return in.Provider == "" || in.Provider == CodexBuiltinOpenAI
}

// codexPostureRules is walked top-down; the first match wins (CLAUDE.md #5).
var codexPostureRules = []codexPostureRule{
	{"openai_via_observer", func(in CodexProviderInput) bool {
		return isBuiltinOpenAI(in) && IsObserverBaseURL(in.OpenAIBaseURL)
	}, CodexPostureProxy},
	{"openai_elsewhere", func(in CodexProviderInput) bool {
		return isBuiltinOpenAI(in) && in.OpenAIBaseURL != ""
	}, CodexPostureDirect},
	{"openai_default", isBuiltinOpenAI, CodexPostureUnrouted},
	{"provider_via_observer", func(in CodexProviderInput) bool {
		return IsObserverBaseURL(in.ProviderBaseURL)
	}, CodexPostureProxy},
	{"bedrock", func(in CodexProviderInput) bool {
		return in.Provider == CodexBuiltinBedrock || in.Provider == CodexBuiltinBedrockRuntime
	}, CodexPostureBedrock},
	{"provider_elsewhere", func(in CodexProviderInput) bool {
		return in.ProviderBaseURL != ""
	}, CodexPostureDirect},
	{"provider_self_resolved", func(CodexProviderInput) bool { return true }, CodexPostureSelfResolved},
}

// ClassifyCodexProvider returns where codex's selected provider sends turns.
// Pure; values are trimmed before matching.
func ClassifyCodexProvider(in CodexProviderInput) CodexPosture {
	in.Provider = strings.TrimSpace(in.Provider)
	in.ProviderBaseURL = strings.TrimSpace(in.ProviderBaseURL)
	in.OpenAIBaseURL = strings.TrimSpace(in.OpenAIBaseURL)
	for _, r := range codexPostureRules {
		if r.match(in) {
			return r.posture
		}
	}
	return CodexPostureSelfResolved
}

// codexSelfResolvedWhere names where a built-in self-resolving provider
// sends turns, for the explanation only (the posture is the same row).
var codexSelfResolvedWhere = map[string]string{
	CodexBuiltinGCP:      "the built-in Google Cloud Vertex AI provider, which sends turns to Vertex AI with Google credentials",
	CodexBuiltinOllama:   "the built-in local Ollama provider, which sends turns to localhost:11434",
	CodexBuiltinLMStudio: "the built-in local LM Studio provider, which sends turns to localhost:1234",
}

// codexSessionLogOnly is the explanation tail every bypassing posture
// shares.
const codexSessionLogOnly = "codex tokens come from its session log only (not proxy-exact)"

// CodexBypassExplanation is the one-line, operator-facing reason a bypassing
// posture leaves the proxy. "" for a non-bypassing posture. provider is the
// selected provider id (for the message only).
func CodexBypassExplanation(p CodexPosture, provider string) string {
	id := displayProvider(provider)
	switch p {
	case CodexPostureBedrock:
		if id == CodexBuiltinOpenAI {
			id = CodexBuiltinBedrock
		}
		return "model_provider=\"" + id + "\" sends turns SigV4-signed straight to Amazon Bedrock; the observer proxy never sees them, so " + codexSessionLogOnly
	case CodexPostureDirect:
		return "model_provider=\"" + id + "\" points at a base URL that is not the observer proxy; its turns bypass the proxy and " + codexSessionLogOnly
	case CodexPostureSelfResolved:
		if where, ok := codexSelfResolvedWhere[id]; ok {
			return "model_provider=\"" + id + "\" is " + where + "; its turns bypass the observer proxy and " + codexSessionLogOnly
		}
		return "model_provider=\"" + id + "\" resolves its own endpoint (no base_url); its turns bypass the observer proxy and " + codexSessionLogOnly
	}
	return ""
}

func displayProvider(p string) string {
	if strings.TrimSpace(p) == "" {
		return CodexBuiltinOpenAI
	}
	return p
}
