package aigateway

import "strings"

// ProviderKind is an upstream's wire/auth family. The string values are the
// EXACT llmprovider vocabulary (internal/orgserver/llmprovider): the core
// carries them as plain strings so it need not import the org package, and
// provider_drift_test.go pins that these literals equal the llmprovider
// constants — a rename on either side fails loudly.
type ProviderKind string

const (
	// KindOpenAICompatible carries OpenRouter/Gemini-compat/Groq/Mistral/
	// DeepSeek/xAI/local behind the OpenAI chat/responses wire.
	KindOpenAICompatible ProviderKind = "openai_compatible"
	// KindAnthropic is the Anthropic Messages wire.
	KindAnthropic ProviderKind = "anthropic"
	// KindOpenRouter is OpenRouter's OpenAI-compatible surface.
	KindOpenRouter ProviderKind = "openrouter"
	// KindAzureOpenAI is Azure OpenAI (needs an api_version).
	KindAzureOpenAI ProviderKind = "azure_openai"
	// KindLocal is a self-hosted OpenAI-compatible endpoint.
	KindLocal ProviderKind = "local"
	// KindCustom is an explicitly OpenAI-chat-compatible custom endpoint.
	KindCustom ProviderKind = "custom"
)

// Parser is the response/stream parser a kind binds to. Lane→kind binding
// replaces path-sniffing when the kind is known (design §2.5): a declared kind
// selects its parser directly, fixing the today-bug where an Azure/Bedrock-
// shaped lane URL falls through to the Anthropic default and is parsed wrong.
type Parser int

const (
	// ParserUnsupported means no gateway-native parser exists for this kind
	// yet — the pluggable adapter contract is gateway v2 (§2.5 HG6). The
	// gateway refuses such a lane rather than guessing a parser.
	ParserUnsupported Parser = iota
	// ParserAnthropic parses the Anthropic Messages SSE/JSON.
	ParserAnthropic
	// ParserOpenAI parses the OpenAI chat/responses SSE/JSON (covers every
	// openai_compatible-family kind).
	ParserOpenAI
)

// parserForKind is the table-driven binding (CLAUDE.md rule #5). azure_openai
// speaks the OpenAI wire with a version-stamped URL, so it binds ParserOpenAI;
// only genuinely unknown/native protocols (native Bedrock/Vertex generateContent)
// remain ParserUnsupported until v2.
var parserForKind = map[ProviderKind]Parser{
	KindOpenAICompatible: ParserOpenAI,
	KindOpenRouter:       ParserOpenAI,
	KindAzureOpenAI:      ParserOpenAI,
	KindLocal:            ParserOpenAI,
	KindCustom:           ParserOpenAI,
	KindAnthropic:        ParserAnthropic,
}

// ParserForKind returns the parser bound to kind, and false when the kind is
// unknown or has no native parser. A caller that gets false must refuse the
// lane — never fall through to a default parser (that is exactly the
// wrong-parser-fallthrough bug this binding closes).
func ParserForKind(kind ProviderKind) (Parser, bool) {
	p, ok := parserForKind[ProviderKind(strings.ToLower(strings.TrimSpace(string(kind))))]
	if !ok || p == ParserUnsupported {
		return ParserUnsupported, false
	}
	return p, true
}

// ValidKind reports whether kind is one of the six closed wire kinds.
func ValidKind(kind ProviderKind) bool {
	_, ok := parserForKind[ProviderKind(strings.ToLower(strings.TrimSpace(string(kind))))]
	return ok
}

// Upstream is a registered gateway upstream (the org's own provider account).
// The credential is referenced ONLY by SecretRef (a secretref "store:<id>" /
// "env:NAME" / "file:/path" string) — never held here — so custody is
// structural: this struct can be logged in full without leaking a key.
type Upstream struct {
	UpstreamID string
	OrgID      string
	Name       string
	Kind       ProviderKind
	BaseURL    string
	APIVersion string // required for azure_openai

	// SecretRef points at the sealed org credential. Resolved in-memory in the
	// dialer, never persisted in a request log (design §2.3).
	SecretRef string

	CredentialMode CredentialMode
	DataControl    DataControl

	// AllowPrivateNetwork lets a self-hosted `local` upstream target an
	// RFC1918 address; every other kind is SSRF-guarded to public hosts.
	AllowPrivateNetwork bool

	Enabled bool
}

// Normalize fills defaults and coerces the closed-vocabulary fields so an
// admin-supplied upstream is always in a known state. It does not validate the
// URL or secret ref — that is the store/dialer's job with the SSRF guard.
func (u Upstream) Normalize() Upstream {
	u.Kind = ProviderKind(strings.ToLower(strings.TrimSpace(string(u.Kind))))
	u.CredentialMode = NormalizeCredentialMode(u.CredentialMode)
	u.DataControl = NormalizeDataControl(u.DataControl)
	return u
}

// PseudonymousMemberID derives the stable, non-reversible member identifier
// the gateway stamps on every upstream call that has a field for it
// (metadata.user_id / safety_identifier / Azure user — ToS research finding
// 7). It is the blast-radius limiter when a provider's abuse detection fires
// on multiplexed org traffic: the org can be told WHICH member's traffic
// tripped it without exposing the member's real identity to the provider.
//
// It is HashVirtualKey-style (SHA-256 hex) over the org+user pair so the same
// member maps to the same pseudonym across calls but the value reveals neither
// the email nor the user id. Truncated to 32 hex chars — ample to avoid
// collision within one org, short enough for a header value.
func PseudonymousMemberID(orgID, userID string) string {
	if strings.TrimSpace(userID) == "" {
		return ""
	}
	return HashVirtualKey(orgID + "\x00" + userID)[:32]
}
