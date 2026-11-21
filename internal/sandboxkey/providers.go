package sandboxkey

import (
	"slices"
	"strings"
)

// AuthForm is how a provider's API takes its key.
type AuthForm string

// The closed AuthForm vocabulary.
const (
	// AuthXAPIKey: the key in an x-api-key header.
	AuthXAPIKey AuthForm = "x-api-key"
	// AuthBearer: the key as "Authorization: Bearer <key>".
	AuthBearer AuthForm = "bearer"
	// AuthGoogKey: the key in an x-goog-api-key header.
	AuthGoogKey AuthForm = "x-goog-api-key"
)

// Header is the request header the form puts the key in.
func (a AuthForm) Header() string {
	switch a {
	case AuthBearer:
		return "Authorization"
	case AuthGoogKey:
		return "X-Goog-Api-Key"
	}
	return "X-Api-Key"
}

// Value renders the header value for key.
func (a AuthForm) Value(key string) string {
	if a == AuthBearer {
		return "Bearer " + key
	}
	return key
}

// Provider is one model provider injection can serve: its model host (the
// one host the real key is ever sent to), its auth form, the variable a
// tool reads its key from, the API reference that documents the form,
// every variable that carries a credential for it (CredEnv, KeyEnv among
// them: the credential table boxEnvRules reads), and the API-key variables
// an in-box custody copies into a box (InBoxEnv: plain API keys only, never
// a file path, a login token or a refresh token).
type Provider struct {
	ID       string
	Host     string
	Auth     AuthForm
	KeyEnv   string
	Docs     string
	KeyLabel string
	CredEnv  []string
	InBoxEnv []string
}

// providers is the table (provider family ids as internal/integration's
// model catalogue names them). Each auth form is the provider's own API
// reference's.
var providers = []Provider{
	{
		ID: "anthropic", Host: "api.anthropic.com", Auth: AuthXAPIKey, KeyEnv: "ANTHROPIC_API_KEY",
		Docs: "https://docs.anthropic.com/en/api/overview", KeyLabel: "Anthropic API key",
		// Every Anthropic credential variable Claude Code reads (the
		// agentconfig catalog marks each Secret; audit FU3-A2): the bearer
		// token it sends in place of the key, its subscription OAuth
		// tokens, and the Foundry, Claude Platform on AWS and Bedrock keys.
		CredEnv: []string{
			"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
			"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
			"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
			"ANTHROPIC_AWS_API_KEY", "AWS_BEARER_TOKEN_BEDROCK",
		},
		// The plain API key only: the bearer and OAuth tokens are a login
		// (in_box_oauth_seed, not built), and the Foundry, AWS and Bedrock
		// keys belong to another platform's account.
		InBoxEnv: []string{"ANTHROPIC_API_KEY"},
	},
	{
		ID: "openai", Host: "api.openai.com", Auth: AuthBearer, KeyEnv: "OPENAI_API_KEY",
		Docs: "https://platform.openai.com/docs/api-reference/authentication", KeyLabel: "OpenAI API key",
		CredEnv:  []string{"OPENAI_API_KEY"},
		InBoxEnv: []string{"OPENAI_API_KEY"},
	},
	{
		ID: "google", Host: "generativelanguage.googleapis.com", Auth: AuthGoogKey, KeyEnv: "GEMINI_API_KEY",
		Docs: "https://ai.google.dev/gemini-api/docs/api-key", KeyLabel: "Gemini API key",
		// GOOGLE_API_KEY and GOOGLE_APPLICATION_CREDENTIALS (a service
		// account key file): the Gemini CLI's other credential variables
		// (its integration row's AuthEnv).
		CredEnv: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"},
		// Both API key variables; never GOOGLE_APPLICATION_CREDENTIALS, a
		// path to a key file on this machine that means nothing in a box.
		InBoxEnv: []string{"GEMINI_API_KEY", "GOOGLE_API_KEY"},
	},
	{
		ID: "xai", Host: "api.x.ai", Auth: AuthBearer, KeyEnv: "XAI_API_KEY",
		Docs: "https://docs.x.ai/docs/api-reference", KeyLabel: "xAI API key",
		CredEnv:  []string{"XAI_API_KEY"},
		InBoxEnv: []string{"XAI_API_KEY"},
	},
	{
		ID: "openrouter", Host: "openrouter.ai", Auth: AuthBearer, KeyEnv: "OPENROUTER_API_KEY",
		Docs: "https://openrouter.ai/docs/api-reference/authentication", KeyLabel: "OpenRouter API key",
		CredEnv:  []string{"OPENROUTER_API_KEY"},
		InBoxEnv: []string{"OPENROUTER_API_KEY"},
	},
}

// Providers returns the table (a copy).
func Providers() []Provider { return append([]Provider(nil), providers...) }

// ProviderFor returns the provider row for id.
func ProviderFor(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// ProviderForHost returns the provider whose model host is host (a
// trailing dot and the letter case ignored).
func ProviderForHost(host string) (Provider, bool) {
	for _, p := range providers {
		if hostIs(host, p.Host) {
			return p, true
		}
	}
	return Provider{}, false
}

// hostIs reports whether host names want (a trailing dot and the letter
// case ignored; a look-alike suffix never matches).
func hostIs(host, want string) bool {
	return want != "" && strings.EqualFold(strings.TrimSuffix(host, "."), want)
}

// HostIs is hostIs for the injection matcher (internal/sandboxcred), which
// judges a request's destination host the same way.
func HostIs(host, want string) bool { return hostIs(host, want) }

// InBoxKeyEnv is every API-key variable an in-box custody may copy into a
// box, in table order (the one owner of that list: each provider's
// InBoxEnv).
func InBoxKeyEnv() []string {
	var out []string
	for _, p := range providers {
		out = append(out, p.InBoxEnv...)
	}
	return out
}

// InBoxEnvProvider is the provider an in-box API-key variable belongs to
// ("" when name is none of them).
func InBoxEnvProvider(name string) string {
	for _, p := range providers {
		if slices.Contains(p.InBoxEnv, name) {
			return p.ID
		}
	}
	return ""
}

// CredEnvProvider is the provider a credential variable belongs to ("" when
// the credential table does not class name).
func CredEnvProvider(name string) string {
	for _, p := range providers {
		if slices.Contains(p.CredEnv, name) {
			return p.ID
		}
	}
	return ""
}

// Known keeps the ids of ids the table carries, in table order, each once.
func Known(ids []string) []string {
	var out []string
	for _, p := range providers {
		if slices.Contains(ids, p.ID) {
			out = append(out, p.ID)
		}
	}
	return out
}

// allIDs is every provider id, in table order.
func allIDs() []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.ID)
	}
	return out
}

// Intersect keeps the ids of a that the table carries and b holds, in
// table order.
func Intersect(a, b []string) []string {
	var out []string
	for _, id := range Known(a) {
		if slices.Contains(b, id) {
			out = append(out, id)
		}
	}
	return out
}

// ProviderLabels names ids for a person ("Anthropic API key", "Anthropic
// API key and OpenAI API key"), joined with conj ("and" or "or").
func ProviderLabels(ids []string, conj string) string {
	labels := make([]string, 0, len(ids))
	for _, id := range ids {
		labels = append(labels, providerKeyLabel(id))
	}
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	}
	return strings.Join(labels[:len(labels)-1], ", ") + " " + conj + " " + labels[len(labels)-1]
}

// KeyName is the keystore entry name of a provider's key.
func KeyName(provider string) string { return "provider:" + provider }

// KeystoreService is the keystore service the user's provider keys live
// under.
const KeystoreService = "sbo-sandbox-cred-v1"
