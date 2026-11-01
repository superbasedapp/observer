package sandboxcred

import "strings"

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
// tool reads its key from, and the API reference that documents the form.
type Provider struct {
	ID       string
	Host     string
	Auth     AuthForm
	KeyEnv   string
	Docs     string
	KeyLabel string
}

// providers is the table (provider family ids as internal/integration's
// model catalogue names them). Each auth form is the provider's own API
// reference's.
var providers = []Provider{
	{
		ID: "anthropic", Host: "api.anthropic.com", Auth: AuthXAPIKey, KeyEnv: "ANTHROPIC_API_KEY",
		Docs: "https://docs.anthropic.com/en/api/overview", KeyLabel: "Anthropic API key",
	},
	{
		ID: "openai", Host: "api.openai.com", Auth: AuthBearer, KeyEnv: "OPENAI_API_KEY",
		Docs: "https://platform.openai.com/docs/api-reference/authentication", KeyLabel: "OpenAI API key",
	},
	{
		ID: "google", Host: "generativelanguage.googleapis.com", Auth: AuthGoogKey, KeyEnv: "GEMINI_API_KEY",
		Docs: "https://ai.google.dev/gemini-api/docs/api-key", KeyLabel: "Gemini API key",
	},
	{
		ID: "xai", Host: "api.x.ai", Auth: AuthBearer, KeyEnv: "XAI_API_KEY",
		Docs: "https://docs.x.ai/docs/api-reference", KeyLabel: "xAI API key",
	},
	{
		ID: "openrouter", Host: "openrouter.ai", Auth: AuthBearer, KeyEnv: "OPENROUTER_API_KEY",
		Docs: "https://openrouter.ai/docs/api-reference/authentication", KeyLabel: "OpenRouter API key",
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

// ProviderForTool picks the one provider a tool's model catalogue names
// (the tool's own capability row, never its name): a vendor-locked tool
// with exactly one provider family; "" otherwise.
func ProviderForTool(vendorLocked bool, families []string) string {
	if !vendorLocked || len(families) != 1 {
		return ""
	}
	if p, ok := ProviderFor(families[0]); ok {
		return p.ID
	}
	return ""
}

// KeyName is the keystore entry name of a provider's key.
func KeyName(provider string) string { return "provider:" + provider }

// KeystoreService is the keystore service the user's provider keys live
// under.
const KeystoreService = "sbo-sandbox-cred-v1"
