package inference

import "strings"

// Dialect selects the provider API surface a route speaks. It is stored on
// route_registry.dialect (the CHECK constraint there is the SQL mirror of the
// dialect table below).
type Dialect string

const (
	// DialectChatCompletions is the Azure AI Foundry (Azure OpenAI-compatible)
	// stateless Chat Completions dialect.
	DialectChatCompletions Dialect = "chat_completions"
	// DialectResponsesStoreFalse is the Azure Responses API with store:false
	// forced. It stays dark without an operator verification record.
	DialectResponsesStoreFalse Dialect = "responses_store_false"
	// DialectAnthropicMessages is the Anthropic Messages API (POST
	// /v1/messages), one stateless call with strict structured output.
	DialectAnthropicMessages Dialect = "anthropic_messages"
	// DialectOpenAICompatible is the OpenAI chat-completions wire served by
	// OVH AI Endpoints and other compatible servers (POST {base}/chat/completions).
	// The wire code is internal/llmwire. It needs the route registry CHECK
	// widened (cloud migration 0045, E1.3) before a route can store it.
	DialectOpenAICompatible Dialect = "openai_compatible"
)

// Family names the provider (and therefore the credential) behind a dialect.
type Family string

const (
	// FamilyFoundry is Azure AI Foundry.
	FamilyFoundry Family = "foundry"
	// FamilyAnthropic is the Anthropic API.
	FamilyAnthropic Family = "anthropic"
	// FamilyOpenAICompatible is any OpenAI-compatible endpoint (OVH AI Endpoints).
	FamilyOpenAICompatible Family = "openai_compatible"
)

// Attestation names how a family's provider posture can be attested before a
// real-evidence call is authorized.
type Attestation string

const (
	// AttestationContentLogging: the provider exposes (or an operator can
	// assert) the Azure ContentLogging capability. The live ARM canary, the
	// operator-attested mode and the disclosed mode all apply.
	AttestationContentLogging Attestation = "content_logging"
	// AttestationDisclosedOnly: no machine-readable provider-retention
	// attestation exists for this provider. ONLY the disclosed mode
	// (attest.ModeProviderRetentionDisclosed) may authorize it, and its
	// verdict must say that nothing about provider-side retention was
	// verified.
	AttestationDisclosedOnly Attestation = "disclosed_only"
)

// DialectSpec is one row of the dialect capability table. Callers branch on
// these fields, never on a dialect or provider name.
type DialectSpec struct {
	Dialect Dialect
	Family  Family
	// RequiresVerificationRecord: the execution lease refuses the dialect
	// unless a live operator dialect-verification record binds the exact route
	// snapshot (plan 2.3, FA5).
	RequiresVerificationRecord bool
	// DeploymentIsModelID: route.deployment is the provider's public model id,
	// so the call can be priced from the shared pricing table by that id.
	DeploymentIsModelID bool
	// Attestation is how the family's provider posture is attested.
	Attestation Attestation
	// NeedsAPIVersion: a route of this dialect is callable only with an
	// api_version on its binding (Foundry's api-version query parameter, the
	// Anthropic-Version header). The openai_compatible dialect has none, so a
	// bound route of it carries an empty api_version.
	NeedsAPIVersion bool
}

// dialectTable is the closed set of dialects the service can execute. A
// dialect absent from it is unsupported everywhere (fail closed).
var dialectTable = []DialectSpec{
	{Dialect: DialectChatCompletions, Family: FamilyFoundry, Attestation: AttestationContentLogging, NeedsAPIVersion: true},
	{Dialect: DialectResponsesStoreFalse, Family: FamilyFoundry, RequiresVerificationRecord: true, Attestation: AttestationContentLogging, NeedsAPIVersion: true},
	{Dialect: DialectAnthropicMessages, Family: FamilyAnthropic, DeploymentIsModelID: true, Attestation: AttestationDisclosedOnly, NeedsAPIVersion: true},
	{Dialect: DialectOpenAICompatible, Family: FamilyOpenAICompatible, DeploymentIsModelID: true, Attestation: AttestationDisclosedOnly},
}

// SpecFor returns the capability row for a stored dialect string.
func SpecFor(dialect string) (DialectSpec, bool) {
	for _, s := range dialectTable {
		if string(s.Dialect) == dialect {
			return s, true
		}
	}
	return DialectSpec{}, false
}

// Dialects returns a copy of the dialect table, in table order.
func Dialects() []DialectSpec {
	return append([]DialectSpec(nil), dialectTable...)
}

// DialectsOf returns the dialects a family speaks, in table order.
func DialectsOf(f Family) []Dialect {
	var out []Dialect
	for _, s := range dialectTable {
		if s.Family == f {
			out = append(out, s.Dialect)
		}
	}
	return out
}

// ParseFamily resolves a configured provider name (case-insensitive) against
// the families the dialect table knows.
func ParseFamily(s string) (Family, bool) {
	want := Family(strings.ToLower(strings.TrimSpace(s)))
	for _, spec := range dialectTable {
		if spec.Family == want {
			return want, true
		}
	}
	return "", false
}

// Attestation returns how the family's provider posture is attested ("" for
// a family the table does not know).
func (f Family) Attestation() Attestation {
	for _, s := range dialectTable {
		if s.Family == f {
			return s.Attestation
		}
	}
	return ""
}
