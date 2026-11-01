package sandboxvocab

import "strings"

// providers.go is the model-provider host set of section 7.3: the hosts a
// sandboxed agent holding its own credential could call directly to skip
// the proxy. While a run claims or requires full capture on the internet
// tier, the egress gateway (internal/sandboxnet) refuses a CONNECT or
// absolute-form target whose host is one of these, or a subdomain of one,
// and every literal-IP target. The cmd layer adds the proxy's own
// configured upstream hosts ([proxy.upstreams]) to this closed list, so the
// set has one owner per source and the gateway never imports the proxy.
//
// The block is by host NAME. A second, narrower rule refuses a name whose
// resolved address equals a provider's address, but only for the rows
// marked DedicatedAddresses: hosts served from address ranges the provider
// owns. Most provider hosts sit on shared front ends (Google's
// googleapis.com front end serves proxy.golang.org, storage.googleapis.com
// and oauth2.googleapis.com from the same addresses as the Gemini API, and
// Cloudflare's anycast addresses serve chatgpt.com, openrouter.ai and many
// package registries alike), so an address match there would refuse
// ordinary go and npm traffic (lane sbx-p1a2, audit finding P-006 (1)).

// ProviderHost is one row of the closed provider list.
type ProviderHost struct {
	// Host is the API host name, lower case.
	Host string
	// DedicatedAddresses is true only when the host is served from address
	// ranges the provider owns, so a different name resolving to one of
	// those addresses is that provider. False for every host on a shared
	// front end (Google, Cloudflare and other CDNs).
	DedicatedAddresses bool
}

// modelProviderHosts are the major providers' API hosts. Only Anthropic's
// API is known to answer from the provider's own address block; every other
// row is a shared front end or unverified, and stays name-only (the
// conservative choice: a false address match refuses unrelated traffic).
var modelProviderHosts = []ProviderHost{
	{Host: "api.anthropic.com", DedicatedAddresses: true},
	{Host: "api.openai.com"},
	{Host: "chatgpt.com"},
	{Host: "generativelanguage.googleapis.com"},
	{Host: "aiplatform.googleapis.com"},
	{Host: "cloudcode-pa.googleapis.com"},
	{Host: "api.githubcopilot.com"},
	{Host: "openrouter.ai"},
	{Host: "api.mistral.ai"},
	{Host: "api.deepseek.com"},
	{Host: "api.x.ai"},
	{Host: "api.groq.com"},
	{Host: "api.together.xyz"},
	{Host: "api.fireworks.ai"},
	{Host: "api.cohere.com"},
	{Host: "api.cohere.ai"},
	{Host: "dashscope.aliyuncs.com"},
	{Host: "dashscope-intl.aliyuncs.com"},
	{Host: "api.moonshot.ai"},
	{Host: "api.moonshot.cn"},
	{Host: "open.bigmodel.cn"},
	{Host: "api.z.ai"},
}

// ModelProviderHosts returns a copy of the closed provider host names.
func ModelProviderHosts() []string {
	out := make([]string, 0, len(modelProviderHosts))
	for _, p := range modelProviderHosts {
		out = append(out, p.Host)
	}
	return out
}

// DedicatedAddressHosts returns the provider hosts whose resolved addresses
// identify the provider (the rows marked DedicatedAddresses).
func DedicatedAddressHosts() []string {
	var out []string
	for _, p := range modelProviderHosts {
		if p.DedicatedAddresses {
			out = append(out, p.Host)
		}
	}
	return out
}

// MatchesHost reports whether host is one of hosts or a subdomain of one.
// Both sides are compared case-insensitively with a trailing dot ignored;
// an empty host never matches.
func MatchesHost(host string, hosts []string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	for _, p := range hosts {
		p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if p == "" {
			continue
		}
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// ProviderDirect is the organization's posture on direct model-provider
// egress from a sandboxed internet run (operator ruling DEC-9, 2026-10-27,
// gap review OBS-8a). It is the node.governance pin
// terminal.sandbox.provider_direct, honoured only on a managed node; an
// individual node always computes ProviderDirectCaptureRule. The refusal
// itself is the egress gateway's provider-host block (section 7.3, ledger
// SBX-CAP-1); this value only decides when that one block is on.
type ProviderDirect string

// The closed ProviderDirect vocabulary.
const (
	// ProviderDirectRefuseAll: the gateway refuses the provider hosts in
	// every sandboxed internet run it enforces, beyond capture rule C6.
	ProviderDirectRefuseAll ProviderDirect = "refuse_all"
	// ProviderDirectCaptureRule: capture rule C6 alone decides (the
	// default, and what an empty value means).
	ProviderDirectCaptureRule ProviderDirect = "capture_rule"
	// ProviderDirectAllow: no provider-host refusal; a run whose full
	// capture depended on the block reads proxy_and_transcripts instead.
	ProviderDirectAllow ProviderDirect = "allow"
)

// ProviderDirects returns the closed vocabulary, strictest first.
func ProviderDirects() []ProviderDirect {
	return []ProviderDirect{ProviderDirectRefuseAll, ProviderDirectCaptureRule, ProviderDirectAllow}
}

// Valid reports whether p is in the closed vocabulary ("" is not; it
// normalizes to ProviderDirectCaptureRule through Normalize).
func (p ProviderDirect) Valid() bool {
	for _, v := range ProviderDirects() {
		if p == v {
			return true
		}
	}
	return false
}

// Normalize returns p, or ProviderDirectCaptureRule for "" or an unknown
// value (the conservative reading: today's behaviour).
func (p ProviderDirect) Normalize() ProviderDirect {
	if p.Valid() {
		return p
	}
	return ProviderDirectCaptureRule
}
