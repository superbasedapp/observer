package sandboxvocab

import (
	"slices"
	"strings"
)

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
	// Lane FU8 (ledger OSH-43, sweep E3): direct model endpoints an
	// allow-list can plausibly open. A row matches the host and every name
	// below it, so the Azure rows cover each resource's own subdomain
	// (<resource>.openai.azure.com, <resource>.services.ai.azure.com,
	// <resource>.cognitiveservices.azure.com, the serverless
	// <endpoint>.<region>.models.ai.azure.com and the managed online
	// endpoints <endpoint>.<region>.inference.ml.azure.com).
	{Host: "api.perplexity.ai"},
	{Host: "api.cerebras.ai"},
	{Host: "models.github.ai"},
	{Host: "openai.azure.com"},
	{Host: "services.ai.azure.com"},
	{Host: "cognitiveservices.azure.com"},
	{Host: "inference.ai.azure.com"},
	{Host: "models.ai.azure.com"},
	{Host: "inference.ml.azure.com"},
	{Host: "prediction.vertexai.goog"},
}

// providerLabel is one label rule of a ProviderPattern. Exactly one field
// is set.
type providerLabel struct {
	// family: the label is the family name or starts with it and a dash
	// ("bedrock", "bedrock-runtime", "bedrock-agent-runtime-fips").
	family string
	// suffix: the label ends with suffix and has something before it
	// ("us-central1-aiplatform" for "-aiplatform").
	suffix string
	// region: the label has the shape of an AWS region (us-east-1,
	// ap-southeast-2, us-gov-west-1, cn-north-1).
	region bool
}

// match reports whether one DNS label satisfies the rule.
func (l providerLabel) match(label string) bool {
	switch {
	case l.family != "":
		return label == l.family || strings.HasPrefix(label, l.family+"-")
	case l.suffix != "":
		return len(label) > len(l.suffix) && strings.HasSuffix(label, l.suffix)
	case l.region:
		return awsRegionLabel(label)
	}
	return false
}

// awsRegionLabel reports whether label looks like an AWS region: two
// letters, one or more letter groups, then a number (us-east-1,
// us-gov-west-1, ap-southeast-2).
func awsRegionLabel(label string) bool {
	parts := strings.Split(label, "-")
	if len(parts) < 3 || len(parts[0]) != 2 {
		return false
	}
	for i, p := range parts {
		if p == "" {
			return false
		}
		for j := 0; j < len(p); j++ {
			c := p[j]
			last := i == len(parts)-1
			if last && (c < '0' || c > '9') || !last && (c < 'a' || c > 'z') {
				return false
			}
		}
	}
	return true
}

// ProviderPattern is a provider host family a plain host row cannot name
// because the varying part sits inside a label or between fixed labels:
// Vertex AI's regional hosts (<region>-aiplatform.googleapis.com) and
// Bedrock's regional hosts (bedrock-runtime.<region>.amazonaws.com). A host
// matches when it ends with Parent and the labels left of Parent, read from
// the right, satisfy Labels in order; any further labels on the left are a
// subdomain and match too (the host rows' rule).
type ProviderPattern struct {
	// Name is the family as the refusal names it.
	Name string
	// Parent is the fixed domain the family lives under.
	Parent string
	labels []providerLabel
}

// modelProviderPatterns are the closed list's family rows (lane FU8, ledger
// OSH-43). Every consumer of the closed list reaches them through
// MatchesProvider and ProviderOverlap, so sandboxnet and the OpenShell
// compiler read one table.
var modelProviderPatterns = []ProviderPattern{
	{Name: "<region>-aiplatform.googleapis.com", Parent: "googleapis.com", labels: []providerLabel{{suffix: "-aiplatform"}}},
	{Name: "bedrock*.<region>.amazonaws.com", Parent: "amazonaws.com", labels: []providerLabel{{region: true}, {family: "bedrock"}}},
	{Name: "bedrock*.<region>.vpce.amazonaws.com", Parent: "vpce.amazonaws.com", labels: []providerLabel{{region: true}, {family: "bedrock"}}},
	{Name: "bedrock*.<region>.amazonaws.com.cn", Parent: "amazonaws.com.cn", labels: []providerLabel{{region: true}, {family: "bedrock"}}},
}

// ProviderPatternNames returns the family rows' names, in table order.
func ProviderPatternNames() []string {
	out := make([]string, len(modelProviderPatterns))
	for i, p := range modelProviderPatterns {
		out[i] = p.Name
	}
	return out
}

// normHost lower-cases host and drops surrounding space and a trailing dot.
func normHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// relLabels returns the labels of name left of parent, nearest first, and
// whether name is strictly below parent.
func relLabels(name, parent string) ([]string, bool) {
	rest, ok := strings.CutSuffix(name, "."+parent)
	if !ok || rest == "" {
		return nil, false
	}
	labels := strings.Split(rest, ".")
	slices.Reverse(labels)
	return labels, true
}

// matches reports whether host is in the family (host already normalized).
func (p ProviderPattern) matches(host string) bool {
	rel, ok := relLabels(host, p.Parent)
	if !ok || len(rel) < len(p.labels) {
		return false
	}
	for i, l := range p.labels {
		if !l.match(rel[i]) {
			return false
		}
	}
	return true
}

// coveredBy reports whether some name below name (a "*.<name>" wildcard's
// names) is in the family: name is the parent or above it, or name is below
// the parent and its labels so far fit the rules (more labels can complete
// the match).
func (p ProviderPattern) coveredBy(name string) bool {
	if name == p.Parent || strings.HasSuffix(p.Parent, "."+name) {
		return true
	}
	rel, ok := relLabels(name, p.Parent)
	if !ok {
		return false
	}
	for i := 0; i < len(rel) && i < len(p.labels); i++ {
		if !p.labels[i].match(rel[i]) {
			return false
		}
	}
	return true
}

// MatchesProvider reports whether host is a model provider's: one of hosts
// (the closed list plus any extra hosts the caller adds) or a subdomain of
// one (MatchesHost), or a member of a family row (ProviderPattern). It is
// the one host test every egress owner applies.
func MatchesProvider(host string, hosts []string) bool {
	if MatchesHost(host, hosts) {
		return true
	}
	h := normHost(host)
	if h == "" {
		return false
	}
	for _, p := range modelProviderPatterns {
		if p.matches(h) {
			return true
		}
	}
	return false
}

// ProviderOverlap reports the provider an allow-list entry reaches, for a
// compiler that turns the entry into a rule (the OpenShell row): an exact
// entry that is a provider host, below one or in a family; or a "*.<name>"
// wildcard whose names include a provider host, a name below one or a
// member of a family (so "*.amazonaws.com" and "*.azure.com" are refused:
// they cover a provider family). hosts is the closed list plus the
// caller's extra hosts. The result names the host or the family row.
func ProviderOverlap(entry string, hosts []string) (string, bool) {
	e := normHost(entry)
	name, wildcard := strings.CutPrefix(e, "*.")
	if name == "" {
		return "", false
	}
	for _, p := range hosts {
		p = normHost(p)
		if p == "" {
			continue
		}
		// The entry's names are at or below a provider host.
		if MatchesHost(name, []string{p}) {
			return p, true
		}
		// A wildcard's names include the provider host (p below name).
		if wildcard && strings.HasSuffix(p, "."+name) {
			return p, true
		}
	}
	for _, p := range modelProviderPatterns {
		if p.matches(name) || wildcard && p.coveredBy(name) {
			return p.Name, true
		}
	}
	return "", false
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
