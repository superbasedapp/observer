package ownagent

import (
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// OTLP claim (PT-55, phase 2; docs/own-agents.md "Send OpenTelemetry
// spans"): a developer's own agent can also report through the node's OTLP
// receiver instead of (or beside) the proxy. The resource that carries the
// agent identity attribute is Plane B (the coding-agent plane, the node
// dashboard); a resource that carries a hosted-app identity is Plane A
// (internal/obs) and is never claimed here. The decision is one ordered
// table, OTLPClaimRules, walked top-down per resource; this file only turns
// plain facts the caller resolved into a plane, so it stays pure.

// ResourceAttr is the OpenTelemetry RESOURCE attribute that names the agent,
// the span-side twin of the AgentHeader request header. Its value goes
// through NormalizeName exactly like the header's, so "My Bot" sent as a
// header and as OTEL_RESOURCE_ATTRIBUTES=sbo.agent=My%20Bot is one agent.
const ResourceAttr = "sbo.agent"

// HostedAppAttrs are the attributes that identify a hosted application's
// tenant or END USER: exactly the identity keys Plane A reads
// (otelident.HostedAppKeys, the one owner internal/obs/ingest also uses).
// Any one of them on the resource, or on any record inside it, makes the
// resource a hosted app's: it is never claimed into Plane B, even when it
// also names an agent. That includes the generic "tenant", "user" and
// "user.id": Plane A attributes a trace to an end user by them, so an own
// agent must not set them (docs/own-agents.md).
var HostedAppAttrs = otelident.HostedAppKeys()

// OTLPResource is what the receiver resolved about one OTLP resource before
// any of its records are read.
type OTLPResource struct {
	// Echo: the resource is Observer's own export (sbo.emitted_by).
	Echo bool
	// CodingTool is the registry tool a coding-tool mapping row claims the
	// resource for by its service.name ("" when none does, or when the
	// caller has no mapping table in this build).
	CodingTool string
	// Hosted: a HostedAppAttrs key is present on the resource or on any of
	// its records.
	Hosted bool
	// AgentRaw is the raw ResourceAttr value; AgentPresent says whether the
	// attribute was set at all (a present but empty value is malformed, not
	// absent).
	AgentRaw     string
	AgentPresent bool
}

// OTLPPlane is where a resource's records go.
type OTLPPlane int

// Planes. The zero value is OTLPUnclaimed so a missing decision never
// claims anything.
const (
	// OTLPUnclaimed: no Plane B row claims the resource. Its spans go to the
	// Plane A trace handler when one runs (otherwise they are dropped), and
	// its logs are read only by the event-name rows (Claude Code).
	OTLPUnclaimed OTLPPlane = iota
	// OTLPCodingTool: a coding-tool mapping row claims it by service.name.
	OTLPCodingTool
	// OTLPOwnAgent: the developer's own agent, tool custom-agent.
	OTLPOwnAgent
	// OTLPDropped: the resource names an own agent but the name is
	// malformed. It reaches neither plane: a resource that asked to be the
	// developer's own agent is never handed to the hosted-app plane.
	OTLPDropped
)

// String names the plane for logs and test failures.
func (p OTLPPlane) String() string {
	switch p {
	case OTLPCodingTool:
		return "coding-tool"
	case OTLPOwnAgent:
		return "own-agent"
	case OTLPDropped:
		return "dropped"
	default:
		return "unclaimed"
	}
}

// PlaneB reports whether the plane is one of the node's Plane B claims.
func (p OTLPPlane) PlaneB() bool { return p == OTLPCodingTool || p == OTLPOwnAgent }

// KeptFromPlaneA reports whether a resource with this plane must never reach
// the Plane A trace handler: every plane except OTLPUnclaimed.
func (p OTLPPlane) KeptFromPlaneA() bool { return p != OTLPUnclaimed }

// OTLPClaim is the decision for one resource.
type OTLPClaim struct {
	Plane OTLPPlane
	// Agent is the normalized agent name (OTLPOwnAgent only).
	Agent string
	// Rule names the table row that decided, for logs and tests.
	Rule string
}

// otlpClaimRule is one row of the ordered claim table.
type otlpClaimRule struct {
	name string
	when func(in OTLPResource) bool
	then func(in OTLPResource) OTLPClaim
}

// OTLPClaimRules is the ordered claim table, walked top-down; the first row
// whose condition holds decides.
//
//  1. echo: Observer's own export is never read back as Plane B data (it
//     keeps its existing route).
//  2. coding-tool: a registered coding tool's service.name wins over the
//     agent attribute, as an existing identity wins over the agent header on
//     the proxy (phase 1, docs/security.md OWNAGENT-1), so a header or
//     attribute can never move a governed tool's data off that tool.
//  3. hosted-app: a tenant or end-user identity marks a hosted application
//     (Plane A). It is never claimed into Plane B, even with an agent name:
//     a hosted app's end-user data must not land on the developer plane.
//  4. own-agent: a well-formed agent name claims the resource for the
//     developer's own agent.
//  5. malformed: an agent attribute that does not normalize drops the
//     resource from both planes.
//  6. default: unclaimed, exactly as before phase 2.
var otlpClaimRules = []otlpClaimRule{
	{
		name: "echo",
		when: func(in OTLPResource) bool { return in.Echo },
		then: func(OTLPResource) OTLPClaim { return OTLPClaim{Plane: OTLPUnclaimed} },
	},
	{
		name: "coding-tool",
		when: func(in OTLPResource) bool { return in.CodingTool != "" },
		then: func(OTLPResource) OTLPClaim { return OTLPClaim{Plane: OTLPCodingTool} },
	},
	{
		name: "hosted-app",
		when: func(in OTLPResource) bool { return in.Hosted },
		then: func(OTLPResource) OTLPClaim { return OTLPClaim{Plane: OTLPUnclaimed} },
	},
	{
		name: "own-agent",
		when: func(in OTLPResource) bool {
			_, st := NormalizeName(in.AgentRaw)
			return in.AgentPresent && st == StatusOK
		},
		then: func(in OTLPResource) OTLPClaim {
			name, _ := NormalizeName(in.AgentRaw)
			return OTLPClaim{Plane: OTLPOwnAgent, Agent: name}
		},
	},
	{
		name: "malformed",
		when: func(in OTLPResource) bool { return in.AgentPresent },
		then: func(OTLPResource) OTLPClaim { return OTLPClaim{Plane: OTLPDropped} },
	},
	{
		name: "default",
		when: func(OTLPResource) bool { return true },
		then: func(OTLPResource) OTLPClaim { return OTLPClaim{Plane: OTLPUnclaimed} },
	},
}

// ClaimOTLPResource decides one resource's plane through OTLPClaimRules.
func ClaimOTLPResource(in OTLPResource) OTLPClaim {
	for _, r := range otlpClaimRules {
		if r.when(in) {
			c := r.then(in)
			c.Rule = r.name
			return c
		}
	}
	return OTLPClaim{Plane: OTLPUnclaimed, Rule: "none"}
}

// OTLPClaimRuleNames lists the table's rows in walk order (for the
// one-test-per-row pin).
func OTLPClaimRuleNames() []string {
	out := make([]string, len(otlpClaimRules))
	for i, r := range otlpClaimRules {
		out[i] = r.name
	}
	return out
}

// SpanSessionID is the capture session id for a span of the agent. raw is
// the session the span names (session.id or gen_ai.conversation.id); it is
// the X-Session-Id value of the proxy path, so a call that is both proxied
// with X-Session-Id: run-1 and traced with session.id=run-1 lands on ONE
// session (SessionID is the shared join key). With no session on the span,
// trace is the span's trace id: one trace is then one session, which does
// not fold with the proxy's implicit idle-gap session (that id is minted by
// the proxy and the exporter cannot know it). ok is false when neither is
// usable.
func SpanSessionID(agent, raw, trace string) (string, bool) {
	if agent == "" {
		return "", false
	}
	if s, st := NormalizeSessionID(raw); st == StatusOK {
		return SessionID(agent, s), true
	}
	if trace != "" {
		return SessionID(agent, "trace:"+trace), true
	}
	return "", false
}

// ReadOTLPResource extracts the claim facts every caller shares from a raw
// resource attribute set and the attribute sets of every record inside it
// (spans or log records): the echo marker, the agent attribute and whether
// a hosted-app identity appears anywhere. CodingTool is left empty: only a
// caller holding the coding-tool mapping table (internal/otlpvendor) can
// fill it. One extraction, so the vendor ingest and the Plane A guard can
// never disagree on what a resource says.
func ReadOTLPResource(res []*commonpb.KeyValue, records [][]*commonpb.KeyValue) OTLPResource {
	var in OTLPResource
	for _, kv := range res {
		switch kv.GetKey() {
		case otelident.EchoAttr:
			in.Echo = in.Echo || kv.GetValue().GetStringValue() == otelident.EchoValue
		case ResourceAttr:
			if !in.AgentPresent && kv.GetValue() != nil {
				in.AgentPresent = true
				in.AgentRaw = kv.GetValue().GetStringValue()
			}
		}
	}
	in.Hosted = hasHostedAttr(res)
	for _, r := range records {
		if in.Hosted {
			break
		}
		in.Hosted = hasHostedAttr(r)
	}
	return in
}

// hasHostedAttr reports whether any HostedAppAttrs key carries a value.
func hasHostedAttr(kvs []*commonpb.KeyValue) bool {
	for _, kv := range kvs {
		if kv.GetValue().GetValue() == nil {
			continue
		}
		for _, k := range HostedAppAttrs {
			if kv.GetKey() == k {
				return true
			}
		}
	}
	return false
}
