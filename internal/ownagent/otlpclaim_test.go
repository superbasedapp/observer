package ownagent

import (
	"strings"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// TestOTLPClaimTable is the one-test-per-row pin of OTLPClaimRules (PT-55):
// every row is hit by at least one case, the cases cover the boundary in
// both directions (a hosted-app resource is never claimed into Plane B, and
// an own-agent resource never reaches Plane A), and nothing here depends on
// a build tag, so the same table decides in obs-on and no_obs builds.
func TestOTLPClaimTable(t *testing.T) {
	cases := []struct {
		name      string
		in        OTLPResource
		wantRule  string
		wantPlane OTLPPlane
		wantAgent string
	}{
		{
			name:     "echo with an agent name stays on its old route",
			in:       OTLPResource{Echo: true, AgentRaw: "bot", AgentPresent: true},
			wantRule: "echo", wantPlane: OTLPUnclaimed,
		},
		{
			name:     "coding tool service.name wins over the agent attribute",
			in:       OTLPResource{CodingTool: "codex", AgentRaw: "bot", AgentPresent: true},
			wantRule: "coding-tool", wantPlane: OTLPCodingTool,
		},
		{
			name:     "coding tool keeps its resource even with a hosted marker (unchanged behaviour)",
			in:       OTLPResource{CodingTool: "copilot-cli", Hosted: true},
			wantRule: "coding-tool", wantPlane: OTLPCodingTool,
		},
		{
			name:     "hosted app with an agent name is never claimed into Plane B",
			in:       OTLPResource{Hosted: true, AgentRaw: "support-bot", AgentPresent: true},
			wantRule: "hosted-app", wantPlane: OTLPUnclaimed,
		},
		{
			name:     "hosted app without an agent name stays Plane A",
			in:       OTLPResource{Hosted: true},
			wantRule: "hosted-app", wantPlane: OTLPUnclaimed,
		},
		{
			name:     "own agent is claimed with its normalized name",
			in:       OTLPResource{AgentRaw: "  My Bot! ", AgentPresent: true},
			wantRule: "own-agent", wantPlane: OTLPOwnAgent, wantAgent: "my-bot",
		},
		{
			name:     "malformed agent name is dropped from both planes",
			in:       OTLPResource{AgentRaw: "!!!", AgentPresent: true},
			wantRule: "malformed", wantPlane: OTLPDropped,
		},
		{
			name:     "present but empty agent attribute is malformed, not absent",
			in:       OTLPResource{AgentRaw: "", AgentPresent: true},
			wantRule: "malformed", wantPlane: OTLPDropped,
		},
		{
			name:     "control character in the agent name is malformed",
			in:       OTLPResource{AgentRaw: "bot\x07", AgentPresent: true},
			wantRule: "malformed", wantPlane: OTLPDropped,
		},
		{
			name:     "a plain app resource stays unclaimed",
			in:       OTLPResource{},
			wantRule: "default", wantPlane: OTLPUnclaimed,
		},
	}
	hit := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClaimOTLPResource(tc.in)
			if got.Rule != tc.wantRule || got.Plane != tc.wantPlane || got.Agent != tc.wantAgent {
				t.Fatalf("ClaimOTLPResource(%+v) = %+v, want rule %q plane %s agent %q", tc.in, got, tc.wantRule, tc.wantPlane, tc.wantAgent)
			}
			// The two boundary properties hold for every row.
			if tc.in.Hosted && got.Plane == OTLPOwnAgent {
				t.Fatalf("a hosted-app resource was claimed as an own agent")
			}
			if got.Plane == OTLPOwnAgent && !got.Plane.KeptFromPlaneA() {
				t.Fatalf("an own-agent resource is allowed to reach Plane A")
			}
		})
		hit[tc.wantRule] = true
	}
	for _, name := range OTLPClaimRuleNames() {
		if !hit[name] {
			t.Errorf("claim rule %q has no test case", name)
		}
	}
}

// TestOTLPPlaneProperties pins which planes reach Plane A and which are
// Plane B.
func TestOTLPPlaneProperties(t *testing.T) {
	for _, tc := range []struct {
		p             OTLPPlane
		planeB, keptA bool
	}{
		{OTLPUnclaimed, false, false},
		{OTLPCodingTool, true, true},
		{OTLPOwnAgent, true, true},
		{OTLPDropped, false, true},
	} {
		if tc.p.PlaneB() != tc.planeB || tc.p.KeptFromPlaneA() != tc.keptA {
			t.Errorf("%s: PlaneB=%v KeptFromPlaneA=%v, want %v %v", tc.p, tc.p.PlaneB(), tc.p.KeptFromPlaneA(), tc.planeB, tc.keptA)
		}
	}
}

// TestSpanSessionIDJoinsTheProxy pins the join key: the session a span names
// maps to the same capture session id the proxy mints for the same
// X-Session-Id value, so a proxied and traced run is ONE session.
func TestSpanSessionIDJoinsTheProxy(t *testing.T) {
	got, ok := SpanSessionID("my-bot", " run-1 ", "abcd")
	if !ok || got != SessionID("my-bot", "run-1") {
		t.Fatalf("SpanSessionID = %q %v, want the proxy's %q", got, ok, SessionID("my-bot", "run-1"))
	}
	tr := NewTracker(0)
	claim, st := tr.Resolve("my-bot", "run-1", time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	if st != StatusOK || claim.SessionID != got {
		t.Fatalf("proxy claim %q, span session %q: not one session", claim.SessionID, got)
	}
	// No session on the span: one trace is one session.
	byTrace, ok := SpanSessionID("my-bot", "", "abcd")
	if !ok || byTrace != SessionID("my-bot", "trace:abcd") || byTrace == got {
		t.Fatalf("trace fallback = %q %v", byTrace, ok)
	}
	// A malformed session falls back to the trace.
	if s, _ := SpanSessionID("my-bot", strings.Repeat("x", MaxSessionIDLen+1), "abcd"); s != byTrace {
		t.Fatalf("malformed session did not fall back to the trace: %q", s)
	}
	if _, ok := SpanSessionID("my-bot", "", ""); ok {
		t.Fatalf("no session and no trace must yield no session")
	}
	if _, ok := SpanSessionID("", "run-1", "abcd"); ok {
		t.Fatalf("no agent must yield no session")
	}
	// Distinct agents never share a session.
	other, _ := SpanSessionID("other-bot", "run-1", "")
	if other == got {
		t.Fatalf("two agents share session %q", got)
	}
}

// TestHostedAppAttrsArePlaneAIdentity (fix round 1, L2): the hosted-app
// keys are exactly the tenant and end-user keys Plane A reads, from their
// one owner, so a hosted app that sets sbo.agent beside ANY Plane A
// identity key stays in Plane A.
func TestHostedAppAttrsArePlaneAIdentity(t *testing.T) {
	want := otelident.HostedAppKeys()
	if strings.Join(HostedAppAttrs, ",") != strings.Join(want, ",") {
		t.Fatalf("HostedAppAttrs = %v, want otelident.HostedAppKeys() %v", HostedAppAttrs, want)
	}
	for _, k := range append(append([]string{}, otelident.TenantKeys...), otelident.UserKeys...) {
		in := ReadOTLPResource([]*commonpb.KeyValue{
			{Key: ResourceAttr, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "bot"}}},
			{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "x"}}},
		}, nil)
		if c := ClaimOTLPResource(in); c.Plane != OTLPUnclaimed || c.Rule != "hosted-app" {
			t.Errorf("sbo.agent beside Plane A key %q: %+v, want the hosted-app row", k, c)
		}
	}
}

// TestReadOTLPResource pins the shared extraction: the echo marker, the
// agent attribute (present but empty counts as present), and a hosted-app
// identity found on the resource or on any record.
func TestReadOTLPResource(t *testing.T) {
	str := func(k, v string) *commonpb.KeyValue {
		return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
	}
	for _, tc := range []struct {
		name    string
		res     []*commonpb.KeyValue
		records [][]*commonpb.KeyValue
		want    OTLPResource
	}{
		{"agent", []*commonpb.KeyValue{str(ResourceAttr, "bot")}, nil, OTLPResource{AgentRaw: "bot", AgentPresent: true}},
		{"empty agent is present", []*commonpb.KeyValue{str(ResourceAttr, "")}, nil, OTLPResource{AgentPresent: true}},
		{"echo", []*commonpb.KeyValue{str("sbo.emitted_by", "observer")}, nil, OTLPResource{Echo: true}},
		{"hosted on the resource", []*commonpb.KeyValue{str("sbo.tenant", "acme")}, nil, OTLPResource{Hosted: true}},
		{"hosted on one record", nil, [][]*commonpb.KeyValue{{str("x", "y")}, {str("enduser.id", "u1")}}, OTLPResource{Hosted: true}},
		{"user.id is a Plane A end-user key", []*commonpb.KeyValue{str("user.id", "me")}, nil, OTLPResource{Hosted: true}},
		{"tenant is a Plane A tenant key", []*commonpb.KeyValue{str("tenant", "acme")}, nil, OTLPResource{Hosted: true}},
		{"user on one record", nil, [][]*commonpb.KeyValue{{str("user", "u1")}}, OTLPResource{Hosted: true}},
		{"an unrelated key is not hosted", []*commonpb.KeyValue{str("user.name", "me")}, nil, OTLPResource{}},
		{"valueless hosted key is ignored", []*commonpb.KeyValue{{Key: "enduser.id"}}, nil, OTLPResource{}},
	} {
		if got := ReadOTLPResource(tc.res, tc.records); got != tc.want {
			t.Errorf("%s: ReadOTLPResource = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
