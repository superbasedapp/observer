//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ownAgentFixture is the export the stock OpenTelemetry Python SDK sent for
// a developer's own agent (testdata/otlp/custom-agent, sbo.agent=fixture-bot,
// session.id=run-1): two chat turns and one execute_tool span.
var ownAgentFixture = otlpFixture{tool: "custom-agent", file: "traces.json", path: "/v1/traces"}

// ownAgentOnly enables the custom-agent capture and nothing else.
func ownAgentOnly(tool string) bool { return tool == models.ToolCustomAgent }

// TestOwnAgentSpansLandAsPlaneBSession (PT-55 scope 1): the export lands as
// ONE custom-agent session carrying the same surface the proxy header path
// stamps, with its two turns (source agent_otel, the instrumentor's own
// counts) and its tool call, and a redelivery adds nothing.
func TestOwnAgentSpansLandAsPlaneBSession(t *testing.T) {
	database, base := startOTLPNode(t, ownAgentOnly, nil)
	body, ctype := wireBody(t, ownAgentFixture)
	postOTLP(t, base+ownAgentFixture.path, body, ctype)
	postOTLP(t, base+ownAgentFixture.path, body, ctype) // at-least-once redelivery

	session := ownagent.SessionID("fixture-bot", "run-1")
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions WHERE id = ? AND tool = ? AND surface = 'sdk' AND surface_host = 'agent:fixture-bot'`,
		session, models.ToolCustomAgent); n != 1 {
		t.Fatalf("own-agent session row = %d, want 1", n)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions`); n != 1 {
		t.Fatalf("sessions = %d, want exactly the one own-agent session", n)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE session_id = ? AND source = ? AND input_tokens = 1234 AND output_tokens = 56 AND provider = 'openai'`,
		session, store.SourceAgentOTel); n != 2 {
		t.Errorf("own-agent turns = %d, want 2", n)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM actions WHERE session_id = ? AND tool = ? AND raw_tool_name = 'list_files' AND source_file = 'otlp:custom-agent'`,
		session, models.ToolCustomAgent); n != 1 {
		t.Errorf("own-agent tool calls = %d, want 1", n)
	}
	agents, err := store.New(database).ListOwnAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].Agent != "fixture-bot" || agents[0].Sessions != 1 || agents[0].Turns != 2 ||
		agents[0].Via != store.OwnAgentViaOTLP {
		t.Fatalf("Own agents view = %+v", agents)
	}
}

// TestOwnAgentSpansNeedTheAdapter: with the custom-agent adapter off the
// export lands nothing, the same switch the proxy header path obeys.
func TestOwnAgentSpansNeedTheAdapter(t *testing.T) {
	database, base := startOTLPNode(t, func(string) bool { return false }, nil)
	body, ctype := wireBody(t, ownAgentFixture)
	postOTLP(t, base+ownAgentFixture.path, body, ctype)
	for _, q := range []string{`SELECT COUNT(*) FROM sessions`, `SELECT COUNT(*) FROM api_turns`, `SELECT COUNT(*) FROM actions`} {
		if n := countRows(t, database, q); n != 0 {
			t.Errorf("%s = %d with the adapter off", q, n)
		}
	}
}

// proxyTurn writes the row the proxy writes for one own-agent call: the
// session through the own-agent seam, then the turn with InsertAPITurn
// (exact provider figures: 234 net input, 1000 cached).
func proxyTurn(t *testing.T, st *store.Store, session, requestID, root string) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if err := st.EnsureOwnAgentSession(ctx, session, "fixture-bot", root, "gpt-5.5-mini-2026-10-01", at); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: session, Provider: "openai", Model: "gpt-5.5-mini-2026-10-01", RequestID: requestID, Timestamp: at,
		InputTokens: 234, OutputTokens: 56, CacheReadTokens: 1000, Source: store.SourceProxy,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOwnAgentProxyAndSpansFoldIntoOneSession (PT-55 scope 1, the join
// key): an agent that proxies with X-Session-Id: run-1 AND traces with
// session.id=run-1 is ONE session; a call seen both ways is ONE turn
// carrying the proxy's exact figures, whichever path wrote first; the
// tool call lands under the project the proxy resolved.
func TestOwnAgentProxyAndSpansFoldIntoOneSession(t *testing.T) {
	session := ownagent.SessionID("fixture-bot", "run-1")
	body, ctype := wireBody(t, ownAgentFixture)
	check := func(t *testing.T, database *sql.DB) {
		t.Helper()
		if n := countRows(t, database, `SELECT COUNT(*) FROM sessions`); n != 1 {
			t.Fatalf("sessions = %d, want 1", n)
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'chatcmpl-mock-1'`); n != 1 {
			t.Fatalf("rows for the proxied call = %d, want 1", n)
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'chatcmpl-mock-1' AND input_tokens = 234 AND cache_read_tokens = 1000 AND source = ?`, store.SourceProxy); n != 1 {
			t.Fatalf("the proxied call does not carry the proxy's figures")
		}
		// The second call was only traced: it keeps the span row.
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'chatcmpl-mock-2' AND source = ?`, store.SourceAgentOTel); n != 1 {
			t.Fatalf("traced-only call rows = %d, want 1", n)
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns WHERE session_id = ?`, session); n != 2 {
			t.Fatalf("turns on the one session = %d, want 2", n)
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ? AND p.root_path = '/work/bot'`, session); n != 1 {
			t.Fatalf("the session lost the proxy's project")
		}
		if n := countRows(t, database, `SELECT COUNT(*) FROM actions a JOIN projects p ON p.id = a.project_id WHERE a.session_id = ? AND p.root_path = '/work/bot'`, session); n != 1 {
			t.Fatalf("the span tool call did not land under the proxy's project")
		}
	}
	t.Run("proxy first", func(t *testing.T) {
		database, base := startOTLPNode(t, ownAgentOnly, nil)
		proxyTurn(t, store.New(database), session, "chatcmpl-mock-1", "/work/bot")
		postOTLP(t, base+ownAgentFixture.path, body, ctype)
		check(t, database)
	})
	// The spans open the session on the [custom-agent] placeholder; the
	// proxy's later turn, which knows the working directory, moves the
	// session and its span tool call onto /work/bot (fix round 1, L1).
	t.Run("spans first", func(t *testing.T) {
		database, base := startOTLPNode(t, ownAgentOnly, nil)
		postOTLP(t, base+ownAgentFixture.path, body, ctype)
		if n := countRows(t, database, `SELECT COUNT(*) FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ? AND p.root_path = '[custom-agent]'`, session); n != 1 {
			t.Fatalf("spans did not open the session on the placeholder project")
		}
		proxyTurn(t, store.New(database), session, "chatcmpl-mock-1", "/work/bot")
		check(t, database)
	})
}

// planeRecorder is a Plane A trace handler that records every resource it is
// handed.
type planeRecorder struct {
	mu   sync.Mutex
	seen []*tracepb.ResourceSpans
}

func (p *planeRecorder) handle(_ context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, req.GetResourceSpans()...)
	return nil
}

func (p *planeRecorder) agents() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, rs := range p.seen {
		for _, kv := range rs.GetResource().GetAttributes() {
			if kv.GetKey() == "service.name" {
				out = append(out, kv.GetValue().GetStringValue())
			}
		}
	}
	return out
}

// strKV is one string attribute.
func strKV(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

// mixedExport is one trace export carrying four resources: the developer's
// own agent, a hosted app that also names an agent, a plain app and a
// malformed agent name, each with one usage-bearing chat span.
func mixedExport() *coltracepb.ExportTraceServiceRequest {
	chat := func(id byte) *tracepb.Span {
		return &tracepb.Span{
			Name: "chat m", SpanId: []byte{id, 1, 2, 3, 4, 5, 6, 7}, TraceId: []byte{id, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
			StartTimeUnixNano: 1_793_712_795_000_000_000, EndTimeUnixNano: 1_793_712_796_000_000_000,
			Attributes: []*commonpb.KeyValue{
				strKV("gen_ai.operation.name", "chat"), strKV("gen_ai.provider.name", "openai"), strKV("gen_ai.request.model", "m"),
				strKV("gen_ai.response.id", "r"+string(rune('0'+id))),
				{Key: "gen_ai.usage.output_tokens", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: 5}}},
			},
		}
	}
	res := func(id byte, kvs ...*commonpb.KeyValue) *tracepb.ResourceSpans {
		return &tracepb.ResourceSpans{
			Resource:   &resourcepb.Resource{Attributes: kvs},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{chat(id)}}},
		}
	}
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{
		res(1, strKV("service.name", "own"), strKV("sbo.agent", "bot")),
		res(2, strKV("service.name", "hosted"), strKV("sbo.agent", "bot"), strKV("sbo.tenant", "acme")),
		res(3, strKV("service.name", "plain")),
		res(4, strKV("service.name", "malformed"), strKV("sbo.agent", "***")),
	}}
}

// TestOwnAgentPlaneBoundary (PT-55 scope 2): with the vendor ingest on, the
// own-agent resource lands in Plane B and never reaches Plane A; the hosted
// app (even naming an agent) and the plain app reach Plane A and land no
// Plane B row; the malformed one reaches neither.
func TestOwnAgentPlaneBoundary(t *testing.T) {
	rec := &planeRecorder{}
	database, base := startOTLPNode(t, ownAgentOnly, guardPlaneA(rec.handle, nil))
	body, err := proto.Marshal(mixedExport())
	if err != nil {
		t.Fatal(err)
	}
	postOTLP(t, base+"/v1/traces", body, "application/x-protobuf")
	got := rec.agents()
	if len(got) != 2 || got[0] != "hosted" || got[1] != "plain" {
		t.Fatalf("Plane A saw %v, want [hosted plain]", got)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM sessions WHERE tool = ? AND surface_host = 'agent:bot'`, models.ToolCustomAgent); n != 1 {
		t.Fatalf("own-agent sessions = %d, want 1", n)
	}
	if n := countRows(t, database, `SELECT COUNT(*) FROM api_turns`); n != 1 {
		t.Fatalf("Plane B turns = %d, want only the own agent's", n)
	}
}

// TestOwnAgentGuardAgreesWithVendorIngest: the Plane A guard
// (otlp_planeguard.go, every build) and the vendor ingest split decide the
// mixed export's resources the same way, apart from the coding-tool row the
// guard cannot know.
func TestOwnAgentGuardAgreesWithVendorIngest(t *testing.T) {
	req := mixedExport()
	keep, held := withoutOwnAgentResources(req)
	mine, rest, dropped := splitClaimedTraces(mixedExport())
	if held != len(mine.GetResourceSpans())+dropped || len(keep.GetResourceSpans()) != len(rest.GetResourceSpans()) {
		t.Fatalf("guard held %d kept %d; split mine %d dropped %d rest %d", held, len(keep.GetResourceSpans()),
			len(mine.GetResourceSpans()), dropped, len(rest.GetResourceSpans()))
	}
	if otlpvendor.ClaimTraceResource(req.GetResourceSpans()[0]).Plane != ownagent.OTLPOwnAgent {
		t.Fatal("the own-agent resource is not claimed by the vendor ingest")
	}
}

// TestAgentOTelSourceTagMirrorsStore pins the own-agent row's source tag to
// the store's, which ranks it below the proxy (otlpvendor cannot import the
// store).
func TestAgentOTelSourceTagMirrorsStore(t *testing.T) {
	if otlpvendor.SourceAgentOTel != store.SourceAgentOTel {
		t.Fatalf("otlpvendor.SourceAgentOTel %q != store.SourceAgentOTel %q", otlpvendor.SourceAgentOTel, store.SourceAgentOTel)
	}
	v, _ := otlpvendor.ForTool(models.ToolCustomAgent)
	if v.SourceTag != store.SourceAgentOTel {
		t.Fatalf("own-agent row source tag %q", v.SourceTag)
	}
}
