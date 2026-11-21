package otlpvendor

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"

	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// ccAPIRequest is a Claude Code api_request log record (doc-grounded shape,
// the TestDocRows convention) with extra attributes appended.
func ccAPIRequest(session, request string, extra ...any) *logspb.LogRecord {
	attrs := append([]any{
		"event.name", s("claude_code.api_request"), "session.id", s(session),
		"request_id", s(request), "model", s("claude-opus-5-5"),
		"input_tokens", i(10), "output_tokens", i(20),
	}, extra...)
	return &logspb.LogRecord{TimeUnixNano: 1_790_000_000_000_000_000, Attributes: kvs(attrs...)}
}

// TestClaudeCodeCloudExecutionMarker pins the Claude Code row's
// cloud-execution marker (cloud-agents lane CA-B4): ccr.session.id, on the
// record or the resource, maps to vendor_session_ref and stamps
// vendor_cloud, once per session per export; an export without it (every
// local Claude Code session) stamps nothing.
func TestClaudeCodeCloudExecutionMarker(t *testing.T) {
	t.Parallel()
	const (
		sid = "5d3c6c6e-0000-5000-8000-000000000001"
		cse = "cse_0123456789abcdefABCDEFGH"
	)
	withResource := func(extra ...any) func() Result {
		return func() Result {
			req := logsExport("claude-code", ccAPIRequest(sid, "req_1"), ccAPIRequest(sid, "req_2"))
			rl := req.ResourceLogs[0]
			rl.Resource.Attributes = append(rl.Resource.Attributes, kvs(extra...)...)
			return ParseLogs(req)
		}
	}
	tests := []struct {
		name string
		run  func() Result
		want []Execution
	}{
		{
			name: "record attribute",
			run: func() Result {
				return ParseLogs(logsExport("claude-code",
					ccAPIRequest(sid, "req_1", "ccr.session.id", s(cse)),
					ccAPIRequest(sid, "req_2", "ccr.session.id", s(cse))))
			},
			want: []Execution{{Tool: "claude-code", SessionID: sid, Location: models.ExecutionVendorCloud, VendorRef: cse, CreatesSession: true, Model: "claude-opus-5-5"}},
		},
		{
			name: "resource attribute",
			run:  withResource("ccr.session.id", s(cse)),
			want: []Execution{{Tool: "claude-code", SessionID: sid, Location: models.ExecutionVendorCloud, VendorRef: cse, CreatesSession: true, Model: "claude-opus-5-5"}},
		},
		{
			name: "local session: no marker",
			run:  func() Result { return ParseLogs(logsExport("claude-code", ccAPIRequest(sid, "req_1"))) },
		},
		{
			name: "empty marker value",
			run:  withResource("ccr.session.id", s("")),
		},
		{
			name: "two sessions, one each",
			run: func() Result {
				return ParseLogs(logsExport("claude-code",
					ccAPIRequest(sid, "req_1", "ccr.session.id", s(cse)),
					ccAPIRequest("other-session", "req_2", "ccr.session.id", s("cse_otherotherotherotherother"))))
			},
			want: []Execution{
				{Tool: "claude-code", SessionID: sid, Location: models.ExecutionVendorCloud, VendorRef: cse, CreatesSession: true, Model: "claude-opus-5-5"},
				{Tool: "claude-code", SessionID: "other-session", Location: models.ExecutionVendorCloud, VendorRef: "cse_otherotherotherotherother", CreatesSession: true, Model: "claude-opus-5-5"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := tc.run()
			if len(res.Executions) != len(tc.want) {
				t.Fatalf("executions = %+v; want %+v", res.Executions, tc.want)
			}
			for n, w := range tc.want {
				got := res.Executions[n]
				got.Timestamp = w.Timestamp // timing is the record's, not pinned here
				if got != w {
					t.Errorf("execution[%d] = %+v; want %+v", n, got, w)
				}
			}
			// The marker never changes the turns themselves.
			if len(res.Turns) == 0 {
				t.Fatal("no turns mapped")
			}
		})
	}
}

// TestOwnAgentExecutionUsesResolvedSession (fold of the cloud-agents line,
// P-230): apply notes a record's execution marker AFTER the own-agent
// session resolution, so an own-agent (ClaimByAgent) record's execution
// lands on the agent's capture session id (ownagent.SpanSessionID), the one
// its turns use, never on the raw session attribute; a record whose own-agent
// session cannot be resolved notes nothing.
func TestOwnAgentExecutionUsesResolvedSession(t *testing.T) {
	t.Parallel()
	base, ok := ForTool(models.ToolCustomAgent)
	if !ok || !base.ClaimByAgent {
		t.Fatalf("own-agent row = %+v", base)
	}
	vd := base
	vd.Execution = []ExecutionMarker{{Keys: []string{"test.cloud.run"}, Location: models.ExecutionVendorCloud, ValueIsVendorRef: true}}
	rule := &agentTurnRules()[0]
	rec := attrMap(kvs(
		"gen_ai.operation.name", s(agentInferenceOps[0]), "gen_ai.request.model", s("m"), "gen_ai.response.model", s("m"),
		"gen_ai.response.id", s("r1"), "gen_ai.usage.output_tokens", i(7), "test.cloud.run", s("run_ref_1"),
	))
	ts := time.Unix(1_790_000_000, 0)
	for _, tc := range []struct {
		name  string
		res   attrs
		trace string
		want  string // resolved session id, "" for nothing noted
	}{
		{name: "span session", res: attrMap(kvs("session.id", s("run-1"))), want: ownagent.SessionID("bot", "run-1")},
		{name: "trace as session", res: attrMap(kvs()), trace: "abcd", want: ownagent.SessionID("bot", "trace:abcd")},
		{name: "no session and no trace", res: attrMap(kvs())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out Result
			apply(&out, &vd, rule, view{rec: rec, res: tc.res}, recordCtx{agent: "bot", trace: tc.trace}, ts, 0, "k", "")
			if tc.want == "" {
				if len(out.Executions) != 0 || len(out.Turns) != 0 {
					t.Fatalf("an unresolved own-agent record was noted: %+v", out)
				}
				return
			}
			if len(out.Executions) != 1 {
				t.Fatalf("executions = %+v, want one", out.Executions)
			}
			ex := out.Executions[0]
			if ex.SessionID != tc.want || ex.Tool != models.ToolCustomAgent || ex.Location != models.ExecutionVendorCloud || ex.VendorRef != "run_ref_1" {
				t.Fatalf("execution = %+v, want session %s", ex, tc.want)
			}
			if len(out.Turns) != 1 || out.Turns[0].SessionID != ex.SessionID {
				t.Fatalf("turns = %+v, want one on the execution's session %s", out.Turns, ex.SessionID)
			}
		})
	}
}

// TestExecutionMarkersAreKnownLocations pins every row's markers to the
// closed models vocabulary and to at least one key, so a row can never
// emit a location the store refuses.
func TestExecutionMarkersAreKnownLocations(t *testing.T) {
	t.Parallel()
	for _, v := range vendors {
		for _, m := range v.Execution {
			if !models.KnownExecutionLocation(m.Location) {
				t.Errorf("%s: marker %v has unknown location %q", v.Tool, m.Keys, m.Location)
			}
			if len(m.Keys) == 0 {
				t.Errorf("%s: marker with no keys", v.Tool)
			}
		}
	}
}
