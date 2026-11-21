package ccfixture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// Identity and environment values the fixture stamps. The identity values
// (UserEmail, UserID, AccountUUID, AccountID, OrganizationID) are exported so
// a test can prove none of them reaches a mapped row.
const (
	DefaultSessionID = "4b6f0d1e-7a2c-4e9b-9d3f-2c1a0b9e8d7f"
	AppVersion       = "2.1.330"
	Entrypoint       = "cli"
	ServiceName      = "claude-code"
	OrganizationID   = "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"
	AccountUUID      = "1b2c3d4e-5f60-4718-92a3-b4c5d6e7f809"
	AccountID        = "user_01ABCDEFGHJKMNPQRSTVWXYZ0"
	UserID           = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0"
	UserEmail        = "dev@acme.example"
	HostPath         = "/home/dev/src/payments-api"
	RepositoryURL    = "https://github.com/acme/payments-api"
	Branch           = "fix/decline-retry"
	EditedFile       = "/home/dev/src/payments-api/internal/retry/handler.go"
	BashCommand      = "go test ./internal/retry/..."
	// PromptText is every prompt's text (sent only under Session.Prompt).
	PromptText = "Refactor the payment retry handler so a declined card is not retried, add a table-driven test for the three decline codes, and run the package tests."
	// MainModel and SmallModel are the two models the session calls: the
	// last call of every prompt goes to SmallModel.
	MainModel  = "claude-opus-4-8"
	SmallModel = "claude-haiku-4-5"
)

// Tools is the tool-name rotation the session's tool calls walk.
var Tools = []string{"Read", "Read", "Grep", "Edit", "Bash", "Read", "Glob", "Edit", "Bash", "TodoWrite", "Write", "WebFetch", "Task"}

// Session describes the synthetic session. The default shape (Default) is a
// "typical" interactive coding session: 45 minutes, a dozen prompts, five
// model calls and nine tool calls per prompt, two retried API errors.
type Session struct {
	ID        string
	Start     time.Time
	Minutes   int
	Prompts   int
	CallsPer  int // model calls per prompt
	ToolsPer  int // tool calls per prompt
	APIErrors int
	// Prompt is OTEL_LOG_USER_PROMPTS=1: user_prompt carries the text.
	Prompt bool
	// ToolDetail is OTEL_LOG_TOOL_DETAILS=1: tool events carry
	// tool_parameters.
	ToolDetail bool
	// Repo is OTEL_METRICS_INCLUDE_REPOSITORY: the vcs.repository.*
	// attributes ride on every record.
	Repo bool
}

// Default is the default session starting at start: 45 minutes, 12 prompts,
// 5 calls and 9 tool calls per prompt, 2 API errors, no content flags. It
// emits 290 log records: 12 user_prompt, 60 api_request, 108 tool_decision,
// 108 tool_result and 2 api_error.
func Default(start time.Time) Session {
	return Session{ID: DefaultSessionID, Start: start, Minutes: 45, Prompts: 12, CallsPer: 5, ToolsPer: 9, APIErrors: 2}
}

func str(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func i64(i int64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: i}}
}

func dbl(f float64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}}
}

func kv(k string, v *commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: v}
}

// Standard is the documented standard attribute set Claude Code stamps on
// every log record (event true: workspace.host_paths included) and metric
// data point (event false).
func Standard(s Session, event bool) []*commonpb.KeyValue {
	out := []*commonpb.KeyValue{
		kv("session.id", str(s.ID)),
		kv("app.version", str(AppVersion)),
		kv("app.entrypoint", str(Entrypoint)),
		kv("organization.id", str(OrganizationID)),
		kv("user.account_uuid", str(AccountUUID)),
		kv("user.account_id", str(AccountID)),
		kv("user.id", str(UserID)),
		kv("user.email", str(UserEmail)),
		kv("terminal.type", str("vscode")),
	}
	if s.Repo {
		out = append(out,
			kv("vcs.repository.url.full", str(RepositoryURL)),
			kv("vcs.owner.name", str("acme")),
			kv("vcs.repository.name", str("payments-api")),
			kv("vcs.provider.name", str("github")),
		)
	}
	if event {
		out = append(out, kv("workspace.host_paths", &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
			ArrayValue: &commonpb.ArrayValue{Values: []*commonpb.AnyValue{str(HostPath)}},
		}}))
	}
	return out
}

// Resource is the resource Claude Code's exporter sends.
func Resource() *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		kv("service.name", str(ServiceName)),
		kv("service.version", str(AppVersion)),
		kv("os.type", str("linux")),
		kv("os.version", str("6.8.0-45-generic")),
		kv("host.arch", str("amd64")),
	}}
}

// RequestID is the Anthropic request id of the session's call-th model call
// (1-based, counted across the whole session).
func RequestID(call int) string { return fmt.Sprintf("req_011CV%016d", call) }

// ToolUseID is the tool_use_id of the k-th tool call (0-based) asked for by
// model call call.
func ToolUseID(call, k int) string { return fmt.Sprintf("toolu_01%020d", call*100+k) }

// PromptID is the prompt.id of the p-th prompt (0-based).
func PromptID(p int) string { return fmt.Sprintf("prm_%04d", p) }

// ErrorRequestID is the request_id of the api_error of prompt p.
func ErrorRequestID(p int) string { return fmt.Sprintf("req_011CVerr%011d", p) }

// CallCost is the cost_usd the fixture reports for one call's token counts.
func CallCost(in, out, cacheRead int64) float64 {
	return 0.0001*float64(in+out) + 0.0000005*float64(cacheRead)
}

// LogRecords builds every log record of the session, in time order.
func LogRecords(s Session) []*logspb.LogRecord {
	var recs []*logspb.LogRecord
	seq := int64(0)
	add := func(at time.Time, name string, attrs ...*commonpb.KeyValue) {
		seq++
		a := append([]*commonpb.KeyValue{
			kv("event.name", str(strings.TrimPrefix(name, "claude_code."))),
			kv("event.timestamp", str(at.UTC().Format("2006-01-02T15:04:05.000Z"))),
			kv("event.sequence", i64(seq)),
		}, Standard(s, true)...)
		a = append(a, attrs...)
		recs = append(recs, &logspb.LogRecord{
			TimeUnixNano: uint64(at.UnixNano()), ObservedTimeUnixNano: uint64(at.UnixNano()),
			EventName: name, Body: str(name), Attributes: a,
		})
	}
	per := time.Duration(s.Minutes) * time.Minute / time.Duration(s.Prompts)
	call := 0
	for p := 0; p < s.Prompts; p++ {
		t0 := s.Start.Add(time.Duration(p) * per)
		promptID := PromptID(p)
		pa := []*commonpb.KeyValue{
			kv("prompt_length", i64(int64(len(PromptText)))), kv("prompt.id", str(promptID)),
			kv("message.uuid", str(fmt.Sprintf("8c1d%04d-0000-4000-8000-000000000000", p))),
		}
		if s.Prompt {
			pa = append(pa, kv("prompt", str(PromptText)))
		}
		add(t0, "claude_code.user_prompt", pa...)
		step := per / time.Duration(s.CallsPer+s.ToolsPer+1)
		at := t0
		tool := 0
		for c := 0; c < s.CallsPer; c++ {
			call++
			at = at.Add(step)
			model := MainModel
			in, out, cr, cw := int64(6+c), int64(380+40*c), int64(42000+1800*call), int64(1400+90*c)
			if c == s.CallsPer-1 {
				model, in, out, cr, cw = SmallModel, 1200, 60, 0, 0
			}
			reqID := RequestID(call)
			add(at, "claude_code.api_request",
				kv("model", str(model)), kv("cost_usd", dbl(CallCost(in, out, cr))),
				kv("cost_usd_micros", i64(100*(in+out))), kv("duration_ms", i64(int64(4200+300*c))),
				kv("input_tokens", i64(in)), kv("output_tokens", i64(out)),
				kv("cache_read_tokens", i64(cr)), kv("cache_creation_tokens", i64(cw)),
				kv("cache_creation_5m_tokens", i64(cw)), kv("cache_creation_1h_tokens", i64(0)),
				kv("request_id", str(reqID)), kv("client_request_id", str(fmt.Sprintf("c7a1%012d", call))),
				kv("speed", str("normal")), kv("query_source", str("repl_main_thread")), kv("effort", str("high")),
				kv("prompt.id", str(promptID)),
			)
			// tool calls this model call asked for
			n := s.ToolsPer / s.CallsPer
			if c == 0 {
				n += s.ToolsPer % s.CallsPer
			}
			for k := 0; k < n; k++ {
				at = at.Add(step / 2)
				name := Tools[(p*7+tool)%len(Tools)]
				tool++
				tuid := ToolUseID(call, k)
				da := []*commonpb.KeyValue{
					kv("tool_name", str(name)), kv("tool_use_id", str(tuid)), kv("request_id", str(reqID)),
					kv("decision", str("accept")), kv("source", str("config")), kv("tool_source", str("builtin")),
					kv("permission_mode", str("default")), kv("prompt.id", str(promptID)),
				}
				ra := []*commonpb.KeyValue{
					kv("tool_name", str(name)), kv("tool_use_id", str(tuid)), kv("request_id", str(reqID)),
					kv("success", str(fmt.Sprint(k%11 != 10))), kv("duration_ms", i64(int64(30+17*k))),
					kv("decision_type", str("accept")), kv("decision_source", str("config")),
					kv("tool_input_size_bytes", i64(220)), kv("tool_result_size_bytes", i64(3800)),
					kv("vcs.ref.head.name", str(Branch)), kv("vcs.ref.head.type", str("branch")),
					kv("vcs.ref.head.revision", str("4f1c2a9e0b7d6c5a4f3e2d1c0b9a8f7e6d5c4b3a")), kv("prompt.id", str(promptID)),
				}
				if s.ToolDetail {
					param := `{"file_path":"` + EditedFile + `"}`
					if name == "Bash" {
						param = `{"bash_command":"go","full_command":"` + BashCommand + `","timeout":120000,"description":"Run retry tests"}`
					}
					da = append(da, kv("tool_parameters", str(param)))
					ra = append(ra, kv("tool_parameters", str(param)), kv("tool_input", str(param)))
				}
				add(at, "claude_code.tool_decision", da...)
				add(at.Add(time.Duration(30+17*k)*time.Millisecond), "claude_code.tool_result", ra...)
			}
		}
		if p < s.APIErrors {
			add(at.Add(step/3), "claude_code.api_error", kv("model", str(MainModel)), kv("error", str("Overloaded")),
				kv("status_code", str("529")), kv("duration_ms", i64(900)), kv("attempt", i64(1)),
				kv("request_id", str(ErrorRequestID(p))), kv("prompt.id", str(promptID)))
		}
	}
	return recs
}

// LogBatches groups records the way the SDK's batch processor does at the
// default OTEL_LOGS_EXPORT_INTERVAL of 5 s: one export per 5 s window that
// has any record, in window order.
func LogBatches(recs []*logspb.LogRecord) []*collogspb.ExportLogsServiceRequest {
	byWin := map[int64][]*logspb.LogRecord{}
	var wins []int64
	for _, r := range recs {
		w := int64(r.TimeUnixNano) / int64(5*time.Second)
		if _, ok := byWin[w]; !ok {
			wins = append(wins, w)
		}
		byWin[w] = append(byWin[w], r)
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i] < wins[j] })
	out := make([]*collogspb.ExportLogsServiceRequest, 0, len(wins))
	for _, w := range wins {
		out = append(out, &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource: Resource(),
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code.events", Version: AppVersion},
				LogRecords: byWin[w],
			}},
		}}})
	}
	return out
}

// MetricBatches builds the metrics exports: one per 60 s interval (delta
// temporality, Claude Code's default), each carrying the data points that
// changed in that minute.
func MetricBatches(s Session) []*colmetricspb.ExportMetricsServiceRequest {
	var out []*colmetricspb.ExportMetricsServiceRequest
	std := Standard(s, false)
	pt := func(at time.Time, v float64, extra ...*commonpb.KeyValue) *metricspb.NumberDataPoint {
		return &metricspb.NumberDataPoint{
			StartTimeUnixNano: uint64(at.Add(-time.Minute).UnixNano()), TimeUnixNano: uint64(at.UnixNano()),
			Attributes: append(append([]*commonpb.KeyValue{}, std...), extra...),
			Value:      &metricspb.NumberDataPoint_AsDouble{AsDouble: v},
		}
	}
	sum := func(name, unit string, pts ...*metricspb.NumberDataPoint) *metricspb.Metric {
		return &metricspb.Metric{Name: name, Unit: unit, Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			DataPoints: pts, AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA, IsMonotonic: true,
		}}}
	}
	for m := 1; m <= s.Minutes; m++ {
		at := s.Start.Add(time.Duration(m) * time.Minute)
		var ms []*metricspb.Metric
		if m == 1 {
			ms = append(ms, sum("claude_code.session.count", "", pt(at, 1, kv("start_type", str("fresh")))))
		}
		var tok, cost []*metricspb.NumberDataPoint
		for _, model := range []string{MainModel, SmallModel} {
			for _, typ := range []string{"input", "output", "cacheRead", "cacheCreation"} {
				tok = append(tok, pt(at, 1000, kv("type", str(typ)), kv("model", str(model)),
					kv("query_source", str("repl_main_thread")), kv("speed", str("normal")), kv("effort", str("high"))))
			}
			cost = append(cost, pt(at, 0.12, kv("model", str(model)), kv("query_source", str("repl_main_thread")),
				kv("speed", str("normal")), kv("effort", str("high"))))
		}
		ms = append(ms, sum("claude_code.token.usage", "tokens", tok...), sum("claude_code.cost.usage", "USD", cost...),
			sum("claude_code.active_time.total", "s", pt(at, 22, kv("type", str("cli"))), pt(at, 9, kv("type", str("user")))))
		if m%3 == 0 {
			ms = append(ms,
				sum("claude_code.lines_of_code.count", "", pt(at, 18, kv("type", str("added")), kv("model", str(MainModel))),
					pt(at, 4, kv("type", str("removed")), kv("model", str(MainModel)))),
				sum("claude_code.code_edit_tool.decision", "", pt(at, 2, kv("tool_name", str("Edit")), kv("decision", str("accept")),
					kv("source", str("config")), kv("language", str("Go")))))
		}
		out = append(out, &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: Resource(),
			ScopeMetrics: []*metricspb.ScopeMetrics{{
				Scope: &commonpb.InstrumentationScope{Name: "com.anthropic.claude_code", Version: AppVersion}, Metrics: ms,
			}},
		}}})
	}
	return out
}
