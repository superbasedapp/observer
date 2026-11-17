package otlpvendor

import (
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/otelident"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// attrService is the resource attribute a mapping row claims by.
const attrService = "service.name"

// IsEcho reports whether a resource's attributes mark it Observer-emitted
// (the echo marker, owned by internal/otelident): such a resource is never
// read back in.
func IsEcho(res []*commonpb.KeyValue) bool {
	return attrMap(res)[otelident.EchoAttr].GetStringValue() == otelident.EchoValue
}

// claim returns the vendor whose ServiceNames contains svc, else the first
// vendor one of whose ServiceNamePrefixes svc starts with (an exact name
// always wins over a prefix).
func claim(svc string) (*Vendor, bool) {
	if svc == "" {
		return nil, false
	}
	for i := range vendors {
		for _, n := range vendors[i].ServiceNames {
			if n == svc {
				return &vendors[i], true
			}
		}
	}
	for i := range vendors {
		for _, p := range vendors[i].ServiceNamePrefixes {
			if p != "" && strings.HasPrefix(svc, p) {
				return &vendors[i], true
			}
		}
	}
	return nil, false
}

// ParseLogs maps an OTLP logs export.
func ParseLogs(req *collogspb.ExportLogsServiceRequest) Result {
	var out Result
	if req == nil {
		return out
	}
	seen := map[string]bool{}
	for _, rl := range req.GetResourceLogs() {
		if IsEcho(rl.GetResource().GetAttributes()) {
			continue
		}
		res := attrMap(rl.GetResource().GetAttributes())
		var records [][]*commonpb.KeyValue
		for _, sl := range rl.GetScopeLogs() {
			for _, rec := range sl.GetLogRecords() {
				records = append(records, rec.GetAttributes())
			}
		}
		rc := claimResource(rl.GetResource().GetAttributes(), records)
		matched := false
		for _, sl := range rl.GetScopeLogs() {
			for ord, rec := range sl.GetLogRecords() {
				names := logNames(rec)
				ts := logTime(rec)
				v := view{rec: attrMap(rec.GetAttributes()), res: res}
				for _, vd := range rc.cands {
					for ri := range vd.Rules {
						r := &vd.Rules[ri]
						if r.Signal != SignalLogs || !nameMatch(r, names) || !condsHold(v, r.Where) {
							continue
						}
						matched = true
						body := contentBody(rec.GetBody().GetStringValue(), names, r.Names)
						apply(&out, vd, r, v, recordCtx{agent: rc.Agent, trace: hex.EncodeToString(rec.GetTraceId())},
							ts, rec.GetTimeUnixNano(), recordKey(ts, nil, ord), body)
					}
				}
			}
		}
		noteUnclaimed(&out, seen, res, matched || rc.Plane != ownagent.OTLPUnclaimed)
	}
	out.GenTimings = timedOnly(out.GenTimings)
	return out
}

// ParseSpans maps an OTLP trace export.
func ParseSpans(req *coltracepb.ExportTraceServiceRequest) Result {
	var out Result
	if req == nil {
		return out
	}
	seen := map[string]bool{}
	for _, rs := range req.GetResourceSpans() {
		if IsEcho(rs.GetResource().GetAttributes()) {
			continue
		}
		res := attrMap(rs.GetResource().GetAttributes())
		rc := claimResource(rs.GetResource().GetAttributes(), spanRecords(rs))
		matched := false
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				v := view{rec: attrMap(sp.GetAttributes()), res: res}
				ts := spanTime(sp)
				rcx := recordCtx{agent: rc.Agent, trace: hex.EncodeToString(sp.GetTraceId())}
				for _, vd := range rc.cands {
					for ri := range vd.Rules {
						r := &vd.Rules[ri]
						if r.Signal != SignalSpans || !nameMatch(r, []string{sp.GetName()}) || !condsHold(v, r.Where) {
							continue
						}
						matched = true
						rv := v
						if r.F.FromSpanEvents {
							rv = v.withEvents(spanEventAttrs(sp))
						}
						beforeTurns, before, beforeTiming := len(out.Turns), len(out.Tools), len(out.GenTimings)
						apply(&out, vd, r, rv, rcx, ts, sp.GetStartTimeUnixNano(), recordKey(ts, sp.GetSpanId(), 0), "")
						// Only a record apply actually appended takes the
						// span's duration: a skipped one (no request id
						// under RequireRequest, no own-agent session) must
						// never stamp the previous record.
						if (r.Kind == KindTurn && len(out.Turns) > beforeTurns) || (r.Kind == KindTool && len(out.Tools) > before) {
							setSpanDuration(&out, r.Kind, sp)
						}
						if r.Kind == KindTool && r.F.SuccessFromStatus && len(out.Tools) > before {
							setSpanOutcome(&out.Tools[len(out.Tools)-1], sp)
						}
						if r.Kind == KindGenTiming && len(out.GenTimings) > beforeTiming {
							setSpanGenTiming(&out.GenTimings[len(out.GenTimings)-1], &r.F, sp)
						}
					}
				}
			}
		}
		noteUnclaimed(&out, seen, res, matched || rc.Plane != ownagent.OTLPUnclaimed)
	}
	out.GenTimings = timedOnly(out.GenTimings)
	return out
}

// noteUnclaimed records a resource's service.name when no row read it.
func noteUnclaimed(out *Result, seen map[string]bool, res attrs, matched bool) {
	svc := res[attrService].GetStringValue()
	if matched || svc == "" || seen[svc] {
		return
	}
	if _, ok := claim(svc); ok {
		return
	}
	seen[svc] = true
	out.Unclaimed = append(out.Unclaimed, svc)
}

// logNames returns the candidate event names of a log record: the typed
// EventName and the event.name attribute (Codex sets the typed field to its
// tracing target and the real name in the attribute).
func logNames(rec interface {
	GetEventName() string
	GetAttributes() []*commonpb.KeyValue
},
) []string {
	names := []string{rec.GetEventName()}
	for _, kv := range rec.GetAttributes() {
		if kv.GetKey() == "event.name" {
			names = append(names, kv.GetValue().GetStringValue())
			break
		}
	}
	return names
}

// contentBody is a log record's body as a content fallback: the body, or ""
// when the body is only the record's event name. Claude Code (and Kimchi,
// which reuses its event names) set every event's body to the event name
// ("claude_code.tool_result"), so without this every tool_result,
// tool_decision and flag-less user_prompt became a content row holding its
// own event name (the OTel-direct spike's finding; docs/security.md
// OTELDIRECT-5). A body that differs from every name is kept as before.
func contentBody(body string, names, ruleNames []string) string {
	b := strings.TrimSpace(body)
	if b == "" {
		return ""
	}
	for _, list := range [][]string{names, ruleNames} {
		for _, n := range list {
			if n != "" && b == n {
				return ""
			}
		}
	}
	return body
}

// nameMatch reports whether any candidate name satisfies the rule.
func nameMatch(r *Rule, names []string) bool {
	for _, n := range names {
		if n == "" {
			continue
		}
		for _, want := range r.Names {
			if n == want || (r.NamePrefix && strings.HasPrefix(n, want)) {
				return true
			}
		}
	}
	return false
}

// condsHold reports whether every condition holds on the record.
func condsHold(v view, conds []Cond) bool {
	for _, c := range conds {
		if len(c.AnyOf) > 0 {
			if !anyPresent(v.rec, c.AnyOf) {
				return false
			}
			continue
		}
		val, ok := v.rec[c.Key]
		present := ok && val != nil && val.GetValue() != nil
		if c.Absent {
			if present {
				return false
			}
			continue
		}
		if !present {
			return false
		}
		if c.Equals != "" && val.GetStringValue() != c.Equals {
			return false
		}
	}
	return true
}

// anyPresent reports whether any of keys is set on the record.
func anyPresent(rec attrs, keys []string) bool {
	for _, k := range keys {
		if val, ok := rec[k]; ok && val != nil && val.GetValue() != nil {
			return true
		}
	}
	return false
}

// recordCtx is what a record inherits from its resource's claim and its own
// envelope: the own-agent name (empty unless the own-agent row claimed the
// resource) and the record's trace id (hex, empty when it has none).
type recordCtx struct {
	agent string
	trace string
}

// sessionOf resolves a record's session id. For the own-agent row it is the
// agent's capture session id (ownagent.SpanSessionID: the span's session,
// else its trace), so the record lands on the same session the proxy path
// uses; ok is false when the own-agent record has neither, and the record
// is then not mapped (a session-less own-agent row would land nowhere the
// dashboard can show). Every other row reads the session as sent.
func sessionOf(vd *Vendor, f *Fields, v view, rc recordCtx) (string, bool) {
	raw := v.str(f.Session)
	if !vd.ClaimByAgent {
		return raw, true
	}
	return ownagent.SpanSessionID(rc.agent, raw, rc.trace)
}

// apply maps one matched record by the rule's kind.
func apply(out *Result, vd *Vendor, r *Rule, v view, rc recordCtx, ts time.Time, tsNano uint64, key, body string) {
	f := &r.F
	session, ok := sessionOf(vd, f, v, rc)
	if !ok {
		return
	}
	// Only the own-agent row's records carry the agent name: an event-name
	// row reading the same resource's logs (Claude Code) maps its own tool.
	if !vd.ClaimByAgent {
		rc.agent = ""
	}
	// The execution marker is noted under the RESOLVED session id, so an
	// own-agent record's cloud-execution stamp lands on the same session the
	// proxy path and the turn rows use.
	noteExecution(out, vd, v, session, v.str(f.Model), ts)
	switch r.Kind {
	case KindTurn:
		request := v.str(f.Request)
		synthetic := false
		if request == "" {
			if r.RequireRequest {
				out.Skipped++
				return
			}
			request = synthID(vd.Tool, session, key)
			synthetic = true
		}
		t := Turn{
			Tool: vd.Tool, SourceTag: vd.SourceTag, Provider: firstNonEmpty(v.str(f.Provider), vd.Provider),
			SessionID: session, Agent: rc.agent, RequestID: request, RequestSynthetic: synthetic,
			Model: v.str(f.Model), Timestamp: ts,
			CacheReadTokens:    v.int64Of(f.CacheRead),
			CacheWriteTokens:   v.int64Of(f.CacheWrite),
			CacheWrite1hTokens: v.int64Of(f.CacheWrite1h),
			ReasoningTokens:    v.int64Of(f.Reasoning),
			DurationMS:         v.int64Of(f.Duration),
			TimeToFirstTokenMS: v.int64Of(f.TTFT),
			ViaProxyRoute: v.res[RouteResourceAttr].GetStringValue() == RouteProxy &&
				v.res[RouteToolResourceAttr].GetStringValue() == vd.Tool,
			BillingID: v.str(f.BillingID),
			Member: Member{
				Email: strings.ToLower(strings.TrimSpace(v.str(f.MemberEmail))), UserID: v.str(f.MemberUserID),
				AccountID: v.str(f.MemberAccountID), TeamID: v.str(f.MemberTeamID),
			},
		}
		t.CostUSD, _ = v.num(f.Cost)
		t.InputTokens, t.OutputTokens = normalize(vd.Norm, v.int64Of(f.Input), v.int64Of(f.Output), v.int64Of(f.Total), t)
		out.Turns = append(out.Turns, t)
	case KindTool:
		tc := ToolCall{
			Tool: vd.Tool, SessionID: session, Agent: rc.agent, Name: v.str(f.ToolName),
			CallID: v.str(f.CallID), DurationMS: v.int64Of(f.Duration), Timestamp: ts,
		}
		if tc.CallID == "" {
			tc.CallID = synthID(vd.Tool, session, key)
		}
		if ok, known := v.boolOf(f.Success); known {
			tc.Success, tc.SuccessKnown = ok, true
		} else if len(f.Failure) > 0 {
			tc.Success, tc.SuccessKnown = !v.has(f.Failure), true
		}
		out.Tools = append(out.Tools, tc)
	case KindGenTiming:
		// Only a record that names its session and its per-call key can be
		// joined to the transcript's row, and only a vendor whose row
		// declares the join may emit one (TestTimingRowsDeclareJoin).
		key := v.str(f.Request)
		if vd.TranscriptTiming == "" || session == "" || key == "" {
			return
		}
		out.GenTimings = append(out.GenTimings, GenTiming{
			Tool: vd.Tool, SessionID: session, Key: vd.TranscriptTiming, KeyValue: key,
			DurationMS: v.int64Of(f.Duration), Timestamp: ts,
		})
	case KindContent:
		content := v.str(f.Content)
		if content == "" && f.ContentFromBody {
			content = body
		}
		if content == "" || isPlaceholder(content, f.ContentPlaceholders) {
			return
		}
		out.Contents = append(out.Contents, Content{
			Tool: vd.Tool, SourceTag: vd.SourceTag, SessionID: session, Agent: rc.agent,
			RequestID: v.str(f.Request), ToolUseID: v.str(f.ToolUseID),
			Kind: f.ContentKind, Content: content, TimeUnixNano: tsNano,
		})
	}
}

// noteExecution walks the vendor's cloud-execution marker table for one
// matched record and records the first hit for its session, once per
// (tool, session) per export. A record without a session, or a vendor with
// no markers, records nothing.
func noteExecution(out *Result, vd *Vendor, v view, session, model string, ts time.Time) {
	if session == "" || len(vd.Execution) == 0 {
		return
	}
	for i := range out.Executions {
		if out.Executions[i].Tool == vd.Tool && out.Executions[i].SessionID == session {
			return
		}
	}
	for _, m := range vd.Execution {
		val := v.str(m.Keys)
		if val == "" {
			continue
		}
		ex := Execution{
			Tool: vd.Tool, SessionID: session, Location: m.Location,
			CreatesSession: m.CreatesSession, Model: model, Timestamp: ts,
		}
		if m.ValueIsVendorRef {
			ex.VendorRef = val
		}
		out.Executions = append(out.Executions, ex)
		return
	}
}

// normalize converts raw input/output counts to the proxy-row convention.
// total is the vendor's own total (0 when absent), read only under
// Normalize.ReasoningByTotal.
func normalize(n Normalize, input, output, total int64, t Turn) (netInput, grossOutput int64) {
	netInput, grossOutput = input, output
	if n.InputIncludesCacheRead {
		netInput -= t.CacheReadTokens
	}
	if n.InputIncludesCacheWrite {
		netInput -= t.CacheWriteTokens
	}
	if netInput < 0 {
		netInput = 0
	}
	if outputExcludesReasoning(n, input, output, total, t.ReasoningTokens) {
		grossOutput += t.ReasoningTokens
	}
	return netInput, grossOutput
}

// outputExcludesReasoning resolves whether a record's output count leaves
// its reasoning out (so the gross output adds it back). Under
// ReasoningByTotal the record's own arithmetic decides when it can; the
// static OutputExcludesReasoning flag is the fallback.
func outputExcludesReasoning(n Normalize, input, output, total, reasoning int64) bool {
	if n.ReasoningByTotal && total > 0 && reasoning > 0 {
		switch total {
		case input + output + reasoning:
			return true
		case input + output:
			return false
		}
	}
	return n.OutputExcludesReasoning
}

// setSpanDuration fills a span-derived turn/tool's duration from the span's
// own start/end when no duration attribute was mapped.
func setSpanDuration(out *Result, k Kind, sp *tracepb.Span) {
	end, start := sp.GetEndTimeUnixNano(), sp.GetStartTimeUnixNano()
	if end <= start {
		return
	}
	ms := int64((end - start) / uint64(time.Millisecond))
	switch k {
	case KindTurn:
		if t := &out.Turns[len(out.Turns)-1]; t.DurationMS == 0 {
			t.DurationMS = ms
		}
	case KindTool:
		if tc := &out.Tools[len(out.Tools)-1]; tc.DurationMS == 0 {
			tc.DurationMS = ms
		}
	}
}

// setSpanGenTiming resolves a span-derived generation timing's duration.
// With Fields.FirstTokenEvent the duration is rebuilt end to end from the
// first-token event (firstTokenSpanMS), and nothing else is a substitute;
// otherwise a mapped duration attribute wins, then the span's own
// start-to-end.
func setSpanGenTiming(gt *GenTiming, f *Fields, sp *tracepb.Span) {
	if f.FirstTokenEvent != "" {
		gt.DurationMS = firstTokenSpanMS(sp, f)
		return
	}
	if gt.DurationMS == 0 {
		if end, start := sp.GetEndTimeUnixNano(), sp.GetStartTimeUnixNano(); end > start {
			gt.DurationMS = int64((end - start) / uint64(time.Millisecond))
		}
	}
}

// firstTokenSpanMS is the call's end-to-end duration in milliseconds: from
// the request start (the first-token event's time minus its time to first
// token) to the span end. 0 when the event, a positive TTFT on it, or a
// consistent ordering is missing.
func firstTokenSpanMS(sp *tracepb.Span, f *Fields) int64 {
	end := sp.GetEndTimeUnixNano()
	for _, ev := range sp.GetEvents() {
		if ev.GetName() != f.FirstTokenEvent {
			continue
		}
		at := ev.GetTimeUnixNano()
		ttft, ok := view{rec: attrMap(ev.GetAttributes()), res: attrMap(sp.GetAttributes())}.num(f.TTFT)
		if !ok || ttft <= 0 || at == 0 || end < at {
			return 0
		}
		ns := int64(end-at) + int64(ttft*float64(time.Millisecond))
		return ns / int64(time.Millisecond)
	}
	return 0
}

// timedOnly drops the generation timings that resolved no positive
// duration: a stamp carries nothing else.
func timedOnly(in []GenTiming) []GenTiming {
	out := in[:0]
	for _, gt := range in {
		if gt.DurationMS > 0 {
			out = append(out, gt)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// spanEventAttrs indexes the attributes of every event on a span, in event
// order, keeping the FIRST value per key (Fields.FromSpanEvents).
func spanEventAttrs(sp *tracepb.Span) attrs {
	m := attrs{}
	for _, ev := range sp.GetEvents() {
		for _, kv := range ev.GetAttributes() {
			if _, seen := m[kv.GetKey()]; !seen {
				m[kv.GetKey()] = kv.GetValue()
			}
		}
	}
	return m
}

// setSpanOutcome resolves a tool call's outcome from its span status when no
// attribute decided it (Fields.SuccessFromStatus). UNSET stays unknown.
func setSpanOutcome(tc *ToolCall, sp *tracepb.Span) {
	if tc.SuccessKnown {
		return
	}
	switch sp.GetStatus().GetCode() {
	case tracepb.Status_STATUS_CODE_ERROR:
		tc.Success, tc.SuccessKnown = false, true
	case tracepb.Status_STATUS_CODE_OK:
		tc.Success, tc.SuccessKnown = true, true
	}
}

// logTime resolves a log record's timestamp: emit time, else observed time,
// else the event.timestamp attribute; zero when none is set.
func logTime(rec interface {
	GetTimeUnixNano() uint64
	GetObservedTimeUnixNano() uint64
	GetAttributes() []*commonpb.KeyValue
},
) time.Time {
	if ns := rec.GetTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	if ns := rec.GetObservedTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	for _, kv := range rec.GetAttributes() {
		if kv.GetKey() == "event.timestamp" {
			if t, ok := parseTimestamp(kv.GetValue().GetStringValue()); ok {
				return t
			}
		}
	}
	return time.Time{}
}

// spanTime is a span's end time (when the call's usage is known), else its
// start time.
func spanTime(sp *tracepb.Span) time.Time {
	if ns := sp.GetEndTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	if ns := sp.GetStartTimeUnixNano(); ns != 0 {
		return time.Unix(0, int64(ns)).UTC()
	}
	return time.Time{}
}

// recordKey is the stable per-record discriminator synthesized ids are built
// from: the span id when there is one, else the record timestamp plus the
// record's ordinal inside its scope (Gemini stamps millisecond times, so two
// records can share one). A retried export resends the same batch, so the
// same record keeps the same key.
func recordKey(ts time.Time, spanID []byte, ordinal int) string {
	if len(spanID) > 0 {
		return hex.EncodeToString(spanID)
	}
	n := int64(0)
	if !ts.IsZero() {
		n = ts.UnixNano()
	}
	return strconv.FormatInt(n, 10) + "-" + strconv.Itoa(ordinal)
}

// synthID builds a deterministic id for a record the export gives no id
// for, so a redelivered record maps to the same row.
func synthID(tool, session, key string) string {
	return "otel:" + tool + ":" + session + ":" + key
}

func isPlaceholder(s string, placeholders []string) bool {
	for _, p := range placeholders {
		if s == p {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
