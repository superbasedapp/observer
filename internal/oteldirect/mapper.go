package oteldirect

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// AgentVersion is the envelope agent_version every mapped export carries
// unless Options.AgentVersion overrides it.
const AgentVersion = "otel-direct/1"

// DefaultContentMaxBytes is the per-row cap on a stored otel_content body. It
// copies the node's config.DefaultIngestOTelContentMaxBytes (32 KiB;
// internal/config is not a pure package) and equals the org ingest's own
// otelContentMaxBytes belt.
const DefaultContentMaxBytes = 32 << 10

// Rejection reasons (Mapped.Reasons). A rejected record lands no row.
const (
	// ReasonUnsupportedTool: the record's resource service.name is in no
	// tool row (ToolForService).
	ReasonUnsupportedTool = "unsupported_tool"
	// ReasonObserverEcho: the resource carries Observer's own echo marker
	// (otlpvendor.IsEcho); Observer never reads its own telemetry back in.
	ReasonObserverEcho = "observer_echo"
	// ReasonUnmappedEvent: the event name is in no entry of the tool's
	// vocabulary (ToolRow.Events), or the record has no event name.
	ReasonUnmappedEvent = "unmapped_event"
	// ReasonNoSession: the record carries no session id.
	ReasonNoSession = "no_session"
	// ReasonNoTimestamp: the record carries no time at all.
	ReasonNoTimestamp = "no_timestamp"
	// ReasonNoRequestID: a model-call record without the vendor request id
	// its otlpvendor rule requires (a turn without it could double a
	// proxied row).
	ReasonNoRequestID = "no_request_id"
	// ReasonTurnUnmapped: a model-call record the otlpvendor row did not
	// turn into a turn for any other reason.
	ReasonTurnUnmapped = "turn_unmapped"
)

// Options tunes MapLogs. The zero value is valid.
type Options struct {
	// AgentVersion is the envelope agent_version; AgentVersion when empty.
	AgentVersion string
	// Scrubber scrubs content bodies, command targets and error text; the
	// default scrubber (scrub.New) when nil.
	Scrubber *scrub.Scrubber
	// ContentMaxBytes caps a stored content body; DefaultContentMaxBytes
	// when <= 0.
	ContentMaxBytes int
}

// Mapped is one export mapped to a push envelope.
type Mapped struct {
	// Envelope carries sessions, actions, api_turns and otel_content only.
	Envelope orgcontract.PushEnvelope
	// Records is every log record in the export: Records = Accepted +
	// Rejected.
	Records int
	// Accepted counts the records that landed at least one row, plus the
	// known-but-unmapped ones (Ignored is a subset of Accepted).
	Accepted int
	// Ignored counts accepted records of a known event phase 1 does not map
	// that produced no row (EventIgnored, e.g. tool_decision).
	Ignored int
	// Rejected counts the records that landed nothing, by reason in Reasons.
	Rejected int
	// Reasons counts the rejected records per Reason* value.
	Reasons map[string]int
	// Tools lists the tool ids of the accepted records, sorted.
	Tools []string
}

// sessionAgg accumulates one session's facts across an export.
type sessionAgg struct {
	id                    string
	row                   *ToolRow
	first, last           time.Time
	firstVer, lastVer     string
	firstVerAt, lastVerAt time.Time
	entrypoint            string
	root, remote          string
	branch                string
	branchAt              time.Time
	models                map[string]int
	actions               int
	execLocation          string
	execRef               string
	execSet               bool
}

// touch extends the session's span and facts by one accepted record.
func (s *sessionAgg) touch(row *ToolRow, a attrs, at time.Time) {
	if s.first.IsZero() || at.Before(s.first) {
		s.first = at
	}
	if at.After(s.last) {
		s.last = at
	}
	if v := a.str(row.Attrs.Version); v != "" {
		if s.firstVer == "" || at.Before(s.firstVerAt) {
			s.firstVer, s.firstVerAt = v, at
		}
		if s.lastVer == "" || !at.Before(s.lastVerAt) {
			s.lastVer, s.lastVerAt = v, at
		}
	}
	if s.entrypoint == "" {
		s.entrypoint = a.str(row.Attrs.Entrypoint)
	}
	if s.root == "" {
		s.root = a.str(row.Attrs.HostPaths)
	}
	if s.remote == "" {
		s.remote = a.str(row.Attrs.RepositoryURL)
	}
	if b := a.str(row.Attrs.Branch); b != "" && (s.branch == "" || !at.Before(s.branchAt)) {
		s.branch, s.branchAt = b, at
	}
}

// mapper is one MapLogs run.
type mapper struct {
	opts     Options
	out      Mapped
	sessions map[string]*sessionAgg
	order    []string
	tools    map[string]bool
}

// MapLogs maps one OTLP logs export to a push envelope. Every record is
// either accepted (into at least one row, or as a known-but-unmapped event)
// or rejected with a reason. The export's identity attributes (user.email,
// user.id, user.account_uuid, organization.id) are never read.
func MapLogs(req *collogspb.ExportLogsServiceRequest, opts Options) Mapped {
	if opts.AgentVersion == "" {
		opts.AgentVersion = AgentVersion
	}
	if opts.Scrubber == nil {
		opts.Scrubber = defaultScrubber
	}
	if opts.ContentMaxBytes <= 0 {
		opts.ContentMaxBytes = DefaultContentMaxBytes
	}
	m := &mapper{
		opts:     opts,
		out:      Mapped{Reasons: map[string]int{}},
		sessions: map[string]*sessionAgg{},
		tools:    map[string]bool{},
	}
	m.out.Envelope.AgentVersion = opts.AgentVersion
	for _, rl := range req.GetResourceLogs() {
		m.resource(rl)
	}
	m.finish()
	return m.out
}

var defaultScrubber = scrub.New()

func (m *mapper) reject(reason string, n int) {
	if n <= 0 {
		return
	}
	m.out.Rejected += n
	m.out.Reasons[reason] += n
}

// resource maps one ResourceLogs.
func (m *mapper) resource(rl *logspb.ResourceLogs) {
	n := 0
	for _, sl := range rl.GetScopeLogs() {
		n += len(sl.GetLogRecords())
	}
	m.out.Records += n
	resAttrs := rl.GetResource().GetAttributes()
	if otlpvendor.IsEcho(resAttrs) {
		m.reject(ReasonObserverEcho, n)
		return
	}
	row := rowForService(indexAttrs(resAttrs).str([]string{"service.name"}))
	if row == nil {
		m.reject(ReasonUnsupportedTool, n)
		return
	}
	for _, sl := range rl.GetScopeLogs() {
		for _, rec := range sl.GetLogRecords() {
			m.record(row, rl, sl, rec)
		}
	}
}

// kindOf resolves a record's event kind through the row's vocabulary.
func (r *ToolRow) kindOf(names []string) (EventKind, bool) {
	for _, n := range names {
		if n == "" {
			continue
		}
		if k, ok := r.Events[n]; ok {
			return k, true
		}
	}
	return 0, false
}

// record maps one log record.
func (m *mapper) record(row *ToolRow, rl *logspb.ResourceLogs, sl *logspb.ScopeLogs, rec *logspb.LogRecord) {
	a := indexAttrs(rec.GetAttributes())
	kind, ok := row.kindOf(eventNames(rec, a))
	if !ok {
		m.reject(ReasonUnmappedEvent, 1)
		return
	}
	sid := a.str(row.Attrs.Session)
	if sid == "" {
		m.reject(ReasonNoSession, 1)
		return
	}
	at := recordTime(rec, a)
	if at.IsZero() {
		m.reject(ReasonNoTimestamp, 1)
		return
	}
	// The otlpvendor row of the same tool maps the record's turn, content
	// and cloud-execution marker. One record per call keeps the per-record
	// accounting exact.
	res := otlpvendor.ParseLogs(&collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: rl.GetResource(), SchemaUrl: rl.GetSchemaUrl(),
		ScopeLogs: []*logspb.ScopeLogs{{Scope: sl.GetScope(), SchemaUrl: sl.GetSchemaUrl(), LogRecords: []*logspb.LogRecord{rec}}},
	}}})
	c := &recordCtx{row: row, a: a, sid: sid, at: at, root: a.str(row.Attrs.HostPaths), res: res}
	km := kindMappers[kind]
	produced, reason := km.rows(m, c)
	if reason != "" {
		m.reject(reason, 1)
		return
	}
	produced += m.contents(c)
	s := m.session(row, sid)
	s.noteExecution(c)
	for _, mo := range c.turnModels {
		if mo != "" {
			s.models[mo]++
		}
	}
	if km.isAction {
		s.actions++
	}
	s.touch(row, a, at)
	m.tools[row.Tool] = true
	m.out.Accepted++
	if produced == 0 {
		m.out.Ignored++
	}
}

// recordCtx is one accepted-so-far record being mapped.
type recordCtx struct {
	row        *ToolRow
	a          attrs
	sid        string
	at         time.Time
	root       string
	res        otlpvendor.Result
	turnModels []string
}

// kindMapper is how one event kind becomes rows: rows appends them and
// returns how many, or a rejection reason; isAction marks the kinds whose
// row is an action (counted into the session's total_actions).
type kindMapper struct {
	rows     func(*mapper, *recordCtx) (int, string)
	isAction bool
}

// kindMappers is the event-kind table: one row per EventKind.
var kindMappers = map[EventKind]kindMapper{
	EventTurn:       {rows: (*mapper).turnRows},
	EventToolResult: {rows: (*mapper).toolResultRow, isAction: true},
	EventPrompt:     {rows: (*mapper).promptRow, isAction: true},
	EventAPIError:   {rows: (*mapper).apiErrorRow, isAction: true},
	// Known, not mapped in phase 1; a content row may still land.
	EventIgnored: {rows: func(*mapper, *recordCtx) (int, string) { return 0, "" }},
}

// turnRows lands the record's otlpvendor turn as an api_turns row.
func (m *mapper) turnRows(c *recordCtx) (int, string) {
	n := 0
	for _, t := range c.res.Turns {
		if t.Tool != c.row.Tool || t.SessionID != c.sid {
			continue
		}
		m.out.Envelope.APITurns = append(m.out.Envelope.APITurns, orgcontract.APITurnRow{
			SessionID: c.sid, ProjectRoot: c.root, ProjectRootHash: hashRaw(c.root),
			Timestamp: stamp(t.Timestamp), Provider: t.Provider, Model: t.Model, RequestID: t.RequestID,
			InputTokens: t.InputTokens, OutputTokens: t.OutputTokens,
			CacheReadTokens: t.CacheReadTokens, CacheCreationTokens: t.CacheWriteTokens,
			CacheCreation1hTokens: t.CacheWrite1hTokens, CostUSD: t.CostUSD,
			TimeToFirstTokenMS: t.TimeToFirstTokenMS, TotalResponseMS: t.DurationMS, HTTPStatus: 200,
		})
		c.turnModels = append(c.turnModels, t.Model)
		n++
	}
	switch {
	case n > 0:
		return n, ""
	case c.res.Skipped > 0:
		return 0, ReasonNoRequestID
	}
	return 0, ReasonTurnUnmapped
}

// toolResultRow lands a tool_result as an action.
func (m *mapper) toolResultRow(c *recordCtx) (int, string) {
	m.out.Envelope.Actions = append(m.out.Envelope.Actions, m.toolAction(c.row, c.a, c.sid, c.at, c.root))
	return 1, ""
}

// promptRow lands a user prompt as a user_prompt action.
func (m *mapper) promptRow(c *recordCtx) (int, string) {
	id := c.a.str(c.row.Attrs.PromptID)
	if id == "" {
		id = synthID("", c.sid, c.at, "prompt")
	}
	m.out.Envelope.Actions = append(m.out.Envelope.Actions, m.baseAction(c.row, c.sid, c.at, "prompt:"+id, models.ActionUserPrompt, true))
	return 1, ""
}

// apiErrorRow lands a failed model call as a failed api_error action.
func (m *mapper) apiErrorRow(c *recordCtx) (int, string) {
	id := c.a.str(c.row.Attrs.RequestID)
	if id == "" {
		id = synthID("", c.sid, c.at, "api_error")
	}
	act := m.baseAction(c.row, c.sid, c.at, "apierr:"+id, models.ActionAPIError, false)
	act.DurationMs = c.a.int64Of(c.row.Attrs.Duration)
	if e := c.a.str(c.row.Attrs.Error); e != "" {
		act.ErrorMessage = scrub.Truncate(m.opts.Scrubber.String(e))
	}
	m.out.Envelope.Actions = append(m.out.Envelope.Actions, act)
	return 1, ""
}

// contents lands the record's otlpvendor content bodies: scrubbed, hashed
// over the FULL scrubbed body, then capped (the node's rule:
// cmd/observer/otlp_ingest.go ingestContent, store.HashOTelContent).
func (m *mapper) contents(c *recordCtx) int {
	n := 0
	for _, ct := range c.res.Contents {
		if ct.Tool != c.row.Tool || ct.SessionID != c.sid {
			continue
		}
		scrubbed := m.opts.Scrubber.String(ct.Content)
		ts := c.at
		if ct.TimeUnixNano != 0 {
			ts = time.Unix(0, int64(ct.TimeUnixNano)).UTC()
		}
		m.out.Envelope.OTelContent = append(m.out.Envelope.OTelContent, orgcontract.OTelContentRow{
			RequestID: ct.RequestID, SessionID: c.sid, ToolUseID: ct.ToolUseID, Kind: ct.Kind,
			ContentHash: hashRaw(scrubbed), Content: scrub.TruncateN(scrubbed, m.opts.ContentMaxBytes),
			Timestamp: stamp(ts),
		})
		n++
	}
	return n
}

// noteExecution records the session's cloud-execution marker, first wins;
// a vendor reference that fails orgcontract.ValidVendorSessionRef is
// dropped and the location kept.
func (s *sessionAgg) noteExecution(c *recordCtx) {
	for _, ex := range c.res.Executions {
		if s.execSet || ex.Tool != c.row.Tool || ex.SessionID != c.sid {
			continue
		}
		s.execSet, s.execLocation = true, ex.Location
		if ex.VendorRef != "" && orgcontract.ValidVendorSessionRef(ex.VendorRef) {
			s.execRef = ex.VendorRef
		}
	}
}

// session returns (creating) the aggregate of session sid.
func (m *mapper) session(row *ToolRow, sid string) *sessionAgg {
	s := m.sessions[sid]
	if s == nil {
		s = &sessionAgg{id: sid, row: row, models: map[string]int{}}
		m.sessions[sid] = s
		m.order = append(m.order, sid)
	}
	return s
}

// baseAction is the part every mapped action shares.
func (m *mapper) baseAction(row *ToolRow, sid string, at time.Time, sourceEventID, actionType string, success bool) orgcontract.ActionRow {
	src := SourceFileFor(row.Tool)
	return orgcontract.ActionRow{
		SessionID: sid, SourceEventID: sourceEventID, Timestamp: stamp(at),
		Tool: row.Tool, ActionType: actionType,
		SourceFile: src, SourceFileHash: hashRaw(src), Success: success,
	}
}

// toolAction maps one tool_result record.
func (m *mapper) toolAction(row *ToolRow, a attrs, sid string, at time.Time, root string) orgcontract.ActionRow {
	name := a.str(row.Attrs.ToolName)
	id := a.str(row.Attrs.ToolUseID)
	if id == "" {
		id = synthID("tool:", sid, at, name)
	}
	actionType := ActionTypeFor(row.Tool, name)
	success, known := a.boolOf(row.Attrs.Success)
	act := m.baseAction(row, sid, at, id, actionType, !known || success)
	act.DurationMs = a.int64Of(row.Attrs.Duration)
	act.MessageID = a.str(row.Attrs.RequestID)
	if target := m.target(row, actionType, a.str(row.Attrs.ToolParameters), root); target != "" {
		act.Target, act.TargetHash = target, hashRaw(target)
	}
	return act
}

// target reads an action's target from the tool-parameters JSON through the
// row's target rule for the action type.
func (m *mapper) target(row *ToolRow, actionType, params, root string) string {
	rule, ok := row.Targets[actionType]
	if !ok || params == "" {
		return ""
	}
	var in map[string]any
	if json.Unmarshal([]byte(params), &in) != nil {
		return ""
	}
	v := ""
	for _, k := range rule.Keys {
		if s, ok := in[k].(string); ok && strings.TrimSpace(s) != "" {
			v = s
			break
		}
	}
	if v == "" {
		return ""
	}
	if rule.RelativeToRoot {
		v = relativeTo(root, v)
	}
	if rule.Scrub {
		v = m.opts.Scrubber.String(v)
	}
	return v
}

// actionMaps holds each table tool's native-name to action-type map, read
// out of internal/tooltax: the same source the node's adapters use
// (internal/adapter/claudecode/adapter.go actionMap = tooltax.For).
var actionMaps = func() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, r := range toolRows {
		out[r.Tool] = tooltax.For(r.Tool)
	}
	return out
}()

// ActionTypeFor is the action type of tool's native tool name native, the
// node adapter's rule: the tooltax literal rows, else mcp_call for an
// mcp__<server>__<tool> name, else unknown.
func ActionTypeFor(tool, native string) string {
	if t, ok := actionMaps[tool][native]; ok {
		return t
	}
	if models.IsMCPToolName(native) {
		return models.ActionMCPCall
	}
	return models.ActionUnknown
}

// finish synthesizes the session rows and the tool list.
func (m *mapper) finish() {
	for _, id := range m.order {
		s := m.sessions[id]
		row := orgcontract.SessionRow{
			ID: id, Tool: s.row.Tool, Model: majority(s.models),
			StartedAt: stamp(s.first), EndedAt: stamp(s.last), TotalActions: s.actions,
			ProjectRoot: s.root, ProjectRootHash: hashRaw(s.root),
			GitRemote: s.remote, GitRemoteHash: hashRaw(s.remote), GitBranch: s.branch,
			ToolVersion: s.firstVer, ToolVersionLast: s.lastVer,
			ExecutionLocation: s.execLocation, VendorSessionRef: s.execRef,
		}
		if sf, ok := s.row.surface(s.entrypoint); ok {
			row.Surface, row.SurfaceHost = sf.Kind, sf.Host
		}
		m.out.Envelope.Sessions = append(m.out.Envelope.Sessions, row)
	}
	for t := range m.tools {
		m.out.Tools = append(m.out.Tools, t)
	}
	sort.Strings(m.out.Tools)
}

// majority is the most frequent model, ties broken by lexical order.
func majority(counts map[string]int) string {
	best, n := "", 0
	for mo, c := range counts {
		if c > n || (c == n && mo < best) {
			best, n = mo, c
		}
	}
	return best
}
