package cloudagents

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Server-sent events (the WHATWG event-stream format) and the Cursor run
// stream reducer (lane CA-B2). The egress package reads the response body
// line by line and feeds each line to an SSEDecoder; the decoder is pure, so
// the stream contract is tested from recorded streams without a network.

// MaxSSEEventID bounds an event id kept as a resume position.
const MaxSSEEventID = 300

// SSEEvent is one dispatched event.
type SSEEvent struct {
	// ID is the stream's last event id when the event was dispatched (the
	// value a resumed request sends as Last-Event-ID).
	ID string
	// Event is the event type ("message" when the stream named none).
	Event string
	// Data is the event's data lines joined with "\n".
	Data string
}

// SSEDecoder turns event-stream lines into events.
type SSEDecoder struct {
	lastID string
	event  string
	data   []string
	has    bool
}

// LastEventID is the last id the stream set ("" before any).
func (d *SSEDecoder) LastEventID() string { return d.lastID }

// Line feeds one line (without its line terminator) and returns the event a
// blank line dispatches. Comment lines (":") and unknown fields are ignored;
// an id carrying NUL is ignored, as the format requires.
func (d *SSEDecoder) Line(line string) (SSEEvent, bool) {
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		if !d.has {
			d.event = ""
			return SSEEvent{}, false
		}
		ev := SSEEvent{ID: d.lastID, Event: d.event, Data: strings.Join(d.data, "\n")}
		if ev.Event == "" {
			ev.Event = "message"
		}
		d.event, d.data, d.has = "", nil, false
		return ev, true
	}
	if strings.HasPrefix(line, ":") {
		return SSEEvent{}, false
	}
	field, value, found := strings.Cut(line, ":")
	if found {
		value = strings.TrimPrefix(value, " ")
	}
	switch field {
	case "event":
		d.event = value
	case "data":
		d.data = append(d.data, value)
		d.has = true
	case "id":
		if !strings.ContainsRune(value, 0) && len(value) <= MaxSSEEventID {
			d.lastID = value
		}
	}
	return SSEEvent{}, false
}

// ActivityKind is the closed kind of one activity record a connector lands
// as metadata (never text).
type ActivityKind string

const (
	// ActivityPrompt is a message a person sent.
	ActivityPrompt ActivityKind = "prompt"
	// ActivityResponse is a message the agent sent.
	ActivityResponse ActivityKind = "response"
	// ActivityToolCall is one tool call the agent made.
	ActivityToolCall ActivityKind = "tool_call"
)

// Activity is one history or stream record, already reduced to metadata:
// when, what kind, which tool and, for a tool call, the one argument a local
// adapter keeps as its target (a path, a glob, a command; scrubbed and
// capped). Prompt and response text, the other arguments and tool output
// are never carried.
type Activity struct {
	// ID is stable per session (dedup key with the connector's source file).
	ID   string
	At   time.Time
	Kind ActivityKind
	// Tool is the vendor's tool name (a bounded token), for a tool call.
	Tool string
	// Target is the call's target argument, scrubbed and capped ("" when
	// the tool has none or it was not reported).
	Target string
	// Failed is true when the vendor reported the call failed.
	Failed bool
	// OutcomeKnown is true when the call's completion was seen, so Failed
	// is measured; a call still running when the read ended is not (the
	// completion read later patches it, MapOutcomes).
	OutcomeKnown bool
	// Pending marks a tool call whose outcome is not known yet (only the
	// Cursor run streams report that; history records are final).
	Pending bool
}

// cursorStreamRule is one row of the Cursor run-stream event table
// (reference chapter 02, CU01: status, assistant, thinking, tool_call,
// interaction_update, heartbeat, result, error, done).
type cursorStreamRule struct {
	// tool is true when the event is a tool lifecycle record.
	tool bool
	// status is true when the event carries a run status.
	status bool
	// done ends the stream.
	done bool
}

var cursorStreamRules = map[string]cursorStreamRule{
	"status":             {status: true},
	"assistant":          {}, // text delta: counted, never stored
	"thinking":           {}, // reasoning delta: counted, never stored
	"tool_call":          {tool: true},
	"interaction_update": {},
	"heartbeat":          {},
	"result":             {status: true},
	"error":              {},
	"done":               {done: true},
}

// cursorStreamData is the shape of an event's data, live-verified
// 2026-11-01: a tool_call event is {callId, name, status, args?, result?};
// status and result events carry {runId, status, ...}. Each call arrives as
// two or three "running" events (the first without args) and one
// "completed" event carrying result ({success:{...}} or
// {error:{errorMessage}}). Arguments are kept as raw JSON only long enough
// to pick the target; the result is never decoded beyond whether it
// succeeded (and, for create_agent, the child agent id).
type cursorStreamData struct {
	CallID string          `json:"callId"`
	Name   string          `json:"name"`
	Status string          `json:"status"`
	Args   json.RawMessage `json:"args"`
	Result *struct {
		Success json.RawMessage `json:"success"`
		Error   json.RawMessage `json:"error"`
	} `json:"result"`
}

// reCallID is a call id usable verbatim inside an action id.
var reCallID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

// callKey is a stable key for a vendor call id: the id itself when it is a
// plain token, else a digest of it. Live call ids are not always plain
// tokens; the old fallback keyed such calls by their event sequence, so
// every event of one call landed as its own action (18 calls, 72 actions,
// live check 2026-11-01). A digest keeps one call one action across reads.
func callKey(id string) string {
	if reCallID.MatchString(id) {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return "h" + hex.EncodeToString(sum[:12])
}

// eventTime reads a Cursor event id "<epoch milliseconds>-<sequence>"
// (live-verified); ok is false when the id does not have that shape.
func eventTime(id string) (time.Time, bool) {
	ms, _, found := strings.Cut(id, "-")
	if !found {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	// 2001 .. 2286: an epoch in milliseconds, not a counter.
	if err != nil || n < 1e12 || n >= 1e13 {
		return time.Time{}, false
	}
	return time.UnixMilli(n).UTC(), true
}

// cursorToolArgs is, per live tool name, the argument a local adapter keeps
// as its target. A tool not listed keeps none: communicate_update and
// send_message carry message text, create_agent a prompt (its target is the
// child agent id from its result instead).
var cursorToolArgs = map[string][]string{
	"read_file":        {"path"},
	"edit_file":        {"path"},
	"file_search":      {"globPattern"},
	"run_terminal_cmd": {"command"},
}

// toolSpawnsAgent names the tools whose success result carries the id of a
// child agent the call created (live: create_agent {success:{agentId}}).
var toolSpawnsAgent = map[string]bool{"create_agent": true}

// maxActivityTarget caps a stored target (after scrubbing).
const maxActivityTarget = 2048

// targetScrubber is the scrubber the local adapters use for targets.
var targetScrubber = sync.OnceValue(scrub.New)

// cleanTarget scrubs and caps a target argument.
func cleanTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return scrub.TruncateN(targetScrubber().String(s), maxActivityTarget)
}

// argTarget picks a tool's target from its raw arguments.
func argTarget(tool string, args json.RawMessage) string {
	keys := cursorToolArgs[tool]
	if len(keys) == 0 || len(args) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil {
		return ""
	}
	for _, k := range keys {
		var s string
		if json.Unmarshal(m[k], &s) == nil && s != "" {
			return cleanTarget(s)
		}
	}
	return ""
}

// callState is one tool call being reduced within a read.
type callState struct {
	act     Activity
	hasArgs bool
	emitted int // index in Activity + 1 (0 = not emitted yet)
}

// RunStream reduces one Cursor run's event stream to ONE activity per tool
// call (callId), never one per event.
type RunStream struct {
	// RunID scopes activity ids ("run:<id>:...").
	RunID string
	// Activity are the tool calls, in the order they became known, one per
	// call id. A call is emitted once its arguments or its completion are
	// seen (the first "running" event carries neither); a call whose
	// completion arrives in a later read is emitted again there under the
	// same id, which patches the outcome (MapOutcomes) without a second row.
	Activity []Activity
	// Children are the agent ids a create_agent call reported creating,
	// in stream order (the only link from a child agent to its parent).
	Children []string
	// Status is the last run status a status or result event carried
	// (lowercased token, "" when none).
	Status string
	// Done is true once the stream sent done.
	Done bool
	// Events counts dispatched events; Unknown counts event types outside
	// the table (a drift signal; the type name is never kept).
	Events  int
	Unknown int
	// LastAt is the newest time the stream reached (the receive time of
	// the last event, from the caller's clock).
	LastAt time.Time
	calls  map[string]*callState
	order  []string
}

// Add folds one event in, received at at, and reports whether to keep
// reading. A tool call's time is its first event's (the event id's epoch
// milliseconds); when an id does not carry a time, the activity's At stays
// zero and the caller supplies one.
func (r *RunStream) Add(ev SSEEvent, at time.Time) bool {
	r.Events++
	if at.After(r.LastAt) {
		r.LastAt = at
	}
	rule, ok := cursorStreamRules[ev.Event]
	if !ok {
		r.Unknown++
		return true
	}
	if rule.done {
		r.Done = true
		r.flush()
		return false
	}
	if !rule.tool && !rule.status {
		return true
	}
	var d cursorStreamData
	if err := json.Unmarshal([]byte(ev.Data), &d); err != nil {
		return true
	}
	if rule.status && d.Status != "" {
		r.Status = boundToken(d.Status)
	}
	if rule.tool {
		r.addCall(ev, d)
	}
	return true
}

// addCall folds one tool_call event into its call.
func (r *RunStream) addCall(ev SSEEvent, d cursorStreamData) {
	raw := strings.TrimSpace(d.CallID)
	if raw == "" {
		raw = "ev:" + ev.ID // no call id at all: the event is its own call
	}
	id := "run:" + r.RunID + ":tool:" + callKey(raw)
	if r.calls == nil {
		r.calls = map[string]*callState{}
	}
	cs, seen := r.calls[id]
	if !seen {
		cs = &callState{act: Activity{ID: id, Kind: ActivityToolCall, Pending: true}}
		if t, ok := eventTime(ev.ID); ok {
			cs.act.At = t
		}
		r.calls[id] = cs
		r.order = append(r.order, id)
	}
	if name := toolToken(d.Name); name != "" && (cs.act.Tool == "" || cs.act.Tool == "other") {
		cs.act.Tool = name
	}
	if len(d.Args) > 0 && string(d.Args) != "null" {
		cs.hasArgs = true
		if t := argTarget(cs.act.Tool, d.Args); t != "" {
			cs.act.Target = t
		}
	}
	if d.Result != nil || completedStatus[boundToken(d.Status)] || failedStatus[boundToken(d.Status)] {
		cs.act.OutcomeKnown, cs.act.Pending = true, false
		cs.act.Failed = failedStatus[boundToken(d.Status)] || (d.Result != nil && len(d.Result.Error) > 0 && string(d.Result.Error) != "null")
		if !cs.act.Failed && d.Result != nil && toolSpawnsAgent[cs.act.Tool] {
			r.addChild(cs, d.Result.Success)
		}
	}
	if cs.hasArgs || cs.act.OutcomeKnown {
		r.emit(cs)
	}
}

// addChild records the child agent a successful spawn reported; the id is
// the call's target (an id, not content). Nothing is guessed: a result
// without a valid agent id records none.
func (r *RunStream) addChild(cs *callState, success json.RawMessage) {
	var s struct {
		AgentID string `json:"agentId"`
	}
	if json.Unmarshal(success, &s) != nil || !reAgentID.MatchString(s.AgentID) {
		return
	}
	cs.act.Target = s.AgentID
	for _, c := range r.Children {
		if c == s.AgentID {
			return
		}
	}
	r.Children = append(r.Children, s.AgentID)
}

// reAgentID is a Cursor cloud agent id (bc-<uuid>, the A4 driver's rule).
var reAgentID = regexp.MustCompile(`^bc[-_][A-Za-z0-9_-]{1,200}$`)

// emit puts the call's current state into Activity (once; later updates
// rewrite its slot).
func (r *RunStream) emit(cs *callState) {
	if cs.emitted == 0 {
		r.Activity = append(r.Activity, cs.act)
		cs.emitted = len(r.Activity)
		return
	}
	r.Activity[cs.emitted-1] = cs.act
}

// flush emits the calls still waiting for arguments when the stream ends
// for good (done): they will not get them later.
func (r *RunStream) flush() {
	for _, id := range r.order {
		if cs := r.calls[id]; cs.emitted == 0 {
			r.emit(cs)
		}
	}
}

// completedStatus are the tool-call statuses that mean the call finished.
var completedStatus = map[string]bool{"completed": true, "succeeded": true, "success": true}

// failedStatus are the tool-call statuses that mean the call failed.
var failedStatus = map[string]bool{"error": true, "failed": true, "rejected": true}

// toolToken bounds a vendor tool name: letters, digits and "_.-:", at most
// 64 bytes, case kept (the taxonomy normalizes it); anything else is
// "other".
func toolToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxToken {
		s = s[:maxToken]
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return "other"
		}
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// StreamState is the per-run checkpoint of a live stream.
type StreamState string

const (
	// StreamOpen: the stream was read up to a resume position and may have
	// more.
	StreamOpen StreamState = "open"
	// StreamDone: the stream sent done; nothing more to read.
	StreamDone StreamState = "done"
	// StreamExpired: the stream could not be resumed (retention passed);
	// the uncovered interval is a gap on the checkpoint.
	StreamExpired StreamState = "expired"
)

// StreamCursor is a live checkpoint's cursor: the resume position and the
// stream's state.
type StreamCursor struct {
	LastEventID string      `json:"id,omitempty"`
	State       StreamState `json:"s"`
}

// EncodeStreamCursor renders a stream cursor for the checkpoint.
func EncodeStreamCursor(c StreamCursor) string {
	if len(c.LastEventID) > MaxSSEEventID {
		c.LastEventID = ""
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// DecodeStreamCursor reads a checkpoint cursor; junk reads as no position.
func DecodeStreamCursor(s string) StreamCursor {
	var c StreamCursor
	if json.Unmarshal([]byte(s), &c) != nil {
		return StreamCursor{}
	}
	switch c.State {
	case StreamOpen, StreamDone, StreamExpired:
	default:
		return StreamCursor{}
	}
	return c
}

// StreamAction is what a pass does with one run's stream.
type StreamAction string

const (
	StreamSkip      StreamAction = "skip"
	StreamFromStart StreamAction = "from_start"
	StreamResume    StreamAction = "resume"
	// StreamPastRetention: the run ended longer ago than the vendor keeps
	// its stream, so it is recorded as a gap without a request (a request
	// would only answer 410 stream_expired and spend a stream slot).
	StreamPastRetention StreamAction = "past_retention"
)

// StreamPlanInput is what the plan table decides on: the run, its stored
// checkpoint (Found false when none), the time of the pass and the stream
// retention in force (0 = not known: nothing is skipped for age).
type StreamPlanInput struct {
	Run       Run
	Cursor    StreamCursor
	Found     bool
	Now       time.Time
	Retention time.Duration
}

// streamRule is one row of the stream plan table, walked top-down.
type streamRule struct {
	name   string
	match  func(in StreamPlanInput) bool
	action StreamAction
}

var streamRules = []streamRule{
	{"a stream that sent done is never re-read", func(in StreamPlanInput) bool {
		return in.Found && in.Cursor.State == StreamDone
	}, StreamSkip},
	{"an expired stream stays a recorded gap", func(in StreamPlanInput) bool {
		return in.Found && in.Cursor.State == StreamExpired
	}, StreamSkip},
	{"a run that ended longer ago than the retention is a gap, not a request", func(in StreamPlanInput) bool {
		// Never a run still going (or of unknown state): only an ended
		// run's stream stops being replayable.
		return in.Retention > 0 && in.Run.Lifecycle.Terminal() && !in.Run.UpdatedAt.IsZero() &&
			in.Now.Sub(in.Run.UpdatedAt) > in.Retention
	}, StreamPastRetention},
	{"a stored position resumes with Last-Event-ID", func(in StreamPlanInput) bool {
		return in.Found && in.Cursor.LastEventID != ""
	}, StreamResume},
	{"a run never read is read from its start (live or within retention)", func(StreamPlanInput) bool {
		return true
	}, StreamFromStart},
}

// PlanStream returns what to do with a run's stream and the rule that
// decided.
func PlanStream(in StreamPlanInput) (StreamAction, string) {
	for _, r := range streamRules {
		if r.match(in) {
			return r.action, r.name
		}
	}
	return StreamSkip, ""
}

// StreamRetentionFor is the stream retention a pass plans with: the last
// retention the vendor sent (X-Cursor-Stream-Retention-Seconds, observed
// seconds > 0), else the row's default (0 when the row declares none).
func StreamRetentionFor(c Connector, observedSeconds int64) time.Duration {
	if observedSeconds > 0 {
		return time.Duration(observedSeconds) * time.Second
	}
	return c.StreamRetention
}

// StreamRetentionScope is the scope of the account-level live checkpoint
// that keeps the last observed stream retention (a run's scope is
// "<agent>/<run>", so it cannot collide).
const StreamRetentionScope = "retention"

// EncodeStreamRetention renders an observed retention for that checkpoint.
func EncodeStreamRetention(seconds int64) string {
	b, _ := json.Marshal(struct {
		Seconds int64 `json:"retention_s"`
	}{seconds})
	return string(b)
}

// DecodeStreamRetention reads it back (0 for junk or none).
func DecodeStreamRetention(s string) int64 {
	var v struct {
		Seconds int64 `json:"retention_s"`
	}
	if json.Unmarshal([]byte(s), &v) != nil || v.Seconds < 0 {
		return 0
	}
	return v.Seconds
}

// StreamEndReason says how one stream read ended.
type StreamEndReason string

const (
	// StreamEndDone: the consumer stopped (the stream sent done).
	StreamEndDone StreamEndReason = "done"
	// StreamEndWindow: the read window elapsed; resume from the last id.
	StreamEndWindow StreamEndReason = "window"
	// StreamEndEOF: the server closed the stream; resume from the last id.
	StreamEndEOF StreamEndReason = "eof"
	// StreamEndCapped: the byte cap was reached; resume from the last id.
	StreamEndCapped StreamEndReason = "capped"
)

// StreamEnd is how a stream read ended and what the vendor said about its
// retention (X-Cursor-Stream-Retention-Seconds; 0 when not sent).
type StreamEnd struct {
	Reason           StreamEndReason
	RetentionSeconds int64
}
