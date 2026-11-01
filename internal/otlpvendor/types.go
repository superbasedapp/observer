package otlpvendor

import "time"

// Signal names which OTLP signal a Rule reads.
type Signal int

// Signals a Rule can read.
const (
	// SignalLogs reads LogRecords; a rule's Names match the event name (the
	// event.name attribute or the typed LogRecord.EventName field).
	SignalLogs Signal = iota + 1
	// SignalSpans reads Spans; a rule's Names match the span name (exactly,
	// or as a prefix when NamePrefix is set).
	SignalSpans
)

// Kind names what a matched record becomes.
type Kind int

// Record kinds.
const (
	// KindTurn is one model call with token usage.
	KindTurn Kind = iota + 1
	// KindTool is one tool call.
	KindTool
	// KindContent is one captured content body (prompt, tool input/output).
	KindContent
	// KindGenTiming is one model call's generation duration, keyed so it can
	// be stamped onto the tool's OWN transcript token row for the same call
	// (Vendor.TranscriptTiming). It never becomes a turn and carries no
	// tokens.
	KindGenTiming
)

// Grain says whose data one export carries. It decides WHERE the export may
// land: a user-grain export is one developer's own activity and belongs on
// that developer's node; a team-grain export is configured once by an admin
// for a whole team and is sent from the vendor's cloud, so it belongs on the
// org server (never on one developer's node).
type Grain string

// Export grains.
const (
	GrainUser Grain = "user"
	GrainTeam Grain = "team"
)

// Content kinds carried on Content.Kind. They equal the otel_content kinds
// the Claude Code path has always written.
const (
	ContentPrompt     = "prompt"
	ContentToolInput  = "tool_input"
	ContentToolOutput = "tool_output"
	ContentRawBody    = "raw_body"
)

// Turn is one model call normalized to the proxy-row token convention:
// InputTokens is NET of cache reads (and of cache writes where the vendor
// counts them inside input) and OutputTokens is GROSS of reasoning, so a
// turn folds against the same call's transcript row in internal/sessionmsg
// exactly the way a proxy row does.
type Turn struct {
	Tool      string
	SourceTag string
	Provider  string
	SessionID string
	// RequestID is the vendor's per-call id when the export carries one,
	// otherwise a deterministic id derived from the record (RequestSynthetic
	// true), so an at-least-once redelivery of the same record upserts the
	// same row instead of adding one.
	RequestID        string
	RequestSynthetic bool
	Model            string
	Timestamp        time.Time
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	ReasoningTokens  int64
	CostUSD          float64
	DurationMS       int64
	// TimeToFirstTokenMS is the vendor's own time-to-first-token for the
	// call (Fields.TTFT); 0 when the export carries none. It lands on
	// api_turns.time_to_first_token_ms, an enrichment column the merge
	// fills only when empty (internal/turnmerge).
	TimeToFirstTokenMS int64
	// ViaProxyRoute: the export's resource carries the launcher's route
	// marker (RouteResourceAttr=RouteProxy), so this call went through the
	// node's proxy.
	ViaProxyRoute bool
	// Member identifies the team member a TEAM-grain export's call belongs
	// to (T-535: the org server lands it per member). Empty on a user-grain
	// export, and on a team call the vendor sent with no owner (a service
	// account or team API key run), which the org server holds visibly as
	// unmatched rather than dropping.
	Member Member
	// BillingID is the vendor's request-grain billing key when the export
	// carries one (Cursor cursor.usage_event.id), used by the org server to
	// join a billing correction to its call.
	BillingID string
}

// Member is a team export's per-call owner, as the vendor reports it.
type Member struct {
	Email string
	// UserID / AccountID are the vendor's own ids (Cursor cursor.user.id
	// and cursor.user.account_id, the Admin API member id).
	UserID    string
	AccountID string
	TeamID    string
}

// ToolCall is one tool invocation reported by the export.
type ToolCall struct {
	Tool         string
	SessionID    string
	CallID       string
	Name         string
	Success      bool
	SuccessKnown bool
	DurationMS   int64
	Timestamp    time.Time
}

// Content is one captured content body. Content is the RAW text as emitted;
// the caller scrubs, bounds and hashes it before storage.
type Content struct {
	Tool         string
	SourceTag    string
	SessionID    string
	RequestID    string
	ToolUseID    string
	Kind         string
	Content      string
	TimeUnixNano uint64
}

// GenTiming is one model call's generation duration as the export reports
// it, keyed to the tool's own transcript token row for the same call. The
// caller stamps DurationMS onto the token_usage row whose Key column equals
// KeyValue in SessionID (gen_basis "otel"), and only where that row has no
// timing of its own: the transcript's native timing always wins.
type GenTiming struct {
	Tool      string
	SessionID string
	// Key names the transcript token_usage column KeyValue equals
	// (Vendor.TranscriptTiming).
	Key      TimingKey
	KeyValue string
	// DurationMS is the call's END-TO-END duration (time to first token
	// included), never a stream-only span; always positive.
	DurationMS int64
	Timestamp  time.Time
}

// Result is everything one export mapped to.
type Result struct {
	Turns    []Turn
	Tools    []ToolCall
	Contents []Content
	// GenTimings are the per-call generation durations for the transcript's
	// own token rows (KindGenTiming rules).
	GenTimings []GenTiming
	// Skipped counts turn records dropped because their rule requires a
	// vendor request id and the record had none (the Claude Code rule: a
	// turn without its request id could duplicate a proxied row).
	Skipped int
	// Unclaimed lists, once each, the service.name of every resource no
	// vendor row claimed and no rule matched. The caller logs it so an
	// operator can see a tool exporting to the node that has no mapping.
	Unclaimed []string
}
