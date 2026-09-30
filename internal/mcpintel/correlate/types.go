package correlate

import "time"

// Confidence is the honesty grade of a link at its Level (R10.7): the closed
// vocabulary of the corr_confidence columns (mcp_decision, mcp_relay_record,
// mcp_node_decision_event).
type Confidence string

// Confidences.
const (
	// Exact: an id anchor the relay carried pins the link.
	Exact Confidence = "exact"
	// Inferred: a heuristic inside an anchored session picked the link.
	Inferred Confidence = "inferred"
	// None: no trusted anchor links the call to this session.
	None Confidence = "none"
)

// Level is the finest granularity a link reaches.
type Level string

// Levels.
const (
	LevelAction  Level = "action"
	LevelTurn    Level = "turn"
	LevelSession Level = "session"
	LevelNone    Level = "none"
)

// Source is where a Record was captured. The order of SourceRank is the
// precedence Derive uses when two copies of one call disagree.
type Source string

// Sources.
const (
	// SourceGateway is the org front's own mcp_decision / mcp_audit row.
	SourceGateway Source = "gateway"
	// SourceNode is the node relay's mcp_relay_record (node side) or its
	// pushed mcp_node_decision_event copy (org side).
	SourceNode Source = "node"
)

// SourceRank orders sources for de-duplication: a lower rank wins a field
// both copies carry. The gateway row is the org's authoritative verdict for
// a remote call; the node row is the only record for a node-local call.
var SourceRank = map[Source]int{SourceGateway: 0, SourceNode: 1}

// Kind is the record kind (decision or completion; gap rows never reach
// correlation).
type Kind string

// Kinds.
const (
	KindDecision   Kind = "decision"
	KindCompletion Kind = "completion"
)

// Method names the rule that produced a Link (closed vocabulary; one per
// row of the rules table in derive.go).
const (
	MethodUntrusted           = "untrusted_carrier"
	MethodActionRef           = "action_ref"
	MethodActionRefMessage    = "action_ref_message"
	MethodSessionMismatch     = "session_mismatch"
	MethodNoAnchor            = "no_session_anchor"
	MethodActionRefUnresolved = "action_ref_unresolved"
	MethodTurnRef             = "turn_ref"
	MethodTurnRefTool         = "turn_ref_tool"
	MethodSessionToolTime     = "session_tool_time"
	MethodSessionTime         = "session_time"
	MethodSessionOnly         = "session_only"

	// The UNANCHORED tier (a trusted relay call that carried no session,
	// action or turn ref). Every link it produces is at most inferred.
	//
	// MethodUnanchoredToolTime: this session owns the call and one of its
	// captured tool calls names the call's tool (and server) in the window.
	MethodUnanchoredToolTime = "unanchored_tool_time"
	// MethodUnanchoredServerTime: the call carried no tool name (capture
	// below L2) and the one candidate in the window names its server.
	MethodUnanchoredServerTime = "unanchored_server_time"
	// MethodUnanchoredSession: this session owns the call but every matching
	// action here is already claimed by an earlier call - session level.
	MethodUnanchoredSession = "unanchored_session"
	// MethodUnanchoredProtocol: the record is protocol / catalogue traffic
	// (initialize, notifications/*, tools/list, ...), never the invocation
	// behind a captured tool call, so it can reach session level at most and
	// never claims an action (Call.invokesTool). This session owns it by the
	// server name its tool calls carry and time.
	MethodUnanchoredProtocol = "unanchored_protocol"
	// MethodUnanchoredAmbiguous: this session is a candidate but so is
	// another one, too close to call - attached to NO session (none).
	MethodUnanchoredAmbiguous = "unanchored_ambiguous"
	// MethodUnanchoredOther / MethodUnanchoredNoMatch: another session owns
	// the call, or nothing in this session matches it; neither attached nor
	// counted here.
	MethodUnanchoredOther   = "unanchored_other_session"
	MethodUnanchoredNoMatch = "unanchored_no_match"
)

// CandidateActionTypes are the action types an unanchored call may be
// matched against (the normalized models.ActionMCPCall / ActionUnknown): an
// adapter that recognises an MCP call tags it mcp_call; one that does not
// (OpenCode names a relay tool "<entry key>_<tool>", which carries no mcp
// marker) leaves it unknown. Both seams load the pool with exactly this list
// so the node panel and the org drawer see the same candidates.
var CandidateActionTypes = []string{actionTypeMCPCall, actionTypeUnknown}

// PoolAction is one candidate action of ANY session that could own an
// unanchored call: same node (the node store is one node; the org seam
// keeps the session's machine when both sides carry one) and same owner,
// inside the unanchored window. Its Action.Target is the display name the
// unanchored tier matches on - the one name column both the node and the
// org carry (the org has no raw_tool_name), so the two surfaces agree.
type PoolAction struct {
	SessionID string
	Action
}

// Record is one decision or completion row as a seam loaded it. Trusted is
// the SEAM's verdict on the carrier, set on decisions AND completions: true
// only when the row was carried by the node relay (a node mcp_relay_record,
// a pushed node event, or a gateway row - and its completion - whose token
// was relay-originated, node_fp present). An untrusted record's anchors are
// ignored and it never folds into another call (a direct OAuth / API-key
// client is 'none').
type Record struct {
	Source  Source
	Kind    Kind
	CallID  string
	TS      int64 // unix seconds
	Trusted bool

	VirtualServer, Server, Tool, Method string
	Decision, Reason                    string

	CodingSessionID, TurnRef, ActionRef string
	// StoredConfidence is the corr_confidence the capturing side stamped
	// (the carrier grade), echoed for audit; Derive computes the link.
	StoredConfidence string

	CaptureLevel                           string
	ArgsExcerpt, ArgsFull, ArgsScrubStatus string

	ResultStatus                  string
	LatencyMS, ResultSizeBytes    *int64
	ResultFull, ResultScrubStatus string
	ErrorFull, ErrorScrubStatus   string
	// SchemaTokensEst / ResultTokensEst / TokenizerVersion /
	// AttributionMethod / AttributionConfidence are the P11(b) estimate
	// columns of a gateway completion (mcp_audit); empty elsewhere.
	SchemaTokensEst, ResultTokensEst *int64
	TokenizerVersion                 string
	AttributionMethod                string
	AttributionConfidence            string
}

// Action is one of the session's actions as a seam loaded it (only the
// columns correlation reads). Key is actions.source_event_id - for a tool
// call the tool-use id the AI client also puts in the MCP request _meta.
type Action struct {
	Key         string
	MessageID   string
	TurnIndex   *int64
	TurnID      string
	TS          time.Time
	ActionType  string
	RawToolName string
	Target      string
}

// DeriveInput is one session's correlation input.
type DeriveInput struct {
	// SessionID is the session the panel is for (sessions.id).
	SessionID string
	// Records are the decision + completion rows the seam selected for the
	// session (by coding_session_id OR by an action_ref naming one of the
	// session's actions), in any order.
	Records []Record
	// Actions are the session's MCP-call + user-prompt actions plus any
	// action an anchor names, in any order.
	Actions []Action
	// Pool is the unanchored tier's candidate set: the CandidateActionTypes
	// actions of every session of the same node / owner inside the window
	// the seam derived from the unanchored records (PoolWindow), this
	// session's included. Empty disables the tier (no unanchored call is
	// ever attached without it).
	Pool []PoolAction
	// AnchoredKeys are pool action keys a TRUSTED record names by action_ref
	// (the action is exactly claimed by its own call): never a candidate for
	// an unanchored call.
	AnchoredKeys []string
	// Limit caps the returned calls (<= 0: no cap).
	Limit int
}

// Link is one call's derived correlation.
type Link struct {
	Confidence Confidence `json:"confidence"`
	Level      Level      `json:"level"`
	Method     string     `json:"method"`
	// ActionKey / MessageID / TurnIndex / TurnID locate the matched action or
	// turn in the session ("" / nil at session level).
	ActionKey string `json:"action_key,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	TurnIndex *int64 `json:"turn_index,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	// PromptKey is the user-prompt action that opened the matched turn (its
	// source_event_id), when one precedes the match.
	PromptKey string `json:"prompt_key,omitempty"`
}

// Call is one de-duplicated MCP call attached to the session, the row both
// the node panel and the org drawer render.
type Call struct {
	CallID  string   `json:"call_id,omitempty"`
	Sources []Source `json:"sources"`
	TS      int64    `json:"ts"`

	VirtualServer string `json:"virtual_server,omitempty"`
	Server        string `json:"server,omitempty"`
	Tool          string `json:"tool,omitempty"`
	Method        string `json:"method,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Reason        string `json:"reason,omitempty"`

	CodingSessionID  string `json:"coding_session_id,omitempty"`
	TurnRef          string `json:"turn_ref,omitempty"`
	ActionRef        string `json:"action_ref,omitempty"`
	StoredConfidence string `json:"stored_corr_confidence,omitempty"`

	CaptureLevel    string `json:"capture_level,omitempty"`
	ArgsExcerpt     string `json:"args_excerpt,omitempty"`
	ArgsFull        string `json:"args_full,omitempty"`
	ArgsScrubStatus string `json:"args_scrub_status,omitempty"`

	// Completed is true when a completion record joined the decision.
	Completed         bool   `json:"completed"`
	ResultStatus      string `json:"result_status,omitempty"`
	LatencyMS         *int64 `json:"latency_ms,omitempty"`
	ResultSizeBytes   *int64 `json:"result_size_bytes,omitempty"`
	ResultFull        string `json:"result_full,omitempty"`
	ResultScrubStatus string `json:"result_scrub_status,omitempty"`
	ErrorFull         string `json:"error_full,omitempty"`
	ErrorScrubStatus  string `json:"error_scrub_status,omitempty"`

	// SchemaTokensEst / ResultTokensEst are the P11(b) ESTIMATES (org
	// gateway completions only); TokensEstimated is always true when either
	// is set so no surface renders them as measured.
	SchemaTokensEst        *int64 `json:"schema_tokens_est,omitempty"`
	ResultTokensEst        *int64 `json:"result_tokens_est,omitempty"`
	TokensEstimated        bool   `json:"tokens_estimated,omitempty"`
	TokenizerVersion       string `json:"tokenizer_version,omitempty"`
	AttributionMethod      string `json:"attribution_method,omitempty"`
	AttributionConfidence  string `json:"attribution_confidence,omitempty"`
	Correlation            Link   `json:"correlation"`
	FoldedDuplicateRecords int    `json:"folded_duplicate_records,omitempty"`

	// serverNames are every server / virtual-server name the call's decision
	// copies carry (the node's slug AND the gateway's vserver id), which the
	// unanchored tier matches a client's projected tool name against.
	serverNames []string
}

// Totals summarises one Result.
type Totals struct {
	// Calls is len(Result.Calls) before the Limit cap.
	Calls    int `json:"calls"`
	Exact    int `json:"exact"`
	Inferred int `json:"inferred"`
	// Unlinked counts candidate calls whose link was none (never attached).
	Unlinked int `json:"unlinked"`
	// Ambiguous counts the unanchored calls (a subset of Unlinked) that this
	// session and at least one other session both matched too closely to
	// tell apart, so neither shows them.
	Ambiguous int `json:"ambiguous"`
	// FoldedDuplicates counts extra records folded by call_id.
	FoldedDuplicates int `json:"folded_duplicates"`
}

// Result is one session's MCP calls, oldest first.
type Result struct {
	SessionID string `json:"session_id"`
	Calls     []Call `json:"calls"`
	Totals    Totals `json:"totals"`
	Truncated bool   `json:"truncated"`
}
