package sessionmsg

// GroupMode selects the group-key precedence Derive uses to bucket
// token/proxy rows into messages. RollupTurn (the default on both engines)
// prefers turn_id — several per-inference token_usage rows sharing one
// turn_id (codex, and its openinterpreter retag) fold into ONE row.
// RollupInference is the node's ?detail=inference mode: one row per
// token_count event / per model inference, ignoring turn_id.
type GroupMode int

const (
	// RollupTurn groups by turn_id, else message_id, else source_event_id.
	RollupTurn GroupMode = iota
	// RollupInference groups by message_id, else source_event_id (turn_id
	// is never consulted), producing one row per inference call.
	RollupInference
)

// ProxyRow is one api_turns row: a proxy-observed HTTP call to an upstream
// model. Fields mirror the columns both engines already select.
type ProxyRow struct {
	RequestID         string
	Timestamp         string // RFC3339Nano
	Model             string
	Input             int64
	Output            int64
	CacheRead         int64
	CacheCreation     int64
	CacheCreation1h   int64
	WebSearchRequests int64
	CostUSD           float64
	Fast              bool
	TTFBMs            int64
	TotalMs           int64
	StopReason        string
}

// TokenRow is one token_usage row: a transcript/JSONL-captured usage
// observation. Tool is the adapter id (used only by the caller to resolve
// the ShadowCapable flag before calling Derive — never branched on inside
// this package).
type TokenRow struct {
	SourceEventID     string
	MessageID         string
	TurnID            string
	Timestamp         string // RFC3339Nano
	Model             string
	Tool              string
	Input             int64
	Output            int64
	CacheRead         int64
	CacheCreation     int64
	CacheCreation1h   int64
	Reasoning         int64
	WebSearchRequests int64
	CostUSD           float64
	Fast              bool
	// SourceFileHash is token_usage.source_file_hash: a content-free
	// SHA-256 hex digest of the row's originating capture file, shipped
	// UNCONDITIONALLY on the wire — never gated by shipsRawContent() the
	// way SourceFile itself is (internal/store/orgpush.go's token_usage
	// SELECT scans tu.source_file_hash unconditionally; only ProjectRoot/
	// SourceFile are blanked when the node hasn't opted into full-content
	// sharing) and computed from SourceFile when the stored hash is empty
	// (internal/orgserver/ingest/ingest.go::hashOrComputed), so it lands
	// verbatim at ingest either way. Round 10 finding F4 (docs/security.md):
	// included in fingerprintTokenRow as a real discriminator between two
	// keyless rows that share an identical token bundle/timestamp but
	// originate from different capture files — see that function's doc
	// comment.
	SourceFileHash string
	// GenMs is the per-call duration the ADAPTER captured for this model
	// call (token_usage.gen_ms, agent migration 136), 0 when none was
	// captured - the common case. GenBasis names its basis (BasisNative /
	// BasisTranscript). Feeds Row.Speed only; never derived from Timestamp.
	GenMs    int64
	GenBasis string
}

// ActionRow is one actions row bucketed onto a message. It is a deliberate
// superset of what the node and the org each need: the node populates the
// content-bearing display fields (FullText, Excerpt is filled by the caller
// afterward via a separate batch query — see ExcerptPending), the org
// leaves them at their zero value and uses only the content-free identity
// fields (TargetHash, Tool, Success, DurationMs).
type ActionRow struct {
	// ActionID is the caller's own stable per-action identity: the node's
	// actions.id (formatted as a string) or the org's source_event_id.
	// Round-tripped verbatim into Row.Actions — Derive never parses it.
	ActionID      string
	SourceEventID string
	MessageID     string
	ActionType    string
	Timestamp     string // RFC3339Nano
	EffortLevel   string
	StopReason    string
	ServiceTier   string
	Tool          string // raw_tool_name (node) / tool (org)
	Target        string
	TargetHash    string
	Success       *bool
	DurationMs    *int64

	// Node-only rich display fields. Zero value on the org side; Derive
	// never reads or writes them — it only carries them through unchanged
	// inside the Row this action lands on, so the node can rebuild its
	// existing toolCallRow shape without a second lookup pass.
	FullText            string
	FullTextElided      bool
	HasFullOutput       bool
	ErrorMessage        string
	PermissionMode      string
	IsInterrupt         bool
	RequestURL          string
	IDSource            string
	Granularity         string
	PromptTokensEst     int64
	ResponseTokensEst   int64
	UserAttachmentsJSON string

	// StatusRaw is the stored reading body (actions.raw_tool_input) of a
	// STATUS action (status.go: IsStatusAction), loaded by a caller that
	// has it (the node) so Derive can tell a changed reading from a
	// repeat. Empty on the org's content-free load; empty for every other
	// action. Never shown.
	StatusRaw string
}

// TokenBundle is the shared token/cost accumulator for one derived message
// row. It intentionally excludes any AI/tool cost SPLIT (node's
// cost.ComputeBreakdown needs live pricing-table lookups keyed by
// model+timestamp; the org has no per-model pricing table at all) — that
// split is a display-layer decision made by each caller AFTER Derive,
// using RecordedCostUSD + Model + Timestamp + Fast.
type TokenBundle struct {
	Input             int64
	Output            int64
	CacheRead         int64
	CacheCreation     int64
	CacheCreation1h   int64
	Reasoning         int64
	WebSearchRequests int64
	Fast              bool
}

// Row is one derived message: the engine-agnostic core shared between the
// node's rich per-message display row and the org's metrics-only row.
// Callers project this into their own richer/content-free display struct.
type Row struct {
	// Key is the group key Derive resolved this row to (turn_id, else
	// message_id, else source_event_id for a token/proxy-sourced row; for a
	// synthesized action-only row, the action's own COALESCE(message_id,
	// source_event_id)).
	Key       string
	Timestamp string
	Role      string // "user" | "assistant"
	Model     string
	// Source names the substrate this row's PRIMARY data came from: "proxy"
	// (api_turns, possibly twin-enriched from a token_usage row), "jsonl"
	// (token_usage only), or "actions" (a synthesized row with no
	// token/cost data — a user prompt, or a non-billing action whose join
	// key matched no token/proxy bucket).
	Source          string
	Bundle          TokenBundle
	RecordedCostUSD float64
	TTFBMs          int64
	TotalMs         int64
	StopReason      string
	// EffortLevel / ServiceTier are the per-turn reasoning-effort / served
	// capacity-tier signals, first-non-empty-wins across every action
	// bucketed to this row (chronological order) — computed once, shared
	// by both engines' identical "first non-empty wins" rule.
	EffortLevel string
	ServiceTier string

	// Actions is every action bucketed to this row, in the order Derive
	// processed them (stable: by timestamp, then SourceEventID). Status
	// actions (status.go) are never here.
	Actions []ActionRow

	// StatusActions are the status readings (a rate_limit snapshot) that
	// followed this message, folded onto it instead of rendering as rows
	// of their own; see status.go. Not tool calls.
	StatusActions []StatusAction

	// AccountKey is Role+":"+Key — the exact convention the node's
	// dashboard.go already uses to resolve a message's vendor-login
	// attribution (`accounts[mr.Role+":"+mr.MessageID]`) and the org's
	// messageaccounts.go now shares. Every row carries one; a caller with
	// no per-message account substrate simply never looks it up.
	AccountKey string

	// AliasKeys is every distinct identity key that folded into this row —
	// a proxy request_id, a contributing token row's message_id/turn_id/
	// source_event_id, each bucketed action's message_id/source_event_id,
	// and the row's own final Key. Generalizes the org's pre-existing
	// bucketIndex/messageRowKeys mechanism (a vendor-login observation's
	// binding_id can name ANY of these, not just the row's final group
	// key) into the shared package; the node doesn't need it (its own
	// store.LoadMessageAccounts already resolves to the same group-key
	// space its bucketing uses) but nothing stops it from using it too.
	AliasKeys []string

	// Speed is this row's output-throughput accumulator (speed.go) - the
	// ONE Tok/s source for every surface. GapToNextMs is the wall-clock gap
	// to the next row in final order (nil on the last row / unparsable
	// stamps) - a timeline figure shown as "Elapsed", never a Tok/s
	// denominator. TurnRollup marks a bucket keyed by turn_id; IsProxy marks
	// a bucket whose Source is "proxy" (proxy rows are stamped at request
	// START, transcript rows at inference END - a caller resolving
	// per-inference sub-buckets needs this boundary distinction, see
	// PickInferenceBucket).
	Speed       Speed
	GapToNextMs *int64
	TurnRollup  bool
	IsProxy     bool

	// Keyless is true when this row's Key was synthesized by Derive (see
	// keylessKey) because the underlying proxy/token row carried none of
	// its real identity fields — a legacy pre-fallback capture, the only
	// shape this ever fires for (review round 5 finding #7). A caller that
	// renders Key to the user (the node's Messages tab shows it as
	// message_id) can use this to label the row as a synthetic id rather
	// than implying it is a real captured message/turn/source-event id.
	Keyless bool

	// Seq is the row's 1..N chronological ordinal, assigned once by Derive
	// after the final sort.
	Seq int

	// Contributions is every individual raw proxy/token row that folded
	// into this Row's combined Bundle (excluding a twin/shadow row's
	// duplicate contribution, which adds nothing — its figures already
	// live on the row it was folded into), in the order Derive processed
	// them. A caller with its own per-model, date-aware pricing table
	// (the node's cost.Engine; the org has none) needs this to price EACH
	// raw contribution SEPARATELY before summing: pricing the merged
	// Bundle once would falsely apply a long-context-threshold rate to a
	// message whose individual underlying turns never crossed it
	// (TestAPISessionMessages_LongContextPerTurn's regression case —
	// two 150K-token turns summing to 300K must NOT be priced as one
	// 300K-token long-context call). The org ignores this field.
	Contributions []Contribution
}

// Contribution is one raw ProxyRow's or TokenRow's own token bundle, cost,
// timestamp, model and fast-tier signal, captured at the moment Derive
// folds it into its parent Row — see Row.Contributions.
type Contribution struct {
	Timestamp       string
	Model           string
	Bundle          TokenBundle
	RecordedCostUSD float64
	// OwnFast is this specific raw row's own fast flag (ProxyRow.Fast /
	// TokenRow.Fast). InheritedFast is set only for a proxy-row
	// contribution enriched by a fast JSONL twin (the codex
	// "inherited_fast" signal, F1) — always false for a token-row
	// contribution, which has no twin of its own.
	OwnFast       bool
	InheritedFast bool
	// Proxy is true for a contribution that came from a proxy (api_turns)
	// row, false for a token_usage row. Totals counts these as the
	// session's proxy-observed turns (the "N proxy turns" figure both
	// dashboards can show from one rule).
	Proxy bool
}

// DeriveInput is everything Derive needs. Every row slice should already be
// ordered by the caller's own SQL (Derive re-sorts defensively, but a
// caller relying on that is a smell — order it explicitly so the intent is
// visible at the query site, per the review's finding #6).
type DeriveInput struct {
	ProxyRows  []ProxyRow
	TokenRows  []TokenRow
	ActionRows []ActionRow

	// Mode selects the group-key precedence (RollupTurn by default).
	Mode GroupMode

	// ShadowCapable is internal/integration.Capability.TokenTier.
	// OutputOnlyShadow for this session's tool, resolved by the caller
	// BEFORE calling Derive. This package dispatches on this bool alone —
	// never a tool name — per CLAUDE.md's capability-not-identity rule.
	ShadowCapable bool

	// ReasoningDisjoint is internal/integration.Capability.TokenTier.
	// ReasoningDisjoint for this session's tool, resolved by the caller: true
	// when the adapter's token_usage output_tokens and reasoning_tokens are
	// audited DISJOINT, so a row's generated tokens are Output + Reasoning.
	// False (the unaudited default) counts Output only. Speed only.
	ReasoningDisjoint bool

	// SessionCumulative is internal/integration.Capability.TokenTier.
	// SessionCumulative for this session's tool, resolved by the caller: true
	// when the adapter writes ONE running-total token row per session
	// ("tokens:"-prefixed source_event_id), which Derive reconciles
	// wholesale against the session's per-turn capture (cumulative.go).
	SessionCumulative bool

	// DefaultModel is the session's own overall model (sessions.model),
	// used only as the last-resort fallback for a synthesized row whose
	// peer bucket (see the "user:"/"assistant:" key-prefix convention in
	// foldActions) carries no model either.
	DefaultModel string
}
