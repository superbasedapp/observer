package orgcontract

// SessionRow is a session as pushed to the server.
//
// Privacy posture (v1.8.0+): a session identifies its project via the
// CONTENT-FREE hashes ProjectRootHash + GitRemoteHash, which are always
// present and let the server map the session to a team via pre-shared
// project-root hash registration without ever seeing the developer's
// filesystem layout.
//
// ProjectRoot + GitRemote are the raw / human-readable values; they ship
// under store.ShareOptions.shipsRawContent() — TEAMS posture: ONLY when the
// node operator has set [org_client.share].full_content = true in their
// local config (a per-node opt-in; the org admin cannot force it on) OR the
// node is admin_managed (itself a node-authored provisioning config, never a
// remote toggle). ENTERPRISE posture adds a third, structurally distinct
// path: a managed node's own enrolment grant may satisfy
// govern.Effective.GrantsEnterpriseContent(), minted at enrolment under the
// org's chosen product_posture — never a live remote command (see
// internal/store/orgpush.go's ShareOptions doc for the full three-path
// statement). With none of the three, these fields are empty strings (json
// omitempty).
//
// Project Identity Resolver v2 (docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
// §3.2, agent migration 102 / server migration 121) widens the single origin
// remote into a full identity bundle. GitUpstreamRemoteHash, GitRemoteOwnerHash,
// GitUpstreamOwnerHash, RootCommitHash, ContentFingerprintHash, and
// WorkspaceHash are unsalted sha256 hashes that ship ALWAYS — joinable across
// nodes, disclosing nothing a raw value would not. IsWorktree is a
// content-free bool and also always ships. GitUpstreamRemote and Workspace
// are the two RAW counterparts among these new fields; like ProjectRoot /
// GitRemote above, they ship ONLY under store.ShareOptions.shipsRawContent()
// and are stripped per row in internal/store/orgpush.go::SelectUnpushedSince.
// There is no raw counterpart for the other four hashes (the pre-images —
// root_commit_sha, content_fingerprint — never leave the node in any share
// mode; the owner hashes have no raw form on the wire at all). An older agent
// omits every field in this block; the server degrades to remote-only
// resolution. All additive/omitempty for compat in both directions.
type SessionRow struct {
	ID string `json:"id"`

	// Content-free hashes — always present.
	ProjectRootHash string `json:"project_root_hash"`
	GitRemoteHash   string `json:"git_remote_hash,omitempty"`

	// Raw values — present only when the node opted in to full-content sharing.
	ProjectRoot string `json:"project_root,omitempty"`
	GitRemote   string `json:"git_remote,omitempty"`

	Tool         string `json:"tool"`
	Model        string `json:"model,omitempty"`
	GitBranch    string `json:"git_branch,omitempty"`
	StartedAt    string `json:"started_at"` // RFC3339
	EndedAt      string `json:"ended_at,omitempty"`
	TotalActions int    `json:"total_actions"`
	OrgID        string `json:"org_id"`
	UserEmail    string `json:"user_email"`

	// Project Identity Resolver v2 additions — content-free hashes, always
	// present when the node has resolved them (older agents omit them).
	GitUpstreamRemoteHash  string `json:"git_upstream_remote_hash,omitempty"`
	GitRemoteOwnerHash     string `json:"git_remote_owner_hash,omitempty"`
	GitUpstreamOwnerHash   string `json:"git_upstream_owner_hash,omitempty"`
	RootCommitHash         string `json:"root_commit_hash,omitempty"`
	ContentFingerprintHash string `json:"content_fingerprint_hash,omitempty"`
	WorkspaceHash          string `json:"workspace_hash,omitempty"`
	IsWorktree             bool   `json:"is_worktree,omitempty"`

	// Raw values — present only under shipsRawContent(). The only two
	// resolver-v2 fields with a raw counterpart on the wire.
	GitUpstreamRemote string `json:"git_upstream_remote,omitempty"`
	Workspace         string `json:"workspace,omitempty"`

	// Capture-surface attribution (node session-detail trickle-up W1;
	// agent migration 107 / server migration 139). METADATA, not content:
	// Surface is a CLOSED vocabulary (models.KnownSurface — cli | ide |
	// desktop | sdk | web) that the node's Store.SetSessionSurface refuses
	// to write outside of, and SurfaceHost is the bounded host token that
	// refines it (vscode | cursor | jetbrains | neovim | kiro |
	// claude-desktop | codex-desktop | ...). Neither can carry a path, a
	// prompt or a branch name, so both ship BY DEFAULT — unconditionally
	// populated by SelectUnpushedSince, with no share key and no
	// shipsRawContent() gate. Empty means UNKNOWN (a pre-107 agent, or a
	// session whose transcript was never re-scanned); a projection must
	// render that absence honestly and NEVER as "cli".
	Surface     string `json:"surface,omitempty"`
	SurfaceHost string `json:"surface_host,omitempty"`

	// ToolVersion is the captured AI-tool/CLI build version the node
	// resolved from a grounded on-disk field the adapter itself controls
	// (server migration 161 / pg 0027; agent migration 125,
	// internal/store/toolversion.go::SetSessionToolVersion, FIRST-WINS-
	// UNLESS-EMPTY). METADATA, not content: unlike Surface it is not a
	// closed vocabulary, but it is a bounded (64-rune), non-prose,
	// whitespace/control-char-rejected token
	// (internal/store/toolversion.go::validToolVersion) sourced only from a
	// vendor-authored field — never developer-typed text — so it ships BY
	// DEFAULT alongside Surface/SurfaceHost, with no share key and no
	// shipsRawContent() gate. Empty means UNKNOWN: a pre-125 agent, an
	// adapter with no grounded version source, or a session whose
	// transcript predates the field. Never rendered as a guess.
	ToolVersion string `json:"tool_version,omitempty"`

	// ToolVersionLast is the LATEST tool/CLI build the node saw for the
	// session (agent migration 162 / server migration 232 / pg 0099,
	// internal/store/toolversion.go::SetSessionToolVersion, which moves it
	// forward on every valid stamp while ToolVersion stays the first build
	// seen). Same METADATA class and same grammar as ToolVersion, so it ships
	// BY DEFAULT with no share key and no shipsRawContent() gate, and the
	// ingest re-validates it the same way. Empty means the node never
	// stamped it (an older agent, or a session not re-parsed since 162):
	// readers then treat it as equal to ToolVersion. A session where the two
	// differ was upgraded mid-session.
	ToolVersionLast string `json:"tool_version_last,omitempty"`

	// ParentThreadID is the node-local session-lineage pointer (agent
	// migrations 069/102, internal/store::SetSessionLineage) — for Cursor
	// the parent session of a sub-agent child, also Codex fork lineage
	// (server migration 162 / pg 0028). METADATA, not content: it is an
	// OPAQUE vendor-minted session id, never developer-typed text, and the
	// child session it points at already ships as its own SessionRow on the
	// wire, so shipping the pointer adds structure (fan-out), not content —
	// the same reasoning that lets ToolVersion ship unconditionally. It
	// ships BY DEFAULT, with no share key and no shipsRawContent() gate.
	// ForkedFromID and ThreadSource (the fork's existence/kind) stay
	// NODE-LOCAL and are deliberately NOT added here — only the pointer
	// itself ships. Empty means the session has no recorded parent. Lets
	// the org drawer's per-session tool-account column resolve a Cursor
	// CHILD session's account the way the node's
	// internal/store/toolaccount.go::LoadMessageAccounts already does, by
	// joining through this column (rollup/messageaccounts.go). See
	// docs/security.md ledger row LINEAGE-1.
	ParentThreadID string `json:"parent_thread_id,omitempty"`
	// ExecutionLocation is where the session's agent ran (cloud-agents arc
	// CA-D1; agent migration 240 / server 300 / pg 0170): one of the closed
	// models.Execution* kinds ("local", "vendor_cloud", "customer_worker").
	// METADATA like Surface: a closed vocabulary, so it ships BY DEFAULT with
	// no share key and no shipsRawContent() gate; the ingest lands an
	// out-of-vocabulary value as NULL. Empty means UNKNOWN (an older agent,
	// or a session no capture path stamped), never a defaulted "local".
	ExecutionLocation string `json:"execution_location,omitempty"`
	// VendorSessionRef is the vendor's second native session reference used
	// to join one session across capture rails (CA-D2; same migrations): a
	// Claude Code `cse_...` id, a `ccr.session.id`, a GitHub
	// `agent_session_id`. METADATA like ParentThreadID: an opaque
	// vendor-minted id, never content, bounded by ValidVendorSessionRef,
	// which the ingest re-checks (a malformed value lands NULL). Ships BY
	// DEFAULT. Empty means the session has no recorded reference.
	VendorSessionRef string `json:"vendor_session_ref,omitempty"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// ActionRow is an action as pushed to the server.
//
// Privacy posture (v1.8.0+):
//
//   - The classic four content columns (raw_tool_input, raw_tool_output,
//     preceding_reasoning, error_message) are intentionally absent — they
//     have never shipped.
//   - TargetHash and SourceFileHash are content-free and ALWAYS present.
//     They give the server stable dedup / cardinality signals (how often
//     does the same shell command run? how many distinct JSONL files?)
//     without revealing the underlying bytes.
//   - Target and SourceFile are the raw, human-readable values. The
//     2026-06-02 teams test found that these were shipping raw and
//     contained command bodies (run_command), assistant prose
//     (task_complete), and raw filesystem paths. v1.8.0 ships them under
//     store.ShareOptions.shipsRawContent() — TEAMS posture: ONLY when the
//     node operator has set [org_client.share].full_content = true (a
//     per-node opt-in the org admin cannot force on) OR admin_managed
//     (also node-authored, never a remote toggle). ENTERPRISE posture adds
//     the structurally distinct enrolment-grant path
//     (govern.Effective.GrantsEnterpriseContent(), minted at enrolment
//     under the org's chosen product_posture, never a live remote command
//     — see internal/store/orgpush.go's ShareOptions doc). With none of
//     the three, these fields are empty strings (json omitempty).
type ActionRow struct {
	SessionID     string `json:"session_id"`
	SourceEventID string `json:"source_event_id"`
	Timestamp     string `json:"timestamp"` // RFC3339
	Tool          string `json:"tool"`
	ActionType    string `json:"action_type"`

	// Content-free hashes — always present.
	TargetHash     string `json:"target_hash,omitempty"`
	SourceFileHash string `json:"source_file_hash"`

	// Raw values — present only when the node opted in to full-content sharing.
	Target     string `json:"target,omitempty"`
	SourceFile string `json:"source_file,omitempty"`

	// Tool-call BODIES — the four actions columns the local dashboard renders
	// inline. Present ONLY under the distinct full_tool_bodies tier
	// (ShareOptions.shipsToolBodies), which on an individual node is node-opt-in
	// and on a managed node the org may raise (extract.managed). They are NEVER
	// present under full_content/admin_managed alone. Additive/omitempty: a
	// pre-P2 server ignores them, a pre-P2 agent never sends them.
	RawToolInput       string `json:"raw_tool_input,omitempty"`
	RawToolOutput      string `json:"raw_tool_output,omitempty"`
	PrecedingReasoning string `json:"preceding_reasoning,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`

	TurnIndex   int   `json:"turn_index"`
	Success     bool  `json:"success"`
	DurationMs  int64 `json:"duration_ms"`
	IsSidechain bool  `json:"is_sidechain"`
	// MessageID is the id of the assistant/user MESSAGE this action belongs to
	// (actions.message_id on the node, e.g. an Anthropic "msg_…"), the key the
	// org message-metrics rollup buckets tool calls by. Without it the rollup
	// falls back to SourceEventID, which differs per adapter and shows 0 tools
	// per message for tools whose ids are not message ids (OpenCode, etc.).
	// CONTENT-FREE (an opaque provider id, never prose), so it ships in every
	// tier; empty when the node never recorded one. Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	MessageID string `json:"message_id,omitempty"`
	// EffortLevel is the reasoning-effort selection in force when the action
	// ran (minimal | low | medium | high | xhigh | max — accepted verbatim,
	// no enum check, matching the node's claudecode_effort sidecar posture).
	// Content-free (a closed vocabulary, never prose), so it ships in every
	// tier alongside the other action metadata. Extracted at push time from
	// the node's actions.metadata JSON; empty when the node never captured an
	// effort signal for this action (pre-feature rows, tools without an
	// effort concept). Additive/omitempty both directions: an older server
	// ignores it, an older agent never sends it.
	EffortLevel string `json:"effort_level,omitempty"`
	// StopReason is the turn-completion reason recorded on the action
	// (end_turn | max_tokens | stop_sequence | tool_use | …), extracted at
	// push time from the node's actions.metadata JSON ($.stop_reason) exactly
	// like EffortLevel. It is the JSONL-turn counterpart of APITurnRow's
	// proxy-observed StopReason: proxy sessions carry it on the api_turn, but a
	// JSONL-only (non-proxied) session records it only in the action metadata,
	// so without this field the org message table has no stop reason for those
	// turns. Content-free (a closed provider vocabulary, never prose), so it
	// ships in every tier; empty when the node never captured one (pre-feature
	// rows, tools without a stop-reason concept). Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	StopReason string `json:"stop_reason,omitempty"`
	OrgID      string `json:"org_id"`
	UserEmail  string `json:"user_email"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// APITurnRow is a proxy-observed API turn as pushed. Prompt/completion
// bodies are never present; only token counts, cost, timing, hashes
// (not content), and a parsed error class (a category, not a message).
//
// Privacy posture (v1.8.0+): ProjectRootHash is always present;
// ProjectRoot ships only when the node opted in to full-content sharing.
type APITurnRow struct {
	SessionID             string  `json:"session_id"`
	ProjectRootHash       string  `json:"project_root_hash,omitempty"`
	ProjectRoot           string  `json:"project_root,omitempty"`
	Timestamp             string  `json:"timestamp"` // RFC3339
	Provider              string  `json:"provider"`
	Model                 string  `json:"model,omitempty"`
	RequestID             string  `json:"request_id,omitempty"`
	InputTokens           int64   `json:"input_tokens"`
	OutputTokens          int64   `json:"output_tokens"`
	CacheReadTokens       int64   `json:"cache_read_tokens"`
	CacheCreationTokens   int64   `json:"cache_creation_tokens"`
	CacheCreation1hTokens int64   `json:"cache_creation_1h_tokens"`
	WebSearchRequests     int64   `json:"web_search_requests"`
	CostUSD               float64 `json:"cost_usd"`
	MessageCount          int     `json:"message_count"`
	ToolUseCount          int     `json:"tool_use_count"`
	SystemPromptHash      string  `json:"system_prompt_hash,omitempty"`
	MessagePrefixHash     string  `json:"message_prefix_hash,omitempty"`
	TimeToFirstTokenMS    int64   `json:"time_to_first_token_ms"`
	TotalResponseMS       int64   `json:"total_response_ms"`
	StopReason            string  `json:"stop_reason,omitempty"`
	HTTPStatus            int     `json:"http_status"`
	ErrorClass            string  `json:"error_class,omitempty"`
	OrgID                 string  `json:"org_id"`
	UserEmail             string  `json:"user_email"`
	// Route / RoutingGeneration / AuthoritySource are the Plane B per-turn
	// authority stamps (Sol S5 / Luna L15). CONTENT-FREE metadata — enum
	// strings + an integer generation, never any text from a request — so
	// they ship UNCONDITIONALLY (not gated by ShareOptions.shipsRawContent,
	// pinned by tests/invariant/privacy_test.go). omitempty on all three
	// keeps the wire backward-compatible both directions: an old agent
	// omits them and a new server reads direct/0/node defaults; a new agent
	// sends them and an old server ignores unknown keys.
	//
	// Route is "direct" | "gateway" | "fallback"; AuthoritySource is
	// "node" | "gateway" — the org rollup lets a gateway-authoritative row
	// win on a request_id collision so a mixed-mode window single-counts.
	Route             string `json:"route,omitempty"`
	RoutingGeneration uint64 `json:"routing_generation,omitempty"`
	AuthoritySource   string `json:"authority_source,omitempty"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
	// RequestClass is the client-declared kind of request (node agent
	// migration 144, org server migration 188 / pg 0054): one of the closed
	// internal/requestclass vocabulary (main | subagent | workflow |
	// compaction | auxiliary), or empty when the client sent no class hint.
	// CONTENT-FREE metadata (a closed enum, never request text), so it ships
	// in every posture like Route. Additive/omitempty both directions: an
	// older agent never sends it and the org stores NULL (never a guessed
	// class); an older server ignores the unknown key. The org re-validates
	// it against the vocabulary at ingest, so an unknown spelling lands NULL.
	RequestClass string `json:"request_class,omitempty"`
}

// GuardEventRow is a guard-layer audit event as pushed to the server
// (guard spec §14.3 central reporting).
//
// Privacy posture (guard spec §10.2 — mirrors ActionRow):
//
//   - rule_id, category, severity, decision, degraded_from, enforced,
//     source, tool, event_kind, timestamps and TargetHash are
//     content-free and always ship.
//   - Reason, TargetExcerpt and TaintOrigin are content-bearing
//     (verdict prose, a bounded excerpt of the command/path, a taint
//     source description). They ship under store.ShareOptions
//     .shipsRawContent() — the same gate as actions.target: TEAMS posture
//     ONLY when the node operator has set [org_client.share].full_content
//     = true or admin_managed (both node-authored; the org admin cannot
//     force either on), ENTERPRISE posture also via the structurally
//     distinct enrolment-grant path (EnterpriseGranted, minted at
//     enrolment, never a live remote command).
//     With the default config they are empty strings (json omitempty).
//   - ChainPrev/ChainHash are SHA-256 hex links of the node's
//     tamper-evidence chain (guard spec §10.4) — content-free, shipped
//     so server-side rollups can detect broken/truncated chains.
//
// Local row-id anchors (action_id / api_turn_id) are deliberately
// absent: they are meaningless outside the originating node.
type GuardEventRow struct {
	SessionID string `json:"session_id,omitempty"`
	Timestamp string `json:"timestamp"` // RFC3339
	Tool      string `json:"tool,omitempty"`
	EventKind string `json:"event_kind,omitempty"`
	RuleID    string `json:"rule_id"`
	Category  string `json:"category,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Decision  string `json:"decision,omitempty"`
	// DegradedFrom is the pre-degradation decision when a capability
	// downgrade applied (guard spec §6.2); empty otherwise.
	DegradedFrom string `json:"degraded_from,omitempty"`
	Enforced     bool   `json:"enforced"`
	Source       string `json:"source,omitempty"`

	// Content-free hash — always present when the event had a target.
	TargetHash string `json:"target_hash,omitempty"`

	// Content-bearing values — present only when the node opted in to
	// full-content sharing.
	Reason        string `json:"reason,omitempty"`
	TargetExcerpt string `json:"target_excerpt,omitempty"`
	TaintOrigin   string `json:"taint_origin,omitempty"`

	// Tamper-evidence chain links (content-free SHA-256 hex).
	ChainPrev string `json:"chain_prev,omitempty"`
	ChainHash string `json:"chain_hash,omitempty"`

	OrgID     string `json:"org_id"`
	UserEmail string `json:"user_email"`

	// GrantID is the org access grant that covered this event (request-grants
	// design §3.2; agent 152 / org 196). Zero (omitted) means no grant, and is
	// all a node or server that predates the design ever sends or reads.
	GrantID int64 `json:"grant_id,omitempty"`
}

// TokenUsageRow is an adapter-derived token-usage row as pushed. All
// fields are counts/metadata — no content.
//
// Privacy posture (v1.8.0+): ProjectRootHash + SourceFileHash are always
// present; ProjectRoot + SourceFile ship only when the node opted in to
// full-content sharing.
type TokenUsageRow struct {
	SessionID             string  `json:"session_id"`
	ProjectRootHash       string  `json:"project_root_hash,omitempty"`
	ProjectRoot           string  `json:"project_root,omitempty"`
	Timestamp             string  `json:"timestamp"` // RFC3339
	Tool                  string  `json:"tool"`
	Model                 string  `json:"model,omitempty"`
	InputTokens           int64   `json:"input_tokens"`
	OutputTokens          int64   `json:"output_tokens"`
	CacheReadTokens       int64   `json:"cache_read_tokens"`
	CacheCreationTokens   int64   `json:"cache_creation_tokens"`
	CacheCreation1hTokens int64   `json:"cache_creation_1h_tokens"`
	ReasoningTokens       int64   `json:"reasoning_tokens"`
	WebSearchRequests     int64   `json:"web_search_requests"`
	EstimatedCostUSD      float64 `json:"estimated_cost_usd"`
	Source                string  `json:"source"`
	Reliability           string  `json:"reliability"`
	SourceFileHash        string  `json:"source_file_hash"`
	SourceFile            string  `json:"source_file,omitempty"`
	SourceEventID         string  `json:"source_event_id"`
	// MessageID is the per-API-call / per-message id this usage row belongs to
	// (token_usage.message_id on the node), the key the org message-metrics
	// rollup joins token/cost columns to actions by. CONTENT-FREE opaque id;
	// empty when the node never recorded one. Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	// (The proxy api_turn's message id is api_turns.request_id, already carried
	// as APITurnRow.RequestID — no new field needed there.)
	MessageID string `json:"message_id,omitempty"`
	// IsSidechain reports whether this usage row was emitted inside a Claude
	// Code sub-agent (Task) window — token_usage.is_sidechain on the node
	// (agent migration 087), the token counterpart of the ActionRow.IsSidechain
	// flag that has ridden the wire since the baseline. METADATA (one bool over
	// a row that already ships, closed by construction), so it ships BY DEFAULT:
	// populated unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate. Additive/omitempty both directions — an older
	// server ignores it, an older agent never sends it and the server lands the
	// same honest false the node would have stored.
	IsSidechain bool `json:"is_sidechain,omitempty"`
	// TurnID groups several per-inference token_usage rows into the SAME
	// user-turn — token_usage.turn_id on the node (agent migrations 032/033),
	// server migration 160 / pg 0026. The node's own Messages-tab bucket key
	// (dashboard.go's tokenGroupExpr) PREFERS turn_id over message_id/
	// source_event_id: for codex (and its openinterpreter retag), several
	// per-inference calls within one user-turn share a turn_id and merge into
	// ONE row. Before this field, the org rollup had no way to reproduce that
	// merge and over-counted (one row per token_usage row instead of one per
	// turn) — the §7 follow-up to the 2026-09-22 node-vs-org parity fix.
	// CONTENT-FREE opaque id (an adapter-minted grouping token, never
	// agent-authored text), so it is METADATA and ships BY DEFAULT: populated
	// unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate — same posture as IsSidechain/MessageID above.
	// Additive/omitempty both directions: an older agent that never sends the
	// key lands NULL/empty (byte-identical to a pre-160 row); an older server
	// ignores the new wire key.
	TurnID string `json:"turn_id,omitempty"`
	// GenMs is the per-model-call generation duration the adapter captured
	// for this row — token_usage.gen_ms on the node (agent migration 136),
	// server migration 174 / pg 0040. It feeds the Tok/s throughput figure
	// (internal/sessionmsg's Speed accumulator) the same way on both
	// engines: TimingWire.TpsMs sums GenMs across a message's contributing
	// token rows. NUMERIC metadata over a row that already ships (a
	// duration, never agent-authored text), so it ships BY DEFAULT: populated
	// unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate — same posture as IsSidechain/TurnID above.
	// Additive/omitempty both directions: an older agent that never sends
	// the key lands 0/NULL (byte-identical to a pre-174 row, and
	// indistinguishable from "not measured" — the same honest-absence shape
	// GenMs already has node-side); an older server ignores the new wire key.
	GenMs int64 `json:"gen_ms,omitempty"`
	// GenBasis names GenMs's basis (models.GenBasisNative /
	// GenBasisTranscript / GenBasisOTel on the node) — a closed,
	// capture-minted enum, never agent-authored text, so it is METADATA and ships BY DEFAULT alongside
	// GenMs under the same rule. GenTimingV (the adapter's gen-timing parser
	// version) deliberately has NO wire counterpart: it is a node-local
	// upsert-precedence input only, meaningless once GenMs/GenBasis have
	// already been chosen on the node — the same posture as the node-local
	// `fast` pricing flag next to token_usage's other wire fields.
	GenBasis  string `json:"gen_basis,omitempty"`
	OrgID     string `json:"org_id"`
	UserEmail string `json:"user_email"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// OTelContentRow is one captured native-OTel content body on the wire
// (native-console integration, Phase 2b body-ingest Layer B). ContentHash
// always ships; Content (the raw, scrubbed body) ships only when the node
// shares full content (full_content or admin_managed) — gated in
// SelectUnpushedSince exactly like the other content-bearing columns.
type OTelContentRow struct {
	RequestID   string `json:"request_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	ToolUseID   string `json:"tool_use_id,omitempty"`
	Kind        string `json:"kind"`
	ContentHash string `json:"content_hash"`
	Content     string `json:"content,omitempty"`
	Timestamp   string `json:"timestamp"` // RFC3339
	OrgID       string `json:"org_id"`
	UserEmail   string `json:"user_email"`
}

// RoutingSummaryRow is the §R19.4 org rollup wire shape: AGGREGATE
// ONLY — counts and dollars by (day, tier, reason, mode). No model
// ids, no session detail, no per-decision rows: router_decisions and
// model_calibration stay node-local (privacy-sentinel-pinned); this
// aggregate is the only routing data that ever crosses the wire, and
// only when the node operator opts in via
// [org_client.share] routing_summary = true.
type RoutingSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same
	// stamping rule as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD).
	Day string `json:"day"`
	// Tier is the ORIGINAL model's tier class (an enum, not a model id).
	Tier string `json:"tier"`
	// Reason is the decision's primary closed-enum reason code.
	Reason string `json:"reason"`
	// Mode is advise | enforce.
	Mode string `json:"mode"`
	// Decisions / Applied are row counts.
	Decisions int64 `json:"decisions"`
	Applied   int64 `json:"applied"`
	// EstSavingsUSD / CacheForfeitUSD are decision-time estimate sums.
	EstSavingsUSD   float64 `json:"est_savings_usd"`
	CacheForfeitUSD float64 `json:"cache_forfeit_usd"`
}

// CacheSummaryRow is the Arc 4 P5c cache-detail aggregate — one row per
// (day, model, kind) of the node-local cache_events log (cache_segments /
// cache_entries / cache_events are otherwise NODE-LOCAL per spec §11 and
// never leave the agent). It carries only content-free counts: no prompt
// prefix, no raw scope (cache_scope is a hash), no path. It ships ONLY under
// the cache_detail tier (node opt-in on an individual node, admin-raised on a
// managed one) — the tier is what sanctions shipping per-turn cache-hit
// patterns the privacy sentinel otherwise treats as private.
type CacheSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the cache events.
	Day string `json:"day"`
	// Model is the model the cache belief/event is for.
	Model string `json:"model"`
	// Kind is the cache-event class (hit | write | expiry_rewrite | ...).
	Kind string `json:"kind"`
	// Events is the row count for the (day, model, kind) bucket.
	Events int64 `json:"events"`
	// TokensRead / TokensWritten are the summed cache token movements.
	TokensRead    int64 `json:"tokens_read"`
	TokensWritten int64 `json:"tokens_written"`
	// CostDeltaUSD is the summed write-vs-read cost delta estimate.
	CostDeltaUSD float64 `json:"cost_delta_usd"`
}

// CodeintelSummaryRow is the Arc 4 P5f codeintel-detail aggregate — one row per
// (project-hash, language) of the node-local code-intelligence index
// (codeintel_files / codeintel_nodes / codeintel_edges are otherwise
// NODE-LOCAL and never leave the agent). It carries only content-free STRUCTURE
// counts: no symbol name, no fully-qualified name, no signature excerpt, and no
// raw file or project path (the project path is one-way domain-separated-hashed
// on the node). It ships ONLY under the codeintel_detail tier (node opt-in on an
// individual node, admin-raised on a managed one via the DISTINCT
// extract.codeintel authority) — the highest-sensitivity extraction tier, so it
// gets its own explicit consent rather than riding the umbrella extract.managed.
type CodeintelSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// ProjectHash is the opaque one-way hash of the project's git-root path —
	// a stable grouping key that never discloses the path itself.
	ProjectHash string `json:"project_hash"`
	// Lang is the resolved language of the files in this bucket (e.g. go,
	// typescript). A public language label, never source.
	Lang string `json:"lang"`
	// Files / Symbols / Edges are the structure counts for the bucket:
	// indexed files, extracted symbols (nodes), and call/import edges.
	Files   int64 `json:"files"`
	Symbols int64 `json:"symbols"`
	Edges   int64 `json:"edges"`
}

// ProcessSummaryRow is the Arc 4 P5g process-detail aggregate — one row per
// (day, tool) of the node-local process-observability log (process_runs /
// process_events / process_network_bodies are otherwise NODE-LOCAL and never
// leave the agent). It carries only content-free counts: no executable path,
// no argv, no cwd, no network request/response body, and none of the
// process/network domain-separated hashes. It ships ONLY under the
// process_detail tier (node opt-in on an individual node, admin-raised on a
// managed one via the DISTINCT extract.process authority — the process/eBPF
// trees are a highest-sensitivity tier, so they get their own explicit
// consent rather than riding the umbrella extract.managed).
type ProcessSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the process runs started.
	Day string `json:"day"`
	// Tool is the attributed AI tool (e.g. claude-code) or '' when unattributed.
	Tool string `json:"tool"`
	// Runs is the number of process runs in the bucket; Exited how many have
	// exited; NonzeroExits how many exited with a non-zero code.
	Runs         int64 `json:"runs"`
	Exited       int64 `json:"exited"`
	NonzeroExits int64 `json:"nonzero_exits"`
	// DurationMsSum is the summed wall-clock duration of the runs in the bucket.
	DurationMsSum int64 `json:"duration_ms_sum"`
}

// TerminalSummaryRow is one half of the Arc 4 P5h terminal-detail aggregate —
// one row per (day, tool, kind) of the node-local terminal_run log (joined to
// terminal_commands for the command count). terminal_run / terminal_commands /
// remote_audit are otherwise pinned ENTIRELY out of the push wire (dedicated
// end-to-end never-ships tests); this content-free count aggregate under the
// DISTINCT terminal_detail tier is the deliberate, reviewed reversal. It never
// carries a command, a project_root_hash, a correlation_token_hash, a cmd_hash,
// or a source_session_id.
type TerminalSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the terminal runs launched.
	Day string `json:"day"`
	// Tool is the target tool (e.g. claude-code); Kind is handoff | fresh.
	Tool string `json:"tool"`
	Kind string `json:"kind"`
	// Runs / Ended / NonzeroExits are per-run counts; Commands is the number of
	// command boundaries observed across those runs.
	Runs         int64 `json:"runs"`
	Ended        int64 `json:"ended"`
	NonzeroExits int64 `json:"nonzero_exits"`
	Commands     int64 `json:"commands"`
}

// RemoteAuditSummaryRow is the other half of the Arc 4 P5h terminal-detail
// aggregate — one row per (day, kind, decision, principal) of the node-local
// remote_audit log. Content-free: it carries only the public event taxonomy
// (kind), the allow/deny/ok/fail decision, and the resolved capability class
// (principal: public|view|execute|anonymous) — never a session id, a peer
// address, a route, or a detail string.
type RemoteAuditSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the audit events.
	Day string `json:"day"`
	// Kind is the event kind; Decision the allow/deny/ok/fail verdict;
	// Principal the resolved capability class.
	Kind      string `json:"kind"`
	Decision  string `json:"decision"`
	Principal string `json:"principal"`
	// Events is the row count for the bucket.
	Events int64 `json:"events"`
}

// RoutingDetailRow is the Arc 4 P5d routing-detail aggregate — the
// MODEL-ID-BEARING per-decision rollup the tier-only RoutingSummaryRow omits:
// one row per (day, original_model, selected_model, turn_kind, mode) of the
// node-local router_decisions log. router_decisions / model_calibration are
// otherwise NODE-LOCAL (spec §R9.1); this content-free aggregate ships ONLY
// under the routing_detail tier (node opt-in / admin raise). Distinct from
// RoutingSummaryRow, which is model-id-free and ships under routing_summary.
type RoutingDetailRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD).
	Day string `json:"day"`
	// OriginalModel / SelectedModel are the ACTUAL model ids the decision
	// mapped between (unlike the tier-only summary).
	OriginalModel string `json:"original_model"`
	SelectedModel string `json:"selected_model"`
	// TurnKind is the classifier's turn-kind bucket; Mode is advise | enforce.
	TurnKind string `json:"turn_kind"`
	Mode     string `json:"mode"`
	// Decisions / Applied are row counts.
	Decisions int64 `json:"decisions"`
	Applied   int64 `json:"applied"`
	// EstSavingsUSD / CacheForfeitUSD are decision-time estimate sums.
	EstSavingsUSD   float64 `json:"est_savings_usd"`
	CacheForfeitUSD float64 `json:"cache_forfeit_usd"`
}

// LimitGaugeRow is the Arc 4 P5e predictions tier — one row per (day, provider)
// of the node-local limit_snapshots log (the 5h/weekly rate-limit gauge the
// Next-Message Cost & Limit Predictor records). limit_snapshots is otherwise
// NODE-LOCAL; this content-free aggregate — utilization stats only, no
// scope_hash, no session id, no raw headers — ships ONLY under the limit_gauge
// tier (node opt-in / admin raise).
type LimitGaugeRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the observations.
	Day string `json:"day"`
	// Provider is anthropic | openai.
	Provider string `json:"provider"`
	// Snapshots is the observation count for the (day, provider) bucket.
	Snapshots int64 `json:"snapshots"`
	// Max/Avg utilization of the 5h and weekly windows (0..1). Zero when the
	// provider never returned that window's header.
	Max5hUtil float64 `json:"max_5h_util"`
	Avg5hUtil float64 `json:"avg_5h_util"`
	Max7dUtil float64 `json:"max_7d_util"`
	Avg7dUtil float64 `json:"avg_7d_util"`
}
