package orgcontract

// --- Org-tier observability wire shapes (obs-org-tier plan §3) -------------
//
// All four tiers are AGGREGATE-or-STRUCTURE-or-GATED-CONTENT; none carries a
// raw body except ObsContentRow (gated by shipsRawContent()). They are
// composed in orgpush.go via the obs provider seam, so the privacy sentinel
// never sees an obs_* table name there. OrgID/UserEmail are agent-stamped like
// every other wire row.

// ObsSummaryRow is the T1 AGGREGATE rollup: per (day, model, provider,
// project_hash, source) counts + token/cost/latency sums. CONTENT-FREE — no
// trace ids, no span topology, no names, no bodies. Pinned aggregate-only by a
// reflect test. project_hash is the content-free key (sha256 of project_root),
// the same posture sessions/api_turns already ship; the raw path never enters
// this row.
type ObsSummaryRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	Day       string `json:"day"` // UTC YYYY-MM-DD

	Model       string `json:"model,omitempty"`
	Provider    string `json:"provider,omitempty"`
	ProjectHash string `json:"project_hash,omitempty"`
	Source      string `json:"source,omitempty"` // provenance tag (otlp_trace/sdk_otlp/…)

	Traces           int64   `json:"traces"`
	Spans            int64   `json:"spans"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	ErrorTraces      int64   `json:"error_traces"`
	DurationMsSum    int64   `json:"duration_ms_sum"` // sum+count → server derives mean
	DurationMsCount  int64   `json:"duration_ms_count"`

	// TracesPrimary / ErrorTracesPrimary count each trace in exactly ONE row
	// of a push: the row of the trace's primary (model, provider) bucket
	// (finding F17). Traces above counts every trace that TOUCHED this
	// bucket, so it double-counts a trace that used two models; summing it
	// over models inflates the total. A server sums the *Primary fields for
	// totals. nil = a pre-F17 agent (the server then falls back to the
	// per-group MAX of Traces, a never-inflated lower bound). Old servers
	// ignore the keys (compat invariant, both directions).
	TracesPrimary      *int64 `json:"traces_primary,omitempty"`
	ErrorTracesPrimary *int64 `json:"error_traces_primary,omitempty"`
}

// ObsTraceRow is the T2 trace skeleton (STRUCTURE, hashes only). ProjectRoot
// ships only under shipsRawContent(); ProjectHash always.
type ObsTraceRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	TraceID     string  `json:"trace_id"`
	SessionID   string  `json:"session_id,omitempty"`
	ThreadID    string  `json:"thread_id,omitempty"`
	Source      string  `json:"source,omitempty"`
	Status      string  `json:"status,omitempty"`
	StartedAt   string  `json:"started_at,omitempty"`
	EndedAt     string  `json:"ended_at,omitempty"`
	ProjectHash string  `json:"project_hash,omitempty"`
	ProjectRoot string  `json:"project_root,omitempty"` // gated by shipsRawContent()
	RootSpanID  string  `json:"root_span_id,omitempty"`
	SpanCount   int64   `json:"span_count"`
	TotalTokens int64   `json:"total_tokens"`
	CostUSD     float64 `json:"cost_usd"`

	// Identity contract (W1a-2, finding F11; key lists in internal/otelident).
	// Service / Environment / Release are the app's deployment labels and
	// always ship. EndUser (PII) and Tenant (the customer's own tenant), and
	// since D23 their org-bound hashes too, ship ONLY under
	// shipsRawContent() (PrepareForWire clears both below it). Tags and Metadata
	// are free-form customer text and are gated like the raw values. All are
	// additive and omitempty: an old server ignores them, an old agent sends
	// none (compat invariant). Apply the gate with PrepareForWire.
	Service     string            `json:"service,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Release     string            `json:"release,omitempty"`
	EndUser     string            `json:"end_user,omitempty"`      // gated by shipsRawContent()
	EndUserHash string            `json:"end_user_hash,omitempty"` // gated by shipsRawContent() (D23)
	Tenant      string            `json:"tenant,omitempty"`        // gated by shipsRawContent()
	TenantHash  string            `json:"tenant_hash,omitempty"`   // gated by shipsRawContent() (D23)
	Tags        []string          `json:"tags,omitempty"`          // gated by shipsRawContent()
	Metadata    map[string]string `json:"metadata,omitempty"`      // gated by shipsRawContent()
}

// ObsSpanRow is the T2 span skeleton. RequestID is the CONTENT-FREE soft join
// key the server uses for the proxy-exact wedge (obs_spans × api_turns). Name
// is an operation label (chat/get_weather/…), not a body (§8 decision 2).
type ObsSpanRow struct {
	OrgID            string  `json:"org_id,omitempty"`
	UserEmail        string  `json:"user_email,omitempty"`
	TraceID          string  `json:"trace_id"`
	SpanID           string  `json:"span_id"`
	ParentSpanID     string  `json:"parent_span_id,omitempty"`
	Kind             string  `json:"kind,omitempty"`
	Name             string  `json:"name,omitempty"`
	StartedAt        string  `json:"started_at,omitempty"`
	EndedAt          string  `json:"ended_at,omitempty"`
	DurationMs       int64   `json:"duration_ms"`
	Status           string  `json:"status,omitempty"`
	Model            string  `json:"model,omitempty"`
	Provider         string  `json:"provider,omitempty"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	CostSource       string  `json:"cost_source,omitempty"`
	RequestID        string  `json:"request_id,omitempty"`
	ToolCallID       string  `json:"tool_call_id,omitempty"`
}

// ObsSpanEventRow is a T2 span-event (metadata only — name + time, no
// attribute bodies).
type ObsSpanEventRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	TraceID   string `json:"trace_id"`
	SpanID    string `json:"span_id"`
	Time      string `json:"time,omitempty"`
	Name      string `json:"name,omitempty"`
}

// ObsContentRow is the T3 raw span body, mirroring OTelContentRow: Content
// present only under shipsRawContent(), ContentHash always.
type ObsContentRow struct {
	OrgID       string `json:"org_id,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
	SpanID      string `json:"span_id"`
	Kind        string `json:"kind"` // prompt/response/tool_io
	ContentHash string `json:"content_hash"`
	Content     string `json:"content,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

// ObsEvalRow is the T4 eval-run health summary (content-free).
type ObsEvalRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	Day         string  `json:"day"`
	DatasetName string  `json:"dataset_name,omitempty"`
	RunName     string  `json:"run_name,omitempty"`
	ScorerName  string  `json:"scorer_name,omitempty"`
	Total       int64   `json:"total"`
	Passed      int64   `json:"passed"`
	MeanScore   float64 `json:"mean_score"`
	MinScore    float64 `json:"min_score"`
	Source      string  `json:"source,omitempty"` // offline/online
}

// ObsEndUserSpendRow is the T5 per-END-USER spend aggregate (org-budget
// guardrails plan §2.1) — the cross-instance attribution the node-local
// budget surfaces can't provide. EndUser is the hosted-app end-user id
// (obs_traces.user: OTel enduser.id / the admission `user` / the proxy
// X-Superbased-User header), NOT an org member — it is PII, so this row rides
// ONLY under shipsRawContent() (composed in orgpush.go under ObsSummary &&
// shipsRawContent). OrgID/UserEmail are agent-stamped, UserEmail = the pushing
// developer/operator (re-pinned server-side to the authenticated pusher);
// EndUser is app-shared and NOT re-pinned. Content-free otherwise (a $ + token
// + trace-count aggregate, no bodies).
type ObsEndUserSpendRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	Day         string  `json:"day"` // UTC YYYY-MM-DD
	EndUser     string  `json:"end_user"`
	CostUSD     float64 `json:"cost_usd"`
	Traces      int64   `json:"traces"`
	TotalTokens int64   `json:"total_tokens"`
}

// ObsCursor bounds an incremental obs structure/content push (T2/T3). v1 uses
// windowed-recompute (the server upserts by composite key), so the cursor is a
// simple since-day; the obs-owned high-water cursor is a documented follow-up.
type ObsCursor struct {
	SinceDay string `json:"since_day,omitempty"`
}

// ObsSpanBatch is the T2 structure push payload (traces + spans + events +
// cursor) returned by the obs provider in one shot.
type ObsSpanBatch struct {
	Traces []ObsTraceRow     `json:"traces"`
	Spans  []ObsSpanRow      `json:"spans"`
	Events []ObsSpanEventRow `json:"events"`
	Cursor ObsCursor         `json:"cursor"`
}

// ObsAdmissionRow is one input-admission verdict on the wire (Plane-A
// admission org tier, gap-audit 2026-07-10 §2.1 / #1a). It mirrors one
// obs_admission_events row: the node judges an end-user request against its
// admission policy and records the verdict; this row ships that verdict to the
// org server so admins get a READ-ONLY, monitoring-only fleet view. Authoring
// stays node-side — there is deliberately NO remote policy write.
//
// Privacy posture (mirrors GuardEventRow / ObsContentRow): the verdict
// METADATA is content-free and always ships (decision/severity/criterion +
// judge facts + latency + the soft-join ids + the node hash-chain links +
// message_hash — the raw request text is NEVER stored on the node, only its
// hash). The three content-bearing columns — Tenant, EndUser (PII: the
// hosted-app end-user id, obs_admission_events.user) and ReasonExcerpt (verdict
// prose that may quote the request) — ship ONLY under
// ShareOptions.shipsRawContent(), zeroed in orgpush.go otherwise. OrgID /
// UserEmail are agent-stamped like every other wire row (UserEmail = the
// pushing developer/operator, re-pinned server-side; EndUser is app-shared and
// NOT re-pinned).
type ObsAdmissionRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// TS is the verdict instant (RFC3339).
	TS string `json:"ts"`
	// Mode is the policy mode that judged the request: observe | enforce
	// (off never records).
	Mode string `json:"mode"`
	// Decision is the node's stored verdict vocabulary: allow | flag | ask |
	// deny. It ships VERBATIM — do NOT translate on the agent wire. The web2
	// contract renders blocked verdicts (ask/deny) as "would_block", but that
	// display mapping is the SERVER rollup's job; the agent must ship exactly
	// what the node stored so the server has the raw vocabulary.
	Decision string `json:"decision"`
	// Severity is the criterion severity: info | warn | high | critical.
	Severity string `json:"severity"`
	// CriterionID is the criterion that fired ('' when none did).
	CriterionID string `json:"criterion_id,omitempty"`
	// PolicyHash is the soft join to the ObsAdmissionPolicyRow that judged
	// this verdict.
	PolicyHash string `json:"policy_hash"`
	// JudgeUsed reports whether an LLM judge was invoked (vs a purely
	// deterministic verdict).
	JudgeUsed bool `json:"judge_used"`
	// JudgeHosting is the judge hosting bucket: local | provider | aggregator
	// | private | off.
	JudgeHosting string `json:"judge_hosting,omitempty"`
	// Degraded is the degradation cause when the judge did not cleanly decide:
	// '' | timeout-failopen | cache | prefiltered.
	Degraded string `json:"degraded,omitempty"`
	// LatencyMS is the admission-pipeline latency for this verdict.
	LatencyMS int64 `json:"latency_ms"`
	// MessageHash is the content-free hash of the raw request (the raw request
	// is NEVER stored on the node — this is the only always-present request
	// provenance).
	MessageHash string `json:"message_hash"`
	// TraceID / RequestID are content-free SOFT join keys (to obs_spans /
	// api_turns) so a verdict renders as enrichment on the trajectory view.
	TraceID   string `json:"trace_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// PrevHash / RowHash are the node's tamper-evidence hash-chain links
	// (content-free SHA-256 hex). RowHash doubles as the server-side dedup key.
	PrevHash string `json:"prev_hash,omitempty"`
	RowHash  string `json:"row_hash"`
	// CredID / WorkspaceID / EnvironmentID / VerdictID are set ONLY on an org
	// SDK verdict record (POST /v1/sdk/admit, source org_sdk) that the org
	// server itself publishes to its durable log (R-A06, ruling D22): the
	// asking ingest credential, its workspace and environment, and the
	// verdict id the API returned. Non-secret ids, content-free. A node never
	// sets them and ingest ignores them on a node push; on an SDK record
	// ingest computes RowHash / PrevHash itself (a per-credential chain).
	CredID        string `json:"cred_id,omitempty"`
	WorkspaceID   string `json:"workspace_id,omitempty"`
	EnvironmentID string `json:"environment_id,omitempty"`
	VerdictID     string `json:"verdict_id,omitempty"`

	// --- Content-bearing (PII / prose) — ship ONLY under shipsRawContent() ---
	// Tenant is the hosted-app tenant identifier.
	Tenant string `json:"tenant,omitempty"`
	// EndUser is the hosted-app end-user id (obs_admission_events.user) — PII.
	EndUser string `json:"end_user,omitempty"`
	// ReasonExcerpt is the verdict prose, which may quote the request.
	ReasonExcerpt string `json:"reason_excerpt,omitempty"`
}

// ObsAdmissionPolicyRow is one content-addressed admission policy snapshot on
// the wire (Plane-A admission org tier). It mirrors one
// obs_admission_policy_versions row. Body is the ADMIN's authored policy
// (config, not end-user content), so — like RoutingPolicyDoc.Body — it ALWAYS
// ships (never gated by shipsRawContent()); user requests never land in this
// table. OrgID / UserEmail are agent-stamped attribution.
type ObsAdmissionPolicyRow struct {
	OrgID         string `json:"org_id,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	PolicyHash    string `json:"policy_hash"`
	CreatedAt     string `json:"created_at"`
	Mode          string `json:"mode"`
	Scope         string `json:"scope"`
	CriteriaCount int64  `json:"criteria_count"`
	Body          string `json:"body"`
}

// ObsAdmissionBatch is the admission push payload (verdict events + policy
// snapshots + cursor) returned by the obs provider in one shot, mirroring
// ObsSpanBatch. Windowed-recompute v1 (the server upserts by RowHash /
// PolicyHash), so the cursor is a simple since-day.
type ObsAdmissionBatch struct {
	Events   []ObsAdmissionRow       `json:"events"`
	Policies []ObsAdmissionPolicyRow `json:"policies"`
	Cursor   ObsCursor               `json:"cursor"`
}

// ObsEvalItemRow is one per-item eval score on the wire (Plane-A eval-run
// detail org tier, gap-audit 2026-07-10 §1 / §2.2 / §6). It mirrors one
// obs_eval_scores row (source='run', run_id set) joined to its run
// (obs_eval_runs), dataset (obs_datasets) and dataset item (obs_dataset_items)
// for identity + content. Distinct from ObsEvalRow (T4), which ships run/scorer
// AGGREGATES only; this row is the per-item granularity the org Evals page
// needs to drill into a single run and to diff two runs of the same dataset.
//
// Privacy posture (mirrors ObsContentRow / ObsAdmissionRow): the score
// METADATA is content-free and always ships — the run/dataset identity, the
// span/trace soft-join keys, the scorer, the score/pass verdict, the scored
// span's duration, the score instant, and the dataset item's content_hash (the
// raw input/output are stored on the node ONLY under its ContentGate; the hash
// is the always-present content-free signal). The four content-bearing columns
// — InputExcerpt, ExpectedExcerpt, OutputExcerpt (bounded snapshots of the
// dataset item's input/reference/output) and Rationale (the scorer's verdict
// prose, which may quote the item) — ship ONLY under
// ShareOptions.shipsRawContent(), zeroed in composeObsTiers otherwise. OrgID /
// UserEmail are agent-stamped like every other wire row.
type ObsEvalItemRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// RunID is the node-local obs_eval_runs.id. It is meaningful only paired
	// with the pushing node (re-pinned user_email / pushed_by_user_id) — the
	// server keys a run by (org, node, run_id) and the rollup exposes an opaque
	// composite ref, never this bare integer, to the client.
	RunID   int64  `json:"run_id"`
	RunName string `json:"run_name,omitempty"`
	// DatasetID / DatasetName identify the run's dataset (obs_eval_runs.dataset_id
	// / obs_datasets.name). Same node-local caveat as RunID for the id.
	DatasetID   int64  `json:"dataset_id"`
	DatasetName string `json:"dataset_name,omitempty"`
	// ItemID is the obs_dataset_items.id (0 when the score had no item). SpanID /
	// TraceID are the content-free soft-join keys back to the trajectory view.
	ItemID  int64  `json:"item_id"`
	SpanID  string `json:"span_id,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
	// Scorer / Score / Passed / Source are the verdict (obs_eval_scores).
	Scorer string  `json:"scorer"`
	Score  float64 `json:"score"`
	Passed bool    `json:"passed"`
	Source string  `json:"source,omitempty"` // run | online (only 'run' ships)
	// DurationMs is the scored span's duration (obs_spans ended-started); 0 when
	// the span is gone or has no end. TS is the score instant (RFC3339).
	DurationMs int64  `json:"duration_ms"`
	TS         string `json:"ts"`
	// ContentHash is the dataset item's content-free signal (obs_dataset_items
	// .content_hash) — always present, even when the excerpts are withheld.
	ContentHash string `json:"content_hash,omitempty"`

	// --- Content-bearing (bounded excerpts / prose) — ship ONLY under
	// shipsRawContent() ---
	// InputExcerpt / ExpectedExcerpt / OutputExcerpt are bounded snapshots of the
	// dataset item's input / reference / output (obs_dataset_items), which are
	// themselves stored on the node ONLY under its ContentGate.
	InputExcerpt    string `json:"input_excerpt,omitempty"`
	ExpectedExcerpt string `json:"expected_excerpt,omitempty"`
	OutputExcerpt   string `json:"output_excerpt,omitempty"`
	// Rationale is the scorer's verdict prose (obs_eval_scores.rationale), which
	// may quote the item — gated with the excerpts.
	Rationale string `json:"rationale,omitempty"`
}

// ObsEvalItemBatch is the per-item eval push payload (scores + cursor) returned
// by the obs provider in one shot, mirroring ObsSpanBatch / ObsAdmissionBatch.
// Windowed-recompute v1 (the server upserts by the run/item/scorer natural
// key), so the cursor is a simple since-day.
type ObsEvalItemBatch struct {
	Items  []ObsEvalItemRow `json:"items"`
	Cursor ObsCursor        `json:"cursor"`
}
