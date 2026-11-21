package orgcontract

// SessionProcessRollupRow is one rollup group of a session's process capture
// for one bucket (docs/plans/process-capture-budget-plan-2026-11-04.md §4.8,
// layer O1): the runs the node's capture budget counted but did not keep as
// their own SessionProcessRow (folded console hosts, runs past an exemplar
// budget, a service's subtree past its exemplar cap). It mirrors one row of
// the node-local process_rollups table (agent migration 212), whose UNIQUE
// group key is (session_id, bucket_start, group_kind, parent_process_key,
// service_root_key, exe_basename, argv_template_hash); the server upserts on
// the same key, so a re-pushed trailing window REPLACES the counters rather
// than adding to them (the node is the one place counts are summed).
//
// The machine-level rollup (node session_id NULL, group_kind "unattributed")
// never ships: this is a session-scoped wire.
//
// Privacy posture: the whole row ships under ShareOptions.shipsRawContent(),
// the same tier as SessionProcessRow beside it. ExampleArgvPreview is the one
// content-bearing field (an already-scrubbed, capped argv preview of one run
// in the group, exactly what SessionProcessRow.ArgvPreview carries); the node
// store seam re-applies the gate and empties it when the share options do not
// ship raw content. Every other field is a hash, an opaque process key, a
// closed vocabulary or a counter. Optional both directions.
type SessionProcessRollupRow struct {
	// OrgID / UserEmail are the agent-stamped attribution; the server
	// overwrites both with the authenticated pusher's.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	SessionID string `json:"session_id"`
	// BucketStart is the RFC3339 UTC start of the rollup bucket
	// ([observer.process.capture.rollups].bucket_seconds wide on the node).
	BucketStart string `json:"bucket_start"`
	// GroupKind is "budget", "fold" or "service" ("unattributed" is the
	// machine rollup, which never ships).
	GroupKind        string `json:"group_kind"`
	ParentProcessKey string `json:"parent_process_key,omitempty"`
	ServiceRootKey   string `json:"service_root_key,omitempty"`
	// ActionID is the node action the group's runs were linked to (0 when
	// none).
	ActionID    int64  `json:"action_id,omitempty"`
	ExeBasename string `json:"exe_basename,omitempty"`
	// ArgvTemplateHash identifies the argv template the group's runs share
	// (a hash, never the argv itself).
	ArgvTemplateHash   string `json:"argv_template_hash,omitempty"`
	ExampleArgvPreview string `json:"example_argv_preview,omitempty"`
	ExampleProcessKey  string `json:"example_process_key,omitempty"`

	Count         int64  `json:"count"`
	FailedCount   int64  `json:"failed_count,omitempty"`
	DurationSumMs int64  `json:"duration_sum_ms,omitempty"`
	DurationMaxMs int64  `json:"duration_max_ms,omitempty"`
	CPUSumMs      int64  `json:"cpu_sum_ms,omitempty"`
	PeakRSSBytes  int64  `json:"peak_rss_bytes,omitempty"`
	FirstSeen     string `json:"first_seen,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
}

// SessionProcessCaptureStatsRow is one session's process capture counters
// (the node-local process_capture_stats row, agent migration 212): how many
// runs the backend reported for the session and what the capture budget did
// with them. The count invariant holds on the node and therefore on the wire:
// Kept + Folded + RolledUp + ServiceKept + ServiceRolledUp + Dropped ==
// Observed. Upserted on (org, pusher, session_id), REPLACED by each push.
//
// Its presence is what tells the org drawer the session was captured under
// the budget; a session with process rows and no stats row was captured by an
// agent without the budget (the summary's `legacy`). The machine row (node
// session id ”) never ships. Content-free counters only; ships under the
// same shipsRawContent() tier as SessionProcessRow. Optional both directions.
type SessionProcessCaptureStatsRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	SessionID       string `json:"session_id"`
	Observed        int64  `json:"observed"`
	Kept            int64  `json:"kept"`
	Folded          int64  `json:"folded,omitempty"`
	RolledUp        int64  `json:"rolled_up,omitempty"`
	ServiceKept     int64  `json:"service_kept,omitempty"`
	ServiceRolledUp int64  `json:"service_rolled_up,omitempty"`
	Dropped         int64  `json:"dropped,omitempty"`
	BudgetHits      int64  `json:"budget_hits,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}
