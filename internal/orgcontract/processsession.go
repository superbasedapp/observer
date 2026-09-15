package orgcontract

// SessionProcessRow is the W2.2 session-scoped process-observability wire row
// (org-parity plan §4 W2.2, docs/plans/org-parity-full-depth-plan-2026-08-24.md).
// It is the per-session sibling of ProcessSummaryRow: ProcessSummaryRow ships a
// content-free day×tool fleet aggregate (Arc 4 P5g) that cannot slice to a
// session; this row ships the node's own process_runs columns RAW so the org
// session detail can render the same System tab the node dashboard shows
// (web/src/components/sessiondetail/SystemTab.tsx → ProcessesSection.tsx),
// scoped to one session.
//
// Per §0 of the org-parity plan (enterprise-first — supersedes the teams/
// opt-in framing elsewhere in this file's siblings), this row carries RAW
// fields — exe path, argv preview, cwd — not hashes-only. It ships under
// ShareOptions.shipsRawContent() (full_content or the enterprise
// admin_managed default), exactly like OTelContentRow's raw body. It never
// carries a network body (process_network_bodies stays off this wire — a
// later content wave; see project memory "Process arcs — plaintext bodies
// ONLY") and never carries a derived §14 finding (findings are computed
// on-read from a rules engine over the full run set — internal/processobs —
// which is out of scope for a per-row push; a future wave can port the
// derivation server-side or ship raw finding facts).
type SessionProcessRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID is the owning session. RunKey is the node's process_key
	// (sha256(boot_id:pid:start_time), docs/process-observability.md §9.3) —
	// the natural per-run identity used for idempotent server-side upsert
	// (PIDs are reused, so pid alone is never a key). ParentRunKey is the
	// parent run's process_key when known, carrying the process TREE
	// structure across the wire without a second query.
	SessionID    string `json:"session_id"`
	RunKey       string `json:"run_key"`
	ParentRunKey string `json:"parent_run_key,omitempty"`

	// PID / PPID are the raw OS process ids, kept for the tree view exactly
	// as the node keeps them (never joined on in isolation — RunKey is the
	// identity).
	PID  int64 `json:"pid"`
	PPID int64 `json:"ppid,omitempty"`

	// Tool is the attributed AI tool (e.g. claude-code) or '' when
	// unattributed. ActionID / TurnIndex are the §9.2.4 spawning-message link
	// (0 when absent) — the org-side equivalent of the node's message_id
	// jump-to-message link on a process row.
	Tool      string `json:"tool,omitempty"`
	ActionID  int64  `json:"action_id,omitempty"`
	TurnIndex int64  `json:"turn_index,omitempty"`

	// MessageID is the id of the assistant MESSAGE that spawned this run,
	// resolved node-side from the correlated action (actions.message_id by
	// ActionID; process_runs itself has no message_id column) — the value the
	// node's own System tab uses to jump from a process row back to the message
	// that issued the command. Empty when the run was never action-correlated
	// or the correlated action carries no message id. CONTENT-FREE (an opaque
	// provider id like an Anthropic "msg_…"), so it ships alongside the other
	// process metadata; additive/omitempty both directions.
	MessageID string `json:"message_id,omitempty"`

	// ExePath / ExeBasename / ExeHash / CWD / ArgvPreview / ArgvArgc are the
	// node's process_runs identity columns, RAW (§0.1 — the admin sees all).
	// ArgvPreview is already a scrubbed/capped preview on the node (never the
	// full command line) — this row ships that preview as-is, not a further
	// reduction.
	ExePath     string `json:"exe_path,omitempty"`
	ExeBasename string `json:"exe_basename,omitempty"`
	ExeHash     string `json:"exe_hash,omitempty"`
	CWD         string `json:"cwd,omitempty"`
	ArgvPreview string `json:"argv_preview,omitempty"`
	ArgvArgc    int64  `json:"argv_argc,omitempty"`

	// AttributionSource / AttributionConfidence carry the node's own data
	// quality signal for this row (e.g. env_token/bridge/adapter_pid/
	// inherited/none), so the org UI can render the same trust affordance the
	// node does rather than presenting every row as equally certain.
	AttributionSource     string `json:"attribution_source,omitempty"`
	AttributionConfidence string `json:"attribution_confidence,omitempty"`

	// StartedAt / EndedAt are RFC3339 UTC; EndedAt is empty while the run is
	// still live at push time (mirrors the node's own "running" state).
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at,omitempty"`
	Exited    bool   `json:"exited"`
	ExitCode  int64  `json:"exit_code,omitempty"`
	// ExitSignal is the signal number that terminated the process, 0 when the
	// process exited normally or is still running.
	ExitSignal int64 `json:"exit_signal,omitempty"`
	DurationMs int64 `json:"duration_ms,omitempty"`

	// Resource metrics — cumulative CPU time, peak RSS, current working set,
	// live thread count, disk I/O. All content-free numeric counters (never a
	// path or a command), so they ship alongside the other process metadata.
	CPUUserMs   int64 `json:"cpu_user_ms,omitempty"`
	CPUSystemMs int64 `json:"cpu_system_ms,omitempty"`
	MaxRSSBytes int64 `json:"max_rss_bytes,omitempty"`
	// WorkingSetBytes is the current (instantaneous) RSS at last poll, distinct
	// from MaxRSSBytes (the peak). ThreadCount is the live OS thread count.
	// Both are the node's process_runs.working_set_bytes / thread_count
	// (migration 045), 0 when the node never captured them (non-Windows poll
	// capturer, pre-feature rows) — additive/omitempty both directions.
	WorkingSetBytes int64 `json:"working_set_bytes,omitempty"`
	ThreadCount     int64 `json:"thread_count,omitempty"`
	ReadBytes       int64 `json:"read_bytes,omitempty"`
	WriteBytes      int64 `json:"write_bytes,omitempty"`

	// MetricSamplesJSON is the node's per-process sparkline ring
	// (process_runs.metric_samples_json, migration 045): a compact JSON array
	// of recent {t,cpu_ms,ws,rb,wb,…} samples driving the working-set trend
	// chart. It is HIGH-VOLUME, so unlike the other columns it is CAPPED on the
	// wire (the node-side SELECT keeps only the most-recent samples under a
	// fixed byte ceiling, and the push loop drops the whole ring for a row
	// rather than let the samples overrun the envelope budget). Content-free
	// numeric counters; empty when the node captured no samples or the cap
	// dropped them. Additive/omitempty both directions.
	MetricSamplesJSON string `json:"metric_samples_json,omitempty"`

	// EventCount is the number of process_events rows attributed to this run
	// (network/file/privilege/etc — event TYPE and TARGET stay node-local; a
	// count is all that crosses). This is the "process-event counts" half of
	// W2.2 — no event body, no target, no network body ever rides this row.
	EventCount int64 `json:"event_count,omitempty"`
}
