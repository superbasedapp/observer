package orgcontract

// terminaldev.go carries the W2.6 per-developer RAW terminal + remote-access
// wire rows (see docs/plans/org-parity-full-depth-plan-2026-08-24.md §4
// "W2.6"). It is the per-dev sibling of the existing fleet-aggregate
// terminal_detail tier (internal/store/terminalsummary.go ->
// TerminalSummaryRow / RemoteAuditSummaryRow, gated by
// ShareOptions.TerminalDetail): that tier ships day x tool x kind counts with
// no user attribution and no content. These three row types ship the
// node-side terminal_run / terminal_commands / remote_audit rows themselves,
// scoped to the pushing developer, under the SAME admin_managed /
// full_content gate every other raw-content wire row uses
// (ShareOptions.shipsRawContent()) — not a new opt-in tier.
//
// Per the org-parity plan §1.4 control-plane rule: this is VISIBILITY only.
// The org server never launches, attaches to, or arms a terminal/remote
// session from these rows — it only renders what already happened.
//
// TWO GROUND-TRUTH CORRECTIONS to the shape a naive reading of "terminal
// commands" and "terminal runs" might expect, both confirmed by reading the
// actual node schema/write path before writing this file:
//
//  1. TerminalCommandRow carries NO raw command text or output. The node's
//     own terminal_commands table (internal/store/terminal_commands.go)
//     never stores it — its header comment states plainly: "CONTENT
//     DISCIPLINE (CLAUDE.md 'don't store command outputs'): metadata/
//     coordinates only. NO command text and NO output is ever stored here."
//     A command is represented locally by a domain-separated hash
//     (cmd_hash) plus turn-boundary timing/exit-code/trust metadata, and
//     that is exactly what ships here — shipping a fabricated "raw command"
//     field would misrepresent data the node never captured.
//  2. TerminalRunRow carries NO "sandboxed" flag. internal/store/termrun.go's
//     TerminalRun struct and its sole write site
//     (cmd/observer/terminal_launch.go::termRunRecorder.RecordRun) never
//     record whether a run's PTY was bwrap-sandboxed (internal/sandbox) —
//     there is no such column on terminal_run and no such field anywhere on
//     the launch path. Shipping a flag with nothing behind it would be
//     dishonest; it is omitted.
type TerminalRunRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (see
	// ingest.go forcePusherOrgID / forcePusherEmail).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// RunID is terminal_run.run_id — a crypto-random id, globally unique
	// across every node, so it doubles as the natural key alongside
	// (org_id, user_email). Called "run_key" in the migration/DB column
	// name for consistency with the process/verbosity siblings' "*_key"
	// naming, but it is the same value as the node's run_id.
	RunID string `json:"run_id"`
	// Tool / Kind mirror terminal_run.tool / terminal_run.kind (the
	// launcher tool name, and "fresh" | "attach" | "resume" | similar).
	Tool string `json:"tool,omitempty"`
	Kind string `json:"kind,omitempty"`

	// SourceSessionID is terminal_run.source_session_id — the session the
	// terminal was launched FROM (the dashboard session context), when
	// known. CorrelatedSessionID / CorrelatedConfidence are the terminal's
	// own best-guess correlated session — the SAME single-best-match
	// picked by internal/store/termrun.go::ListTerminalRuns via
	// terminal_run_session ordered by confidence DESC.
	SourceSessionID      string  `json:"source_session_id,omitempty"`
	CorrelatedSessionID  string  `json:"correlated_session_id,omitempty"`
	CorrelatedConfidence float64 `json:"correlated_confidence,omitempty"`

	LaunchedAt string `json:"launched_at"`
	EndedAt    string `json:"ended_at,omitempty"`
	Exited     bool   `json:"exited"`
	// ExitCode is only meaningful when Exited is true (0 is a legitimate
	// exit code, so it is not itself the signal — Exited is).
	ExitCode int64 `json:"exit_code,omitempty"`
	// EndReason mirrors terminal_run.end_reason (migration 072): ""
	// (still live / unknown) or one of internal/termrun/endreason.go's
	// vocabulary ("child_exit", "console_closed", "dashboard_stop",
	// "stopped_outside", "process_gone", "daemon_shutdown", "resumed", the
	// org floor's reason).
	EndReason string `json:"end_reason,omitempty"`

	// CommandCount is COUNT(*) over terminal_commands for this run — the
	// same subquery internal/store/termrun.go::ListTerminalRuns already
	// computes for the node's own terminal history view.
	CommandCount int64 `json:"command_count"`

	// The G19 isolation evidence (sandbox plan v2 section 8.4, node
	// migration 179, server 240 / PostgreSQL 0107). Closed enums from
	// internal/sandboxvocab; empty means not recorded (an old agent omits
	// them, an old server ignores them). They ride on this row, so they ship
	// exactly when it does (shipsRawContent()); nothing per-run is added
	// under terminal_detail. This supersedes the "no sandboxed flag" note
	// above: the node now records what each launch built.
	IsolationClass string `json:"isolation_class,omitempty"`
	// Stack is the backend ids, outermost first, comma separated.
	Stack        string `json:"stack,omitempty"`
	EgressTier   string `json:"egress_tier,omitempty"`
	CaptureLevel string `json:"capture_level,omitempty"`
	CaptureRule  string `json:"capture_rule,omitempty"`
	// CaptureOrigin lets an org tell rows a box could have written
	// (sandboxed, remote_sandbox) from rows the host attested (local).
	CaptureOrigin      string `json:"capture_origin,omitempty"`
	CaptureDegraded    bool   `json:"capture_degraded,omitempty"`
	NativeSandboxState string `json:"native_sandbox_state,omitempty"`
	Verification       string `json:"verification,omitempty"`
	KeyCustody         string `json:"key_custody,omitempty"`
	// EvidenceDigest is the run's execution evidence envelope digest
	// (internal/execevidence, roadmap F0-13).
	EvidenceDigest string `json:"evidence_digest,omitempty"`
	// EvidenceProducer, EvidenceComponent and EvidenceComponentVersion are
	// the producer inputs the digest was sealed over (node migration 181,
	// server 242 / PostgreSQL 0109), so the digest can be recomputed from
	// the row. An old agent omits them; an old server ignores them.
	EvidenceProducer         string `json:"evidence_producer,omitempty"`
	EvidenceComponent        string `json:"evidence_component,omitempty"`
	EvidenceComponentVersion string `json:"evidence_component_version,omitempty"`
	// EvidenceSeal is the run's signed seal (isolation.seal, execseal.go);
	// absent unsealed. An old server ignores it; an old agent's row reads
	// unsealed.
	EvidenceSeal *ExecEvidenceSeal `json:"evidence_seal,omitempty"`
}

// TerminalCommandRow is one terminal_commands row (a turn boundary inside a
// terminal run), scoped to the pushing developer and capped per run at push
// time (see internal/store/terminaldevorgrows.go::terminalCommandsPerRunCap).
// See the TerminalCommandRow ground-truth correction on TerminalRunRow's doc
// comment: there is no raw command text or output anywhere on this row by
// design — the node itself never stores it.
type TerminalCommandRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// RunID is the owning TerminalRunRow.RunID. TurnSeq is
	// terminal_commands.turn_seq — the row's natural key alongside
	// (org_id, user_email, run_id) is (org_id, user_email, run_key,
	// turn_seq).
	RunID   string `json:"run_id"`
	TurnSeq int64  `json:"turn_seq"`

	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
	Exited    bool   `json:"exited"`
	ExitCode  int64  `json:"exit_code,omitempty"`

	// Trust mirrors terminal_commands.trust: "oob" (out-of-band, PTY
	// escape-sequence reported) or "hint" (heuristic best-effort).
	Trust string `json:"trust,omitempty"`
	// CmdHash mirrors terminal_commands.cmd_hash — a domain-separated
	// correlation hash, never the command text itself.
	CmdHash string `json:"cmd_hash,omitempty"`
}

// RemoteAuditRow is one remote_audit row (a remote-session/pairing security
// event — connect/reject/pair/revoke and similar), scoped to the pushing
// developer and capped per push over a trailing window (see
// internal/store/terminaldevorgrows.go::remoteAuditEventCap). Unlike
// terminal_commands, remote_audit's own node-side schema already carries a
// human-readable detail string and a raw peer address by design (it is a
// security/audit log, not a content-discipline-constrained transcript
// table) — both ship here as-is under the same admin_managed /
// full_content gate.
type RemoteAuditRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// EventKey is the stringified node-local remote_audit.id. It is only
	// unique per node — the server's natural key is (org_id, user_email,
	// event_key), so two developers' local id=5 rows never collide.
	EventKey string `json:"event_key"`

	Timestamp string `json:"ts"`
	// Kind mirrors remote_audit.kind (e.g. "connect", "pair", "revoke").
	Kind string `json:"kind,omitempty"`
	// SessionID is the dashboard session this remote event correlates to,
	// when known.
	SessionID string `json:"session_id,omitempty"`
	// Principal is the authenticated remote identity (device/pairing
	// principal), when known.
	Principal string `json:"principal,omitempty"`
	// RemoteAddr is the RAW peer network address — explicitly included per
	// org-parity plan §0.1 ("peer addresses INCLUDED").
	RemoteAddr string `json:"remote_addr,omitempty"`
	// Route is the remote-access route/channel the event occurred on.
	Route string `json:"route,omitempty"`
	// Decision is the audit outcome (e.g. "allow", "deny").
	Decision string `json:"decision,omitempty"`
	// Detail is a short human-readable audit note. Never secrets — the
	// node's own remote_audit table never stores credentials/tokens here
	// (see internal/db/migrations/063_remote_audit.sql).
	Detail string `json:"detail,omitempty"`
}
