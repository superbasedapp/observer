package orgcontract

// taskflowsession.go carries the node's SESSION TASK CHECKLIST to the org —
// wave W2 of docs/plans/node-session-detail-trickle-up-to-org-plan-2026-09-10.md
// (D1 matrix rows T1-T4).
//
// The node has captured this since agent migration 109 (task_items /
// task_transitions, owned by internal/store/taskflow.go and decoded by the
// pure internal/taskflow) and pinned it NODE-LOCAL: both table names sit in
// tests/invariant/privacy_test.go's forbiddenCacheTables sentinel, so the push
// seam could not name them at all. This wire is the deliberate, reviewed
// reversal of that pin, under the SAME node-authored gating model the rest of
// the Teams product uses — never a server-side force.
//
// TWO LEVELS, ONE TIER. The gate is deliberately split, because the two halves
// of a checklist are different disclosure classes:
//
//   - The STATUS half — the shared status vocabulary, the vendor's own
//     raw_status spelling, the ordering, the unmatched (vanish) flag and every
//     transition — is closed-vocabulary metadata plus counters. It ships under
//     [org_client.share].task_detail ALONE, which is what lets an org render
//     "5 of 9 done, 1 vanished, 3 still open" for a session without ever
//     learning what the work was.
//   - The PROSE half — Content / ActiveForm / Owner — is agent-authored free
//     text describing the work plan, the same content class as
//     actions.target / raw_tool_input. It additionally requires the node's raw
//     content posture (ShareOptions.shipsRawContent(): full_content,
//     admin_managed, or the enterprise grant), exactly like obs.content's raw
//     body rides on top of its own tier while the content_hash ships
//     regardless.
//
// Both fields are omitempty, so a task_detail-but-not-content node produces a
// row that is byte-identical to one where the tool genuinely recorded no
// active form or owner. That ambiguity is deliberate and safe in this
// direction: a reader may never present an EMPTY Content as "the task had no
// description", only as "not shared / not recorded" — the same honesty rule
// SessionLOCRow.LanguageMixJSON carries.

// SessionTaskItemRow is one task_items row on the wire: the current known
// state of one checklist item in one session. Grain and identity mirror the
// node exactly — (session_id, key) is the natural key on both sides, so a
// re-pushed window upserts rather than duplicating.
type SessionTaskItemRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row; the server re-stamps both from the
	// authenticated pusher).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID is the session this checklist belongs to. Tool is the AI tool
	// whose todo/plan call produced it (claude-code TodoWrite, codex
	// update_plan, copilot, freebuff, kiro-cli, ...).
	SessionID string `json:"session_id"`
	Tool      string `json:"tool"`

	// Key is the item's identity WITHIN the session and KeyKind says how it
	// was derived: "native_id" when the vendor assigned one (claude-code
	// taskId, copilot id, kiro-cli index) or "content_hash" when the tool ships
	// no id at all and the node hashed the item's own text. A content_hash key
	// is a one-way digest, not the text — it ships in every posture, like every
	// other *_hash column on this wire.
	Key     string `json:"key"`
	KeyKind string `json:"key_kind"`

	// Content / ActiveForm / Owner are the CONTENT half — agent-authored plan
	// prose. They are populated ONLY when the node's task_detail tier is on
	// AND its raw-content posture ships content (shipsRawContent()); otherwise
	// they are empty and omitempty drops them from the wire entirely. EMPTY
	// means "not shared or not recorded", NEVER "the item had no text".
	Content    string `json:"content,omitempty"`
	ActiveForm string `json:"active_form,omitempty"`
	Owner      string `json:"owner,omitempty"`

	// RawStatus is the vendor's OWN spelling of the status (five dialects
	// collapse onto Status's shared vocabulary node-side); Status is the shared
	// vocabulary value (pending | in_progress | completed | cancelled |
	// deleted | vanished). Both are closed enums, so both are metadata: keeping
	// the raw spelling means a per-tool dialect never has to be re-derived
	// server-side.
	RawStatus string `json:"raw_status,omitempty"`
	Status    string `json:"status"`

	// OrderIndex is the item's display position (Snapshot-family tools) and
	// FirstSeenAt / LastSeenAt bound its observed life. Times are RFC3339, the
	// same encoding every other row on this wire uses.
	OrderIndex  int64  `json:"order_index"`
	FirstSeenAt string `json:"first_seen_at"`
	LastSeenAt  string `json:"last_seen_at"`

	// Unmatched is the §R2.3.4 vanish flag: a Snapshot-kind (whole-list
	// rewrite) tool stopped listing this item without ever marking it done.
	// It is a COUNTED LOSS, not an inferred deletion — a projection must
	// render it as "vanished", never fold it into "completed".
	Unmatched bool `json:"unmatched,omitempty"`
}

// SessionTaskTransitionRow is one task_transitions row on the wire: an
// append-only status change for one item. It is pure metadata — two closed-
// vocabulary statuses, a timestamp and two opaque correlation ids — so it
// ships whole under task_detail with no second content gate.
//
// FromStatus is "" for a key's first-observed state (no prior row existed);
// that empty string is meaningful and must not be rendered as a status.
type SessionTaskTransitionRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	SessionID string `json:"session_id"`
	Key       string `json:"key"`

	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status"`
	Ts         string `json:"ts"`

	// ActionID is the node's own actions.id for the tool call that caused the
	// change (0 when unknown) — the join key an org-side rollup uses to
	// attribute elapsed time, actions and tokens to an item. SourceEventID is
	// the vendor's tool_use id, and is part of the natural key on BOTH sides,
	// which is what makes applying the same logical call twice (once via its
	// own actions row, once via a claude-code post_tool_batch envelope) an
	// idempotent no-op rather than a double-counted transition.
	ActionID      int64  `json:"action_id,omitempty"`
	SourceEventID string `json:"source_event_id,omitempty"`
}
