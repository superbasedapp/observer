package orgcontract

// hookactivity.go carries the node's PER-SESSION HOOK LIVENESS counts to the
// org: surface-gap review 2026-10-25 finding OBS-7 ("nothing checks that
// hooks actually fired"), operator decision DEC-5, lane w5-wire.
//
// The node has recorded this since agent migration 198 (hook_activity, owned
// by internal/store/hookactivity.go). That table stays out of orgpush.go by
// name (tests/invariant/privacy_test.go forbiddenCacheTables); the wire is
// composed by internal/store/hookactivitysummary.go through a function call,
// the cache_events precedent.
//
// TWO LEVELS, ONE TIER:
//
//   - The COUNT half (session id, tool, event, count, first and last time,
//     and the coarse env classes such as "loopback" or "on") is closed
//     vocabulary plus opaque ids. It ships under
//     [org_client.share].hook_activity alone (org-raisable on a managed node
//     through extract.hook_activity or the extract.managed umbrella).
//   - A CONTENT-LEVEL env class (today only the CLAUDE_CONFIG_DIR path hash,
//     "hash:" plus 16 hex digits) additionally requires the node's raw-content
//     posture (ShareOptions.shipsRawContent()). Without it the entry is
//     dropped from EnvClasses on the node, never shipped and stripped later.
//
// HONESTY. SessionID "" is the node's EXPLICIT unattributed bucket: hook
// calls whose payload carried no session id. It never proves a session's
// hooks ran, and no org projection may join it to a session. A session with
// no row is "not observed" only on a node that ships this tier at all; an org
// read must not call a session silent for a developer whose node sent no
// hook activity.

// HookActivitySessionRow is one hook_activity row on the wire. Its natural
// key mirrors the node's PRIMARY KEY, (session_id, tool, event), scoped on the
// server by org and pushing user, so a re-pushed window upserts.
type HookActivitySessionRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID is the session the hook payload named; "" is the
	// unattributed bucket.
	SessionID string `json:"session_id"`
	// Tool is the AI tool id; Event the registry binding's native event
	// (for example PreToolUse) or the argv spelling when none resolved.
	Tool  string `json:"tool"`
	Event string `json:"event"`

	// Count is how many invocations the node drained for this key.
	Count int64 `json:"count"`
	// FirstAt / LastAt bound those invocations (RFC 3339, UTC).
	FirstAt string `json:"first_at"`
	LastAt  string `json:"last_at"`

	// EnvClasses maps a route-relevant env variable NAME to its coarse class
	// (internal/hookliveness.EnvProbes). Never a value. A content-level class
	// is present only when the node also ships raw content.
	EnvClasses map[string]string `json:"env_classes,omitempty"`
}
