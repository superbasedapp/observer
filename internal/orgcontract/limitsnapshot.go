package orgcontract

// limitsnapshot.go is the per-session rate-limit snapshot org wire (lane
// F-WIRE, 2026-09-28): the node's proxy-captured subscription-window gauge
// (agent migration 049's node-local limit_snapshots) reaching the org session
// drawer, so the org renders the same "% of limit spent" gauge the node's
// session detail does.
//
// WHAT SHIPS. Metadata only: which provider's window, the 5h / 7d
// utilization (0..1) and reset stamps, when it was observed, and which
// session (and so which tool) observed it. NEVER the node's scope_hash (an
// auth-identity hash), never the raw header subset or the unified-status
// passthrough, never the per-minute request/token counters. Every field is a
// number, a timestamp or an enum.
//
// POSTURE. The row is metadata, so it needs no raw-content grant of its own,
// but it is the per-session sibling of the existing limit_gauge tier
// (LimitGaugeRow), so it ships under the SAME consent: the node's
// [org_client.share].limit_gauge opt-in (or an admin raise of it on a managed
// node), OR a node that already ships everything (shipsRawContent(): every
// enrolled teams/enterprise node under the full-capture ruling). An individual
// node that never opted into limit_gauge ships none, exactly as before. A
// scoped push ([org_client.scope] allow/deny list) treats a snapshot whose
// session is out of scope like an unlinked one: consumed, never shipped.
//
// ONE ROW PER (session, provider). limit_snapshots grows by one row per
// proxied response. The node composes this wire on a CURSOR (the snapshot id
// high-water mark, PushCursor.LimitSnapshots) and coalesces the rows above it
// to the NEWEST observation per (session, provider) before shipping, so a
// busy session costs one row per push, not one per response. The server
// keeps the newest observation per (owner, session, provider) (newest
// observed_at wins, see internal/orgserver/ingest/limitsnapshots.go).
//
// COMPAT (both directions). The envelope key is omitempty: an older agent
// sends no key and the server writes nothing (the org drawer then renders the
// gauge as not reported, never 0%), and an older server ignores the key. The
// pointer fields are nil exactly where the node's column is NULL (the provider
// never sent that window's header), and must stay "unknown" on the org.

// SessionLimitSnapshotRow is the newest rate-limit window observation one
// node recorded for one (session, provider).
type SessionLimitSnapshotRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher, like every wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID is the session whose proxied response carried the headers.
	// Only snapshots linked to a session the node knows ship at all: the
	// gauge is attributed to the TOOL that observed the window (see Tool),
	// and an unlinked snapshot has no tool.
	SessionID string `json:"session_id"`
	// Tool is the observing session's tool, resolved node-side at compose
	// time (the node gauge's own attribution join), so the org can pick "the
	// newest window this developer's <tool> observed" without waiting for the
	// sessions row to arrive.
	Tool string `json:"tool"`
	// Provider is the upstream whose headers were read (anthropic | openai).
	Provider string `json:"provider"`

	// LocalID is the node's limit_snapshots id of the shipped observation.
	// It is a deterministic tie-break only (two observations in the same
	// second), never an identity across nodes.
	LocalID int64 `json:"local_id"`
	// ObservedAt is when the node recorded the observation (unix seconds).
	ObservedAt int64 `json:"observed_at"`

	// Window5hUtil / Window7dUtil are the 5-hour and weekly window
	// utilization (0..1); nil when the provider sent no such header.
	Window5hUtil *float64 `json:"window_5h_util,omitempty"`
	Window7dUtil *float64 `json:"window_7d_util,omitempty"`
	// Window5hReset / Window7dReset are the windows' reset stamps (unix
	// seconds); nil when absent.
	Window5hReset *int64 `json:"window_5h_reset,omitempty"`
	Window7dReset *int64 `json:"window_7d_reset,omitempty"`
}
