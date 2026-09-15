package orgcontract

// toolaccountsession.go carries the node's VENDOR LOGIN OBSERVATIONS to the
// org — wave W3 of
// docs/plans/node-session-detail-trickle-up-to-org-plan-2026-09-10.md (D1
// matrix rows A1-A2).
//
// The node has captured this since agent migration 111
// (tool_account_observations, owned by internal/store/toolaccount.go) with the
// verbatim pin "Never copied by org push or foreign import" — the table name
// sits in tests/invariant/privacy_test.go's forbiddenCacheTables sentinel.
// This wire is the deliberate, reviewed reversal of that pin under the node's
// own [org_client.share].tool_account_detail tier.
//
// TWO LEVELS, ONE TIER — and here the second level is the arc's only genuine
// developer-PII boundary (operator decision D2):
//
//   - The BINDING half — binding_kind / binding_id / role / source / scope /
//     stage, the opaque account_key, the tool and the observation time — is
//     closed enums plus opaque ids. It ships under tool_account_detail ALONE.
//     That is deliberately enough to answer every question the org actually
//     asks of this data: which messages ran under a DIFFERENT account than
//     their neighbours (account_key changed), where the evidence CONFLICTS,
//     how many distinct accounts a session touched, and which messages have no
//     observation at all (unknown). None of it names a person.
//   - The IDENTITY half — Email / Name / AccountID — is the developer's own
//     vendor identity. It additionally requires the node's raw-content posture
//     (ShareOptions.shipsRawContent()).
//
// AccountKey is the node's normalized identity key for an observation
// (internal/toolaccount.Normalize). It is what makes "the account changed
// mid-session" answerable WITHOUT the email: two observations either share a
// key or they do not.
//
// HONESTY. A message with no observation is UNKNOWN. No projection may carry a
// login forward in time, infer an account for an unobserved message, or render
// an empty Email as "no account" — the node's own LoadMessageAccounts holds
// exactly that rule and the org side inherits it.

// SessionToolAccountRow is one tool_account_observations row on the wire. Its
// natural key mirrors the node's composite PRIMARY KEY exactly — (session_id,
// tool, binding_kind, binding_id, role, account_key, source, scope, stage) —
// so a re-pushed window upserts instead of duplicating, and a CONFLICTING
// observation (a second account_key for the same binding) is retained as its
// own row rather than overwriting the first. Retaining conflicts is the point:
// the node keeps them so the surface can say "conflict", never pick a winner.
type SessionToolAccountRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// SessionID / Tool scope the observation.
	SessionID string `json:"session_id"`
	Tool      string `json:"tool"`

	// BindingKind says WHAT the observation is attached to — "message" |
	// "turn" | "tool_call" — and BindingID is that anchor's own opaque
	// provider id (a message id, a turn id, or a tool_use id). Role is the
	// binding's role. All three are how the org joins an account to a
	// particular message on the session drawer.
	BindingKind string `json:"binding_kind"`
	BindingID   string `json:"binding_id"`
	Role        string `json:"role"`

	// AccountKey is the normalized, opaque identity key. It ships under
	// tool_account_detail alone: comparing keys answers "same account or not"
	// with no identity disclosed.
	AccountKey string `json:"account_key"`

	// Email / Name / AccountID are the raw vendor identity — the arc's one
	// developer-PII field set. Populated ONLY when tool_account_detail is on
	// AND the node's raw-content posture ships content (decision D2);
	// otherwise empty and dropped by omitempty. EMPTY means "not shared or not
	// observed", never "no account".
	Email     string `json:"email,omitempty"`
	Name      string `json:"name,omitempty"`
	AccountID string `json:"account_id,omitempty"`

	// Source / Scope / Stage are the closed-vocabulary provenance of the
	// evidence: where it was read, what it covers, and at which point in the
	// tool's lifecycle it was captured. Stage is load-bearing on read — the
	// node's own message-account resolver discards 'stop'-stage evidence — so
	// it ships rather than being collapsed server-side into a boolean.
	Source string `json:"source"`
	Scope  string `json:"scope"`
	Stage  string `json:"stage"`

	// ObservedAt is when the evidence was seen (RFC3339). The node never moves
	// it on replay, so it is a stable ordering key for "which account was in
	// force first".
	ObservedAt string `json:"observed_at"`
}
