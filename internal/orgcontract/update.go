package orgcontract

// Enterprise Update Management wire types
// (docs/plans/enterprise-update-management-plan-2026-09-07.md §2.1 / §3.5).
//
// TWO seams, both OPTIONAL and both additive, so the v1.7-agent <-> v1.8-server
// compat invariant holds in BOTH directions without a version negotiation:
//
//   - server -> node: PushResponse.UpdateVersions, a per-channel version-number
//     NUDGE (see types.go). It carries no document and forces nothing.
//   - node -> server: PushEnvelope.UpdatePosture, the enum-only self-report
//     below.
//
// The manifest itself never rides either one: it is fetched with a separate
// authenticated GET on the agent rail, exactly as an announcement is
// (orgclient/announce.go), so it stays independently verifiable rather than
// smuggled inside a batch ACK.

// UpdatePostureRow is the node's self-reported update state, and it is the
// WHOLE of what a node discloses about updating itself (plan §2.1, ruling
// R10).
//
// Every field is a version string, a coarse platform token, a closed enum or a
// boolean. There is deliberately NO hostname, NO username, NO path, NO
// progress bytes and NO free-text error: an error STRING can leak a path, an
// error CLASS cannot. The row is composed by internal/store/updateposture.go
// (W3) and called BY internal/store/orgpush.go, so the privacy sentinel keeps
// forbidding the node-local update_state / update_events table names inside
// that seam — the routing_summaries precedent.
//
// It only ever NARROWS what the admin believes and never widens access,
// exactly like HeaderGrantReplacementAck: a lying node can at worst halt a
// rollout, which is the fail-safe direction (docs/security.md UPD-4).
//
// The field set is pinned structurally by
// tests/invariant/privacy_test.go::TestUpdatePostureRowWireShapeIsEnumOnly — a
// new field fails there before it can ship.
type UpdatePostureRow struct {
	// Version is the running binary's main.version. Already sent as
	// PushEnvelope.AgentVersion; repeating it here keeps the posture row
	// self-describing for the board that renders it.
	Version string `json:"version,omitempty"`
	// Channel is "stable" / "lts" / "edge" — a configuration choice, not
	// data about the developer.
	Channel string `json:"channel,omitempty"`
	// OS and Arch are the coarse platform needed to pick an artifact. Both
	// are already inferable from the adapter mix.
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// State is update.State: idle / available / downloading / verified /
	// applying / applied / failed / rolled_back / blocked / stale_manifest.
	// An enum, never a message.
	State string `json:"state,omitempty"`
	// Reason qualifies State when it is "blocked" (update.Reason:
	// unsigned_artifact / required_stop / no_artifact / install_method /
	// not_writable / downgrade_not_allowed / window). Also a closed
	// vocabulary — it is the difference between "this fleet needs MDM" and
	// "this fleet is broken", which is precisely what the admin is looking
	// at the board to learn.
	Reason string `json:"reason,omitempty"`
	// TargetVersion and ManifestVersion say what this node is trying to
	// reach; the ring health gate needs both.
	TargetVersion   string `json:"target_version,omitempty"`
	ManifestVersion int64  `json:"manifest_version,omitempty"`
	// ErrorClass is update.ErrorClass: download / hash / signature / probe /
	// swap / permission / healthcheck / window / drain. Never a message.
	ErrorClass string `json:"error_class,omitempty"`
	// InstallMethod is update.Method: binary / binary_readonly / npm / pip /
	// vscode / brew / apt / rpm / unknown. It tells the admin why a node
	// reports blocked, and which nodes a `refuse` skew policy would strand
	// with no automatic remediation (plan §6 O5).
	InstallMethod string `json:"install_method,omitempty"`
	// AutoApply reports whether this node will apply an update without a
	// human. It is a boolean configuration fact the SERVER cannot otherwise
	// know — [update].auto_apply is node-owned and there is no remote
	// toggle — and the Updates board needs it to answer "which of my fleet
	// is actually zero-touch". Enum-shaped in the sense R10 means: a closed
	// value, never free text.
	AutoApply bool `json:"auto_apply,omitempty"`
	// ExtensionVersion is the VS Code extension's version WHEN one is
	// running and has told the daemon. Empty means "no extension reported",
	// never "0" — R6's honest narrowing. The browser extension is not
	// published yet, so v1 ships this field for the editor only.
	ExtensionVersion string `json:"extension_version,omitempty"`
}

// AgentTooOldBody is the typed 426 Upgrade Required body a server returns when
// [server].min_agent_version_action = "refuse" and a node pushes from below
// the floor (plan §4 W5, ruling R3, open decision O5).
//
// It is a SUPERSET of the standard {error, message} error body every other
// refusal on this rail uses, so a node too old to know about this shape still
// decodes and logs something meaningful. The three fields that matter are
// machine-readable:
//
//   - Reason is always update.RefusalReasonAgentTooOld ("agent_too_old"), so a
//     node can tell this apart from every other 4xx without string-matching
//     prose;
//   - MinVersion names what the org requires;
//   - YourVersion echoes what this node reported, so the message a developer
//     sees is complete without a second round trip.
//
// NOTHING is ingested when this is returned. The refusal is decided BEFORE the
// ingest transaction opens, because a partially-ingested refused push would be
// the worst of both answers.
type AgentTooOldBody struct {
	Error       string `json:"error"`
	Message     string `json:"message"`
	Reason      string `json:"reason"`
	MinVersion  string `json:"min_version"`
	YourVersion string `json:"your_version"`
	// UpdateVersions is the SAME optional update nudge PushResponse carries
	// (§3.5): the latest published manifest version per channel.
	//
	// It is here because a refused node is the node that most needs it. The
	// refusal ends the cycle before the 200 path's nudge is ever composed, so
	// without this field a self-updatable node below the floor learns nothing
	// about the release that would lift it over — the remediation gated
	// behind the push the floor refuses. Additive and omitempty, exactly like
	// PolicyVersions: a node too old to know the field ignores it, and a
	// server too old to send it leaves the node's own fallback in charge.
	UpdateVersions map[string]int64 `json:"update_versions,omitempty"`
}
