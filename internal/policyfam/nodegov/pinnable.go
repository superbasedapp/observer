package nodegov

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// Admin-controlled Plane B, Phase 1b: the CLOSED vocabularies for the
// schema-2 directive classes (`pinned`, `share`, `features`).
//
// docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md §1.9,
// §2, §3. Every table here is an ALLOW-LIST, never a deny-list: a body
// naming something outside it is a HARD compile error on both the publish
// lint and the agent accept path, because an admin must never believe a key
// is pinned when the node silently skipped it.

// Direction bounds WHICH values the organization may force for a key. It is
// an alias of postureop.Direction (roadmap F0-8): the direction table and its
// merge operators live in the pure leaf internal/postureop so
// internal/config's overlay applies the same operator for a direction as this
// package's compilePinned checks at publish and accept.
type Direction = postureop.Direction

const (
	// DirFree — the org may set either value.
	DirFree = postureop.DirFree
	// DirRestrictiveOnly — the org may only force the SAFER value, which is
	// the key's Safe field and the only value a body may carry for it.
	DirRestrictiveOnly = postureop.DirRestrictiveOnly
	// DirLoweringOnly is the share block's algebra (§2.1): the effective
	// value is always at or below the node's own local value, so an org
	// directive can pin or reduce, never raise.
	//
	// In PinnableKeys it appears ONLY on an "int" row (the 2026-10-02
	// budget-latency arc's org_client.push_interval_seconds), where it means
	// exactly the numeric lowering the budget rail already uses
	// (govern.LowerInt): the org's value is a CEILING. A node whose own
	// value is lower keeps it; a node whose own value is higher (or unset,
	// i.e. the default) takes the org's. The org can therefore make a node
	// report faster, never slower. Pinned by TestLoweringOnlyPinRowsAreInts.
	DirLoweringOnly = postureop.DirLoweringOnly
	// DirRaisingOnly: the org value is a numeric floor (first row: the
	// Landlock-only sandbox's min_abi, lane SBX-P3B).
	DirRaisingOnly = postureop.DirRaisingOnly
	// DirOrderedFilter: the org list removes entries from the node's
	// preference order, never adds or reorders.
	DirOrderedFilter = postureop.DirOrderedFilter
	// DirSetIntersection: local AND org; an empty intersection allows
	// nothing (never any).
	DirSetIntersection = postureop.DirSetIntersection
	// DirAdditiveMask: the org entries are added to the node's own.
	DirAdditiveMask = postureop.DirAdditiveMask
	// DirRetention: a day count, 0 forever; the org may lengthen, never
	// shorten.
	DirRetention = postureop.DirRetention
)

// PinnableKey is one row of the settings.pin vocabulary: a dotted config
// path the organization may fix, the Go kind its value must have, the
// closed value set (when the key is enum-shaped), and the direction bound.
//
// Key MUST resolve against config.Default() — pinned by
// TestEveryPinnableKeyResolvesInConfig, which walks every row here against a
// reflect-walked default Config. That test exists because four rows of the
// spec's first draft named paths that did not exist in the tree
// (review B1): a table whose prose claims its paths were checked is not a
// check.
type PinnableKey struct {
	// Key is the dotted config path (the TOML tag chain), e.g. "guard.mode".
	Key string
	// Kind is "bool" | "string" | "int" | "string_list".
	Kind string
	// Enum, when non-empty, is the ONLY permitted value set. It exists so a
	// value config.Validate would reject (the live instance is
	// guard.mode = "strict") is refused at PUBLISH and at ACCEPT rather
	// than at config.Load — where it would turn every hook invocation on
	// every node into an early return (review B4).
	Enum []any
	// Direction bounds which values the org may force.
	Direction Direction
	// Safe is the ONLY value a DirRestrictiveOnly key may carry.
	Safe any
	// Format, when non-empty, is a closed value shape a "string" row must
	// have (postureop.CheckFormat, e.g. an image pinned by digest), checked
	// at publish and accept like Enum, so a value the node's own config
	// validation would reject never reaches a node.
	Format string
	// Min / Max bound an "int" row's value, inclusive. Both zero means
	// unbounded (no int row is unbounded today). They are checked by the
	// publish lint and the agent accept path (compilePinned) and again by
	// the config overlay, so a value outside them is refused at publish
	// rather than stranding a node at accept.
	Min, Max int64
	// Hot marks a key the daemon applies LIVE from the resolved posture, in
	// addition to the restart-time config overlay. A hot key is excluded
	// from the pending_restart comparison (cmd/observer's
	// governancePinnedHash) because a changed value converges without a
	// restart; reporting pending_restart for it would be a false claim.
	Hot bool
	// Label is the admin-console display label.
	Label string
	// Help is an optional plain-language note the admin console shows under
	// the row (what a value costs). "" = no note.
	Help string
}

// PinnableKeys is the v1b settings.pin allow-list.
//
// The four rows the spec's first draft carried and the 2026-08-15
// adversarial review deleted are recorded here so they cannot silently
// return:
//
//   - `secrets.enabled` — no such key; SecretsConfig nests under
//     ObserverConfig and its only gate is EnableScrubbing. Corrected to
//     observer.secrets.enable_scrubbing.
//   - `process.enabled` — same nesting mistake; corrected to
//     observer.process.enabled.
//   - `mcp.enabled` — no such key, and honouring one would mean ADDING a
//     governance gate to `observer serve`, which operator ruling R2 and the
//     parent spec §13.5 forbid. Considered and rejected; do not re-add.
//   - `terminal.remote_exec.enabled` — does not exist anywhere in the tree.
//
// `terminal.sandbox.enabled` is also deliberately absent (review M5): the
// sandbox is Linux + WSL2 only and a sandbox that cannot be built FAILS the
// launch, so pinning it on across a mixed fleet would kill dashboard
// terminals for every macOS and native-Windows developer with a failure
// that looks like a product bug. The pin panel lists it as "not pinnable
// yet" with that reason (NotPinnableYet, G48).
var PinnableKeys = []PinnableKey{
	{Key: "guard.enabled", Kind: "bool", Direction: DirFree, Label: "Command guard"},
	{
		Key: "guard.mode", Kind: "string", Direction: DirFree,
		Enum:  []any{"off", "observe", "enforce"},
		Label: "Command guard mode",
	},
	// guard.strict inverts guard's Q2 fail-open default (internal.config's
	// GuardConfig.Strict doc comment): a judge/policy-engine internal error
	// then BLOCKS the action instead of approving it. Like guard.mode this is
	// a fail-posture choice, not a privacy-sharing direction, so it is
	// DirFree — an org may push either true or false, exactly as it may push
	// any guard.mode value — rather than DirRestrictiveOnly (which would be
	// the wrong model here: fail-open and fail-closed are both legitimate
	// postures for different fleets, not a safe/unsafe pair like
	// observer.secrets.enable_scrubbing's scrubbing toggle).
	{Key: "guard.strict", Kind: "bool", Direction: DirFree, Label: "Command guard fail-closed on internal error"},
	// The org-budget POSTURE pair (org-budget plan §3.3a, wave W3a). The
	// NUMBERS deliberately do not ride this rail: a pinned value is ONE value
	// for the whole body (policy.go), and the rail's targeting is three fixed
	// predicate attributes plus user-id cohorts — never a per-developer
	// number. The caps therefore travel on the per-caller signed body
	// GET /api/agent/budget, and only these two fleet-wide booleans are pins.
	// This is the same split the routing rail now uses too (see the
	// routing.enabled row below and the routing.mode note in
	// BootstrapEnvelopeKeys): posture on the pin rail, the enforcement lift
	// on a body + an authority.
	//
	// guard.budget.hard is DirRestrictiveOnly with Safe=true because the
	// RESTRICTIVE value of a spend-blocking flag is true — exactly as
	// observer.secrets.enable_scrubbing's safe value is true and
	// browser.enabled's is false. An org may force budget breaches to BLOCK;
	// it may not force them to stop blocking on a node whose operator chose
	// hard.
	{
		Key: "guard.budget.hard", Kind: "bool",
		Direction: DirRestrictiveOnly, Safe: true, Label: "Budget breaches block requests",
	},
	// guard.budget.from_org is DirFree: it is the node-side switch that says
	// "apply the organization's budget here at all". Both directions are
	// legitimate postures for different fleets (like guard.mode), and the
	// direction that matters — that an applied org budget may only LOWER a
	// developer's own thresholds unless the node is MANAGED and holds
	// enforce.budget — is enforced by the composition algebra
	// (govern.LowerFloat / LowerInt), not by this row.
	{Key: "guard.budget.from_org", Kind: "bool", Direction: DirFree, Label: "Apply the organization's budget on this node"},
	// guard.budget.fail_closed (operator ruling D-502, 2026-10-09). A managed
	// node that requires the org's budget but has no verified document in hand
	// (first pull after enrolment not done yet, org never reached, signature
	// did not verify) now FAILS OPEN on its own numbers by default. This pin is
	// the org's EXPLICIT opt-in to refusing proxied requests (B-625) in that
	// state instead. DirRestrictiveOnly with Safe=true for the reason
	// guard.budget.hard is: an org may force blocking on, never off. A node
	// with no live enrolment never fails closed whatever this says.
	{
		Key: "guard.budget.fail_closed", Kind: "bool",
		Direction: DirRestrictiveOnly, Safe: true, Label: "Refuse requests until the organization's budget is verified",
	},
	// DirRestrictiveOnly with Safe=true, NOT free: §3 requires the `secrets`
	// FEATURE to be on-only ("forcing scrubbing OFF is a privacy downgrade
	// the org must not be able to command"), and §3's own closing sentence
	// requires that direction to have ONE definition, checked at publish and
	// at accept, in this table. A `free` row here would let a `pinned` body
	// command exactly what the `features` body may not — two owners of one
	// constraint.
	{
		Key: "observer.secrets.enable_scrubbing", Kind: "bool",
		Direction: DirRestrictiveOnly, Safe: true, Label: "Secret scrubbing",
	},
	{Key: "compression.conversation.enabled", Kind: "bool", Direction: DirFree, Label: "Conversation compression"},
	{Key: "codeintel.enabled", Kind: "bool", Direction: DirFree, Label: "Code intelligence"},
	{Key: "cachetrack.enabled", Kind: "bool", Direction: DirFree, Label: "Cache tracking"},
	{Key: "predict.enabled", Kind: "bool", Direction: DirFree, Label: "Cost predictor"},
	{Key: "tasks.enabled", Kind: "bool", Direction: DirFree, Label: "Task tracking"},
	{Key: "browser.enabled", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false, Label: "Browser capture"},
	{Key: "observer.process.enabled", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false, Label: "Process observer"},
	{Key: "remote.enabled", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false, Label: "Remote access"},
	// routing.enabled is the POSTURE half of the routing.enabled/routing.mode
	// split the BootstrapEnvelopeKeys comment already anticipated: "posture on
	// the pin rail, the enforcement lift on a body + an authority." It is
	// DirFree — both true and false are legitimate fleet postures, exactly
	// like guard.budget.from_org — and it is gated by the SAME
	// settings.pin authority every other row in this table already requires
	// (a body naming it is inert on a node that never granted settings.pin,
	// the ordinary node.governance dormancy rule; no NEW authority token is
	// introduced for this key). routing.mode stays excluded (below): its
	// value still rides the separate, signed ORG ROUTING POLICY body, honored
	// only for a managed node holding enforce.routing
	// (govern.Effective.GrantsRoutingEnforcement, cmd/observer/routing_live.go)
	// — the two rails do not collide because they set two different fields.
	// W5 (docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4).
	{Key: "routing.enabled", Kind: "bool", Direction: DirFree, Label: "Model routing"},
	// org_client.push_interval_seconds is the push CEILING (2026-10-02
	// budget-latency arc). Enrolment used to write 900 into every node's
	// config, which made a session's spend reach the org up to 15 minutes
	// late; operator ruling: existing nodes are corrected ONLY through this
	// signed rail, never by a config rewrite. DirLoweringOnly: the org value
	// is a ceiling (govern.LowerInt), so a developer who chose a faster
	// cadence keeps it and no org can slow a node's reporting down. Bounded
	// 30..3600 s so a typo can neither hammer the org server nor make
	// reporting effectively stop. Hot: the push loop reads the resolved value
	// live, so a change converges without a daemon restart.
	{
		Key: "org_client.push_interval_seconds", Kind: "int",
		Direction: DirLoweringOnly, Min: 30, Max: 3600, Hot: true,
		Label: "Org push interval ceiling (seconds)",
	},
	// proxy.maintain_routes is the admin's managed route-maintenance switch
	// (lane P1, operator ruling 2026-10-18: "proxy routing at managed node is
	// a fully configurable setting by admin in their org observer admin
	// dashboard UI. They can set it or remove it at their discretion."). ON:
	// the managed daemon keeps every routable AI tool routed through the
	// Observer proxy and puts a removed route back. OFF: it stops and removes
	// exactly the routes the organization wrote, putting back what each one
	// replaced (the same as leaving the organization); routes the developer
	// set are never touched. Unset: the enforce authorities decide (an org
	// governing routing, admission, egress or budget gets ON). DirFree: both
	// values are legitimate admin choices. Hot: the daemon reads the resolved
	// posture live on its maintenance heartbeat (govern.Effective.RoutePosture),
	// so a change converges without a restart. Only meaningful on a managed
	// node (an individual node has no governance to pin it).
	{
		Key: "proxy.maintain_routes", Kind: "bool", Direction: DirFree, Hot: true,
		Label: "Keep AI tools routed through the Observer proxy",
		Help:  MaintainRoutesOffHelp,
	},
	// Surface-gap CLI-1b (operator decision D6, 2026-10-25): command
	// wrapping (shell-wrap, so typing `claude` runs `observer claude`) is
	// org-governable on a managed node. ON: the managed daemon applies the
	// wrap for every wrappable tool when it is not applied and the developer
	// cannot turn it off. OFF: the daemon removes a wrap the organization
	// applied, never one the developer applied. Unset: the developer's own
	// opt-in, as on an individual node, where the key is inert
	// (govern.Effective.ShellWrapPosture). DirFree, Hot.
	{
		Key: "shell_wrap.org_maintain", Kind: "bool", Direction: DirFree, Hot: true,
		Label: "Keep AI tool commands wrapped through Observer (managed nodes only)",
		Help:  ShellWrapMaintainHelp,
	},
	// The sandboxed-terminal settings ([terminal.sandbox], sandbox plan v2
	// sections 8.2, 8.5 and 10.1, lane SBX-P1B). settings.pin reaches
	// individual nodes too, so every row's direction is safe on any plane:
	// an expanding key (the EXPANDS keys of docs/sandboxed-terminals.md) is
	// restrictive-only with its safe value, a list key uses one of the three
	// list operators, and retention may only be lengthened. Each pin set that
	// names one of these keys is also checked on the RESULT at accept by the
	// sandbox module's posture evaluator (pinposture.go, registered from
	// cmd/observer), so pins that are each safe but together make the node's
	// first automatic backend weaker are refused with posture_loosened.
	// Machine paths (workspaces_dir) have no row: a path is per node, never
	// fleet-wide. `enabled` stays out (NotPinnableYet, G48).
	{
		Key: "terminal.sandbox.backends", Kind: "string_list", Direction: DirOrderedFilter,
		Label: "Sandbox backends (the organization list removes entries from the node's preference order)",
		Help:  "Removes backends from each node's own order; it never adds or reorders one. A node refuses a list that would leave its first choice weaker.",
	},
	{
		Key: "terminal.sandbox.remote_allowed_hosts", Kind: "string_list", Direction: DirSetIntersection,
		Label: "Sandbox remote clone hosts (only hosts both allow)",
		Help:  "A node keeps only the hosts both lists allow. A list that shares no host with a node's own allows no host there, and that node refuses it.",
	},
	{
		Key: "terminal.sandbox.mask_paths", Kind: "string_list", Direction: DirAdditiveMask,
		Label: "Sandbox masked paths (added to the node's own)",
	},
	{
		Key: "terminal.sandbox.workspace_retention_days", Kind: "int", Direction: DirRetention, Max: 3650,
		Label: "Sandbox workspace retention (days, 0 keeps forever; may only be lengthened)",
	},
	{
		Key: "terminal.sandbox.home_mode", Kind: "string", Enum: []any{"tmpfs", "readonly"},
		Direction: DirRestrictiveOnly, Safe: "tmpfs", Label: "Sandbox home directory (tmpfs hides the real home)",
	},
	{
		Key: "terminal.sandbox.default_on", Kind: "bool", Direction: DirRestrictiveOnly, Safe: true,
		Label: "Pre-check \"Run in sandbox\" for new terminals",
	},
	{
		Key: "terminal.sandbox.allow_remote_clone", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Sandbox remote clone workspaces",
	},
	{
		Key: "terminal.sandbox.allow_worktree_source", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Sandbox git worktree workspaces",
	},
	{
		Key: "terminal.sandbox.allow_tool_config_writes", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Sandboxed tools may change their own settings",
	},
	{
		Key: "terminal.sandbox.egress_allow_cidrs", Kind: "string_list", Direction: DirRestrictiveOnly, Safe: []string{},
		Label: "Sandbox private network allow-list (may only be emptied)",
	},
	// Lane LEFT-SBX: the agent-run host allow-list; an org list only narrows.
	{
		Key: "terminal.sandbox.egress_allow_hosts", Kind: "string_list", Direction: DirSetIntersection,
		Label: "Hosts a sandboxed agent may reach through the egress gateway (the organization's list narrows the developer's)",
	},
	{
		Key: "terminal.sandbox.extra_ro_binds", Kind: "string_list", Direction: DirRestrictiveOnly, Safe: []string{},
		Label: "Sandbox extra read-only binds (may only be emptied)",
	},
	{
		Key: "terminal.sandbox.extra_rw_binds", Kind: "string_list", Direction: DirRestrictiveOnly, Safe: []string{},
		Label: "Sandbox extra read-write binds (may only be emptied)",
	},
	{
		Key: "terminal.sandbox.prep_timeout_seconds", Kind: "int", Direction: DirFree, Min: 30, Max: 3600,
		Label: "Sandbox workspace preparation timeout (seconds)",
	},
	// lane SBX-P3D (sandbox plan 4.4, D-746 Q17): a vendor policy that forces
	// an agent's own sandbox on; both values keep isolation (DirFree).
	{
		Key: "terminal.sandbox.vendor_forced_native", Kind: "string", Enum: []any{"nest_or_refuse", "refuse"}, Direction: DirFree,
		Label: "When a vendor policy forces an agent's own sandbox on (nest or refuse, or refuse)",
	},
	// Lane SBX-UPD (sandbox plan v2 sections 5.5 and 10.1): how soon an
	// update apply waiting for live sandboxed runs asks; neither value ends
	// a run, so either direction is free.
	{
		Key: "terminal.sandbox.live_run_update_policy", Kind: "string", Enum: []any{"defer", "ask_immediately"}, Direction: DirFree,
		Label: "Sandbox: when a deferred update asks about live sandboxed runs",
	},
	// Operator ruling DEC-9 (2026-10-27, gap review OBS-8a): the
	// organization's posture on direct model-provider egress from sandboxed
	// internet runs. refuse_all turns the egress gateway's provider-host
	// block (SBX-CAP-1) on in every run it enforces, beyond capture rule C6;
	// capture_rule is today's C6 behaviour; allow turns the block off and the
	// run's capture honestly reads proxy_and_transcripts. DirFree: each value
	// is a legitimate admin choice (an org whose developers need direct
	// provider egress, such as a Cursor enterprise seat, picks allow), and
	// the key is inert on an individual node, which always keeps
	// capture_rule (config.sandboxProviderDirectInForce). Never forced on: an
	// unset key is capture_rule.
	{
		Key: "terminal.sandbox.provider_direct", Kind: "string", Enum: []any{"refuse_all", "capture_rule", "allow"}, Direction: DirFree,
		Label: "Sandboxed internet runs: direct model-provider hosts (managed nodes only)",
		Help:  ProviderDirectHelp,
	},
	// The container driver's settings ([terminal.sandbox.oci], lane
	// SBX-P3A). The engine socket is a machine path, so it has no row. The
	// image is pinnable since the signed image trust root (lane SBX-P3B):
	// only an image pinned by digest, which the org then vouches for; an
	// empty value is not pinnable (Observer's default image is chosen by the
	// signed sandbox.image manifest, not by a pin).
	{
		Key: "terminal.sandbox.oci.image", Kind: "string", Direction: DirFree, Format: postureop.FormatImageDigestRef,
		Label: "Container sandbox image (pinned by digest: name@sha256:...)",
	},
	{
		Key: "terminal.sandbox.oci.allow_rootful", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Container sandboxes may use a rootful engine (root-equivalent socket)",
	},
	{
		Key: "terminal.sandbox.oci.allow_devcontainer_image", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Container sandboxes may use a repository's .devcontainer image (after per-repository consent)",
	},
	{
		Key: "terminal.sandbox.oci.install_cache", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Container sandboxes may install the agent's CLI into a per-image cache on first start (after the launch asks)",
	},
	// Lane LEFT-SBX (ruling P-136): an org may hold the first-start install
	// to never running a package's own install script.
	{
		Key: "terminal.sandbox.oci.install_scripts", Kind: "string", Enum: []any{"none", "pinned"}, Direction: DirRestrictiveOnly, Safe: "none",
		Label: "Container sandboxes' first-start install may run a tool package's own install script only when it matches a reviewed pin",
	},
	{
		Key: "terminal.sandbox.oci.podman_userns", Kind: "string", Enum: []any{"keep-id", "default"}, Direction: DirFree,
		Label: "Rootless Podman user namespace (both leave files you own)",
	},
	{
		Key: "terminal.sandbox.oci.stop_grace_seconds", Kind: "int", Direction: DirFree, Min: 0, Max: 600,
		Label: "Container sandbox stop grace (seconds)",
	},
	// The Windows driver's settings ([terminal.sandbox.mxc], lane SBX-P6);
	// neither widens what a box may reach.
	{
		Key: "terminal.sandbox.mxc.stop_grace_seconds", Kind: "int", Direction: DirFree, Min: 0, Max: 600,
		Label: "Windows sandbox stop grace (seconds)",
	},
	{
		Key: "terminal.sandbox.mxc.probe_timeout_seconds", Kind: "int", Direction: DirFree, Min: 5, Max: 300,
		Label: "Windows sandbox probe timeout (seconds)",
	},
	// The macOS drivers' settings ([terminal.sandbox.seatbelt] and
	// [terminal.sandbox.apple_container], lane SBX-P5, beta). The Apple
	// container image is pinnable by digest since lane SBX-P3B, as the OCI
	// image is.
	{
		Key: "terminal.sandbox.apple_container.image", Kind: "string", Direction: DirFree, Format: postureop.FormatImageDigestRef,
		Label: "Apple container sandbox image (pinned by digest: name@sha256:...)",
	},
	{
		Key: "terminal.sandbox.seatbelt.allow_keychain", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "macOS Seatbelt sandboxes may reach the Keychain (for a Keychain-backed login)",
	},
	// Lane SBX-UPD (plan section 10.1, seatbelt_driver): while one driver is
	// built, the plan's set intersection over allowed drivers is an org
	// holding the node on sandbox-exec; it can never force the fallback.
	{
		Key: "terminal.sandbox.seatbelt.driver", Kind: "string", Enum: []any{"sandbox-exec", "mxc-exec-mac"}, Direction: DirRestrictiveOnly, Safe: "sandbox-exec",
		Label: "macOS Seatbelt driver (sandbox-exec only)",
	},
	{
		Key: "terminal.sandbox.apple_container.memory_mib", Kind: "int", Direction: DirFree, Min: 512, Max: 262144,
		Label: "Apple container sandbox memory (MiB)",
	},
	{
		Key: "terminal.sandbox.apple_container.cpus", Kind: "int", Direction: DirFree, Min: 1, Max: 64,
		Label: "Apple container sandbox CPUs",
	}, // The hosted sandbox rows' shared settings ([terminal.sandbox.hosted],
	// lane SBX-P7, beta). The time and spend caps are ceilings an org can
	// only lower (a pin can never force longer, costlier boxes); a memory
	// image policy can only move to refuse. The per-provider region is
	// governed by the allowed_regions floor, the template is data, and
	// box_binary is a machine path, so none of them is pinnable.
	{
		Key: "terminal.sandbox.hosted.min_session_minutes", Kind: "int", Direction: DirLoweringOnly, Min: 5, Max: 1440,
		Label: "Hosted sandbox minimum session (minutes, ceiling)",
	},
	{
		Key: "terminal.sandbox.hosted.max_run_minutes", Kind: "int", Direction: DirLoweringOnly, Min: 5, Max: 1440,
		Label: "Hosted sandbox box timeout (minutes, ceiling)",
	},
	{
		Key: "terminal.sandbox.hosted.daily_box_minutes", Kind: "int", Direction: DirLoweringOnly, Min: 5, Max: 10080,
		Label: "Hosted sandbox box-minutes per provider per day (ceiling)",
	},
	{
		Key: "terminal.sandbox.hosted.checkpoint_minutes", Kind: "int", Direction: DirLoweringOnly, Min: 1, Max: 60,
		Label: "Hosted sandbox transcript checkpoint interval (minutes, ceiling)",
	},
	{
		Key: "terminal.sandbox.hosted.memory_images", Kind: "string", Enum: []any{"avoid", "refuse"}, Direction: DirRestrictiveOnly, Safe: "refuse",
		Label: "Hosted sandbox provider memory images (may only move to refuse)",
	},
	{
		Key: "terminal.sandbox.hosted.db_export", Kind: "bool", Direction: DirRestrictiveOnly, Safe: false,
		Label: "Hosted sandbox database export at teardown (may only be kept off)",
	},
	// Local re-adoption ([terminal.sandbox.readopt], lane GATES-SBX, R-034):
	// an org may only shorten the bound and shrink the checkpoint cap.
	{
		Key: "terminal.sandbox.readopt.bound_minutes", Kind: "int", Direction: DirLoweringOnly, Min: 1, Max: 1440,
		Label: "Container run re-adoption: minutes a run waits to be re-adopted (ceiling)",
	},
	{
		Key: "terminal.sandbox.readopt.checkpoint_cap_mib", Kind: "int", Direction: DirLoweringOnly, Min: 1, Max: 1 << 20,
		Label: "Container run checkpoint export cap in MiB (ceiling)",
	},
	// The MXC tier floor ([terminal.sandbox.windows], R-034): restrictive
	// only, so an org can keep a node off the weaker AppContainer tier and
	// never move one onto it.
	{
		Key: "terminal.sandbox.windows.mxc_tier", Kind: "string", Enum: []any{"process_container", "appcontainer"}, Direction: DirRestrictiveOnly, Safe: "process_container",
		Label: "Windows MXC tier (may only be held on ProcessContainer)",
	},
	// The Landlock-only row's ABI floor ([terminal.sandbox.landlock], lane
	// SBX-P3B, beta): a numeric floor, so an org can only raise it.
	{
		Key: "terminal.sandbox.landlock.min_abi", Kind: "int", Direction: DirRaisingOnly, Min: 9, Max: 64,
		Label: "Landlock-only sandboxes: lowest Landlock ABI accepted (9 or more)",
	},
}

// ShellWrapMaintainHelp is the admin console note under the
// shell_wrap.org_maintain row (CLI-1b).
const ShellWrapMaintainHelp = "ON: each managed machine's daemon puts shims first on PATH so typing a tool's command (claude, codex) runs it through Observer, and the developer cannot turn that off. " +
	"OFF: the daemon removes the shims it put there; shims a developer added themselves stay. Unset: each developer decides. Applies on managed nodes only."

// ProviderDirectHelp is the admin console note under the
// terminal.sandbox.provider_direct row (DEC-9).
const ProviderDirectHelp = "refuse_all: the sandbox egress gateway refuses model-provider hosts in every sandboxed internet run it enforces, so a tool not routed through the Observer proxy cannot reach its provider from the box; hosted sandboxes, whose network the provider runs, cannot refuse them and are unaffected. " +
	"capture_rule (the default): the gateway refuses them only when a run's full capture depends on it. " +
	"allow: no refusal, and those runs report proxy_and_transcripts capture instead of full. Applies on managed nodes only."

// NotPinnable is a setting the admin pin panel lists as "not pinnable yet",
// with the reason, so an admin sees why the key is missing rather than
// assuming it was forgotten.
type NotPinnable struct {
	// Key is the dotted config path.
	Key string
	// Label is the admin-console display label.
	Label string
	// Reason says why the key is not on the pin rail and what to use instead.
	Reason string
}

// NotPinnableYet lists the keys the pin panel shows as "not pinnable yet".
// A key here is never a PinnableKeys row (TestNotPinnableYetIsNotPinnable).
var NotPinnableYet = []NotPinnable{
	{
		Key:   "terminal.sandbox.enabled",
		Label: "Sandboxed terminals",
		Reason: "Not pinnable yet (G48): the sandbox runs on Linux and WSL2 only, so a fleet pin would stop every terminal on macOS and Windows. " +
			"Use Node features > Require a sandboxed terminal instead.",
	},
}

// ShareKey is one row of the capture.pin vocabulary: an [org_client.share]
// key the organization may LOWER or pin at the node's own level, never
// raise (§2.1).
//
// `admin_managed` is structurally absent from this table AND from
// PinnableKeys: it is the flag that flips content-sharing defaults raw, so a
// remote path to it would be the remote-raise mistake wearing a different
// hat. Pinned by TestAdminManagedNotRemotelySettable.
type ShareKey struct {
	// Key is the key's path RELATIVE to [org_client.share], e.g.
	// "full_content" or "obs.traces" — UNLESS ConfigPath is set, in which
	// case Key is just the vocabulary identifier and ConfigPath names the
	// real dotted config path (see ConfigPath).
	Key string
	// Kind is "bool" | "string_list".
	Kind string
	// Label is the admin-console display label.
	Label string
	// ConfigPath, when non-empty, is the FULL dotted config path this share
	// key resolves to, for the rare key that is NOT rooted under
	// [org_client.share]. It exists for "intelligence.org_enrichment" (the
	// org-served Cloud Intelligence result-rail gate, org-served-cloud-
	// intelligence plan §2.1/W5), whose config field lives under
	// [intelligence] yet is directed through the same lowering-only/managed-
	// raise share algebra as every [org_client.share] tier. When empty,
	// ShareKeyConfigPath prepends the "org_client.share." prefix as before, so
	// every existing row is unchanged (CLAUDE.md "additive, not invasive").
	ConfigPath string
}

// ShareKeys is the capture.pin allow-list — the [org_client.share] keys the
// org may DIRECT. The direction is tenancy-gated, not a per-row property: on
// an INDIVIDUAL node every directive is lowering-only (§2.1, applied via
// govern.LowerBool), and on a MANAGED node that granted extract.managed the
// same directive may RAISE the tier (govern.RaiseBool — the sanctioned
// enterprise lift). `admin_managed` remains structurally absent (it is the
// provisioning default-flip, never remotely directable; pinned by
// TestAdminManagedNotRemotelySettable).
//
// Almost every key here roots under [org_client.share]; the one exception is
// "intelligence.org_enrichment", whose config field is [intelligence].
// org_enrichment — it carries an explicit ShareKey.ConfigPath so it resolves
// correctly while still riding the same share algebra.
var ShareKeys = []ShareKey{
	{Key: "full_content", Kind: "bool", Label: "Full file paths and command text"},
	{Key: "full_tool_bodies", Kind: "bool", Label: "Tool inputs, outputs, reasoning, and errors"},
	{Key: "routing_summary", Kind: "bool", Label: "Routing summary rollup"},
	{Key: "cache_detail", Kind: "bool", Label: "Cache hit/write aggregate (day/model/kind)"},
	{Key: "routing_detail", Kind: "bool", Label: "Routing per-decision aggregate (model ids)"},
	{Key: "limit_gauge", Kind: "bool", Label: "Rate-limit gauge (5h/weekly utilization)"},
	{Key: "codeintel_detail", Kind: "bool", Label: "Code-intelligence structure counts (project/language/symbols/edges)"},
	{Key: "process_detail", Kind: "bool", Label: "Process run/exit counts (day/tool)"},
	{Key: "terminal_detail", Kind: "bool", Label: "Terminal-run + remote-audit event counts"},
	{Key: "task_detail", Kind: "bool", Label: "Session task/todo checklist"},
	{Key: "tool_account_detail", Kind: "bool", Label: "Vendor login / account observations"},
	{Key: "hook_activity", Kind: "bool", Label: "Hook activity per session (which hooks fired)"},
	// The org-served Cloud Intelligence result-rail gate (org-served-cloud-
	// intelligence plan §2.1/W5). Unlike every other row its config field is
	// NOT under [org_client.share] — it is [intelligence].org_enrichment — so
	// it carries an explicit ConfigPath. Node-authored (default false) and
	// lowering-only on an individual node; RAISED on a managed node that holds
	// the extract.intel authority (govern.GrantsIntelExtraction). `admin_managed`
	// stays structurally absent from this table (INV-4).
	{Key: "intelligence.org_enrichment", Kind: "bool", Label: "Org-served session enrichment", ConfigPath: "intelligence.org_enrichment"},
	{Key: "policy_state", Kind: "bool", Label: "Effective-policy-state reports"},
	{Key: "target_action_allowlist", Kind: "string_list", Label: "Action types allowed to ship a raw target"},
	{Key: "obs.summary", Kind: "bool", Label: "Observability: aggregate rollup"},
	{Key: "obs.traces", Kind: "bool", Label: "Observability: trace structure"},
	{Key: "obs.content", Kind: "bool", Label: "Observability: span bodies"},
	{Key: "obs.eval_summary", Kind: "bool", Label: "Observability: eval health"},
	{Key: "obs.admission", Kind: "bool", Label: "Observability: admission verdicts"},
	{Key: "obs.eval_items", Kind: "bool", Label: "Observability: per-item eval scores"},
	{Key: "obs.egress", Kind: "bool", Label: "Observability: egress destinations"},
}

// ShareKeyConfigPath is the FULL dotted config path of a share key. It
// exists so the exclusion test can assert no share key is also pinnable
// without hand-writing the prefix in two places.
//
// Almost every share key is rooted under [org_client.share], so the default
// is to prepend that prefix. The rare row that declares an explicit
// ConfigPath (e.g. "intelligence.org_enrichment", rooted under [intelligence])
// returns that path verbatim — its config field does not live under
// [org_client.share]. An unknown key falls back to the prefixed form, which
// is the fail-safe for the exclusion test (it will simply not resolve).
func ShareKeyConfigPath(key string) string {
	if sk, ok := shareByKey[key]; ok && sk.ConfigPath != "" {
		return sk.ConfigPath
	}
	return "org_client.share." + key
}

// Feature is one row of the feature.lock vocabulary. A feature is a
// COMPILE-TIME ALIAS over a pinned key, never a second enforcement
// mechanism: Compile expands it into the same pinned map the `pinned` block
// produces, so a feature lock can never drift from the pin that implements
// it.
type Feature struct {
	// ID is the feature id an org body names, e.g. "guard".
	ID string
	// Key is the pinnable key it expands to. It MUST be a row of
	// PinnableKeys — enforced by TestEveryFeatureExpandsToAPinnableKey.
	Key string
	// Label is the admin-console display label.
	Label string
}

// Features is the v1b feature.lock allow-list. The direction bound of each
// feature is the direction of the PinnableKey it expands to — one
// definition, checked at publish and at accept.
//
// The draft's `terminal_remote_exec` feature is deleted along with its
// non-existent config key (review B1), and no `terminal_sandbox` feature is
// offered (review M5).
var Features = []Feature{
	{ID: "guard", Key: "guard.enabled", Label: "Command guard"},
	{ID: "secrets", Key: "observer.secrets.enable_scrubbing", Label: "Secret scrubbing"},
	{ID: "codeintel", Key: "codeintel.enabled", Label: "Code intelligence"},
	{ID: "compression_conversation", Key: "compression.conversation.enabled", Label: "Conversation compression"},
	{ID: "browser_capture", Key: "browser.enabled", Label: "Browser capture"},
	{ID: "process_observer", Key: "observer.process.enabled", Label: "Process observer"},
	{ID: "remote_access", Key: "remote.enabled", Label: "Remote access"},
}

// BootstrapEnvelopeKeys is the structurally-excluded set (§1.9): keys a
// governance body may NEVER name, because a remotely-set value would either
// sever the rail that could fix it or brick the node before any rail could.
// It is kept as data so TestBootstrapEnvelopeKeysNotPinnable can walk it.
var BootstrapEnvelopeKeys = []string{
	// The remote rail must not be able to re-point or sever the remote rail.
	"org_client.org_server_url",
	"org_client.enabled",
	"org_client.keychain_id",
	// A wrong value strands or bricks the node.
	"dashboard.addr",
	"observer.db_path",
	"proxy.port",
	"ingest.otel.grpc_addr",
	"ingest.otel.http_addr",
	// The privacy-posture flag that flips content sharing raw.
	"org_client.share.admin_managed",
	// routing.mode stays OUT of the nodegov settings-pin vocabulary BY
	// DESIGN: its value is delivered through the ORG ROUTING POLICY body's
	// mode + the enforce.routing authority on a managed node (cmd/observer
	// routing_live.effectiveMode), NOT by letting a node.governance pin set
	// the routing mode directly. Keeping it here means the two rails never
	// collide on WHICH mode wins — a settings pin can never race the
	// authority-gated body for this field.
	//
	// routing.enabled moved OUT of this list (W5,
	// docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4): unlike
	// mode, "should the router run here at all" is a plain posture toggle —
	// the SAME shape as guard.budget.from_org above — so it is now a regular
	// PinnableKeys row (DirFree) instead of a bootstrap-envelope exclusion.
	// It does not collide with routing.mode because the two set different
	// fields through different rails; recorded here so the next reader of
	// this list sees the split was reviewed, not an oversight.
	"routing.mode",
}

var (
	pinnableByKey = func() map[string]PinnableKey {
		m := make(map[string]PinnableKey, len(PinnableKeys))
		for _, k := range PinnableKeys {
			m[k.Key] = k
		}
		return m
	}()
	shareByKey = func() map[string]ShareKey {
		m := make(map[string]ShareKey, len(ShareKeys))
		for _, k := range ShareKeys {
			m[k.Key] = k
		}
		return m
	}()
	featureByID = func() map[string]Feature {
		m := make(map[string]Feature, len(Features))
		for _, f := range Features {
			m[f.ID] = f
		}
		return m
	}()
)

// LookupPinnableKey returns the table row for a dotted config path.
func LookupPinnableKey(key string) (PinnableKey, bool) { k, ok := pinnableByKey[key]; return k, ok }

// IsPinnableKey reports whether the org may pin this dotted config path.
func IsPinnableKey(key string) bool { _, ok := pinnableByKey[key]; return ok }

// LookupShareKey returns the share-table row for a share key.
func LookupShareKey(key string) (ShareKey, bool) { k, ok := shareByKey[key]; return k, ok }

// IsShareKey reports whether key is an org-directable [org_client.share] key.
func IsShareKey(key string) bool { _, ok := shareByKey[key]; return ok }

// LookupFeature returns the feature row for a feature id.
func LookupFeature(id string) (Feature, bool) { f, ok := featureByID[id]; return f, ok }

// PinnableKeyPaths returns every pinnable dotted path, sorted. It is the
// shape internal/config's mirror is compared against by the sync test.
func PinnableKeyPaths() []string {
	out := make([]string, 0, len(PinnableKeys))
	for _, k := range PinnableKeys {
		out = append(out, k.Key)
	}
	sort.Strings(out)
	return out
}

// --- Effective-value reporting (Track C item 3) ---
//
// docs/plans/org-guardrail-control-wave-2026-09-21.md: a node reports, beside
// the pins it ACKED, the EFFECTIVE value of every pinnable key it honours, so
// the organization can tell "the pin was delivered and acked" from "the pin is
// actually in force on that machine". The two can differ without any tampering
// (a restart-bound key, a config the node's own Validate refused), and they
// can differ BECAUSE of tampering — the org server decides which, this table
// only decides what may be said.
//
// THE CONTENT FLOOR IS STRUCTURAL, not a promise. A key's value may be
// reported only when its shape makes a content leak impossible: a bool, or a
// string with a CLOSED Enum. An int (a threshold a developer chose) or a
// string_list (paths, action names) is never reported, because those carry
// information about the developer's own configuration rather than a posture
// the org authored.

// ReportableValue reports whether this key's effective value may cross the
// org wire. True for bools and closed-enum strings only.
func (k PinnableKey) ReportableValue() bool {
	switch k.Kind {
	case "bool":
		return true
	case "string":
		return len(k.Enum) > 0
	default:
		return false
	}
}

// ReportedValueOther is the value a closed-enum key reports when the live
// value is outside its enum — which is possible on a node whose config was
// hand-edited to something config.Validate would refuse. It is deliberately
// a fixed token, not the value: reporting the unknown string is exactly the
// content leak this table exists to prevent.
const ReportedValueOther = "other"

// NormalizeReportedValue maps a live config value onto the closed wire
// spelling for this key, or ok=false when the key is not reportable at all
// or the value's Go type does not match the key's declared Kind (a
// mismatched type is a bug on the reader's side; reporting nothing is the
// safe direction).
func (k PinnableKey) NormalizeReportedValue(v any) (string, bool) {
	if !k.ReportableValue() {
		return "", false
	}
	switch k.Kind {
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return "", false
		}
		if b {
			return "true", true
		}
		return "false", true
	case "string":
		s, ok := v.(string)
		if !ok {
			return "", false
		}
		for _, allowed := range k.Enum {
			if as, isString := allowed.(string); isString && as == s {
				return s, true
			}
		}
		return ReportedValueOther, true
	default:
		return "", false
	}
}

// ReportableKeys returns the pinnable keys whose effective value may be
// reported, in table order. It is the vocabulary the org server validates
// the effective_pins map against.
func ReportableKeys() []PinnableKey {
	out := make([]PinnableKey, 0, len(PinnableKeys))
	for _, k := range PinnableKeys {
		if k.ReportableValue() {
			out = append(out, k)
		}
	}
	return out
}

// ReportableKeyNames returns just the dotted paths of ReportableKeys, sorted.
func ReportableKeyNames() []string {
	out := make([]string, 0, len(PinnableKeys))
	for _, k := range ReportableKeys() {
		out = append(out, k.Key)
	}
	sort.Strings(out)
	return out
}

// ReportedValueAllowed reports whether (key, value) is an acceptable
// effective_pins entry: the key must be reportable and the value must be one
// of the closed spellings that key can produce.
func ReportedValueAllowed(key, value string) bool {
	for _, k := range ReportableKeys() {
		if k.Key != key {
			continue
		}
		switch k.Kind {
		case "bool":
			return value == "true" || value == "false"
		case "string":
			if value == ReportedValueOther {
				return true
			}
			for _, allowed := range k.Enum {
				if as, ok := allowed.(string); ok && as == value {
					return true
				}
			}
			return false
		}
	}
	return false
}

// MaintainRoutesOffHelp is the admin-console note under the
// proxy.maintain_routes row: what turning it OFF costs. Each sentence is
// grounded in this tree (operator ruling D-738): the hook-path budget stop
// (docs/budgets.md "The hook-path budget stop (T-519)") and the hook guard
// keep working without the proxy; a tool with no pre-send seam is only
// flagged after send (D-031); routing, admission and egress are the
// proxy-resident enforcement points (govern proxyResidentEnforcement); exact
// usage (api_turns) and the limit gauge (internal/proxy/limit.go) come only
// from proxied requests.
const MaintainRoutesOffHelp = "If you turn this off: Budgets and guard rules still apply through each tool's hooks. " +
	"A tool with no pre-send hook cannot be blocked before it sends. " +
	"Routing rules, input checks and the outbound guardrail stop applying to tools the developer starts directly. " +
	"Exact token counts and the usage limit gauges stop for those tools."
