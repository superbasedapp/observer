package nodegov

import "sort"

// Admin-controlled Plane B, Phase 1b: the CLOSED vocabularies for the
// schema-2 directive classes (`pinned`, `share`, `features`).
//
// docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md §1.9,
// §2, §3. Every table here is an ALLOW-LIST, never a deny-list: a body
// naming something outside it is a HARD compile error on both the publish
// lint and the agent accept path, because an admin must never believe a key
// is pinned when the node silently skipped it.

// Direction bounds WHICH values the organization may force for a key.
type Direction string

const (
	// DirFree — the org may set either value.
	DirFree Direction = "free"
	// DirRestrictiveOnly — the org may only force the SAFER value, which is
	// the key's Safe field and the only value a body may carry for it.
	DirRestrictiveOnly Direction = "restrictive_only"
	// DirLoweringOnly is the share block's algebra (§2.1): the effective
	// value is always at or below the node's own local value, so an org
	// directive can pin or reduce, never raise. It is a share-key direction
	// only; it never appears in PinnableKeys.
	DirLoweringOnly Direction = "lowering_only"
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
	// Label is the admin-console display label.
	Label string
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
// that looks like a product bug.
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
