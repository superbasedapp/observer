package invariant

import (
	"crypto/ed25519"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// memBearer is a deterministic in-test orgclient.BearerStore (the production
// OpenBearerStore would probe — and on a developer machine, write to — the OS
// keychain, which a test must not do).
type memBearer struct {
	bearer string
	key    ed25519.PrivateKey
}

func (m *memBearer) SaveBearer(b string) error { m.bearer = b; return nil }
func (m *memBearer) LoadBearer() (string, error) {
	if m.bearer == "" {
		return "", orgclient.ErrNoSecret
	}
	return m.bearer, nil
}
func (m *memBearer) SaveAgentKey(k ed25519.PrivateKey) error { m.key = k; return nil }
func (m *memBearer) LoadAgentKey() (ed25519.PrivateKey, error) {
	if m.key == nil {
		return nil, orgclient.ErrNoSecret
	}
	return m.key, nil
}
func (m *memBearer) Clear() error    { m.bearer, m.key = "", nil; return nil }
func (m *memBearer) Backend() string { return "mem" }

// SaveVirtualKey / LoadVirtualKey satisfy the P5a virtual-key extension of
// orgclient.BearerStore (internal/orgclient/bearer_store.go). This fake does
// not exercise Gateway Mode, so the stubs are inert — added only to keep the
// shared invariant package compiling after the interface grew.
func (m *memBearer) SaveVirtualKey(string, uint64) error { return nil }

func (m *memBearer) LoadVirtualKey() (string, uint64, error) {
	return "", 0, orgclient.ErrNoSecret
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// privacy sentinels — distinct, unmistakable markers stuffed into every
// agent-side string column. None may appear in the pushed bytes when the
// node has NOT opted in to full-content sharing.
//
// First four (secRawInput ... secErrMsg): the original v1.5+ posture —
// content columns that have ALWAYS been forbidden on the wire.
// Next four (secTarget ... secGitRemote): the v1.8.0 additions covering
// the four columns the 2026-06-02 teams test found leaking
// (actions.target, actions.source_file, projects.root_path,
// projects.git_remote). Pre-M1.x these ship raw; post-M1.x the seam ships
// only the hashed counterparts (target_hash / source_file_hash /
// project_root_hash / git_remote_hash).
const (
	secRawInput  = "SECRET_RAW_INPUT_xyzzy_42"
	secRawOutput = "SECRET_RAW_OUTPUT_plugh_99"
	secReasoning = "SECRET_REASONING_hunter2_zz"
	secErrMsg    = "SECRET_ERRMSG_swordfish_qq"

	secTarget     = "SECRET_TARGET_correcthorsebatterystaple"
	secSourceFile = "SECRET_SOURCEFILE_tetragrammaton_ww"
	secRootPath   = "SECRET_ROOTPATH_voluptuous_qq"
	secGitRemote  = "SECRET_GITREMOTE_omphaloskepsis_uu"
	// sessions.git_branch: no hash counterpart and no server feature keys on
	// it, but branch names routinely encode client/codename/ticket ids, so it
	// ships raw ONLY under full_content / admin_managed (stripped by default).
	secGitBranch = "SECRET_GITBRANCH_antidisestablishment_bb"

	// Codex fork/subagent lineage (migration 069): forked_from_id /
	// thread_source are NODE-LOCAL — never selected by the push seam, in ANY
	// share mode (unlike git_branch, they don't ship even under
	// full_content). Written only via Store.SetSessionLineage.
	//
	// parent_thread_id is the one exception (server migration 162 / pg
	// 0028): it RECLASSIFIES to a positive canary below
	// (canaryParentThreadID) — see that constant's doc for the ruling.
	secForkedFrom   = "SECRET_FORKEDFROM_grandiloquent_ff"
	secThreadSource = "SECRET_THREADSOURCE_sesquipedalian_ss"

	// Cloud-session sandbox tag (agent migration 245, cloud-agents lane
	// CA-F1, decision CA-D18): sessions.reported_via_token names the node
	// ship token whose batch landed the session. NODE-LOCAL in every share
	// mode: the org carries its own server-set copy (server 302), written
	// from the authenticated route, never from the wire.
	secReportedVia = "SECRET_REPORTEDVIA_cst_floccinaucinihilipilification"

	// Org attribution (agent migration 250, managed SaaS M8.1, operator
	// ruling D-43): a session keyed to ANOTHER organization than the one the
	// node is enrolled in must never reach the wire, nor any of its rows.
	// Its session id and its token row's source_event_id are fields that
	// ALWAYS ship for an own-org row, so their absence proves the selection
	// dropped the rows (not a strip). sessions.authority_org_key itself is
	// node-local: neither the destination's key nor the other org's key may
	// appear in the payload.
	secForeignOrgSession = "SECRET_FOREIGNORGSESSION_quockerwodger_fo"
	secForeignOrgEvent   = "SECRET_FOREIGNORGEVENT_quockerwodger_fe"
	secForeignOrgKey     = "SECRET_FOREIGNORGKEY_quockerwodger_fk"

	// User-attachment metadata (migration 126): actions.user_attachments is
	// NODE-LOCAL — never selected by the push seam, in ANY share mode (like
	// the lineage/tool_version columns above, unlike git_branch it does not
	// ship even under full_content). It carries only kind/count/media_type by
	// design, but a distinctive secret is stuffed into the column here so a
	// regression that ever selected it onto the wire fails loudly. Org-wire
	// promotion is a documented follow-up.
	secUserAttachments = "SECRET_USERATTACH_grandiloquent_ua"

	// Capture-surface attribution (agent migration 107 / server migration
	// 139). These are POSITIVE CANARIES, not sentinels — the opposite
	// polarity of everything else in this block.
	//
	// Until the node session-detail trickle-up wave W1 these were secrets:
	// surface / surface_host were NODE-LOCAL and the push seam selected
	// neither, in any share mode. W1 DELIBERATELY reclassified them as
	// METADATA and put them on the wire unconditionally: `surface` is a
	// closed vocabulary the node's Store.SetSessionSurface refuses to write
	// outside of (models.KnownSurface — cli | ide | desktop | sdk | web) and
	// `surface_host` a bounded host token (vscode | jetbrains |
	// claude-desktop | ...). Neither can carry a path, a prompt or a branch
	// name, so neither is gated — the org needs them to split IDE vs
	// terminal vs desktop spend.
	//
	// Still stuffed directly (bypassing the store's vocabulary check) so the
	// probe reads whatever the COLUMN holds rather than a value the store
	// would have blessed: if the seam ever stopped shipping the column, or
	// started substituting a default, these distinctive bytes would vanish
	// from the wire and TestPushPayloadCarriesNoContent's canary block fails.
	canarySurface = "CANARY_SURFACE_pulchritudinous_uu"
	// canarySurfaceHost is a REAL vocabulary token, not a nonsense sentinel
	// like its sibling above, because since PRIV-2 (codebase audit
	// 2026-09-16) surface_host passes a CLOSED vocabulary at the seam: an
	// unrecognized value ships as "other", so a nonsense canary would
	// correctly never appear and the assertion would be measuring the gate
	// instead of the column. "jetbrains-dataspell" is a genuine, rare
	// jetbrainshost product token — distinctive enough to byte-scan for, and
	// admitted by the vocabulary, so the canary still proves the COLUMN
	// ships. The gate's own behavior is pinned separately by
	// TestSessionSurfaceHostClosedVocabulary.
	canarySurfaceHost = "jetbrains-dataspell"

	// canaryTurnID is the §7 follow-up CANARY (server migration 160 / pg
	// 0026, node/org session-message parity): token_usage.turn_id is an
	// opaque adapter-minted grouping id (agent migrations 032/033), never
	// agent-authored text, so it ships unconditionally as metadata — same
	// posture as is_sidechain above.
	canaryTurnID = "CANARY_TURN_ID_perspicacious_tt"

	// canaryToolVersion is the tool-version-trickle-up CANARY (server
	// migration 161 / pg 0027): sessions.tool_version is now a POSITIVE
	// canary, not a sentinel — the opposite polarity from how this column
	// was originally pinned.
	//
	// Until this change, sessions.tool_version was NODE-LOCAL and the push
	// seam selected it in NO share mode (treated in the same bucket as the
	// Codex fork/lineage columns — stricter than git_branch, which ships
	// raw under full_content). That posture had no documented
	// content-sensitivity rationale distinguishing it from Surface /
	// SurfaceHost (which W1 already reclassified as unconditional
	// metadata): tool_version is not a closed vocabulary like Surface, but
	// it IS a bounded (64-rune), non-prose, whitespace/control-char-rejected
	// token (internal/store/toolversion.go::validToolVersion) sourced only
	// from a vendor-authored on-disk field the adapter itself controls —
	// never developer-typed text. The realistic disclosure risk of a
	// version string like "0.150.0" is the same near-zero class as
	// AgentVersion, which already ships unconditionally on every
	// PushEnvelope for the Observer binary's own build. RULING (this
	// change): reclassify sessions.tool_version as METADATA and ship it
	// unconditionally, the same W1 precedent — org admins can now answer
	// "which tool builds is the fleet running" per-AI-tool, the same
	// fleet-management question org_node_versions already answers for
	// Observer itself. See docs/security.md ledger row TOOLVERSION-1 for
	// the full ruling text.
	canaryToolVersion = "CANARY_TOOL_VERSION_perspicacious_vv"

	// canaryToolVersionLast is the mid-session upgrade CANARY (agent
	// migration 162 / server 232 / pg 0099, T-784): sessions.tool_version_last
	// is the latest tool build seen in a session, the same vendor-authored
	// token class as tool_version, so it is a POSITIVE canary too: it ships
	// in every posture. TOOLVERSION-1 covers both columns.
	canaryToolVersionLast = "CANARY_TOOL_VERSION_LAST_perspicacious_vl"

	// canaryParentThreadID is the tool-account-parity CANARY (server
	// migration 162 / pg 0028): sessions.parent_thread_id is now a
	// POSITIVE canary, not a sentinel — the same polarity flip as
	// canaryToolVersion, out of the same Codex-fork/lineage bucket that
	// forked_from_id and thread_source stay in.
	//
	// RULING (this change): parent_thread_id is an OPAQUE vendor-minted
	// session id (a Cursor sub-agent's parent session, or a Codex fork
	// parent) — never developer-typed text — and the child session it
	// points at already ships as its own session row on the wire, so
	// shipping the pointer adds STRUCTURE (fan-out), not content: the same
	// distinction that let AgentVersion and tool_version ship
	// unconditionally. It closes a real gap: the org drawer's per-session
	// tool-account column (rollup/messageaccounts.go) could not resolve a
	// Cursor CHILD session's account without it, unlike the node's own
	// store.LoadMessageAccounts (internal/store/toolaccount.go), which
	// already joins through parent_thread_id. forked_from_id and
	// thread_source stay NODE-LOCAL sentinels — only the id itself ships,
	// never the fact or kind of the fork. See docs/security.md ledger row
	// LINEAGE-1 for the full ruling text.
	canaryParentThreadID = "CANARY_PARENT_THREAD_perspicacious_ll"

	// canaryVendorSessionRef is the cloud-agents CANARY (agent migration 240
	// / server 300 / pg 0170, lane CA-A1): sessions.vendor_session_ref is the
	// vendor's secondary session id used for cross-rail joins, an opaque
	// vendor-minted id like parent_thread_id, so it is a POSITIVE canary: it
	// ships in every posture. sessions.execution_location (a closed
	// vocabulary, the surface reasoning) ships beside it and is asserted by
	// its wire key and value.
	canaryVendorSessionRef = "CANARY_VENDOR_SESSION_REF_perspicacious_vr"

	// canaryGenBasis is the S10-SPEED generation-timing CANARY (server
	// migration 174 / pg 0040): token_usage.gen_basis is a closed,
	// adapter-minted enum (never developer-typed text), so it ships
	// unconditionally as metadata alongside gen_ms — the same posture as
	// canaryTurnID. gen_ms itself is a plain int64 (424242 below), so its
	// own presence is proven by scanning for its literal JSON number rather
	// than a string sentinel.
	canaryGenBasis = "native"
	canaryGenMs    = 424242

	// Guard-layer additions (migration 040, guard spec §10.2): the
	// three content-bearing guard_events columns. guard_events rows DO
	// push (unlike the node-local cache_*/advisor_* tables) — these
	// columns must be stripped in Go at SelectUnpushedSince unless the
	// node opted into [org_client.share].full_content, while
	// target_hash always ships.
	secGuardReason  = "SECRET_GUARDREASON_balderdash_kk"
	secGuardExcerpt = "SECRET_GUARDEXCERPT_rigmarole_jj"
	secGuardTaint   = "SECRET_GUARDTAINT_skulduggery_mm"
	// guard_events.project_root (agent migration 253, GRANT-20): the raw
	// root of the project the gate matched grants on, for the node request
	// form only. NODE-LOCAL in EVERY share mode: the seam never selects it
	// (nor its project_root_hash twin; the org's guard_events row has no
	// project field), so it must not ship even under full_content.
	secGuardProjectRoot = "SECRET_GUARDPROJECTROOT_lollygag_gg"

	// Native-console (otel_content) addition: the captured content body is
	// content-bearing — it ships ONLY under full_content / admin_managed, with
	// content_hash always shipping. Migration 048 (agent) / 007 (server).
	secOTelContent = "SECRET_OTELCONTENT_flibbertigibbet_pp"

	// Obs input-admission (T6, obs migration 0005): the three content-bearing
	// verdict columns (tenant / user / reason_excerpt). They ride raw out of
	// the obs provider and are stripped in composeObsTiers unless the node
	// opted into full_content / admin_managed — while the content-free verdict
	// metadata (decision / message_hash / row_hash / hash-chain links) always
	// ships. Composed via the obs provider seam (orgpush.go names no obs_*
	// table); the raw request text is NEVER stored on the node at all.
	secAdmTenant = "SECRET_ADMTENANT_collywobbles_xx"
	secAdmUser   = "SECRET_ADMUSER_widdershins_vv"
	secAdmReason = "SECRET_ADMREASON_snollygoster_tt"

	// Obs per-item eval (T7, obs migration 0002 tables): the four
	// content-bearing item columns (input / expected / output excerpts +
	// scorer rationale). They ride raw out of the obs provider and are
	// stripped in composeObsTiers unless the node opted into
	// full_content / admin_managed — while the content-free score metadata
	// (run/dataset identity, scorer, score, pass, content_hash, ts) always
	// ships. Composed via the obs provider seam (orgpush.go names no obs_*
	// table); the raw bodies live on the node only under its ContentGate.
	secEvalInput    = "SECRET_EVALINPUT_borborygmus_aa"
	secEvalExpected = "SECRET_EVALEXPECTED_gongoozler_bb"
	secEvalOutput   = "SECRET_EVALOUTPUT_absquatulate_cc"
	secEvalRational = "SECRET_EVALRATIONALE_mumpsimus_dd"

	// Project Identity Resolver v2 (agent migration 102 / server migration
	// 121, docs/plans/project-identity-resolver-v2-plan-2026-09-06.md §3.2):
	// of the nine new columns, exactly TWO have a raw counterpart on the
	// wire — projects.git_upstream_remote and sessions.workspace. Like
	// git_remote/git_branch above, they ship ONLY under
	// ShareOptions.shipsRawContent() and are stripped in Go by
	// SelectUnpushedSince; the other seven fields in this bundle (the four
	// owner/root-commit/fingerprint hashes, WorkspaceHash,
	// GitUpstreamRemoteHash, IsWorktree) are content-free and always ship —
	// there is no sentinel for them, they're proven present by a positive
	// canary instead.
	secUpstreamRemote = "SECRET_UPSTREAMREMOTE_widdershins_oo"
	secWorkspace      = "SECRET_WORKSPACE_snickersnee_ee"
)

// allSentinels is the union of the original 4 content-column sentinels,
// the 4 v1.8.0 target/path sentinels, the 3 guard-layer verdict sentinels,
// and the 2 Project Identity Resolver v2 raw-field sentinels. Every push in
// the default (full_content=false) mode must ship NONE of these.
//
// canarySurface / canarySurfaceHost / canaryToolVersion / canaryParentThreadID
// are deliberately NOT here: W1 moved the capture-surface columns, and later
// changes moved sessions.tool_version and then sessions.parent_thread_id,
// from node-local to unconditional METADATA, so they are asserted PRESENT
// (see the canary block in TestPushPayloadCarriesNoContent and
// TestSessionSurfaceAndSidechainTokensShipAsMetadata) rather than absent.
var allSentinels = []string{
	secRawInput, secRawOutput, secReasoning, secErrMsg,
	secTarget, secSourceFile, secRootPath, secGitRemote, secGitBranch,
	secForkedFrom, secThreadSource,
	secReportedVia,
	secUserAttachments,
	secGuardReason, secGuardExcerpt, secGuardTaint, secGuardProjectRoot,
	secOTelContent,
	secAdmTenant, secAdmUser, secAdmReason,
	secEvalInput, secEvalExpected, secEvalOutput, secEvalRational,
	secUpstreamRemote, secWorkspace,
}

// forbiddenCacheTables names the three node-local cachetrack tables
// that MUST NEVER appear in the org-push wire path. Spec §11:
// cachetrack data (segments, entries, events) is local, passive,
// node-side telemetry — it never leaves the agent. Adding any
// of them to internal/store/orgpush.go::SelectUnpushedSince (or
// any helper in that file) is a privacy regression — even though
// the rows themselves carry no raw text content, they reveal
// per-turn cache-hit patterns that the operator may treat as
// private even when they've opted into full-content sharing on
// the existing wire surfaces.
//
// Pinned by [TestSelectUnpushedSinceExcludesCacheTables] at the
// SOURCE level so the regression fires before any row is even
// constructed.
var forbiddenCacheTables = []string{
	"cache_segments",
	"cache_entries",
	// cache_events STAYS here after the enterprise-first per-event timeline
	// landed (server migration 142, operator directive item 6) — deliberately,
	// and unlike task_items / tool_account_observations, which LEFT this set
	// when their wires landed. The difference is what each pin was doing. Those
	// two were blanket "never crosses" pins whose reversal had to be recorded
	// by removing them. This entry is a SOURCE-LEVEL module-boundary rule about
	// ONE FILE: the cache_* names may not appear in internal/store/orgpush.go,
	// so every cache read stays with its one owner in a seam file
	// (cachesummary.go, cachesessionorgrows.go, cacheeventorgrows.go). That
	// rule is unchanged and still worth enforcing. The DATA posture — which of
	// those reads may cross, and under what tier — is pinned by the named
	// tests instead: TestPushPayloadCarriesCacheWhenOptedIn (fleet aggregate,
	// cache_detail), TestPushPayloadStripsCacheWhenNotOptedIn (orthogonality)
	// and TestSessionCacheEventsShipOnlyUnderRawContent (the per-event
	// timeline, shipsRawContent(), plus the `detail`-column exclusion).
	"cache_events",
	// Advisor (suggestions engine, spec §15.7) tables are node-local
	// for the same reason and more: suggestion state + the digest
	// snapshot embed file paths and command summaries. Migration 039.
	"advisor_state",
	"advisor_digest",
	// Model-routing tables (model-routing spec §R9.1 + §R20) are
	// node-local: decision rows reveal per-turn model-selection
	// patterns and policy state; calibration rows reveal per-project
	// outcome aggregates. The §R19.4 org rollup pushes a separate
	// AGGREGATE wire shape when it ships — never these rows.
	// Migrations 041 + 042.
	"router_decisions",
	"model_calibration",
	// The agent-side org routing-policy CACHE (migration 043) is
	// received state — its body may describe org-internal projects —
	// and must never round-trip back onto the wire. The §R19.4
	// rollup that IS allowed on the wire is the routing_summaries
	// AGGREGATE, computed in store/routingsummary.go and composed
	// into the push via a function call precisely so this sentinel
	// can keep forbidding the underlying table names here.
	"org_routing_policies",
	// Agent Access P4 node wave (agent migration 131, docs/plans/
	// agent-access-implementation-plan-2026-09-23.md §3.2 "Node migration",
	// R8.27.a / R12.7 / R14.2). All three are NODE-LOCAL by name and owned by
	// internal/mcprelay/record. mcp_relay_state (applied policy state +
	// pending-loss accounting) and mcp_relay_launch_spec (the journal of each
	// AI client's ORIGINAL MCP launch: config paths, commands, env KEY names)
	// NEVER reach the wire. mcp_relay_record - the ONE hash-chained relay
	// record table - IS the source of two wire families
	// (orgcontract.MCPRelayActivityRow + MCPRelayEventRow), but exactly like
	// router_decisions above they are composed by a FUNCTION seam
	// (internal/store/mcprelaysummary.go, through the record package) so the
	// table name stays out of orgpush.go. Pinned by
	// TestForbiddenCacheTablesExpectedRelaySet.
	"mcp_relay_state",
	"mcp_relay_launch_spec",
	"mcp_relay_record",
	// project_patterns (W3.3 Discovery/Patterns) is NODE-LOCAL by table
	// name: orgpush.go must never reference it directly. A derived,
	// capped, enterprise-raw wire row (ProjectPatternRow) DOES ship under
	// shipsRawContent(), computed in store/patternsorgrows.go and
	// composed into the push via a function call — precisely so this
	// sentinel can keep forbidding the underlying table name here, same
	// pattern as org_routing_policies/router_decisions above.
	"project_patterns",
	// project_guidance_files (migration 122) is the per-project inventory
	// of the AI-guidance documents each tool reads — CLAUDE.md, AGENTS.md,
	// .cursor/rules/*.mdc, skills, sub-agents, slash commands. It is
	// NODE-LOCAL for the same reason codeintel_* and project_patterns are:
	// the rows name private project paths, and — uniquely on this list —
	// user-scope rows name files in the OPERATOR'S OWN HOME
	// (~/.claude/CLAUDE.md and friends), which are personal, not
	// project-owned, and which no org opt-in on this node should be read
	// as consenting to. Names and descriptions come out of the files'
	// front matter, so even the metadata halves describe private working
	// practice. Bodies are never stored at all (only a sha256 + a capped
	// description), but that is a separate guarantee from this one.
	//
	// There is no paired orgserver migration, by design. If a team-level
	// "which projects have a CLAUDE.md" rollup is ever wanted it is a
	// separate opt-in AGGREGATE wire shape composed through a function
	// seam (the routing_summary / project_patterns precedent) — never this
	// table, and never the user-scope rows.
	"project_guidance_files",
	// Guard-layer tables (migration 040, guard spec §10.2): pins,
	// policy state and approvals are NODE-LOCAL until the G13/G14
	// teams arc deliberately adds their wire surfaces (pins ship
	// hash-only, approvals ship granted_by — per guard spec §14.3)
	// and consciously updates this sentinel. guard_events is
	// deliberately ABSENT from this list — it DOES push, with its
	// content-bearing columns (reason / target_excerpt / taint_origin)
	// stripped in Go unless [org_client.share].full_content; that
	// posture is pinned data-side by TestPushPayloadCarriesNoContent's
	// guard sentinels + canaries above.
	"guard_pins",
	"guard_policy_state",
	"guard_approvals",
	// The prompt-submit intervention's "reconsider-once" grant table
	// (migration 110, docs/plans/prompt-submit-intervention-exploration-
	// 2026-09-07.md §5.4) is NODE-LOCAL for the same reason as the guard
	// block above: even though the matched secret/PII value is NEVER
	// stored anywhere in this table (or anywhere else — only a
	// composite sha256 fingerprint over detector-id/span-hash pairs is
	// persisted, §5.2), the row's `detectors` + `session_id` still
	// reveal WHICH KIND of sensitive content a developer typed and WHEN
	// — provenance-of-a-near-miss that the node operator should control
	// disclosure of, same posture as guard_pins/guard_policy_state/
	// guard_approvals immediately above. It gets NO paired org-server
	// migration, by design — same posture as the cachetrack tables.
	"guard_prompt_reconsider",
	// The post-hoc prompt lane's pre-send marks (migration 150, prompt
	// guard coverage audit 2026-10-02): session id + a sha256 of the
	// scrubbed prompt. A digest of a short prompt is guessable, so it is
	// NODE-LOCAL; no paired org-server migration.
	"guard_prompt_presend",
	// Process-observability tables (migration 044,
	// docs/process-observability.md §10.1) are NODE-LOCAL: they record
	// OS-level process trees, argv previews, executable identity, and
	// side-effect events for AI sessions — far higher privacy surface than
	// the metadata that DOES push. They never enter the wire path until a
	// separate privacy review designs hash-only rollups. No paired
	// orgserver migration exists, by the same design.
	"process_runs",
	"process_events",
	"process_network_bodies",
	// The process capture budget's rollups and per-session capture stats
	// (migration 212, docs/plans/process-capture-budget-plan-2026-11-04.md
	// §9.2) are NODE-LOCAL like process_runs: rollup rows carry an example
	// argv and process keys. The org layer (O1) adds its own wire shape and
	// server tables later and must consciously update this sentinel.
	"process_rollups",
	"process_capture_stats",
	// Rate-limit snapshots (migration 049, the Next-Message Cost & Limit
	// Predictor's limit half). The RAW log is NODE-LOCAL and its name stays
	// forbidden in orgpush.go: scope_hash (an auth-identity hash), the raw
	// header subset, the unified-status passthrough and the per-minute
	// req_*/tok_* counters never cross. Two DERIVED metadata shapes do, and
	// internal/store/limitgauge.go is the one owner of every read that feeds
	// them (orgpush.go composes both by function call):
	//   - LimitGaugeRow, the per (day, provider) utilization aggregate, under
	//     the limit_gauge opt-in only;
	//   - SessionLimitSnapshotRow (lane F-WIRE, 2026-09-28), the newest window
	//     observation per (session, provider) - session id, observing tool,
	//     provider, observed_at, the two windows' utilization and reset stamps
	//     - a cursor wire (PushCursor.LimitSnapshots) under limit_gauge OR
	//     shipsRawContent(), so the org session drawer renders the node's
	//     "% of limit spent" gauge.
	// Pinned data-side by TestSessionLimitSnapshotsWireShipsMetadataOnly and
	// TestSessionLimitSnapshotRowFieldSet.
	"limit_snapshots",
	// Plane-A P0-5 unified policy resource, agent-side scoped persistence
	// (migration 081, docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md
	// §6.2/§6.9/§6.10): org_enrolment_generation is the durable
	// cross-process enrolment fence (survives unenrol, carries a tombstone
	// bit) and org_policy_resource_state is the per-(org_key, family)
	// replay floor + last-verified-envelope identity. Both are RECEIVED,
	// generation-scoped control-plane state — like org_routing_policies
	// above, round-tripping either back onto the wire is pure noise even
	// setting aside that a generation counter and a replay floor reveal
	// nothing useful to the server it didn't already know, but the
	// underlying resource content (family bodies) could. internal/store/
	// policyresource.go is their one owner; orgpush.go must never read
	// them.
	"org_enrolment_generation",
	"org_policy_resource_state",
	// Admin-controlled Plane B, the ENROLMENT GRANT (migration 082,
	// docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.4). It
	// records the bounded authority THIS machine handed to the
	// organization: consent mode, the consenting local actor, the signed
	// offer, the key pin. The org already knows what it offered; what it
	// must never receive back on the push wire is the node's own consent
	// record, which names a local user and is the developer's evidence of
	// what they agreed to — evidence whose whole value is that it lives on
	// their machine, under their control, deletable by `observer unenroll`.
	// internal/store/orggrant.go is its one owner.
	"org_enrolment_grant",
	// Session-handoff records (migration 055,
	// docs/plans/session-handoff-plan-2026-07-03.md §5) are NODE-LOCAL:
	// which tool a user moved a session to, when, at what fork point and
	// estimated cost is personal workflow telemetry. The rendered
	// HandoverDoc is never stored at all (delivered and forgotten); the
	// row holds counts/enums/hashes/paths only. Cross-machine handoff, if
	// ever built, is a separate opt-in wire shape behind
	// shipsRawContent(), never this table.
	"handoffs",
	// The Terminal Workspace dock-grid layout (migration 073,
	// docs/plans/terminal-dock-grid-design-2026-07-20.md) is NODE-LOCAL:
	// the blob maps terminal handles / session ids to grid cells — the
	// operator's personal screen arrangement, meaningless and unwanted
	// off-node. No paired orgserver migration, by design.
	"workspace_layouts",
	// The org-announcement CACHE (migration 076, rail R3 of
	// docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4)
	// is NODE-LOCAL and must stay that way for a reason specific to
	// this feature: the rail is ONE-WAY by design. Pushing the cached
	// document (or its version) back would tell the server which of its
	// own announcements this node holds — a read receipt, which plan §6
	// rules out as telemetry. The banner has no acknowledgment wire and
	// must never grow one by accident; the row is also RECEIVED state,
	// like org_routing_policies above, so round-tripping it is pure
	// noise even setting the receipt problem aside.
	"org_announcements",
	// The org DISPLAY-POLICY cache (migration 148, the org's signed choice of
	// whether developers' dashboards show dollars or token usage) is
	// RECEIVED state, exactly like org_announcements above: pushing it back
	// would tell the server which version a node holds, a receipt nobody
	// asked for. internal/store/orgdisplaypolicy.go is its one owner.
	"org_display_policy",
	// The org ACCESS-GRANT cache and the request outbox (migration 152,
	// request-grants design §4.1). The grants are RECEIVED state signed for
	// this one member|machine, and pushing them back would be the same
	// receipt problem as org_display_policy; the outbox holds the developer's
	// own unsent words, which leave the node only through the request POST
	// they previewed. internal/store/accessgrant.go is the one owner. The
	// per-event guard_events.grant_id is the one grant fact that does ship,
	// as metadata on the existing guard_events row.
	"org_access_grant_state",
	"org_access_grants",
	"access_request_outbox",
	// Admin and developer messaging (agent migrations 173 to 176,
	// docs/plans/admin-developer-messaging-plan-2026-10-15.md section 6.2,
	// T-854). The inbox and thread headers are RECEIVED state the org signed
	// for this one member (pushing them back would be the same receipt
	// problem as org_display_policy), the rail row is this node's pull cursor
	// and pinned key, and the outbox holds the developer's own unsent words
	// and read marks, which leave the node only through the authenticated
	// message POSTs, never through the telemetry push.
	// internal/store/orgmessages.go is the one owner.
	"org_message_rail",
	"org_message_threads_local",
	"org_messages_inbox",
	"org_message_outbox",
	// The security pillar's findings store (agent migration 177, security
	// pillar plan section 4.6): NODE-LOCAL. Paths, redacted evidence and
	// lifecycle never reach orgpush.go by name; the org rows are composed
	// through the SecurityOrgProviders function seam (Phase E).
	"sec_findings",
	"sec_finding_events",
	"sec_scan_runs",
	"sec_baselines",
	// Local finding exceptions (agent migration 183, lane sec-c3, security
	// pillar plan section 6.3): one finding's key, reason and expiry, and a
	// file fingerprint. NODE-LOCAL; internal/store/secexceptions.go is the
	// one owner; the org's finding_exception requests are Phase E's.
	"sec_finding_exceptions",
	// Per-file sightings of each finding (agent migration 184, lane
	// sec-gate2): a project-relative path and a timestamp per finding.
	// NODE-LOCAL; internal/store/secfindings.go is the one owner.
	"sec_finding_sightings",
	// The unpushed commits each open finding was seen added in (agent
	// migration 185, lane sec-gate3): a commit id and a timestamp per
	// finding. NODE-LOCAL; internal/store/secfindings.go is the one owner.
	"sec_finding_commits",
	// The signed AI change records, the node's signing keys and the
	// per-repository writer consent (agent migration 191, security plan
	// 7.10, lane sec-f2a). NODE-LOCAL; internal/store/secchange.go is the
	// one owner; the change record rows reach the org only through the
	// SecurityOrgProviders.ChangeRecords function seam.
	"sec_change_records",
	"sec_change_keys",
	"sec_change_consent",
	// The org's approvals of this node's baseline references, as the
	// security managed pull last served them (agent migration 194, lane
	// LEFT-SHARED): a label only. NODE-LOCAL;
	// internal/store/secorgrows_approvals.go is the one owner.
	"sec_org_baseline_approvals",
	// The module managed-pull kit's node cache (agent migration 187, roadmap
	// F0-7, lane shr-kit): the ORG's own signed per-caller enabling
	// documents (security, sandbox) as the node last verified them, coming
	// BACK, never going out. NODE-LOCAL; internal/store/managedpull.go is the
	// one owner.
	"managed_pull_cache",
	// The project audience's node index (agent migration 190, security plan
	// section 7.11, lane sec-p): the ORG's own signed project mapping
	// (identity hashes to org project ids) as the node last accepted it,
	// coming BACK, never going out. NODE-LOCAL;
	// internal/store/projectaudience.go is the one owner.
	"org_project_mapping_index",
	// The repository trust accept flow and config baseline of the security
	// pillar (agent migration 178, security pillar plan sections 4.6 and
	// 5.1, component security.trust): a developer's accepts of repository
	// commands, by project root hash and digest. NODE-LOCAL; any org view
	// is composed through the SecurityOrgProviders seam (section 7.4), never
	// by selecting this table. internal/store/sectrust.go is the one owner.
	"sec_config_baseline",
	// The config baseline snapshot (agent migration 180, component
	// security.trust): per-project agent config file paths and digests.
	// NODE-LOCAL; internal/store/sectrust.go is the one owner.
	"sec_config_files",
	// The install gate's online-answer cache (agent migration 182, security
	// pillar plan section 8.3, component security.deps): public package
	// names an agent tried to install and what the online check said.
	// NODE-LOCAL; internal/store/secpkgcache.go is the one owner.
	"sec_pkg_cache",
	// Code-intelligence tables (internal/codeintel, migrations 050+,
	// docs/codeintel/) are NODE-LOCAL: they hold a project's source
	// paths, symbol names, signatures, import specifiers, and the
	// call/import graph — a structural map of private code that must
	// never leave the agent. [codeintel] config is local-only (like
	// [routing]/[cachewarm]); these tables are pre-registered here
	// before the schema lands so any attempt to add one to the push
	// seam fails loudly. If a team-level code-index rollup is ever
	// built it would be a separate opt-in AGGREGATE wire shape, never
	// these tables.
	"codeintel_files",
	"codeintel_nodes",
	"codeintel_edges",
	"codeintel_sites",
	"codeintel_fts",
	"codeintel_embeddings",
	"codeintel_minhash",
	// Corpus-archival tables (docs/plans/observer-corpus-archival-lazyload-
	// design-2026-08-26.md). Two distinct things are pinned here:
	//
	//   - codeintel_archived_projects (migration 092) is a HOT-DB table
	//     naming private project paths, node-local for exactly the same
	//     reason as the codeintel_* rows above.
	//   - the archive_* names live in a DIFFERENT FILE entirely
	//     (~/.observer/archive.db, owned by internal/archivestore with its
	//     own *sql.DB and its own migration lineage), so they are already
	//     unreachable from the push seam BY CONSTRUCTION: orgpush.go builds
	//     wire rows from the single hot handle it is given and has no code
	//     path to a second database. They are listed anyway because "by
	//     construction" is an argument, and this sentinel is a check —
	//     if a future refactor ever hands orgpush.go a second handle, the
	//     failure should be a red test rather than a review someone had to
	//     remember to do. Cold storage never becomes a wire surface: it
	//     holds the same node-local rows, only older.
	"codeintel_archived_projects",
	// Bucket B (process capture) archival, migration 093 + archive
	// migration 002. Same two-part posture as Bucket A above: the marker
	// is a hot-DB table, the archive_process_* rows live in the separate
	// archive file. Bucket B's hot tables carry raw command lines, cwds
	// and scrubbed network bodies, so their cold mirrors are at least as
	// sensitive as the originals — cold storage never becomes a wire
	// surface, it holds the same node-local rows, only older.
	"process_archived_windows",
	"archive_process_runs",
	"archive_process_events",
	"archive_process_network_bodies",
	"archive_codeintel_files",
	"archive_codeintel_nodes",
	"archive_codeintel_edges",
	"archive_codeintel_sites",
	"archive_codeintel_embeddings",
	"archive_codeintel_minhash",
	// Generalized-observability subsystem tables (internal/obs, plan
	// docs/plans/generalized-observability-custom-app-plan-2026-06-27.md
	// §10, decision D3). These are the obs subsystem's OWN tables, read
	// ONLY by internal/obs/store. Their org-tier disclosure IS a real
	// data flow — the obs-org-tier subsystem (docs/plans/
	// obs-org-tier-plan-2026-06-29.md) pushes trace/span STRUCTURE (T2),
	// eval-run SUMMARIES (T4), per-end-user SPEND (T5), and — gated by
	// shipsRawContent() — raw span bodies (T3), each under its own
	// [org_client.share] obs_* opt-in (default OFF; on in the hosted-app
	// admin_managed deployment). What this sentinel enforces is the
	// MODULE BOUNDARY, not "never pushed": orgpush.go must NEVER name an
	// obs_* table directly — the disclosure is composed through the
	// injected obs func seam (store.ObsOrgProviders), exactly like
	// RoutingSummaries. So these names must not appear as literals in
	// orgpush.go even though the data they hold does (selectively) ship.
	"obs_traces",
	"obs_spans",
	"obs_span_events",
	"obs_span_links",
	"obs_span_content",
	// obs eval plane (migration 0002, plan §8): datasets, dataset items
	// (snapshot input/output bodies), eval runs and scores are obs-owned.
	// Eval HEALTH ships as the T4 aggregate (obs_eval_summaries server
	// side) via the EvalRuns func seam; these raw tables are never NAMED
	// in orgpush.go (module boundary — same rule as above).
	"obs_datasets",
	"obs_dataset_items",
	"obs_eval_runs",
	"obs_eval_scores",
	// The machine review queue (obs 0022, Plane A W5-6 machine parity,
	// lane C10): node-local, never on the push wire.
	"obs_review_queues",
	"obs_review_items",
	// The machine's saved explorer views and alert firing state (obs 0020,
	// 0021, Plane A W5-4 / W5-5, lane C9), its prompt registry (obs 0019,
	// lane C8) and its alert event log: node-local, never on the push wire.
	// Named here, not left to the obs_ prefix (review finding R-C23).
	"obs_saved_views",
	"obs_alert_state",
	"obs_alert_events",
	"obs_prompt_versions",
	"obs_prompt_labels",
	"obs_prompt_label_moves",

	// Benchmarks Harness tables (migration 061,
	// docs/plans/benchmarks-harness-plan-2026-07-11.md §3.3) are NODE-LOCAL:
	// they hold repo paths, task prompts, final-answer excerpts, and judge
	// rationales — far higher privacy surface than the metadata that DOES
	// push, and personal benchmarking telemetry besides. They never enter the
	// wire path: no paired orgserver migration exists, and orgpush.go names an
	// explicit table allow-list these are not in. A future team-level
	// leaderboard, if ever built, would be a separate opt-in AGGREGATE wire
	// shape (per-config success-rate + cost, no prompts/paths), composed via a
	// function seam — never these tables (the routing_summary precedent).
	"benchmark_runs",
	"benchmark_attempts",
	"benchmark_session_members",
	"benchmark_scores",
	// obs input-admission audit (migration 0005, admission spec §7): the
	// verdict event log (raw request NEVER stored — only message_hash; the
	// reason_excerpt is gated by ContentGate) and the content-addressed policy
	// snapshots are NODE-LOCAL like the rest of obs_* — never on the org-push
	// wire, no server pair. (Org-level admission rollups, if ever wanted, are a
	// separate opt-in decision — obs plan §15 Q5.)
	"obs_admission_events",
	"obs_admission_policy_versions",

	// Opt-in aggregate rail state (migration 062,
	// docs/plans/g25-optin-aggregate-rail-design-2026-07-11.md §6.5). Both
	// tables are NODE-LOCAL by construction: aggregate_submissions is a
	// per-month submission ledger (month/hash/state/attempt bookkeeping + a
	// bounded snapshot of the CONTENT-FREE allow-listed payload), and
	// aggregate_consent is the single-row consent receipt. The aggregate rail
	// is an org-INDEPENDENT sibling of org-push, never an extension of it: it
	// has its OWN egress seam (internal/aggregateclient), its own consent gate,
	// and it does not round-trip through SelectUnpushedSince at all. These
	// literal sentinels keep both table names out of orgpush.go — the wire that
	// DOES leave under this rail is the aggregate.Submission (24-field
	// allow-list), pinned separately by tests/invariant/aggregate_test.go.
	"aggregate_submissions",
	"aggregate_consent",

	// Remote-access audit log (migration 063, remote-dashboard-access plan
	// §4.8) is NODE-LOCAL: it records remote-exposure events (paired session
	// ids, resolved capability, matched route, decision) for the operator's own
	// `observer remote status`. It never leaves the machine — no paired
	// orgserver migration, and orgpush.go names an explicit table allow-list
	// this is never in. Same posture as the cachetrack tables. If a
	// team-level "who accessed my node remotely" view is ever wanted it is a
	// separate opt-in AGGREGATE wire shape, never this raw table.
	"remote_audit",

	// obs Plane-A egress-routing audit (migration 0007, G22 design §7). The
	// raw request is NEVER stored (only message_hash). Since 2026-08-24
	// (org-parity W5.3) an egress org tier DOES exist — exactly the "future
	// opt-in wire shape + share key + sentinel update" the original G22 §8
	// deferral prescribed: composed as orgcontract.ObsEgressRow via the
	// store.ObsOrgProviders.Egress FUNC SEAM, gated on the node-side
	// [org_client.share.obs].egress opt-in (ShareOptions.ObsEgress, default
	// false), with the Tenant/User content columns additionally stripped
	// under !shipsRawContent(). This literal sentinel therefore still holds:
	// the table NAME never appears in orgpush.go (module-boundary
	// discipline, same as every obs_* table); the tier contract itself is
	// pinned by TestObsEgressTierContract + the compose gating test in
	// internal/store/orgpush_obs_test.go.
	"obs_egress_decisions",

	// Terminal-run identity + correlation (migration 064, terminal-product-
	// exploitation plan §2.1a / §7 — Phase 0 item S0b). Both tables are
	// NODE-LOCAL: they record which tool a dashboard terminal launched, when, at
	// what (hashed) project root, and which agent sessions the launch was
	// confidently correlated to — personal workflow telemetry. They never enter
	// the wire path: no paired orgserver migration exists, and orgpush.go names
	// an explicit table allow-list neither is in. A future team-level "who ran
	// what" view, if ever built, is a separate opt-in AGGREGATE wire shape,
	// never these raw tables. Same posture as the remote_audit node-local
	// table.
	"terminal_run",
	"terminal_run_session",
	// Terminal command/turn boundaries (migration 065, terminal-product-
	// exploitation plan §7 / F3). NODE-LOCAL: command/turn boundary
	// coordinates + exit codes + provenance for a dashboard terminal launch,
	// metadata/coordinates only (never command text or output). Never on the
	// wire — no server pair; same posture as terminal_run.
	"terminal_commands",
	// Persisted remote device sessions (migration 066, persist-remote-sessions
	// plan 2026-07-14). NODE-LOCAL: remote_sessions holds the sha256 hash of a
	// paired device's bearer cookie (never the raw token) + its generation and
	// idle clock; remote_session_state holds the single-row durable generation
	// fence. These let a paired phone survive a daemon restart without weakening
	// the revoke/rotate/disable invariant. They never leave the machine — no
	// paired orgserver migration, and orgpush.go names an explicit table
	// allow-list neither is in. Same posture as remote_audit.
	"remote_sessions",
	"remote_session_state",

	// Session classification (migration 075,
	// docs/plans/session-classification-tags-plan-2026-07-31.md §1). Tag names
	// and notes are the SAME PRIVACY CLASS as sessions.git_branch, which was
	// gated off the org wire on 2026-07-02 (security review M2) precisely
	// because free-text labels a developer authors encode client names,
	// codenames and ticket ids. A tag vocabulary is that failure mode by
	// construction ("acme-migration", "PROJ-1421", "junk"), and the note field
	// is unbounded prose about why a run mattered.
	//
	// Both tables are therefore NODE-LOCAL under EVERY share mode — including
	// admin_managed, which flips content-bearing columns raw for the other
	// surfaces. There is no share key for them and no paired orgserver
	// migration, by design; an org-shared taxonomy would need an explicit new
	// [org_client.share] key plus its own privacy review (plan §0, deferred).
	// session_tags additionally carries the end-to-end pin below
	// (TestSessionClassificationPinnedOutOfPush).
	"session_tags",
	"session_annotations",
	// tag_definitions (migration 101) — the optional human-readable
	// explanation + category attached to a tag name in the vocabulary above.
	// Same privacy class as session_tags/session_annotations (a definition
	// can itself restate the client/codename/ticket meaning a tag encodes),
	// same posture: no share key, no paired orgserver migration.
	"tag_definitions",
	// Node-local cloud-intelligence persistence (migration 097, CI-P2 Lane D —
	// cloud-intelligence Azure Foundry plan of record §6 CI-P2 + §7 invariant
	// 2). These are the SIGNED-IN FREE / PERSONAL cloud plane's own node-side
	// tables, and the personal plane is a SEPARATE destination from the org
	// push wire by construction (plan §7 invariant 3, plane separation). None
	// may ever appear in orgpush.go: consent receipts and the random
	// local<->cloud pseudonym maps are the developer's private evidence of what
	// they agreed to and which local ids they mapped; the outbox names sessions
	// + confirmed digests + retry state; cloud_results (and its overrides) hold
	// the enrichment product plus the user's own edits — all node-local under
	// EVERY share mode. There is no org share key for any of them and no paired
	// orgserver migration. TestCloudLocalTablesPinnedOutOfPush adds the
	// seeded-value end-to-end pin (STRENGTHENED sentinel, Sol SB3): distinctive
	// sentinels stuffed into every text column of every one of these tables,
	// asserted absent from a real SelectUnpushedSince serialization under
	// metadata-only, full_content, AND admin_managed.
	"cloud_consent_receipts",
	"cloud_session_map",
	"cloud_project_map",
	"cloud_outbox",
	"cloud_results",
	"cloud_result_overrides",
	// Migration 098 (W2 structural-insights rail, divergence-remediation plan
	// rev 4.1 §3 W2): the node's own record of which per-day windows it
	// snapshotted, at which revision, with which digest. Same posture as the
	// 097 five — node-local, no org share key, no paired orgserver migration.
	"cloud_structural_windows",
	// Migration 100 (Sol re-review N2, the cross-process dispatch lease for the
	// standing rails): receipt ids, a purpose label, a generation and
	// timestamps — the node's own record of which sends were in flight under
	// which receipt. Same posture as the 097/098 tables.
	"cloud_dispatch_leases",
	// Migration 115 (W2 value-upgrade plan: the developer's own standing
	// enrichment INTENT — which level the background path may mint
	// per-session receipts under, and whether background runs at all). It
	// binds nothing and authorizes no upload by itself (a consent receipt
	// still gates every send), but it is still node-local developer-recorded
	// state with no org share key and no paired orgserver migration — same
	// posture as every other cloud_* table.
	"cloud_enrich_policy",
	// Migration 117 (W3 value-upgrade plan: the outcome of the most recent
	// `observer cloud sync` run — content-free counts and a closed error
	// class only, never a session id or raw output). Same posture as every
	// other cloud_* table: no org share key, no paired orgserver migration.
	"cloud_sync_last",
	// Migration 118 (W5 value-upgrade plan: the weekly project digest a
	// pulled result kind="project_digest" record carries — headline/themes/
	// cost trend/recurring error classes/unfinished threads/suggested next
	// session for one project's own already-uploaded session_enrichment
	// results). NO new content ever left this node to produce a digest — it
	// is a RECEIVED product, the same posture as cloud_results for a session
	// enrichment. Node-local: no org share key, no paired orgserver
	// migration.
	"cloud_digests",
	// Migration 120 (2026-09-16 background-by-default follow-up: the
	// durable backoff for the auto-enrich sweep's permanently-failing
	// candidates — session id, attempt count, next-eligible time, and a
	// short fixed error CLASS token, never subprocess output). Same
	// posture as every other cloud_* table: no org share key, no paired
	// orgserver migration.
	"cloud_enrich_skips",
	// Agent migration 241 (cloud-agents arc, lane CA-A1): the node-local
	// state of cloud-agent connectors. cloud_connector_accounts names the
	// developer's linked vendor accounts (immutable account id, display
	// e-mail), cloud_sync_checkpoints their provider cursors and gap
	// intervals, cloud_usage_ledger the native-unit usage (ACUs, credits,
	// vendor-reported USD) with its scope ids. None ships in any share mode:
	// org usage for cloud agents comes from vendor connections, not from this
	// ledger (plan section 4.2). No org share key, no paired orgserver
	// migration. TestCloudAgentTablesPinnedOutOfPush is the seeded-value pin.
	"cloud_connector_accounts",
	"cloud_sync_checkpoints",
	"cloud_usage_ledger",
	// Agent migration 244 (cloud-agents arc, lane CA-B3): the ship tokens
	// this node minted for its own cloud-session ingest route. Credential
	// digests and labels; never on the wire in any share mode, no org share
	// key, no paired orgserver migration.
	"cloud_session_ship_tokens",
	// Agent migration 246 (cloud-agents arc, lane CA-C5): the pull requests
	// and branches a cloud-agent vendor said a session produced, per
	// repository. Repository slugs name clients and branch names encode
	// ticket ids (the M2 precedent): never on the wire in any share mode.
	// What the credit changes on the wire is only the existing
	// CommitOwnershipRow's owner / reason / share basis. No org share key, no
	// paired orgserver migration. TestCloudSessionLinksPinnedOutOfPush is the
	// seeded-value pin.
	"cloud_session_links",
	// file_changes (migration 103, Lines-of-Code tracking) is NODE-LOCAL BY
	// TABLE NAME: orgpush.go must never reference it. Its grain is ONE ROW
	// PER FILE — a file-level activity map of the developer's working tree,
	// a strictly deeper disclosure than "this session's agent wrote N lines
	// of code", even though every path in it is already a hash.
	//
	// What DOES ship is the SUM over it: the SessionLOCRow / LOCDayRow
	// aggregates, computed in store/locsummary.go and composed into the push
	// via a FUNCTION CALL — precisely so this sentinel can keep forbidding the
	// underlying table name here, the same pattern as
	// router_decisions/routing_summaries and project_patterns above. Adding a
	// per-file wire row is not a matter of widening this list: it would need
	// its own share key and its own privacy review.
	// TestSessionLOCWireShapeIsAggregateOnly pins the wire types' shape;
	// TestFileChangesNeverOnTheWire is the end-to-end seeded-value pin.
	"file_changes",
	// project_commits / project_commit_files / project_commit_scan
	// (agent migration 127, projects-page-roi-and-commit-alignment plan
	// §2 R1/R12) are NODE-LOCAL BY TABLE NAME: orgpush.go must never
	// reference them. Commit capture observes OTHER CONTRIBUTORS'
	// metadata in a shared repository — a hashed author name (unsalted;
	// docs/security.md ledger row COMMIT-2 records this as inadequate
	// pseudonymisation for any future org projection), the commit
	// subject, and the list of files it touched, at a strictly deeper
	// grain than any existing wire surface. The ONE derived projection
	// on the wire is commit ownership (lane F-PROJ, CommitOwnershipRow):
	// ids and counts only, composed through the function seam
	// store.SelectCommitOwnershipRows (commitownersummary.go), the subject
	// gated on shipsRawContent(), and NO author hash and NO path, so these
	// table names stay forbidden here.
	// TestProjectCommitTablesPinnedOutOfPush and
	// TestCommitOwnershipWireCarriesNoAuthorOrPath are the end-to-end
	// seeded-value pins.
	"project_commits",
	"project_commit_files",
	"project_commit_scan",
	// project_prompt_grades (agent migration 128, projects-page-roi-and-
	// commit-alignment plan §2 R6/§3.6/§4 W5a) is NODE-LOCAL BY TABLE
	// NAME, same rule as the project_commit_* block just above: a
	// grading verdict (delivered/missed/extra/notes) is a DERIVED
	// disclosure of the prompt text and commit hunks it was built from,
	// at the same sensitivity as the conversation content itself. Both
	// the J tier (internal/intelligence/alignment) and, later, the C
	// tier (W5b) write here under their own `tier` value; neither has a
	// wire surface. TestProjectPromptGradesTableIsPinnedOutOfPush is the
	// end-to-end seeded-value pin, the sibling of
	// TestProjectCommitTablesPinnedOutOfPush above.
	"project_prompt_grades",
	// Skills history (agent migration 135, S10-SKILLS; docs/projects-page.md
	// "Skills: versions across commits and sessions") is NODE-LOCAL BY
	// TABLE NAME. The hook snapshots name private skill paths (including the
	// operator's home-scope skills) and the reflog/tree memo records when
	// the operator's checkout moved; none of it has a wire surface.
	// TestSkillHistoryTablesPinnedOutOfPush is the end-to-end seeded-value
	// pin.
	"skill_snapshot_members",
	"session_skill_snapshots",
	"project_head_moves",
	"project_skill_trees",
	"project_skill_tree_files",
	"project_skill_worktree",
	"project_skill_scan",
	// project_quality_daily (agent migrations 219 and 221,
	// docs/projects-page.md "Quality metrics", plan item 8 M3L-2 and
	// M3L-4) is NODE-LOCAL BY TABLE NAME: a project's daily coverage,
	// duplication and complexity numbers. (The per-function complexity it
	// rolls up lives on codeintel_nodes, migration 215, already
	// node-local by the codeintel_* names above.) It holds no path
	// or name, but an org roll-up is out of scope (plan 14.10: a wire-shape
	// change with paired migrations and its own review), so orgpush.go must
	// never name it. TestProjectQualityDailyPinnedOutOfPush is the
	// end-to-end seeded-value pin.
	"project_quality_daily",
	// Enterprise Update Management, node side (agent migration 105,
	// docs/plans/enterprise-update-management-plan-2026-09-07.md §3.4). Both
	// tables are NODE-LOCAL BY TABLE NAME: orgpush.go must never reference
	// them.
	//
	// update_state stores three LOCAL PATHS — the preserved rollback binary,
	// the staged download and the pre-apply VACUUM INTO snapshot — plus the
	// bytes of the manifest this node accepted. update_events.detail is
	// deliberately free text (which snapshot was restored, which directory
	// was not writable), which is what makes `observer update history`
	// usable and exactly what ruling R10 keeps off the wire: an error STRING
	// can leak a path, an error CLASS cannot.
	//
	// What DOES ship is orgcontract.UpdatePostureRow — a version string, a
	// coarse platform token, four closed enums and two booleans — composed
	// in internal/store/updateposture.go and reached from the push seam by a
	// FUNCTION CALL, precisely so this sentinel can keep forbidding the
	// underlying names here. That row's field set is pinned separately by
	// TestUpdatePostureRowWireShapeIsEnumOnly, so widening the disclosure is
	// not a matter of widening this list.
	"update_state",
	"update_events",
	// Plans & limits (agent migration 163, docs/plans-and-limits.md, D-640 /
	// D-642). All four tables are NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference them. plan_accounts names which vendor accounts the
	// developer tracks (labels, a GitHub username, an xAI team id) and which
	// keychain secret NAMES are stored; plan_snapshots holds the developer's
	// own plan usage and balances; plan_runs the poll history; plan_optins
	// the per-provider experimental switch. There is no share key and no
	// paired server migration in this phase: a future opt-in posture share
	// would be a separate, enum-only row composed by a function call, the
	// update_state precedent above. Credentials never reach any table.
	"plan_accounts",
	"plan_snapshots",
	"plan_runs",
	"plan_optins",
	// plan_usage_daily (agent migration 248): the vendor's account-wide
	// daily token totals of a Plans & limits account (Codex
	// account/usage/read), reconciled on this node against its own
	// captured tokens. Same posture as the other four: node-local by table
	// name, no share key, no server pair.
	"plan_usage_daily",
	// local_session_holds (agent migration 251, plan 07 M8.8): the sessions
	// this node's own retention keeps (`observer sessions hold`). The
	// developer's local choice; the org's holds are set on the org
	// (session_holds, org PostgreSQL 0230). Node-local by table name, no
	// share key, no server pair.
	"local_session_holds",
	// settings_proposals (agent migration 259, Plane A lane B6, D19): the
	// security-sensitive settings changes an AI agent asked for, waiting for
	// the user's approval. Node-local by table name, no share key, no server
	// pair.
	"settings_proposals",
	// Delivery, commit to PR to merge (agent migrations 166 to 172, D-689,
	// docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md 6.1). All
	// NODE-LOCAL BY TABLE NAME: orgpush.go must never reference them.
	// project_remotes and pull_requests carry the repo slug, PR titles and
	// URLs (they name clients and codenames); delivery_branch_tips keeps the
	// branch NAME for this node's own display (branch names encode ticket
	// ids, the M2 precedent); provider_links names keychain entries;
	// delivery_mirrors holds local mirror paths. What ships is composed by a
	// FUNCTION CALL into internal/store/deliverysummary.go: DeliveryDayRow
	// counts from every node, PullRequestRow only under shipsRawContent().
	// TestDeliveryTablesPinnedOutOfPush is the end-to-end seeded-value pin.
	"project_remotes",
	"commit_landings",
	"provider_links",
	"pull_requests",
	"pull_request_commits",
	"delivery_mirrors",
	"delivery_project_settings",
	"delivery_branch_tips",
	// Enterprise pricing, node side (agent migration 106,
	// docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md
	// §3.3). org_pricing_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the ORG's own signed price document as the node last accepted
	// it — the server's bytes coming BACK, not node data going out — plus the
	// key fingerprint that verified them and the ladder state of the last
	// fetch. It is persisted rather than kept in memory (the sibling budget
	// rail's choice) because a mis-priced captured turn is permanent, so a
	// restart must not silently drop the fleet to seed prices.
	//
	// What DOES ship in the other direction is the enum-only PricingSource /
	// PricingVersion pair on orgcontract.BudgetPostureRow — an envelope field
	// composed by internal/store's posture seam, never a selected wire row —
	// which is precisely why this sentinel can keep forbidding the table name
	// here. Same posture as update_state / update_events above.
	"org_pricing_cache",
	// Org BUDGET rail, node side (agent migration 119, org-observer
	// fundamentals plan 2026-09-13 finding H3). org_budget_cache is NODE-LOCAL
	// BY TABLE NAME: orgpush.go must never reference it.
	//
	// It holds the ORG's own signed PER-CALLER budget document as the node
	// last accepted it — the server's bytes coming BACK, not node data going
	// out — plus the ETag and the key fingerprint that verified them. The
	// direction is the org_pricing_cache posture exactly, one rail over, and
	// the body it stores was resolved and signed BY the server, so echoing it
	// on the push wire would add no information and only widen what a
	// compromised node could assert.
	//
	// What DOES ship in the other direction is the enum-only
	// orgcontract.BudgetPostureRow — composed by internal/store's posture
	// seam, never a selected wire row — which is why this sentinel can keep
	// forbidding the table name here.
	"org_budget_cache",
	// Org-served Cloud Intelligence, node side (agent migration 112,
	// docs/plans/org-served-cloud-intelligence-plan-2026-09-10.md §1.3/§2.4,
	// W3, INV-3). org_intel_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the ORG server's OWN derived per-session enrichment results as
	// the node last PULLED them over GET /api/agent/intel/results — the org's
	// product coming BACK, not node data going out, exactly the posture of
	// org_pricing_cache above. The results are model-generated prose about the
	// developer's own session; they are rendered on the node dashboard and
	// never travel the node→server push wire (that direction is the push
	// envelope). There is no org share key for it and no paired orgserver
	// migration on the push side — the org DERIVES its own result rows from
	// data the node already pushed (B2), so nothing new goes out to produce
	// them. The single store seam is internal/store/intelcache.go.
	"org_intel_cache",
	// Cloud Intelligence parity, node side (agent migration 153,
	// docs/plans/cloud-intelligence-parity-design-2026-10-03.md section 3.7).
	// All three are NODE-LOCAL BY TABLE NAME. org_intel_requirement caches the
	// org's signed terms (the org's document coming BACK); org_intel_consent is
	// the developer's own append-only consent history; org_intel_receipts is
	// the local audit (sweeps, leave, notices). The consent POSTURE reaches the
	// org only as the dedicated signed POST /api/agent/intel/consent report
	// (an enum, a version and a digest), never through the push envelope.
	"org_intel_requirement",
	"org_intel_consent",
	"org_intel_receipts",
	// Parity phase 2 (agent migration 154): the node-built evidence outbox.
	// The evidence leaves only through POST /api/agent/intel/evidence, never
	// the push envelope.
	"org_intel_outbox",
	// Standalone-node public pricing feed, node side (agent migration 113,
	// docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3,
	// Wave N). pricing_feed_cache is NODE-LOCAL BY TABLE NAME: orgpush.go must
	// never reference it.
	//
	// It holds the PUBLIC Tokenomics feed's OWN signed document as the node
	// last pulled it over GET /api/pricing/v1/observer-pricing — a publisher's
	// bytes coming BACK, and a body that names no org and no subject (the SAME
	// document for every consumer on earth), not node data going out. Exactly
	// the org_pricing_cache posture above, for the standalone case instead of
	// the enrolled one: an enrolled node ignores the public feed entirely, so
	// this table is inert while enrolled and never carries anything worth
	// pushing. The single store seam is internal/store/pricingfeed.go; there is
	// no org share key for it and no paired server migration (the org server
	// consumes the feed through its own importer, a separate wave).
	"pricing_feed_cache",
	// --- PRIV-3 / PRIV-4 (codebase audit 2026-09-16) ---
	//
	// Seventeen node-local tables that had never been enumerated here. None
	// leaks today — orgpush.go names an explicit table allow-list and none of
	// them is in it — but that is an argument, and this sentinel is a check.
	// The whole point of the source-level rule is that adding a table to the
	// push seam should fail a test rather than depend on a reviewer noticing;
	// a table absent from BOTH the wire and this list has neither protection.
	//
	// They were found by enumerating every CREATE TABLE in
	// internal/db/migrations and subtracting the tables that have a wire row
	// (actions / api_turns / projects / sessions / token_usage / otel_content /
	// guard_events / task_items / task_transitions /
	// tool_account_observations), the push machinery itself (org_push_log /
	// schema_meta, which orgpush.go legitimately names), the received org
	// roster caches (org_enrolment / org_members / org_teams /
	// org_team_members / org_project_team), and the transient *_new rebuild
	// tables a migration drops behind itself.
	// TestForbiddenCacheTablesCoversEveryNodeLocalTable keeps that derivation
	// honest for future migrations.
	//
	// What each of them would disclose, since "no leak today" is not a reason
	// to leave a table unlisted:
	//
	//   - action_embeddings / retrieval_signals: vector embeddings OF the
	//     developer's tool inputs and outputs, plus which past outputs were
	//     retrieved for which query. An embedding is a lossy but real
	//     projection of the text it came from — closer to the content columns
	//     this file forbids than to metadata.
	//   - compression_events / compaction_events / summary_calls: per-turn
	//     compression/summarization bookkeeping, including what was dropped and
	//     what a summary call cost. Reveals conversation shape turn by turn.
	//   - failure_context: what failed, where, and the surrounding excerpt —
	//     the single most content-bearing node-local table on this list.
	//   - file_state / parse_cursors / adapter_unrecoverable_files: per-FILE
	//     paths and parse positions across the developer's whole machine,
	//     including transcript files outside any project root.
	//   - mcp_audit: which MCP tool each AI client called, with arguments'
	//     provenance — the MCP-side twin of guard_events without its strip.
	//   - arena_runs / arena_candidates: local head-to-head model evaluation,
	//     including the prompts a run was scored on.
	//   - digest_state / observer_log / launch_seeds / session_pid_bridge /
	//     claudecode_effort: daemon-local operational state (advisor digest
	//     cursor, the node's own log ring, launcher seed payloads, the pid↔
	//     session bridge, per-session reasoning-effort sidecar). Operational
	//     telemetry about the developer's machine, not about their org's work.
	//
	// If any of these ever earns a wire surface it follows the established
	// route: a derived, content-free AGGREGATE composed through a function
	// seam in its own file (the routing_summary / file_changes precedent), its
	// own [org_client.share] key, and its own privacy review — the table name
	// stays forbidden HERE either way.
	"action_embeddings",
	"adapter_unrecoverable_files",
	"arena_candidates",
	"arena_runs",
	"claudecode_effort",
	"compaction_events",
	"compression_events",
	"digest_state",
	"failure_context",
	"file_state",
	"launch_seeds",
	"mcp_audit",
	"observer_log",
	"parse_cursors",
	"retrieval_signals",
	"session_pid_bridge",
	"summary_calls",
	// DELIBERATELY NO LONGER HERE — task_items / task_transitions (agent
	// migration 109) and tool_account_observations (agent 111). Migration
	// 109 pinned the task tables node-local "for this first slice" and 111
	// said "Never copied by org push"; the node session-detail trickle-up
	// arc's W2/W3 waves (docs/plans/
	// node-session-detail-trickle-up-to-org-plan-2026-09-10.md, server
	// migrations 140/141) are the deliberate, reviewed reversal of exactly
	// that first slice — the G22 s8 pattern this file has applied before
	// (terminal_run / remote_audit moved the same way under
	// terminal_detail).
	//
	// The one-owner discipline is UNCHANGED and still enforced: orgpush.go
	// names none of the three tables. The reads live in their own files
	// (internal/store/taskflowsummary.go, toolaccountsummary.go), reached
	// from the push seam by a FUNCTION CALL — the same arrangement
	// cache_events, router_decisions and file_changes already use, all of
	// which likewise ship an opt-in wire while their table names stay
	// forbidden here.
	//
	// What replaces the blanket forbid is a pair of NAMED wire-surface
	// tests, which are strictly stronger than the old absence assertion
	// because they pin the GATE rather than the silence:
	// TestSessionTasksShipOnlyUnderTaskDetail and
	// TestSessionToolAccountsShipOnlyUnderToolAccountDetail prove nothing
	// ships under the zero-value posture, that the status/enum halves ship
	// under their own tier, and that the content halves (plan prose;
	// developer identity) stay STRIPPED until the node ALSO ships raw
	// content.
	// Org push re-send tracking (agent migration 140, lane R2-RESEND): the
	// NODE-LOCAL change queue and its counter. They decide WHICH wire rows
	// re-send; they are never themselves on the wire, and orgpush.go reaches
	// the queue only through internal/store/orgpushresend.go's
	// pushChangesFilter, so neither name may appear in orgpush.go.
	"org_push_changes",
	"org_push_rev",
	// Org push DELETE propagation (agent migration 141, lane R2-TOMB): the
	// NODE-LOCAL tombstone queue and the resync manifest queue. The wire
	// carries only the identity fields the rows themselves ship (hashes,
	// ids); orgpush.go reaches both queues only through
	// internal/store/orgpushtomb.go, so neither name may appear there.
	"org_push_deletions",
	"org_push_manifests",
	// Stored spend-dedup verdicts (agent migration 143, lane R2-ONERULE):
	// derived per-row decisions, their re-derive queue and state. The org
	// derives its own verdicts from the rows the node ships (server 179),
	// so none of these ever crosses the wire.
	"spend_verdict_token",
	"spend_verdict_proxy",
	"spend_verdict_dirty",
	"spend_verdict_state",
	// Stored-cost re-price runs and their per-row change log (agent migration
	// 145, lane G-REPRICE, gap PRICE-REPRICE-1). NODE-LOCAL audit and revert
	// records: a re-priced api_turns.cost_usd reaches the org through the
	// existing change queue as an ordinary wire column, never through these.
	"reprice_runs",
	"reprice_changes",
	// Dashboard-installed tools (agent migration 149). The node's own record
	// of AI tools its local dashboard installed — tool, channel, the exact
	// argv executed (which can carry the operator's home path in an npm
	// --prefix) and the install/uninstall lifecycle. It describes this
	// machine's software, not the org's work, and backs the local-only
	// Uninstall affordance. NODE-LOCAL; the single writer is
	// internal/store/toolinstalls.go.
	"tool_installs",
	// Adapter config editor layer store (agent migration 155): which
	// developer layer authored each vendor-file key Observer's editor wrote
	// (value fingerprints, the authored value for display, never a secret)
	// and the per-save history (key NAMES, backup paths). NODE-LOCAL: an
	// individual node reports nothing (operator ruling D-112 is
	// managed-only and composes through a store function seam in phase
	// P7). Single writer internal/store/agentconfig.go.
	"agent_config_layers",
	"agent_config_writes",
	// The org AI tool settings policy on a managed node (agent migration
	// 160, adapter config P6/P7): the cached signed document and the
	// per-directive applied state (with local project roots). NODE-LOCAL;
	// the managed-only state report reaches the wire ONLY as the
	// envelope-level AgentConfigState, composed by a store function seam
	// (internal/store/agentconfigorg.go) from closed fields. Single writer
	// internal/store/agentconfigorg.go.
	"org_agent_config_policy",
	"agent_config_org_state",
	// Component purge plans (agent migration 158, modular packaging P1, lane
	// MP-GATE): the persisted, expiring candidate sets of a component data
	// purge (plan ids, component ids, table names and primary keys). The
	// purge itself is node-local by construction (db.WithRetentionDeletes,
	// no org tombstone). NODE-LOCAL; single writer
	// internal/store/componentpurge.go.
	"component_purge_plans",
	"component_purge_candidates",
	// Hook liveness (agent migration 198, surface-gap review OBS-7 / CC-2):
	// one row per (tool, event, session id) with a count, first/last
	// invocation times and the route-relevant env NAMES the hook saw mapped
	// to coarse classes (never values). The table name stays forbidden
	// here: per-session org reach (decision DEC-5, lane w5-wire) is the
	// HookActivitySessionRow wire composed by
	// internal/store/hookactivitysummary.go through a function call, under
	// [org_client.share].hook_activity, with the config-dir hash behind
	// shipsRawContent() (TestSessionHookActivityShipOnlyUnderHookActivity).
	// Single writer internal/store/hookactivity.go, fed only by the daemon's
	// hook spool drainer (the hook process never opens SQLite).
	"hook_activity",
	// Sandbox egress refusal audit (agent migration 230, OpenShell build
	// lane N1): one row per refused egress attempt of a sandboxed run, at
	// most one per (run, host) per minute, naming the refused host, the
	// closed rule and the deciding config key, plus the run's project root.
	// Decision D6 keeps refusal events on the node: no per-refusal wire row.
	// The org sees only per (day, tier, closed rule) COUNTS, from a managed
	// node only (audit CG-15, decision D-11), composed by
	// internal/store/sandboxegress_org.go through a function call, so the
	// name stays forbidden here (TestSandboxEgressCountsCarryNoHost). Single
	// writer internal/store/sandboxegress.go, fed only by the daemon's
	// refusal receiver (a host helper never opens SQLite).
	"sandbox_egress_refusals",
	// The dropped count beside the refusal audit (agent migration 231,
	// OpenShell build lane OC, audit finding O3-W2): per run, how many
	// refusals a feed or the receiver dropped before they were written.
	// Node-local like the rows it sits beside (decision D6). Single writer
	// internal/store/sandboxegress.go.
	"sandbox_egress_refusal_drops",
	// Legacy Plane A api_turns rows (agent migration 256, plan-of-record
	// F10 / D6, lane A6): a hosted app's SDK/OTLP spend that older nodes
	// wrote into api_turns, relocated so it never reads or ships as coding
	// spend. Node-local; nothing writes it after the migration.
	"api_turns_planea_legacy",
}

// forbiddenGatewayTables names the SERVER-SIDE gateway tables that MUST NEVER be
// referenced as a string literal in internal/store/orgpush.go. Unlike the
// node-local forbiddenCacheTables above, these live in the ORG SERVER's DB — but
// the same source-level sentinel applies: the node→server push seam
// (SelectUnpushedSince) must never name them, because they are SERVER-ONLY ingest
// state the node never possesses. gateway_wal is the P0-9 durable-edge WAL — a
// server-only ingest queue whose payload holds mapped telemetry the node never
// possesses; naming it on the push wire would be nonsensical AND a boundary
// violation. Walked by TestSelectUnpushedSinceExcludesCacheTables alongside
// forbiddenCacheTables.
var forbiddenGatewayTables = []string{
	"gateway_wal",
	// The P1-2/P1-10 generic trace/span attribute-retention tier (server
	// migration 033) makes gateway_span carry retained OTLP attributes, and it
	// references the content-addressed gateway_resource/gateway_scope envelopes;
	// gateway_trace holds synthesized trace summaries. All four are SERVER-ONLY
	// gateway ingest tables (mig 026/027) that the NODE never possesses, so their
	// names must never appear on the org-push wire either.
	"gateway_resource",
	"gateway_scope",
	"gateway_span",
	"gateway_trace",
	// Plane B AI Gateway v1 (design §2, tracker Phase P4; server migrations
	// 108-111). The seven gw_* tables are the inference data plane's SERVER-ONLY
	// state — the per-developer virtual-key registry (stored as hashes only),
	// the org's registered upstreams (credential referenced only by a sealed
	// org_secret ref), the durable worst-case reservation ledger, and the
	// metadata-ONLY audit. The node never possesses any of them, so their names
	// must never appear as a string literal in orgpush.go's push seam. Named
	// gw_* rather than gateway_* deliberately (design §2.1 — grep-space disjoint
	// from the OTLP-ingest gateway_* tables above). Pinned as a fixed expected
	// set by TestForbiddenGatewayTablesExpectedSet.
	"gw_virtual_key",
	"gw_revocation_watermark",
	"gw_upstream",
	"gw_budget_cap",
	"gw_reservation",
	"gw_reservation_scope",
	// 120 (2026-09-02, G1-RESIDUALS): admin-authored model policy + rate card
	// documents and the per_developer dial-time secret-ref mapping.
	"gw_model_policy",
	"gw_rate_card",
	"gw_upstream_member_credential",
	"gw_audit",
	// Provider-billing reconciliation runs (server migration 117, P6, HG5):
	// imported provider billing reconciled against gw_audit. SERVER-ONLY gateway
	// data, never on the push wire.
	"gw_reconciliation_run",
	// Stateless-collectors + durable-log data plane (server migration 136,
	// docs/plans/stateless-collectors-durable-log-plan-2026-09-08.md §4.3/§4.4).
	// ingest_quarantine holds TERMINATED durable-log records - push envelopes or
	// mapped OTLP batches that the log's consumers (applyworker / sorwriter /
	// otlpapplier) could not apply and parked instead of losing. It is
	// SERVER-ONLY ingest state the node never possesses (the node has no concept
	// of the collector's log, let alone a record that failed to apply on the
	// server), so its name must never appear as a string literal in orgpush.go's
	// push seam. Pinned as a fixed expected-set member by
	// TestForbiddenGatewayTablesExpectedSet.
	"ingest_quarantine",
	// Server-only occurrence fences (migration 137), never node push state.
	"ingest_apply_receipt",
}

// forbiddenOrgControlPlaneTables are SERVER-ONLY P1-4/P1-7/P1-9 control-plane
// tables that must never appear in orgpush.go string literals.
var forbiddenOrgControlPlaneTables = []string{
	"org_intelligence_config",
	"insight_playbook",
	"insight_run",
	"insight_recommendation",
	"org_fleet_upgrade_cohorts",
	"org_fleet_cohort_members",
	"org_fleet_self_telemetry",
	"org_fleet_remote_config",
	"org_fleet_cert_events",
	"org_deployment_wizard",
	"org_deployment_connectors",
	// Plane B mode-switch plane (server migration 114, P5b): the routing-mode
	// singleton, the per-node mode-capability fleet-ACK registry that gates
	// Gateway-Mode activation, and the seven §8 preflight gate results. All
	// SERVER-ONLY — the node never sees the org's activation machinery.
	"org_plane_b_mode",
	"org_plane_b_mode_ack",
	"org_plane_b_preflight",
	// Break-glass credential-lease ledger (server migration 115, P6 §4.2 rung 3).
	// The admin request and the minted per-machine leases are SERVER-ONLY: the
	// LEASE is delivered server->node on the push RESPONSE (orgcontract, not a
	// selected wire row), never built by orgpush.go's node->server SELECT.
	"break_glass_request",
	"break_glass_lease",
	"break_glass_seal_key",
	// Recorded-acceptance ledger (server migration 116, P6, HG10): dated admin
	// acknowledgments of convention-grade enforcement. SERVER-ONLY.
	"org_plane_b_acceptance",
	// org_agent_policy_attributes (server migration 044) is the AUTHORITATIVE
	// per-subject policy-targeting binding: it decides which policy version a
	// node is served, and it exists precisely BECAUSE the node must not be the
	// one asserting those attributes. It is control-plane state the node never
	// possesses, so naming it on the node->server push wire would be both
	// nonsensical and a boundary violation. Pinned as a fixed expected member
	// by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_agent_policy_attributes",
	// The WS3 insight-harness trio (server migration 045). org_llm_provider is
	// the org's registered LLM connections and org_secret holds the SEALED
	// credential bodies those connections resolve — a credential store that the
	// node neither possesses nor may ever be shipped. insight_run_step is the
	// server-side audited step trace of an insight run (which query the agent
	// asked for, which model answered, what it cost). All three are org
	// control-plane state with no agent counterpart, so naming any of them on
	// the node->server push wire would be both nonsensical and a boundary
	// violation. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_llm_provider",
	"org_secret",
	"insight_run_step",
	// Enterprise-Managed Tenancy machine-identity binding (server migration
	// 074, Arc 4 P6a): server-only, and the fingerprint rides the managed-bind
	// REQUEST, never the push wire. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"managed_node",
	// The managed-integrity probe posture store (server migration 075, Arc 4
	// P6b): server-only, and the integrity signal rides the managed-integrity
	// REQUEST, never the push wire. Same posture as managed_node. Pinned as a
	// fixed expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"managed_integrity",
	// The ACP-P6c IdP device-code enrolment pairing store (server migration
	// 076): server-only, holding the device-code digest and the human-typed
	// user code of an in-flight browser pairing. Both live ONLY on the two
	// agent-facing idp-enrol endpoints, never on the node->server push wire.
	// Same posture as managed_node / managed_integrity. Pinned as a fixed
	// expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"idp_enrol_requests",
	// The fleet remote-config mutation trail (server migration 046). It
	// records WHICH ADMIN changed a collector's remote config, in which org —
	// server-side attribution for a control-plane mutation the node never
	// makes and never sees. Naming it on the node->server push wire would be
	// both nonsensical and a boundary violation. Pinned as a fixed expected
	// member by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_fleet_config_events",
	// The WS2 guided-setup settings store (server migration 047). Its rows
	// hold the org's storage-connection settings and a secretref pointing at a
	// SEALED credential body in org_secret — org control-plane configuration
	// the node neither possesses nor may ever be shipped. Naming it on the
	// node->server push wire would be both nonsensical and a boundary
	// violation. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_setup_setting",
	// The first-run setup claim (server migration 274, org first-admin setup
	// design 2026-11-02): a singleton holding the claim token's hash and its
	// cleartext SEALED under the org's key, which makes whoever holds it the
	// org's first administrator. Server-only bootstrap state with no agent
	// counterpart; a seam in orgpush.go that named it would be a boundary
	// violation.
	"org_setup_claim",
	// The WS1.4 project display-label store (server migration 048). Rows are
	// ADMIN-AUTHORED display strings for a project hash — org-side naming the
	// node never possesses and must never be asked for. The node ships the
	// hash and only the hash; a seam in orgpush.go that named this table would
	// mean the label had become node data (or, worse, that the wire had grown
	// a raw-path counterpart), which is exactly the inversion the hash posture
	// exists to prevent. Pinned as a fixed expected member by
	// TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_project_labels",
	// The dashboard-registered external harness agent registry (server
	// migration 049). Rows are org control-plane configuration (an admin's
	// choice of which pre-placed binary answers an agent id) with no agent
	// counterpart — the node never registers, resolves, or executes these,
	// it only ever sees the resulting "external:<id>" agent id the same way
	// it would a TOML entry. Naming it on the node->server push wire would be
	// both nonsensical and a boundary violation. Pinned as a fixed expected
	// member by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_external_agent",
	// Datasets foundation (server migration 051, wave item B): reference-only
	// trace/span membership for evals and experiments. Org control-plane
	// state with no agent counterpart — the node neither builds nor reads
	// datasets. Pinned as fixed expected members below.
	"org_dataset",
	"org_dataset_item",
	// LLM job runner + annotations (server migration 052, wave items C/D):
	// deterministic single-shot job state and metadata-class trace labels,
	// org control-plane only — the node never runs or reads these.
	"org_trace_annotation",
	"org_llm_job",
	"org_llm_job_item",
	// Plane A scores, snapshots, online rules and the review queue (server
	// migrations 330-333, lane B7): org-side only, never on the node wire.
	"org_dataset_snapshot",
	"org_dataset_snapshot_item",
	"org_eval_online_rule",
	"org_review_queue",
	"org_review_item",
	"org_review_assignment",
	// Guardrailed chat (server migration 053, wave item F): chat transcripts
	// and proposal state are org control-plane content with no agent
	// counterpart — the node never sees the assistant conversation.
	"org_chat_session",
	"org_chat_message",
	// Plane-B admin intelligence (server migrations 057-059 + the P2 harness
	// trio reserved by the spec's §2.3 nine-table pin;
	// docs/plans/plane-b-admin-intelligence-and-enforcement-spec-2026-08-15.md).
	// All are org control-plane state with no agent counterpart: the coding
	// intelligence config document, session-referencing dataset membership,
	// the single-shot job runner's state, session annotations, and the
	// Plane-B playbook/run tables. The node never builds, runs, or reads any
	// of them; naming one on the node->server push wire would be a boundary
	// violation. The content-adjacent trio (job, job_item, annotation) is
	// additionally pinned as fixed expected members below.
	"org_coding_intel_config",
	"org_coding_dataset",
	"org_coding_dataset_item",
	"org_coding_job",
	"org_coding_job_item",
	"org_coding_annotation",
	"org_coding_playbook",
	"org_coding_run",
	"org_coding_run_step",
	// Self-Improving Policy Plane P0 (server migrations 061-065;
	// docs/plans/self-improving-policy-evolution-p0-build-plan-2026-08-16.md).
	// All five are org control-plane state with no agent counterpart: the
	// per-(org,family,target) evolution config, the review-run ledger, the
	// candidate-proposal store (proposed_body + LLM-authored rationale), the
	// hash-chained approve/reject audit, and the manual-Apply outcome record.
	// The node never builds, runs, or reads any of them; naming one on the
	// node->server push wire would be a boundary violation. The two
	// content-bearing tables (proposal, decision — where LLM-authored text
	// lands) are additionally pinned as fixed expected members below.
	"org_policy_evolution_config",
	"org_policy_evolution_run",
	"org_policy_evolution_proposal",
	"org_policy_evolution_decision",
	"org_policy_evolution_applied",
	// Team Project Identity Mapping Wave B (server migration 083;
	// docs/plans/team-project-identity-mapping-plan-2026-08-21.md §1 L2/L4).
	// org_projects is the admin-authored team-level project identity (name +
	// client_label); org_project_members maps many project_root_hash-derived
	// ids onto one org_projects row. Both are org-side grouping/naming data
	// layered on top of the hash the node already ships — naming either on
	// the node->server push wire would be both nonsensical and a boundary
	// violation, the same posture as org_project_labels (048) above.
	"org_projects",
	"org_project_members",
	// Org Dashboard RBAC Wave A (server migration 084;
	// docs/plans/org-dashboard-rbac-plan-2026-08-21.md §1, §5 Wave A).
	// org_roles/org_role_permissions/org_member_roles are the role/
	// permission model (who may see which slice of the org's already-pushed
	// data), and org_role_bootstrap_applied is the bootstrap-marker gating
	// the one-time builtin-permission seed and the config-email member-role
	// backfill. All four are pure org-server authorization state with no
	// agent counterpart — the node never builds, grants, or reads roles or
	// permissions; naming any of them on the node->server push wire would be
	// both nonsensical and a boundary violation, the same posture as
	// org_project_labels (048) / org_projects (083) above.
	"org_roles",
	"org_role_permissions",
	"org_member_roles",
	"org_role_bootstrap_applied",
	// Pre-045-convention control-plane tables (C1 fix wave, slice A). These
	// predate the migration-file-comment convention the entries above follow,
	// but are the same posture: server-only state the node never possesses.
	// budgets/budget_alert_events (server migrations 002 base +
	// 080_budgets_multilevel widen) are the org-authored spend caps and the
	// evaluator's threshold-crossing audit trail — the node has no budget
	// concept and never fires an alert itself. issued_bearers/revoked_bearers
	// (server migration 001/002) are the bearer-token mint/revoke ledger — a
	// credential store, never shipped. enrolment_tokens (server migration
	// 001) and invite_attempts (server migration 024) are the enrolment/
	// invite rails' own state (who was offered a token, who attempted an
	// invite) — org control-plane bookkeeping about the node, not data from
	// it.
	"budgets",
	"budget_alert_events",
	"issued_bearers",
	"revoked_bearers",
	"enrolment_tokens",
	"invite_attempts",
	// Evals plane versioning/scheduling (server migrations 082_org_eval_run +
	// 085_org_eval_versioning_scheduling). org_eval_run/org_eval_score are the
	// eval-run ledger and its per-item scores; org_eval_run_item/
	// org_eval_schedule (085) added per-run item detail and the recurring-
	// schedule config. All four are org control-plane eval state with no
	// agent counterpart — the node never runs, schedules, or scores an eval.
	"org_eval_run",
	"org_eval_score",
	"org_eval_run_item",
	"org_eval_schedule",
	// Product-posture plane (server migration 112, P2b). org_product_posture
	// is the teams|enterprise singleton + fleet replacement generation;
	// org_grant_replacement is the signed grant-replacement issuance ledger;
	// org_grant_replacement_ack is the per-node fleet-ACK registry that gates
	// enterprise activation; org_collection_settings is the org-side per-
	// share-tier collection toggle. All four are org control-plane state with
	// no agent counterpart -- the node never issues a replacement, records a
	// fleet ACK server-side (it reports its own via a push HEADER, never a
	// wire row), or authors collection toggles. Pinned as fixed expected
	// members by TestForbiddenOrgControlPlaneTablesExpectedSet below.
	"org_product_posture",
	"org_grant_replacement",
	"org_grant_replacement_ack",
	"org_collection_settings",
	// Project Identity Resolver v2 server-only tables (server migration 122,
	// docs/plans/project-identity-resolver-v2-plan-2026-09-06.md §3.3/§3.4).
	// project_identity_signals is the materialized per-project identity
	// bundle (ingest-writer, replaces the per-read loadProjectOrigins scan);
	// org_repositories is the canonical-repo table keyed by remote hash;
	// org_project_rules is the admin's permanent assign/exclude rule ledger;
	// org_identity_settings holds the admin-authored enterprise owner
	// prefixes + auto-apply threshold. All four are server-side resolver
	// state with no agent counterpart — the node never builds, runs, or
	// reads any of them; naming one on the node->server push wire would be
	// both nonsensical and a boundary violation, the same posture as
	// org_project_labels/048 and org_projects/083 above.
	"project_identity_signals",
	"org_repositories",
	"org_project_rules",
	"org_identity_settings",
	// Org budget enforcement + token display server-only tables (server
	// migration 125, docs/plans/org-budget-enforcement-and-token-display-
	// plan-2026-09-07.md §3.1). org_display_settings holds the admin's
	// cosmetic cost_display / tokens_percent_scope choice (rendering only —
	// it changes nothing stored, computed, pushed or enforced);
	// org_budget_policy_version is the per-org counter the agent
	// budget-policy endpoint serves as an ETag. Both are admin/server
	// authored with no agent counterpart — the node RECEIVES budget policy on
	// the agent policy rail, it never PUSHES a budget row — so naming either
	// on the node->server push wire would be both nonsensical and a boundary
	// violation, the same posture as org_identity_settings/122 above.
	"org_display_settings",
	"org_budget_policy_version",
	// Per-team / per-member developer dashboard visibility (server migration
	// 194): the org admin's override layers. The node RECEIVES the composed
	// result on the signed node.governance rail and never pushes a row.
	"org_dashboard_visibility_overrides",
	// The per-member served node.governance version ledger (server migration
	// 205, pass-2 review C156-08): server bookkeeping of what each member was
	// served on the signed node.governance rail; the node never pushes a row.
	"org_nodegov_served_versions",
	// The per-member, per-family served policy-resource version ledger
	// (server migration 207, T-391): server bookkeeping of what each member
	// was served on the signed policy-resource rail; never pushed.
	"org_policy_served_versions",
	// The per-machine Ed25519 credentials (server migration 208, T-656): the
	// node sends its public key once on its own registration route; the
	// table never rides the push wire.
	"org_machine_keys",
	// Its per-member successor (server migration 229, REVIEW-4 P4-06): same
	// credentials keyed by (org, machine, member); equally server-only.
	"org_member_machine_keys",
	// Admin and developer messaging (server migration 237, T-854). The node
	// RECEIVES its own messages on the signed per-caller pull rail and sends
	// replies and receipts by direct POST; no messaging table ever rides the
	// push wire.
	"org_message_settings",
	"org_message_threads",
	"org_messages",
	"org_message_attachments",
	"org_message_delivery",
	"org_message_admin_reads",
	"org_message_suggestions",
	// Cloud-agents arc: the org ship-token credential store (server migration
	// 301, sha256 digests of ingest-only tokens) and the org-wide Rail S
	// switch (server migration 306, CLOUDSESS-13 part 2). Server-only control
	// state: a sandbox reaches the org through the ship-token route, never
	// the node push wire.
	"org_cloud_session_tokens",
	"org_cloud_session_settings",
	// My profile (plan 2026-11-07 section 2b): a member's own email
	// notification choices (server migration 310) and the per-session
	// sign-in registry (server migration 311, ledger PROFILE-1). Server-only
	// control state about the dashboard member; no node ever sends or
	// receives either.
	"org_member_notification_prefs",
	"org_auth_sessions",
	// Per-node agent keys (server migration 312, lane fl32, ledger
	// OSH-116): server-only control state binding each enrolment bearer to
	// the agent key it enrolled with. The node sends its key once at
	// enrolment, never this table.
	"org_member_node_keys",
	// In-flight OIDC sign-in transactions (server migration 313, bug-fix
	// lane B5, ledger AUTHTXN-1): server-only control state; no node ever
	// sends or receives it.
	"org_auth_pending_txns",
	// The one-step attach grant's single-use record (server migration 316 /
	// PG 0478, Getting started v2 lane 8, ledger ONB-9): server-only control
	// state; a node presents its grant once at enrolment, never this table.
	"org_attach_grant_uses",
	// The SDK key grant's single-use record (server migration 392 / PG
	// 0577, AI Apps SDK quickstart lane L4, ledger SDKQS-3): server-only
	// control state; the setup command presents its grant once, never this
	// table.
	"org_sdk_key_grant_uses",
	// The Plane A gateway's monthly usage meter (server migration 325 / PG
	// 0489, W1c-3a) and the pooled gateway's shared request budget (PG 0490,
	// W1c-3b): server-only; no node sends or receives either.
	"gateway_usage_monthly",
	"gateway_throttle_budget",
	// The hosted AI gateway's monthly request meter (server migration 390 /
	// PG 0571, hosted AI gateway lane L4): server-only; no node sends or
	// receives it.
	"aigw_usage_monthly",
	// The prompt registry (server migration 337 / PG 0510, Plane A W3-3
	// lane B8): the org's own authored prompts, served to SDK credentials on
	// the gateway listener. A machine keeps its prompts in its own obs store;
	// no node ever sends or receives these rows.
	"org_prompt_versions",
	"org_prompt_labels",
	"org_prompt_label_moves",
	// Prompt rollout approval (server migration 344 / PG 0519, Plane A W5-3
	// lane C8): proposed production changes and the org's registry settings.
	"org_prompt_proposals",
	"org_prompt_settings",
	// Managed-SaaS pooled host state (org PostgreSQL only; plan 07). The
	// request host map (0240) and the fenced periodic scheduler's lease rows
	// (0220); the host's per-tenant provisioning record (0261, wave 10 L1,
	// ledger TENANTPROV-1) and every organization's keyset sealed under the
	// platform KEK (0265, wave 10 L3). Server-only: no node ever sends or
	// receives a row, and tenant_keys holds key material. The pooled
	// apply's parked push records (0295, wave 12 lane apply, ledger
	// APPLYPARK-1) hold push bodies the node already sent; nothing ever
	// selects them back onto the wire.
	"tenant_hosts",
	"tenant_job_state",
	"tenant_lifecycle",
	"tenant_keys",
	// The availability layer on a pooled host (org PostgreSQL 0300, plan 07
	// M7a.6): the verified entitlements document per tenant, the platform
	// availability envelope, and what the reconciler applied per org. Server-
	// only: a node never sees the envelope (plan 06 18.3.3) and never names
	// these tables.
	"tenant_entitlements",
	"platform_availability",
	"org_availability_applied",
	// The org admin's own module switches (org PostgreSQL 0450, wave 17):
	// server-only; a node never sees them.
	"org_component_choice",
	"apply_parked",
	// Quotas and capacity admission on a pooled host (org PostgreSQL 0318,
	// plan 07 M7a.3): per-org quota state and the host's admission level.
	// Server-only: a node is answered ingest_paused, never shown the state.
	"org_quota_state",
	"platform_capacity",
	"platform_capacity_events",
	// The mounted host API's state on a pooled host (org PostgreSQL 0315,
	// W13 host-listeners): its call record, replay cache and idempotency
	// record. Server-only: the host API is the control plane's, never a
	// node's.
	"host_api_calls",
	"host_api_nonces",
	"host_api_idempotency",
	// The platform AI ledger and the consent-at-login and digest-mail
	// records (org PostgreSQL 0337, plan 07 M9.1/M9.2, W14 intel-provider).
	// Server-only: the platform's spend is never a node's, and a member's
	// login decision travels on no wire (the node reports its own consent
	// on its own rail).
	"platform_intel_spend",
	"platform_intel_holds",
	"org_intel_login_consent",
	"org_intel_digest_mail",
	// The org purge's run record on a pooled host (org PostgreSQL 0470, plan
	// 07 M7a.1): counts per (org, lifecycle generation). Server-only: the
	// purge is the host's, and no node ever names it.
	"org_purge_runs",
	// The org AI tool settings policy documents (server migration 201) and
	// managed nodes' applied state as the server stores it (202). The node
	// RECEIVES the composed policy on its own signed rail and ships its
	// state only as the envelope-level AgentConfigState report; it never
	// names either server table.
	"org_agent_config_policies",
	"org_agent_config_state",
	// Enterprise Update Management server-only tables (server migration 127,
	// docs/plans/enterprise-update-management-plan-2026-09-07.md §3.3).
	// org_update_manifests is the signed publication registry served on the
	// bearer-gated agent rail; org_update_artifacts is the mirror's index of
	// artifact bytes on the SERVER's own disk; org_update_rollouts is the ring
	// ledger the shared rollout engine drives; org_node_versions is the node
	// inventory board upserted at INGEST from the envelope the node pushed.
	// The direction is what matters: a node RECEIVES a manifest and FETCHES
	// bytes, and its only contribution is the enum-only UpdatePosture field on
	// the push ENVELOPE — never a selected wire row. So naming any of these
	// four in internal/store/orgpush.go would be both nonsensical and a
	// boundary violation, the same posture as org_budget_policy_version/125
	// above.
	"org_update_manifests",
	"org_update_artifacts",
	"org_update_rollouts",
	"org_node_versions",
	// Modular packaging plan 5.6 / 5.6.1 (server migration 220, lane
	// MP-REL2): the vendor-signed release index per version and the
	// publication object the v2 agent route serves. Same direction as the
	// 127 tables: a node RECEIVES the v2 document, it never ships a row.
	"org_update_release_indexes",
	"org_update_publications",
	// The node BUDGET posture board (server migration 130, gap
	// G1-BUDGET-POSTURE). It is upserted at INGEST from the enum-only
	// budget_posture field on the push ENVELOPE, exactly as org_node_versions
	// is from update_posture: the node's contribution is an envelope field,
	// never a selected wire row, so naming this table in
	// internal/store/orgpush.go would be both nonsensical and a boundary
	// violation.
	"org_node_budget_posture",
	// The node COMPONENT posture board (server migration 224, T-682): upserted
	// at ingest from the enum-only component_posture ENVELOPE field, the same
	// direction as org_node_budget_posture.
	"org_node_component_posture",
	// Org Dashboard Enterprise Sign-In server-only tables (server migration
	// 128, docs/plans/org-enterprise-sign-in-plan-2026-09-07.md §3.6).
	// org_auth_settings is the dashboard-editable identity singleton (enabled
	// rails, session policy, the org-wide sign-out epoch, ruling R8's
	// provisioning allow-list, the M3 seed marker); org_auth_rail_setting is
	// the per-rail key/value store and is the LOAD-BEARING one -- it is the
	// table carrying secret_ref, so a `store:` reference into the SEALED
	// org_secret body lives here; org_auth_group_role_map is the IdP-group ->
	// role rule set; org_auth_failures is the failed-sign-in counter keyed by
	// attempted email. All four are the configuration of a DASHBOARD HUMAN
	// session, a thing the node has no concept of and can neither produce nor
	// consume, so naming any of them in internal/store/orgpush.go would be
	// both nonsensical and a boundary violation -- the same posture as
	// org_setup_setting/047, whose shape org_auth_rail_setting copies.
	"org_auth_settings",
	"org_auth_rail_setting",
	"org_auth_group_role_map",
	"org_auth_failures",
	// Enterprise pricing server-only tables (server migration 132,
	// docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md
	// §3.1). org_model_prices is the org's ONE authored per-model price table
	// and org_pricing_version its monotonic document version. Both are
	// ADMIN-AUTHORED on the server and travel server -> node on a signed
	// policy rail (GET /api/agent/pricing, W2): the node RECEIVES prices, it
	// never PUSHES one, so naming either on the node -> server push wire would
	// be both nonsensical and a boundary violation — the same posture as
	// org_budget_policy_version/125 above. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"org_model_prices",
	"org_pricing_version",
	// org_pricing_feed_state is the pricing-FEED importer's server-side
	// bookkeeping (server migration 144): the last feed version/digest the
	// leader-only importer saw and the parked diff awaiting approval. It is
	// control-plane (it drives writes to org_model_prices through the same
	// handle) and purely server-side — the node RECEIVES feed-fed prices on the
	// signed GET /api/agent/pricing rail, it never pushes this. Pinned as a
	// fixed expected member by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"org_pricing_feed_state",
	// org_pricing_feed_settings (server migration 191) is the importer's
	// dashboard-owned apply mode + grade threshold: admin config, server-side
	// only, never pushed node -> server.
	"org_pricing_feed_settings",
	// control_schema_data_applied is the ONE-SHOT marker for the DATA
	// retrofits in controlstore/schema.go (that file is replayed on every
	// server start, so a data statement needs a marker or it runs forever);
	// since server migration 175 SQLite creates it too, to carry the one-shot
	// pricing-feed restatement markers. It
	// is server-side bookkeeping about the control schema itself: the node has
	// no concept of it, so naming it in internal/store/orgpush.go would be both
	// nonsensical and a boundary violation. Pinned as a fixed expected member
	// by TestForbiddenOrgControlPlaneTablesExpectedSet.
	"control_schema_data_applied",
	// Agent Access P1 identity wave (server migration 164 / PG lineage 0030,
	// docs/plans/agent-access-implementation-plan-2026-09-23.md §3.1/§3.4
	// item 7). Nine CONTROL tables (the org STS key ring, the agent registry,
	// per-device / workload credentials and their fetched-key thumbprints, the
	// revocation authority + per-jti denylist, the settings singleton and the
	// two SHARED replay stores) and one DATA table (the token issuance log).
	// All ten are SERVER-ONLY with no agent pair: a node authenticates TO the
	// STS, it never pushes identity, credential, key-ring or issuance state on
	// the node -> server wire, so naming any of them in orgpush.go would be
	// both nonsensical and a boundary violation. agent_credential carries
	// secret_hash (argon2id) and agent_signing_key a private-key secretref.
	// Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"agent_signing_key",
	"agent_definition",
	"agent_credential",
	"agent_credential_key",
	"agent_invalidation_state",
	"agent_token_revocation",
	"agent_access_settings",
	"actor_assertion_replay",
	"dpop_replay",
	"agent_token_issuance",
	// Agent Access P2 registry + policy wave (server migration 165 / PG
	// lineage 0031, docs/plans/agent-access-implementation-plan-2026-09-23.md
	// §3.1/§3.4). Seven CONTROL tables owned by internal/mcpgw/regstore: the
	// MCP server registry (upstream credential refs, persisted drift state),
	// its approved snapshots (tool lists + schema hashes), the virtual
	// servers and their members, the grant table, the four-eyes publication
	// ledger and the org API-key model (secret_hash). All seven are
	// SERVER-ONLY with no agent pair: a node calls the gateway, it never
	// pushes registry, grant, publication or key state on the node -> server
	// wire, so naming any of them in orgpush.go would be both nonsensical
	// and a boundary violation. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"mcp_server",
	"mcp_server_snapshot",
	"mcp_virtual_server",
	"mcp_virtual_server_member",
	"mcp_grant",
	"mcp_policy_publication",
	"mcp_api_key",
	// Agent Access P3 audit + data-plane wave (server migration 166 / PG
	// lineage 0032, docs/plans/agent-access-implementation-plan-2026-09-23.md
	// §3.1/§3.4/§9.4/§9.5). Two CONTROL tables owned by internal/mcpgw/
	// auditlease (the ingress-seq allocator head + the durable replica
	// leases) and seven DATA tables: the ONE per-org hash chain
	// (mcp_audit_chain_head / mcp_decision with its L2 args_full /
	// mcp_audit with its L2 result_full, error_full, elicitation_full), the
	// gateway-minted task binding, the SIEM export checkpoint, and the two
	// managed-node INGEST tables (mcp_node_activity_daily aggregate +
	// mcp_node_decision_event per-call, which carry user_id / machine_fp
	// and the L2 payloads). All nine are SERVER-ONLY with no agent pair:
	// the node's own relay chain is mcp_relay_record (forbiddenCacheTables
	// when the P4 node wave lands) and the ingest pair is written by
	// internal/orgserver/ingest FROM the push - a node never names the
	// server's tables on the node -> server wire, so naming any of them in
	// orgpush.go would be both nonsensical and a boundary violation.
	// (mcp_audit is ALSO a node-local table name - agent migration 030 -
	// already in forbiddenCacheTables; both sentinels forbid it, which is
	// harmless and intended: the same name is server-only here and
	// node-local there.) Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"mcp_audit_chain_head",
	"mcp_decision",
	"mcp_audit",
	"mcp_audit_seq_allocator",
	"mcp_audit_seq_lease",
	"mcp_task_binding",
	"siem_export_cursor",
	"mcp_node_activity_daily",
	"mcp_node_decision_event",
	// Agent Access P5-wave group A (server migrations 167-170 / PG lineage
	// 0033-0036, docs/plans/agent-access-implementation-plan-2026-09-23.md
	// §3.1/§3.4/§9.4/§11.8-§11.10). Thirteen CONTROL tables, all
	// SERVER-ONLY with no agent pair: the P5 vault (the org/service
	// upstream credential, the forward_idp custody artifact and the
	// per-user OAuth connection - each a sealed secretref + per-record
	// wrapped DEK - and the single-use connect attempt with its state hash
	// and sealed PKCE verifier), the P5b OAuth AS lifecycle (hashed codes,
	// the CIMD cache, DCR registrations with hashed client secrets, the
	// refresh family + per-generation token hashes), the P7b OBO trust
	// registration + subject_token replay store, and the P6a parked
	// approval request (request digest + redacted preview) + the MCP quota
	// reservation. Credential / vault / authorization state never crosses
	// the node -> server wire. Pinned as fixed expected members by
	// TestForbiddenOrgControlPlaneTablesExpectedSet.
	"mcp_upstream_credential",
	"agent_idp_artifact",
	"mcp_user_connection",
	"mcp_connection_attempt",
	"oauth_authz_code",
	"oauth_client_cache",
	"oauth_client_registration",
	"oauth_refresh_family",
	"oauth_refresh_token",
	"agent_trust_issuer",
	"subject_token_replay",
	"mcp_approval_request",
	"mcp_quota_reservation",
	// Agent Access P11 (server migration 172 / PG lineage 0038): the
	// shadow-MCP discovery queue. It is INGESTED from the node's
	// MCPInventoryRow / GuardPinRow wire rows but is itself an org-side
	// CONTROL table (the diff against the registry + adopt / dismiss
	// state); the node never holds it, so orgpush.go must never name it.
	"mcp_discovery_candidate",
	// Commit ownership (server migration 186 / PG lineage 0052, lane F-PROJ):
	// the org landing tables for the CommitOwnershipRow wire. Data-plane
	// rather than control-plane, but the same rule holds: they exist only on
	// the org server, the node composes the wire through
	// store.SelectCommitOwnershipRows (commitownersummary.go), and orgpush.go
	// must never name them. TestCommitOwnershipWireCarriesNoAuthorOrPath is
	// the end-to-end seeded-value pin.
	"commit_ownership",
	"commit_ownership_contributors",
	// Delivery (server migration 236 / PG lineage 0103, lane COMMITPR): the
	// org landing tables for the DeliveryDayRow / PullRequestRow wire. Data
	// plane, server-only; the node composes the wire through
	// internal/store/deliverysummary.go, and orgpush.go must never name them.
	"delivery_daily",
	"org_pull_requests",
	// Sandbox posture (server migration 243 / PG lineage 0110, lane
	// sbx-p1a2): the org landing tables for the SandboxPostureRow /
	// SandboxCapabilityRow wire. Server-only; the node composes the wire
	// through internal/store/sandboxposture.go.
	"sandbox_posture_days",
	"sandbox_node_capability",
	// Sandbox egress refusal counts (server migration 314 / PG lineage 0184,
	// audit CG-15): the org landing table for SandboxEgressRefusalDayRow.
	// Server-only; the node composes the wire through
	// internal/store/sandboxegress_org.go.
	"sandbox_egress_refusal_days",
	// Org stored-cost re-price (server migration 187 / PG lineage 0053, lane
	// G-REPRICE): the org admin's re-price run record and its per-row change
	// log. Server-only; the node has its own node-local pair (agent 145) and
	// orgpush.go must never name either.
	"org_reprice_runs",
	"org_reprice_changes",
	// Vendor connections (server migration 209 / PG lineage 0076, enterprise
	// vendor API lane F4): the tenancy and binding model (CONTROL) and the
	// runner's run and watermark records (DATA). Server-only: the org server
	// polls vendors itself, a node never holds a vendor admin credential or
	// a vendor connection, and orgpush.go must never name any of them.
	"org_vendor_accounts",
	"org_vendor_auth_bindings",
	"org_vendor_surface_bindings",
	"org_vendor_inbound_bindings",
	"org_vendor_surface_ownership",
	"org_vendor_claims",
	"org_vendor_runs",
	"org_vendor_run_supplies",
	"org_vendor_watermarks",
	// Observation foundations and projection / receipt schema (server
	// migrations 211 / 212, lanes F5 / F6): the vendor resource graph, its
	// change log, identity aliases and suggestions, daily health, manual
	// upload sagas, control projections, validation receipts, model maps and
	// fanout plans. All server-only.
	"org_vendor_identity_aliases",
	"org_vendor_upload_intents",
	"org_vendor_snapshot_manifests",
	"org_vendor_resource_observations",
	"org_vendor_edge_observations",
	"org_vendor_resources",
	"org_vendor_resource_edges",
	"org_vendor_resource_changes",
	"org_vendor_identity_suggestions",
	"org_vendor_health_daily",
	"org_vendor_upload_batches",
	"org_vendor_control_projections",
	"org_vendor_validation_receipts",
	"org_vendor_validation_transitions",
	"org_vendor_model_maps",
	"org_vendor_fanout_plans",
	// G3..G6 (server migrations 215-218, lane F10): usage retractions,
	// aggregate facts, held vendor identities, vendor audit events,
	// snapshots, the inbound replay ledger and the display source policy.
	// All server-only.
	"org_vendor_retractions",
	"org_vendor_facts",
	"org_vendor_held_identities",
	"org_vendor_audit_events",
	"org_vendor_snapshots",
	"org_vendor_replay",
	"org_vendor_source_policy",
	// Cloud-agents arc, lane CA-C3 (server migration 303 / PG 0173): the org
	// vendor-connection projection of cloud sessions (vendor ids, a vendor
	// identity, the member it resolved to). Server-only.
	"org_cloud_session_projections",
	// G7 (server migration 223, lane L12): spend approval thresholds,
	// conversions, comparison reports (member ids, held identities, per-member
	// values) and approvals. All server-only.
	"org_vendor_spend_thresholds",
	"org_vendor_conversions",
	"org_vendor_comparisons",
	"org_vendor_spend_approvals",
	// Vendor control writes (server migration 225, lane L14): the kill
	// switch, proposals (member ids, vendor identities) and their audit
	// events. All server-only.
	"org_vendor_control_write_switch",
	"org_vendor_control_writes",
	"org_vendor_control_write_events",
	// Vendor content (server migration 226, lane L15): the per-connection
	// consent history and the content items themselves (prompts,
	// responses, transcripts). All server-only.
	"org_vendor_content_consents",
	"org_vendor_content",
}

// TestForbiddenOrgControlPlaneTablesExpectedSet is the NON-GAMEABLE membership
// pin for the org control-plane sentinel, mirroring
// TestForbiddenGatewayTablesExpectedSet. Merely APPENDING a name to
// forbiddenOrgControlPlaneTables is trivially removable without any test
// failing, which would silently stop TestSelectUnpushedSinceExcludesCacheTables
// from guarding that name out of orgpush.go. A FIXED expected subset must
// therefore remain present: deleting any of these names fails HERE, by name.
func TestForbiddenOrgControlPlaneTablesExpectedSet(t *testing.T) {
	want := []string{
		"org_agent_policy_attributes",
		"org_intelligence_config",
		"org_fleet_upgrade_cohorts",
		"org_fleet_remote_config",
		"org_deployment_wizard",
		// WS3 insight harness (server migration 045). org_secret in particular
		// is a SEALED CREDENTIAL store: dropping it from the sentinel would
		// stop the orgpush.go guard from ever noticing a seam that named it.
		"org_llm_provider",
		"org_secret",
		"insight_run_step",
		// Fleet mutation attribution (server migration 046): the audit trail
		// of who reconfigured which collector. Server-only control-plane
		// state with no agent counterpart.
		"org_fleet_config_events",
		// WS2 guided setup (server migration 047): the settings store whose
		// secret_ref column points at a SEALED org_secret body. Dropping it
		// from the sentinel would stop the orgpush.go guard from ever noticing
		// a seam that named it.
		"org_setup_setting",
		// WS1.4 project labels (server migration 048): org-side display names
		// for hashed project identities. Dropping it from the sentinel would
		// stop the orgpush.go guard from noticing a seam that tried to carry
		// project naming — in either direction — on the agent wire.
		"org_project_labels",
		// Dashboard-registered external harness agents (server migration
		// 049): org control-plane configuration with no agent counterpart.
		// Dropping it from the sentinel would stop the orgpush.go guard from
		// noticing a seam that named it.
		"org_external_agent",
		// Datasets foundation (server migration 051): dataset membership is
		// org-side only; dropping these would stop the guard from noticing a
		// seam that tried to carry dataset state on the agent wire.
		"org_dataset",
		"org_dataset_item",
		// LLM jobs + annotations (server migration 052): job/annotation
		// state stays org-side; dropping these would stop the guard from
		// noticing a seam that named them.
		"org_trace_annotation",
		"org_llm_job",
		"org_llm_job_item",
		// Plane A scores and evals (server 330-333, lane B7).
		"org_dataset_snapshot",
		"org_dataset_snapshot_item",
		"org_eval_online_rule",
		"org_review_queue",
		"org_review_item",
		"org_review_assignment",
		// Guardrailed chat (server migration 053): transcripts stay
		// org-side; dropping these would stop the guard from noticing a
		// seam that named them.
		"org_chat_session",
		"org_chat_message",
		// Plane-B admin intelligence (server migrations 057-059): the
		// content-adjacent trio — job state, per-item results, and session
		// annotations are the rows an LLM's output lands in. Dropping any of
		// them from the sentinel would stop the orgpush.go guard from
		// noticing a seam that named them.
		"org_coding_job",
		"org_coding_job_item",
		"org_coding_annotation",
		// Self-Improving Policy Plane P0 (server migrations 061-065): the
		// content-bearing pair. org_policy_evolution_proposal holds the
		// candidate proposed_body + LLM-authored rationale, and
		// org_policy_evolution_decision holds the approve/reject reason —
		// the rows an LLM's output lands in. Dropping either from the
		// sentinel would stop the orgpush.go guard from noticing a seam
		// that named them.
		"org_policy_evolution_proposal",
		"org_policy_evolution_decision",
		// Enterprise-Managed Tenancy machine-identity binding (server
		// migration 074, Arc 4 P6a). managed_node binds one managed node to
		// one machine; the fingerprint rides the bearer-authed managed-bind
		// REQUEST, never the node->server push wire, so naming it in
		// orgpush.go would be both nonsensical and a boundary violation.
		"managed_node",
		// The managed-integrity probe posture store (server migration 075,
		// Arc 4 P6b). managed_integrity records per-(org, machine)
		// tamper-evidence; the signal rides the bearer-authed
		// managed-integrity REQUEST, never the node->server push wire. Same
		// boundary as managed_node.
		"managed_integrity",
		// The IdP device-code enrolment pairing store (server migration 076,
		// ACP-P6c). idp_enrol_requests holds the device-code digest and the
		// user code of an in-flight pairing — enrolment-credential-adjacent
		// material that rides the two agent-facing idp-enrol REQUESTS, never
		// the node->server push wire. Dropping it from the sentinel would stop
		// the orgpush.go guard from noticing a seam that named it.
		"idp_enrol_requests",
		// Team Project Identity Mapping Wave B (server migration 083): the
		// admin-authored project-grouping pair. org_projects names a team-
		// level project identity (with an optional client_label);
		// org_project_members maps hash-derived ids onto it. Dropping either
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that tried to carry project grouping/naming on the agent wire.
		"org_projects",
		"org_project_members",
		// Org Dashboard RBAC Wave A (server migration 084): the role/
		// permission model (org_roles, org_role_permissions,
		// org_member_roles) plus its bootstrap-marker
		// (org_role_bootstrap_applied). Dropping any of these from the
		// sentinel would stop the orgpush.go guard from noticing a seam that
		// tried to carry role/permission grant state on the agent wire.
		"org_roles",
		"org_role_permissions",
		"org_member_roles",
		"org_role_bootstrap_applied",
		// Product-posture plane (server migration 112, P2b): the posture
		// singleton, the signed grant-replacement issuance ledger, the per-node
		// fleet-ACK registry, and the org-side collection toggle. Dropping any of
		// these from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named them.
		"org_product_posture",
		"org_grant_replacement",
		"org_grant_replacement_ack",
		"org_collection_settings",
		// Plane B mode-switch plane (server migration 114, P5b).
		"org_plane_b_mode",
		"org_plane_b_mode_ack",
		"org_plane_b_preflight",
		// Break-glass credential-lease ledger (server migration 115, P6).
		"break_glass_request",
		"break_glass_lease",
		// Recorded-acceptance ledger (server migration 116, P6, HG10).
		"org_plane_b_acceptance",
		// Project Identity Resolver v2 server-only tables (server migration
		// 122). Dropping any of these from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"project_identity_signals",
		"org_repositories",
		"org_project_rules",
		"org_identity_settings",
		// Org budget enforcement + token display server-only tables (server
		// migration 125). Dropping either from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"org_display_settings",
		"org_budget_policy_version",
		// The org AI tool settings policy and managed nodes' applied state
		// (server migrations 203 / 204). Dropping either from the sentinel
		// would stop the orgpush.go guard from noticing a seam that named it.
		"org_agent_config_policies",
		"org_agent_config_state",
		// Enterprise Update Management server-only tables (server migration
		// 127). Dropping any of these from the sentinel would stop the
		// orgpush.go guard from noticing a seam that named them.
		"org_update_manifests",
		"org_update_artifacts",
		"org_update_rollouts",
		"org_node_versions",
		// Server migration 220 (modular packaging plan 5.6.1).
		"org_update_release_indexes",
		"org_update_publications",
		// The node budget posture board (server migration 130). Dropping it
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named it.
		"org_node_budget_posture",
		// Org Dashboard Enterprise Sign-In server-only tables (server
		// migration 128). org_auth_rail_setting in particular carries
		// secret_ref, pointing at a SEALED org_secret body: dropping it from
		// the sentinel would stop the orgpush.go guard from ever noticing a
		// seam that named it.
		"org_auth_settings",
		"org_auth_rail_setting",
		"org_auth_group_role_map",
		"org_auth_failures",
		// Enterprise pricing server-only tables (server migration 136). The
		// org's authored per-model rates and their monotonic document
		// version: authored on the SERVER and distributed server -> node on a
		// signed rail, never pushed. Dropping either from the sentinel would
		// stop the orgpush.go guard from noticing a seam that named them.
		"org_model_prices",
		"org_pricing_version",
		// The pricing-FEED importer bookkeeping (server migration 144):
		// control-plane, server-side only, distributed to nodes only on the
		// signed pricing rail — never pushed node -> server.
		"org_pricing_feed_state",
		// The importer's apply mode + grade threshold (server migration 191).
		"org_pricing_feed_settings",
		// The Postgres-only one-shot DATA marker for controlstore/schema.go's
		// retrofits: server-side bookkeeping the node has no concept of.
		"control_schema_data_applied",
		// Agent Access P1 (server migration 164): the nine CONTROL tables and
		// the issuance-log DATA table. Identity, credentials (secret_hash),
		// the signing key ring (private secretref), revocation and replay
		// state are server-side authorization state; dropping any of these
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named them.
		"agent_signing_key",
		"agent_definition",
		"agent_credential",
		"agent_credential_key",
		"agent_invalidation_state",
		"agent_token_revocation",
		"agent_access_settings",
		"actor_assertion_replay",
		"dpop_replay",
		"agent_token_issuance",
		// Agent Access P2 (server migration 165): the seven regstore CONTROL
		// tables. Registry, grant, publication and API-key (secret_hash)
		// state is server-side authorization state; dropping any of these
		// from the sentinel would stop the orgpush.go guard from noticing a
		// seam that named them.
		"mcp_server",
		"mcp_server_snapshot",
		"mcp_virtual_server",
		"mcp_virtual_server_member",
		"mcp_grant",
		"mcp_policy_publication",
		"mcp_api_key",
		// Agent Access P3 (server migration 166): the ONE-chain audit tables
		// (L2 request / result payloads on hashed rows), the allocator +
		// lease CONTROL pair, the task binding, the SIEM checkpoint and the
		// two managed-node ingest tables (subject / device identifiers +
		// L2 payloads). Dropping any of these from the sentinel would stop
		// the orgpush.go guard from noticing a seam that named them.
		"mcp_audit_chain_head",
		"mcp_decision",
		"mcp_audit",
		"mcp_audit_seq_allocator",
		"mcp_audit_seq_lease",
		"mcp_task_binding",
		"siem_export_cursor",
		"mcp_node_activity_daily",
		"mcp_node_decision_event",
		// Agent Access P5-wave group A (server migrations 167-170): the
		// vault (sealed credentials + per-record DEKs), the OAuth AS
		// lifecycle (hashed codes / secrets / refresh tokens), the OBO trust
		// pair and the parked approval + quota reservation. Dropping any of
		// these from the sentinel would stop the orgpush.go guard from
		// noticing a seam that named them.
		"mcp_upstream_credential",
		"agent_idp_artifact",
		"mcp_user_connection",
		"mcp_connection_attempt",
		"oauth_authz_code",
		"oauth_client_cache",
		"oauth_client_registration",
		"oauth_refresh_family",
		"oauth_refresh_token",
		"agent_trust_issuer",
		"subject_token_replay",
		"mcp_approval_request",
		"mcp_quota_reservation",
		// Agent Access P11 (server migration 172): the shadow-MCP discovery
		// queue.
		"mcp_discovery_candidate",
		// Commit ownership (server migration 186, lane F-PROJ).
		"commit_ownership",
		"commit_ownership_contributors",
		// Delivery (server migration 236, lane COMMITPR).
		"delivery_daily",
		"org_pull_requests",
		// Sandbox posture (server migration 243, lane sbx-p1a2).
		"sandbox_posture_days",
		"sandbox_node_capability",
		// Org stored-cost re-price (server migration 187, lane G-REPRICE).
		"org_reprice_runs",
		"org_reprice_changes",
		// Vendor connections (server migration 209, enterprise vendor API
		// lane F4). org_vendor_auth_bindings holds store: references to
		// SEALED vendor admin credentials.
		"org_vendor_accounts",
		"org_vendor_auth_bindings",
		"org_vendor_surface_bindings",
		"org_vendor_inbound_bindings",
		"org_vendor_surface_ownership",
		"org_vendor_claims",
		"org_vendor_runs",
		"org_vendor_run_supplies",
		"org_vendor_watermarks",
		// Observation foundations and projection / receipt schema (server
		// migrations 211 / 212). org_vendor_identity_aliases maps vendor
		// identities onto org members.
		"org_vendor_identity_aliases",
		"org_vendor_upload_intents",
		"org_vendor_snapshot_manifests",
		"org_vendor_resource_observations",
		"org_vendor_edge_observations",
		"org_vendor_resources",
		"org_vendor_resource_edges",
		"org_vendor_resource_changes",
		"org_vendor_identity_suggestions",
		"org_vendor_health_daily",
		"org_vendor_upload_batches",
		"org_vendor_control_projections",
		"org_vendor_validation_receipts",
		"org_vendor_validation_transitions",
		"org_vendor_model_maps",
		"org_vendor_fanout_plans",
		// G3..G6 (server migrations 215-218, lane F10). Held identities
		// and facts carry vendor identities and per-member values.
		"org_vendor_retractions",
		"org_vendor_facts",
		"org_vendor_held_identities",
		"org_vendor_audit_events",
		"org_vendor_snapshots",
		"org_vendor_replay",
		"org_vendor_source_policy",
		// Cloud-agents arc, lane CA-C3 (server migration 303).
		"org_cloud_session_projections",
		// G7 (server migration 223, lane L12).
		"org_vendor_spend_thresholds",
		"org_vendor_conversions",
		"org_vendor_comparisons",
		"org_vendor_spend_approvals",
		// Vendor control writes (server migration 225, lane L14).
		"org_vendor_control_write_switch",
		"org_vendor_control_writes",
		"org_vendor_control_write_events",
		// Vendor content (server migration 226, lane L15).
		"org_vendor_content_consents",
		"org_vendor_content",
		// Per-member machine keys (server migration 229, REVIEW-4 P4-06).
		"org_member_machine_keys",
		// Admin and developer messaging (server migration 237, T-854).
		"org_message_settings",
		"org_message_threads",
		"org_messages",
		"org_message_attachments",
		"org_message_delivery",
		"org_message_admin_reads",
		"org_message_suggestions",
		// Cloud-agents arc: ship tokens (server migration 301) and the Rail S
		// switch (server migration 306, CLOUDSESS-13).
		"org_cloud_session_tokens",
		"org_cloud_session_settings",
		// My profile: member notification preferences (server migration 310)
		// and the per-session sign-in registry (311).
		"org_member_notification_prefs",
		"org_auth_sessions",
		// Per-node agent keys (server migration 312, lane fl32).
		"org_member_node_keys",
		// In-flight OIDC sign-in transactions (server migration 313, B5).
		"org_auth_pending_txns",
		// The attach grant's single-use record (server migration 316, lane 8).
		"org_attach_grant_uses",
		// The SDK key grant's single-use record (server migration 392, L4).
		"org_sdk_key_grant_uses",
		// The Plane A gateway meter and shared budget (server 325, PG 0489,
		// 0490; lane B1).
		"gateway_usage_monthly",
		"gateway_throttle_budget",
		// The hosted AI gateway's request meter (server 390, PG 0571; L4).
		"aigw_usage_monthly",
		// The prompt registry (server migration 337, Plane A W3-3 lane B8).
		"org_prompt_versions",
		"org_prompt_labels",
		"org_prompt_label_moves",
		// Prompt rollout approval (server migration 344, Plane A W5-3 lane C8).
		"org_prompt_proposals",
		"org_prompt_settings",
		// Managed-SaaS pooled host state (org PostgreSQL 0220, 0240, 0261,
		// 0265, 0295).
		"tenant_hosts",
		"tenant_job_state",
		"tenant_lifecycle",
		"tenant_keys",
		// The availability layer (org PostgreSQL 0300, M7a.6).
		"tenant_entitlements",
		"platform_availability",
		"org_availability_applied",
		// The org admin's own module switches (org PostgreSQL 0450, wave 17).
		"org_component_choice",
		"apply_parked",
		// Quotas and capacity admission (org PostgreSQL 0318, M7a.3).
		"org_quota_state",
		"platform_capacity",
		"platform_capacity_events",
		// The mounted host API (org PostgreSQL 0315).
		"host_api_calls",
		"host_api_nonces",
		"host_api_idempotency",
		// The platform AI ledger, consent at login, digest mail (0337, M9).
		"platform_intel_spend",
		"platform_intel_holds",
		"org_intel_login_consent",
		"org_intel_digest_mail",
		// The org purge's run record (0470, M7a.1).
		"org_purge_runs",
	}
	have := make(map[string]struct{}, len(forbiddenOrgControlPlaneTables))
	for _, n := range forbiddenOrgControlPlaneTables {
		have[n] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("expected server-side control-plane table %q is missing from forbiddenOrgControlPlaneTables — "+
				"the privacy sentinel would no longer guard it out of orgpush.go", w)
		}
	}
}

// TestForbiddenGatewayTablesExpectedSet is the NON-GAMEABLE membership pin: a
// FIXED expected set (gateway_wal + the four gateway ingest tables the P1-2/P1-10
// retention tier touches) must be a SUBSET of forbiddenGatewayTables. Merely
// APPENDING a name is removable without a failure (the original TestGatewayWAL…
// only checked gateway_wal), so REMOVING any of these names from
// forbiddenGatewayTables fails HERE — which in turn would stop
// TestSelectUnpushedSinceExcludesCacheTables from guarding that name in
// orgpush.go. Mut 10 (drop gateway_span from forbiddenGatewayTables) fails this
// assertion by name.
func TestForbiddenGatewayTablesExpectedSet(t *testing.T) {
	want := []string{
		"gateway_wal",
		"gateway_resource",
		"gateway_scope",
		"gateway_span",
		"gateway_trace",
		// Plane B AI Gateway v1 (server migrations 108-111): removing any of
		// these from forbiddenGatewayTables fails HERE, which in turn would stop
		// TestSelectUnpushedSinceExcludesCacheTables from guarding the name out
		// of orgpush.go.
		"gw_virtual_key",
		"gw_revocation_watermark",
		"gw_upstream",
		"gw_budget_cap",
		"gw_reservation",
		"gw_reservation_scope",
		"gw_audit",
		// Stateless-collectors durable-log terminal-quarantine table (server
		// migration 136): removing it from forbiddenGatewayTables fails HERE,
		// which in turn would stop TestSelectUnpushedSinceExcludesCacheTables
		// from guarding the name out of orgpush.go.
		"ingest_quarantine",
		"ingest_apply_receipt",
	}
	have := make(map[string]struct{}, len(forbiddenGatewayTables))
	for _, n := range forbiddenGatewayTables {
		have[n] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			t.Errorf("expected server-side gateway table %q is missing from forbiddenGatewayTables — "+
				"the privacy sentinel would no longer guard it out of orgpush.go", w)
		}
	}
}

// TestObsEgressTierContract pins the T8 egress org tier's shape (org-parity
// W5.3, 2026-08-24 — the conscious change the retired
// TestObsEgressHasNoOrgProviderSeam sentinel demanded: G22 design §8 deferred
// an egress org tier to "its own wire shape + share key + sentinel update",
// which is exactly what shipped). Structurally: the tier is reachable ONLY
// through the store.ObsOrgProviders.Egress func seam (never SQL against
// obs_egress_decisions inside orgpush.go — the literal table-name sentinel
// above still enforces that), and it is gated by its OWN node-side share key
// ShareOptions.ObsEgress (default false; zero value ships nothing). The
// behavioral gating — absent without the opt-in, Tenant/User stripped under
// !shipsRawContent() — is pinned by TestObsEgressComposeGating in
// internal/store/orgpush_obs_test.go.
func TestObsEgressTierContract(t *testing.T) {
	t.Parallel()
	pt := reflect.TypeOf(store.ObsOrgProviders{})
	if _, ok := pt.FieldByName("Egress"); !ok {
		t.Errorf("store.ObsOrgProviders lost its Egress provider func — the T8 egress tier must be composed through the func seam, never inline SQL in orgpush.go")
	}
	st := reflect.TypeOf(store.ShareOptions{})
	f, ok := st.FieldByName("ObsEgress")
	if !ok {
		t.Fatalf("store.ShareOptions lost ObsEgress — the T8 egress tier must be gated by its own node-side share key ([org_client.share.obs].egress), default false")
	}
	if f.Type.Kind() != reflect.Bool {
		t.Errorf("ShareOptions.ObsEgress is %s, want bool (a node-side opt-in flag, never a server-driven value)", f.Type)
	}
	if (store.ShareOptions{}).ObsEgress {
		t.Errorf("ShareOptions zero value has ObsEgress=true — the egress tier must default OFF")
	}
}

// TestSelectUnpushedSinceExcludesCacheTables is the structural
// privacy sentinel for the cachetrack arc. Walks every string
// literal in internal/store/orgpush.go (the single SQL seam
// for the push path per CLAUDE.md "Single SQL seam" Teams
// invariant) and fails if any contains a cachetrack table name.
//
// Strict-source check rather than data-side: catches the
// regression at the moment someone writes the JOIN/SELECT,
// before any row even exists. Pairs with
// TestPushPayloadCarriesNoContent which catches the
// alternative-path case (someone exports cache_* via a separate
// seam).
//
// orgpush.go also contains a long list of `*_hash` allowed
// columns — the regex deliberately matches the table NAMES, not
// "cache" substrings — so future "cache_read_hash" / "cache_*"
// column names on api_turns don't trigger a false positive.
func TestSelectUnpushedSinceExcludesCacheTables(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "store", "orgpush.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, name := range forbiddenCacheTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden cachetrack table name %q appears in string literal — "+
					"cache_* tables are NODE-LOCAL per spec §11; they MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		for _, name := range forbiddenGatewayTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden server-side gateway table name %q appears in string literal — "+
					"gateway_wal is a SERVER-ONLY ingest queue (P0-9 durable-edge WAL); it MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		for _, name := range forbiddenOrgControlPlaneTables {
			if strings.Contains(lit.Value, name) {
				pos := fset.Position(lit.Pos())
				t.Errorf("%s:%d: forbidden org control-plane table name %q appears in string literal — "+
					"P1-4/P1-7/P1-9 control-plane tables are SERVER-ONLY and MUST NOT enter the push wire path",
					pos.Filename, pos.Line, name)
			}
		}
		return true
	})

	// Cold storage is a SECOND DATABASE FILE, so a forbidden-name scan alone
	// would not catch the way it could actually leak: orgpush.go importing
	// the archive packages and reading the archive handle directly, never
	// naming a table in a literal because internal/archivestore does that for
	// it. The single-database assumption the whole sentinel rests on is worth
	// asserting outright.
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range []string{
			"github.com/marmutapp/superbased-observer/internal/archivestore",
			"github.com/marmutapp/superbased-observer/internal/archivesvc",
		} {
			if path == bad {
				pos := fset.Position(imp.Pos())
				t.Errorf("%s:%d: orgpush.go imports %q — the push seam must read the ONE hot "+
					"database it is given; cold storage (~/.observer/archive.db) holds the same "+
					"node-local rows, only older, and must never become a wire surface",
					pos.Filename, pos.Line, bad)
			}
		}
	}
}

// wireBackedTables are the agent tables whose rows have a wire surface in
// orgcontract, so the push seam legitimately reads them. They are the reason a
// table may be absent from forbiddenCacheTables.
var wireBackedTables = map[string]string{
	"actions":                   "ActionRow",
	"api_turns":                 "APITurnRow",
	"projects":                  "ProjectRow (joined for the session's hashes)",
	"sessions":                  "SessionRow",
	"token_usage":               "TokenUsageRow",
	"otel_content":              "OTelContentRow (content gated by shipsRawContent)",
	"guard_events":              "GuardEventRow (verdict prose gated in Go)",
	"task_items":                "SessionTaskRow, under task_detail",
	"task_transitions":          "SessionTaskTransitionRow, under task_detail",
	"tool_account_observations": "SessionToolAccountRow, under tool_account_detail",
}

// pushMachineryTables are named by orgpush.go itself and could not be added to
// the forbidden list without breaking the seam. They carry no captured data:
// org_push_log is the cursor ledger, schema_meta the key-value migration/meta
// store.
var pushMachineryTables = map[string]string{
	"org_push_log": "the push cursor ledger the seam advances",
	"schema_meta":  "key-value migration + meta store",
}

// receivedOrgStateTables hold the org's OWN roster/enrolment coming back to the
// node. They are deliberately NOT in the forbidden list because the sentinel is
// about node-captured data crossing outward, and these are the server's own
// bytes; the enrolment identity in them is what the push is authenticated AS.
var receivedOrgStateTables = map[string]string{
	"org_enrolment":    "this node's enrolment record",
	"org_members":      "received org roster cache",
	"org_teams":        "received org roster cache",
	"org_team_members": "received org roster cache",
	"org_project_team": "received org project↔team mapping cache",
}

// TestForbiddenCacheTablesCoversEveryNodeLocalTable keeps the PRIV-3/PRIV-4
// enumeration honest for every FUTURE migration (codebase audit 2026-09-16).
//
// The seventeen tables PRIV-3/4 found had simply never been looked at: the
// forbidden list grew one entry at a time as each feature landed, so a table
// whose author did not think to add it got no source-level protection at all,
// and nothing said so. This test closes that by DERIVING the requirement:
// every CREATE TABLE in internal/db/migrations must be accounted for as either
// (a) wire-backed, (b) push machinery, (c) received org state, (d) a transient
// migration-rebuild table, or (e) present in forbiddenCacheTables.
//
// A new migration that adds a node-local table therefore fails here until
// someone writes down which it is — which is exactly the review the sentinel
// was always meant to force.
func TestForbiddenCacheTablesCoversEveryNodeLocalTable(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("..", "..", "internal", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	// `CREATE TABLE [IF NOT EXISTS] name (` — the only shape the agent
	// lineage uses.
	re := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["` + "`" + `]?([a-z0-9_]+)`)
	forbidden := make(map[string]bool, len(forbiddenCacheTables))
	for _, n := range forbiddenCacheTables {
		forbidden[n] = true
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range re.FindAllStringSubmatch(string(body), -1) {
			seen[strings.ToLower(m[1])] = true
		}
	}
	if len(seen) < 50 {
		t.Fatalf("only %d tables parsed out of the migrations dir — the scan is broken and this test would be vacuous", len(seen))
	}
	for name := range seen {
		switch {
		case forbidden[name]:
		case wireBackedTables[name] != "":
		case pushMachineryTables[name] != "":
		case receivedOrgStateTables[name] != "":
		case strings.HasSuffix(name, "_new"):
			// A migration's own table-rebuild scratch table, dropped by the
			// same migration that creates it. Never a live table.
		case strings.HasSuffix(name, "_fts") || strings.HasSuffix(name, "_fts_data") ||
			strings.HasSuffix(name, "_fts_idx") || strings.HasSuffix(name, "_fts_docsize") ||
			strings.HasSuffix(name, "_fts_config") || strings.HasSuffix(name, "_fts_content"):
			// FTS5 shadow tables, created by the virtual table, not by us.
		default:
			t.Errorf("agent table %q is in NEITHER forbiddenCacheTables nor any accounted-for set — "+
				"if it is node-local, add it to forbiddenCacheTables (that is the source-level rule that "+
				"stops it being added to orgpush.go by accident); if it has a wire row, add it to "+
				"wireBackedTables with the orgcontract type that carries it", name)
		}
	}
	// The inverse direction, so the list cannot rot: every forbidden AGENT
	// table name must still exist in the lineage. Names from other databases
	// (archive_*, the obs lineage, pre-registered codeintel tables) are
	// deliberately exempt — they are listed here precisely because they live
	// elsewhere and must stay unreachable.
	for _, n := range forbiddenCacheTables {
		if wireBackedTables[n] != "" {
			t.Errorf("%q is in BOTH forbiddenCacheTables and wireBackedTables — a table cannot be both", n)
		}
	}
}
