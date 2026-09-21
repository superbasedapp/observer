package govern

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// The CLOSED authority vocabulary a grant may carry (spec §2.4). Only
// AuthorityDashboardVisibility is CONSUMED in Phase 1a — the other three are
// declared because the vocabulary is part of the signed grant and must be
// stable across the phases that add their directive classes, and because a
// node must be able to display the authority it granted even for a class
// this build cannot yet act on.
//
// A token outside this set in a delivered grant is IGNORED and REPORTED
// (Effective.UnknownAuthority), never an enrolment failure: forward compat
// requires an older agent to enrol against a newer server that offered a
// token it has never heard of.
const (
	// AuthorityDashboardVisibility lets the org hide or read-only-lock node
	// dashboard pages and Settings sections. It grants NO read of node data.
	AuthorityDashboardVisibility = "dashboard.visibility"
	// AuthoritySettingsPin (Phase 1b) lets the org pin a closed set of
	// [config] keys — the `pinned` directive class.
	AuthoritySettingsPin = "settings.pin"
	// AuthorityCaptureRaise is RETIRED and PERMANENTLY INERT.
	//
	// It was declared in Phase 1a for a raise-only share merge. Phase 1b
	// reversed that direction (operator ruling R6): the organization may
	// LOWER a node's sharing or pin it at the level the node operator
	// already consented to, and may never raise it. A token whose NAME says
	// "raise" cannot survive as the token for a directive class that can
	// only lower, and it is already in the closed vocabulary of a shipped
	// build, so it cannot simply be renamed.
	//
	// It therefore stays in KnownAuthority for wire stability — an older
	// grant carrying it is not an enrolment failure, and the developer can
	// still read what their machine handed over — but it grants NOTHING.
	// Widening authority to capture.pin requires a fresh `observer enroll`,
	// which is a new node-side act. That is the design working as intended.
	AuthorityCaptureRaise = "capture.raise"
	// AuthorityCapturePin (Phase 1b) lets the org REDUCE, or lock at its
	// current level, what this machine shares. It can never increase it.
	AuthorityCapturePin = "capture.pin"
	// AuthorityFeatureLock (Phase 1b) lets the org force a feature subsystem
	// on or off — the `features` directive class, which is a compile-time
	// alias over `pinned`.
	AuthorityFeatureLock = "feature.lock"

	// The MANAGED-ONLY authority tokens (Enterprise-Managed Tenancy, Arc 4).
	// They are part of the closed vocabulary so a grant can carry them and a
	// node can READ them, but they are HONOURED ONLY when the node enrolled
	// under managed-class consent (ManagedConsent: a managed enrolment
	// token or an IdP-verified device-code enrolment). On an
	// individual / BYO node they are inert — HonoredAuthority strips them —
	// which is what keeps the "Never server-forced" guarantee intact for the
	// individual plane even if an older/mis-configured server put one in an
	// individual token's authority list. They are DECLARED here now (P1) for
	// wire stability; the directive classes that consume them ship in later
	// phases (P2 extraction / P3 enforcement).
	//
	// AuthorityEnforceRouting/Admission/Egress lift §R23 for a managed node:
	// they let the org body's enforcement `mode` be read instead of
	// structurally ignored. AuthorityExtractManaged is the sanctioned lift
	// of the retired capture.raise: it lets the org REMOTELY raise a managed
	// node's extraction tiers (the four body columns + node-local tiers),
	// which is structurally impossible on the individual plane.
	AuthorityEnforceRouting   = "enforce.routing"
	AuthorityEnforceAdmission = "enforce.admission"
	AuthorityEnforceEgress    = "enforce.egress"
	AuthorityExtractManaged   = "extract.managed"

	// AuthorityEnforceBudget is the fourth enforce.* sibling
	// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
	// §3.3c, wave W3a). It makes the ORG's spend cap authoritative on a
	// managed node: without it, an org budget delivered by
	// GET /api/agent/budget may only LOWER the node's own [guard.budget]
	// thresholds (govern.LowerFloat / LowerInt — the numeric analogue of
	// LowerBool, so an individual node's own tighter cap always survives);
	// with it, on a MANAGED node, the org's numbers and the org's enforcement
	// mode REPLACE the local ones, per the Arc-4 managed-tenancy ruling
	// (org-authoritative, enforce ON).
	//
	// It is managed-only exactly like its three siblings: HonoredAuthority
	// strips it on an individual / BYO node, so an individual node keeps
	// deciding its own numbers even if a mis-configured server puts this
	// token in an individual token's authority list.
	//
	// This is the §R23 enforcement-MODE axis, ORTHOGONAL to the
	// data-extraction posture split (teams posture vs ENTERPRISE posture /
	// EnterpriseGranted, design §5.3): the budget numbers are not content — a
	// cap is a number and a period — so distributing them names no
	// content-bearing column and does not touch the privacy sentinel. This
	// token governs only whose number wins, never what the node discloses.
	AuthorityEnforceBudget = "enforce.budget"

	// The HIGH-SENSITIVITY per-tier extraction authorities (Arc 4 P5f-h).
	// Unlike the umbrella extract.managed (which raises the headline tiers —
	// tool bodies, full traces, project folders, cache, routing, predictions),
	// each of these gates the RAISE of exactly ONE highest-sensitivity tier and
	// nothing else, so granting cache/routing extraction does NOT also unlock
	// the developer's source-symbol graph, process/eBPF trees, or terminal/
	// remote-audit activity. They are managed-only (ManagedAuthority) exactly
	// like extract.managed and inert on the individual plane. Each is consumed
	// by its own Effective.GrantsXxxExtraction predicate + a per-tier RaiseBool
	// row in cmd/observer's lowerShareOptions.
	//
	// AuthorityExtractCodeintel raises the codeintel_detail tier: the node's
	// code-intelligence index (codeintel_* — source symbol/import/call graph)
	// shipped ONLY as a content-free per (project-hash × language) count
	// aggregate (files/symbols/edges); never a symbol name, fqn, signature, or
	// raw path.
	AuthorityExtractCodeintel = "extract.codeintel"

	// AuthorityExtractProcess raises the process_detail tier: the node's
	// process-observability log (process_runs / process_events — the process/
	// eBPF trees) shipped ONLY as a content-free per (day × tool) run/exit/
	// duration count aggregate; never an exe path, argv, cwd, network body, or
	// any of the domain-separated hashes.
	AuthorityExtractProcess = "extract.process"

	// AuthorityExtractTerminal raises the terminal_detail tier: the node's
	// terminal-run + remote-access-audit logs (terminal_run / terminal_commands
	// / remote_audit — the launched-terminal and remote-control activity)
	// shipped ONLY as content-free count aggregates (per day×tool×kind terminal
	// runs/commands, and per day×kind×decision×principal remote-audit events);
	// never a command, a project/correlation/command hash, a session id, a peer
	// address, or a route. These tables are otherwise pinned entirely OUT of the
	// push wire (end-to-end never-ships tests); shipping this aggregate under a
	// SEPARATE explicit tier is the deliberate, reviewed reversal.
	AuthorityExtractTerminal = "extract.terminal"

	// AuthorityExtractTasks raises the task_detail tier (node session-detail
	// trickle-up W2): the node's session task/todo checklist (task_items /
	// task_transitions) shipped as per-item STATUS rows + status transitions.
	// The item PROSE (content / active_form / owner — the agent-authored work
	// plan) is a SECOND gate on top of this one (shipsRawContent()), so this
	// token alone discloses what a session's plan looked like STRUCTURALLY
	// (how many items, which finished, which vanished), never what it said.
	// STRICT like its codeintel/process/terminal siblings: the umbrella
	// extract.managed does NOT satisfy it — a work plan is a
	// highest-sensitivity surface and gets its own explicit consent (operator
	// decision D4).
	AuthorityExtractTasks = "extract.tasks"

	// AuthorityExtractToolAccounts raises the tool_account_detail tier (W3):
	// the node's vendor login observations (tool_account_observations) shipped
	// as binding enums + the opaque account_key + the observation time, so the
	// org can render "account changed / conflict / unknown" and count distinct
	// accounts. The raw identity (email / name / account_id) is a SECOND gate
	// on top of this one (shipsRawContent(), decision D2) — this token alone
	// never discloses a developer's vendor email. STRICT for the same reason
	// as extract.tasks: the umbrella never unlocks it (decision D4).
	AuthorityExtractToolAccounts = "extract.tool_accounts"

	// AuthorityExtractIntel raises the org-served Cloud Intelligence RESULT
	// rail (org-served-cloud-intelligence plan §2.1/W5): the node's node-authored
	// [intelligence].org_enrichment gate (config default false) is RAISED on a
	// managed node that holds this token, so the node PULLS the org server's own
	// derived per-session enrichment results beside the pricing/budget rails. It
	// authorizes nothing that SHIPS — the rail is a request/response PULL of the
	// org's product coming back to the node, never evidence egress. STRICT like
	// its codeintel/process/terminal/tasks/tool_accounts siblings: the umbrella
	// extract.managed does NOT satisfy it (GrantsIntelExtraction uses the strict
	// grantsExtraction gate), because org enrichment is a high-sensitivity
	// decision that gets its own explicit per-tier consent. It IS a member of
	// the extract.* family, so EnterpriseAuthoritySet() sweeps it up on every
	// enterprise-posture enrolment — the deliberate fleet-wide auto-grant the
	// operator ACCEPTED (decision D11); the node config key still defaults false
	// so nothing is pulled until the org turns the feature on.
	AuthorityExtractIntel = "extract.intel"

	// The HEADLINE per-tier extraction authorities (Arc 4 P4a). Where P5f-h
	// gave the three highest-sensitivity tiers their own token, these split the
	// SIX headline tiers the umbrella extract.managed used to raise as one bloc
	// (operator ruling §8a.1: every tier is an INDEPENDENT admin-UI toggle).
	// Each raises exactly ONE headline tier and nothing else, so an admin can
	// grant just cache extraction without also lifting tool bodies or full
	// traces. They are managed-only (ManagedAuthority) and inert on the
	// individual plane exactly like the umbrella and the P5f-h tokens.
	//
	// Back-compat is preserved without a wire change: extract.managed remains
	// in the vocabulary as an "all-headline" ALIAS — each headline predicate
	// (GrantsXxxExtraction below) is satisfied by EITHER its own token OR the
	// umbrella, so a grant carrying only extract.managed still raises all six,
	// exactly as it did before this split.
	//
	// Each maps to its ShareOptions tier:
	//   extract.tool_bodies  -> FullToolBodies (the four action body columns)
	//   extract.folders      -> FullContent (raw project_root / git / paths)
	//   extract.traces       -> the obs.* family (full traces + eval/admission)
	//   extract.cache        -> CacheDetail (cache_events aggregate)
	//   extract.routing      -> RoutingSummary + RoutingDetail (both routing grains)
	//   extract.predictions  -> LimitGauge (limit_snapshots aggregate)
	AuthorityExtractToolBodies  = "extract.tool_bodies"
	AuthorityExtractFolders     = "extract.folders"
	AuthorityExtractTraces      = "extract.traces"
	AuthorityExtractCache       = "extract.cache"
	AuthorityExtractRouting     = "extract.routing"
	AuthorityExtractPredictions = "extract.predictions"

	// The Plane B dual-mode gateway / RBAC-IA per-tier extraction authorities
	// (docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §5).
	// Each closes a shareTierTable gap that used to sit in shareTierExempt: the
	// key mapped to no real authority row at all, so no grant of any shape —
	// not even the umbrella — could ever raise it. That is now fixed by giving
	// each its own dedicated token, following the P5f-h high-sensitivity
	// pattern (grantsExtraction, STRICT — the umbrella extract.managed does
	// NOT satisfy any of these) rather than the P4a headline pattern:
	//
	//   - AuthorityExtractTargetActions and AuthorityExtractScope govern
	//     access-control-adjacent surfaces (which action types may ship a raw
	//     target; the node's own [org_client.scope] restriction lists), so
	//     they get the same "own explicit consent, umbrella never unlocks it"
	//     treatment as codeintel/process/terminal.
	//   - AuthorityExtractPolicyState governs a distinct governance-reporting
	//     channel (policy acknowledgement state), kept strict for the same
	//     reason: it is a narrow, sensitive surface, not a bulk content tier.
	//
	// AuthorityExtractObsEgress is the one exception: it is a HEADLINE token
	// (grantsExtractionOrManaged — own token OR the umbrella), because it is
	// simply the T8 member of the SAME obs.* family whose other seven members
	// (obs.summary/traces/content/eval_summary/admission/eval_items) already
	// raise under the umbrella-eligible extract.traces. Giving the T8 sibling
	// a strict-only token would mean an admin who already granted "raise every
	// obs.* tier" for the other seven has to separately re-grant the eighth —
	// an inconsistency the design brief's "own extract token" ask does not
	// require; it asks for a DEDICATED token, not necessarily a strict one.
	AuthorityExtractTargetActions = "extract.target_actions"
	AuthorityExtractScope         = "extract.scope"
	AuthorityExtractPolicyState   = "extract.policy_state"
	AuthorityExtractObsEgress     = "extract.obs_egress"
)

// KnownAuthority reports whether tok is in the closed vocabulary.
//
// capture.raise is deliberately still known: forward/backward compat
// requires an agent to be able to READ a token a differently-versioned
// server offered. Known is not the same as honoured — see
// AuthorityCaptureRaise.
func KnownAuthority(tok string) bool {
	switch tok {
	case AuthorityDashboardVisibility, AuthoritySettingsPin,
		AuthorityCaptureRaise, AuthorityCapturePin, AuthorityFeatureLock,
		AuthorityEnforceRouting, AuthorityEnforceAdmission, AuthorityEnforceEgress,
		AuthorityEnforceBudget,
		AuthorityExtractManaged, AuthorityExtractCodeintel,
		AuthorityExtractProcess, AuthorityExtractTerminal,
		AuthorityExtractTasks, AuthorityExtractToolAccounts,
		AuthorityExtractIntel,
		AuthorityExtractToolBodies, AuthorityExtractFolders,
		AuthorityExtractTraces, AuthorityExtractCache,
		AuthorityExtractRouting, AuthorityExtractPredictions,
		AuthorityExtractTargetActions, AuthorityExtractScope,
		AuthorityExtractPolicyState, AuthorityExtractObsEgress:
		return true
	}
	return false
}

// ManagedAuthority reports whether tok is one of the managed-only tokens,
// honoured only under Enterprise-Managed Tenancy (managed-class consent,
// ManagedConsent). It is the single owner of that classification: the node
// resolver (HonoredAuthority), the org-server mint gate, and the developer-
// transparency surfaces all branch on it, never on a hardcoded token list.
func ManagedAuthority(tok string) bool {
	switch tok {
	case AuthorityEnforceRouting, AuthorityEnforceAdmission,
		AuthorityEnforceEgress, AuthorityEnforceBudget, AuthorityExtractManaged,
		AuthorityExtractCodeintel, AuthorityExtractProcess,
		AuthorityExtractTerminal, AuthorityExtractTasks,
		AuthorityExtractToolAccounts, AuthorityExtractIntel,
		AuthorityExtractToolBodies,
		AuthorityExtractFolders, AuthorityExtractTraces,
		AuthorityExtractCache, AuthorityExtractRouting,
		AuthorityExtractPredictions, AuthorityExtractTargetActions,
		AuthorityExtractScope, AuthorityExtractPolicyState,
		AuthorityExtractObsEgress:
		return true
	}
	return false
}

// ExtractionAuthority reports whether tok is one of the EXTRACTION
// authorities — the umbrella extract.managed or any per-tier extract.* token.
// It is the single owner of that classification, exactly as ManagedAuthority
// owns "managed-only": the resolver's `share` directive-class gate and any
// future surface that needs "does this grant ask to RAISE anything" must call
// this rather than re-listing the tokens.
//
// It is deliberately NARROWER than ManagedAuthority: the enforce.* tokens are
// managed-only too, but they govern enforcement MODE, not extraction, and must
// never by themselves authorize the share block.
func ExtractionAuthority(tok string) bool {
	switch tok {
	case AuthorityExtractManaged, AuthorityExtractCodeintel,
		AuthorityExtractProcess, AuthorityExtractTerminal,
		AuthorityExtractTasks, AuthorityExtractToolAccounts,
		AuthorityExtractIntel,
		AuthorityExtractToolBodies, AuthorityExtractFolders,
		AuthorityExtractTraces, AuthorityExtractCache,
		AuthorityExtractRouting, AuthorityExtractPredictions,
		AuthorityExtractTargetActions, AuthorityExtractScope,
		AuthorityExtractPolicyState, AuthorityExtractObsEgress:
		return true
	}
	return false
}

// RetiredAuthority reports whether tok is a known token that grants nothing
// in this build. It is surfaced by the CLI and the Enrolment page so a
// developer holding an older grant can see WHY a directive did not take.
func RetiredAuthority(tok string) bool { return tok == AuthorityCaptureRaise }

// EnterpriseAuthoritySet is the authority set an enterprise-posture enrolment
// (or grant-replacement) mints (design §5.2, P2b): every extraction authority
// token, so effective sharing is ALL by default, PLUS the two GOVERNING tokens
// without which the posture governs nothing. It is the single owner of "what
// the enterprise grant contains" — the org server's enterprise auto-grant, its
// grant-replacement issuance, and the posture-derived enrolment default
// (orgserver/posture.DefaultInviteAuthority) all source the list here rather
// than re-enumerating the vocabulary, so they can never drift. Returned sorted
// so the signing message is stable.
//
// WHY THE TWO GOVERNING TOKENS BELONG HERE (org-observer fundamentals plan
// 2026-09-13, W7). A fleet that signed up for managed governance and is then
// offered no governing authority is the shape the 2026-09-13 diagnosis found
// in production: the org signed budgets nothing could apply.
//
//   - AuthorityEnforceBudget is what makes the org's own cap authoritative on
//     a managed node. Without it the signed per-caller body from
//     GET /api/agent/budget may only LOWER the developer's own thresholds, so
//     the fail-closed budget stop (guard rule B-625) never engages and the
//     coverage table tells an admin their cap is enforced by nobody.
//   - AuthoritySettingsPin is what makes any of it land: govern/resolve.go
//     gates the whole `pinned` directive class on this token, so without it
//     EVERY pin in the default node.governance body — guard.mode, guard.strict,
//     guard.budget.from_org, guard.budget.hard — is dropped node-side and a
//     developer can set guard.mode = "observe" to turn the fail-closed budget
//     row back into a flag.
//
// The individual plane is unaffected. AuthorityEnforceBudget is managed-only
// (ManagedAuthority), so HonoredAuthority strips it on a BYO node and the mint
// gate refuses it on an individual-tenancy token; the posture-derived INVITE
// default is additionally narrowed to its non-managed tokens for an individual
// mint (api.nonManagedAuthority). AuthoritySettingsPin is deliberately NOT
// managed-only — pinning config keys is a thing an individual node may consent
// to, exactly like dashboard.visibility and capture.pin — so it is offered on
// both planes, as it already was.
//
// The set is otherwise exactly the tokens ExtractionAuthority recognises (the
// extract.* family, umbrella included). It still omits the other three
// enforce.* tokens (routing/admission/egress), which switch an enforcement
// subsystem's MODE for subsystems an enterprise fleet may not run at all;
// those stay an authored per-org act.
//
// AuthorityExtractIntel is included DELIBERATELY (org-served-cloud-intelligence
// plan decision D11, operator ruling 2026-09-11): because it is an extract.*
// token, adding it here auto-grants it on every enterprise-posture node at its
// next enrolment with no per-node admin act. The operator ACCEPTED that
// fleet-wide raise as the enterprise-first posture working as designed; the
// node's own [intelligence].org_enrichment key still defaults false, so the
// rail pulls nothing until the org turns the feature on.
func EnterpriseAuthoritySet() []string {
	set := []string{
		// The two governing tokens (see above): the org's numbers win, and
		// the pins that carry them are honoured rather than dropped.
		AuthoritySettingsPin, AuthorityEnforceBudget,

		AuthorityExtractManaged, AuthorityExtractCodeintel,
		AuthorityExtractProcess, AuthorityExtractTerminal,
		AuthorityExtractTasks, AuthorityExtractToolAccounts,
		AuthorityExtractIntel,
		AuthorityExtractToolBodies, AuthorityExtractFolders,
		AuthorityExtractTraces, AuthorityExtractCache,
		AuthorityExtractRouting, AuthorityExtractPredictions,
		AuthorityExtractTargetActions, AuthorityExtractScope,
		AuthorityExtractPolicyState, AuthorityExtractObsEgress,
	}
	sort.Strings(set)
	return set
}

// ConsentMode records HOW the node came to hold this grant (spec §2).
// ConsentInteractive is a TTY-confirmed individual enrolment (the developer
// answered a y/N prompt themselves). ConsentManaged is a managed
// enrolment-token redemption (Arc 4 P1: an org-minted, scripted/MDM token).
// ConsentIdP is an IdP-verified device-code enrolment (ACP-P6c): the
// developer completes SSO on the org's identity provider and approves the
// pairing in a browser — that browser approval is the consent of record.
const (
	ConsentInteractive = "interactive"
	ConsentIdP         = "idp"
	ConsentManaged     = "managed"
)

// ManagedConsent reports whether mode is one of the managed-class consent
// modes: ConsentManaged or ConsentIdP. It is the single owner of that
// classification — the node resolver (HonoredAuthority), Effective.Managed,
// and any future surface that needs to know whether a grant carries
// managed-tenancy authority must call this, never compare ConsentMode
// against ConsentManaged directly.
//
// ConsentIdP is managed-class because an IdP-verified sign-in IS the
// enterprise consent act (ACP-P6c): the developer's SSO through the org's
// identity provider, confirmed by approving the device-code pairing in a
// browser, carries the same authority as redeeming a managed enrolment
// token — the org's IdP already vouched for who is enrolling and that they
// are entitled to bind this machine as managed.
func ManagedConsent(mode string) bool {
	return mode == ConsentManaged || mode == ConsentIdP
}

// Grant is the node-side record of the bounded authority this machine handed
// to an organization at enrolment. It is the consent boundary: a directive
// outside it is dropped and reported, so widening authority requires a new
// enrolment, which requires a new node-side act.
//
// It is written by cmd/observer at enrolment (never by internal/orgclient —
// orgclient has no TTY and has already committed the bearer by the time a
// human could answer), stored by internal/store/orggrant.go, and deleted by
// `observer unenroll`.
type Grant struct {
	OrgKey       string
	Generation   int64
	OrgID        string
	OrgName      string
	OrgServerURL string
	// KeyPinSHA256 is the org policy signing key hash bound at grant time.
	// Resolve compares it against the LIVE TOFU pin (rule 4): a grant signed
	// under a key the node no longer pins is not authority, it is a
	// substitution attempt.
	KeyPinSHA256 string
	Authority    []string
	ConsentMode  string
	ConsentActor string
	GrantedAt    time.Time
	ExpiresAt    time.Time
	// Signature is the base64url Ed25519 signature over the grant's canonical
	// signing message. Kept as EVIDENCE (an operator, an auditor, or a court
	// can verify what the organization actually asked for) — it is verified
	// at write time against the pinned key, not re-verified on every Resolve.
	Signature   string
	ReceiptHash string
	// Integrity is the boundary's verdict on whether the STORED grant
	// document still verifies under the org distribution key this node
	// holds (Track C item 1). internal/govern does no crypto — the check
	// runs once per identity refresh at the cmd boundary
	// (cmd/observer/nodegov_wire.go::governanceIdentityLoader) and is
	// resolved into this plain enum, exactly as CLAUDE.md #3 requires.
	//
	// The ZERO value is GrantIntegrityUnchecked, which keeps a caller that
	// does not (or cannot) verify on today's behaviour — that is what makes
	// this additive.
	Integrity GrantIntegrity
}

// GrantIntegrity is the tri-state verdict of the runtime re-verification of
// a STORED grant. Tri-state, not a bool, because "we could not check" and
// "we checked and it failed" are different facts and only the second one may
// be loud: a node that never recorded the org key material (a pre-2026-09-13
// enrolment, or a server that delivered no key) must not be reported as
// tampered with.
type GrantIntegrity string

const (
	// GrantIntegrityUnchecked — no verification was attempted or none was
	// possible (no key material on this node). The zero value.
	GrantIntegrityUnchecked GrantIntegrity = ""
	// GrantIntegrityValid — the stored document verified under the key.
	GrantIntegrityValid GrantIntegrity = "valid"
	// GrantIntegrityInvalid — the stored document did NOT verify: it is not
	// the document the organization signed.
	GrantIntegrityInvalid GrantIntegrity = "invalid"
)

// LiveIdentity is the node's CURRENT enrolment identity plus its live org
// policy key pin — the facts a grant is checked against on every resolve, so
// a raced unenrol/re-enrol (or a key substitution) wins immediately rather
// than at the next restart.
type LiveIdentity struct {
	Enrolled     bool
	OrgKey       string
	Generation   int64
	KeyPinSHA256 string
}

// Delivered is the org-published resource the node accepted for the
// node.governance family, or the zero value when nothing is installed.
type Delivered struct {
	// Present is false when no resource is installed (404/withdrawn/never
	// published, or an install the accept gates refused).
	Present bool
	Version int64
	// BodyHash is the SIGNED body hash — the org-rail wire identity this
	// family reports as EffectiveHash, exactly like admitter/egress/gateway.
	BodyHash string
	Spec     nodegov.PolicySpec
	// InertReason is the accept-path's own inert verdict (e.g. the
	// [org_client.policy].preauthorize_enforce gate refused to let the body
	// run). Non-empty means the node accepted the resource but must not
	// apply it.
	InertReason string
}

// State is the resolver's verdict — the ONE value the whole node branches
// on. It is deliberately coarser than the wire status enum: the mapping onto
// (status, reason) lives at the policystate boundary, not here.
type State string

const (
	// StateNoGrant — this node holds no enrolment grant. The delivered body,
	// however valid, is ignored entirely. This is the solo/unenrolled/
	// enrolled-but-ungoverned node, and it is the zero value.
	StateNoGrant State = "no_grant"
	// StateGrantExpired — the grant's TTL lapsed; the node has reverted to
	// its local settings and says so.
	StateGrantExpired State = "grant_expired"
	// StateIdentityChanged — the grant belongs to an enrolment identity or
	// generation the node no longer holds (a raced unenrol/re-enrol).
	StateIdentityChanged State = "identity_changed"
	// StateKeyPinMismatch — the grant was bound to an org signing key the
	// node no longer pins (adversarial review A2 / spec §3.7 row 3b).
	StateKeyPinMismatch State = "key_pin_mismatch"
	// StateGrantSignatureInvalid — the STORED grant document no longer
	// verifies under the org signing key this node holds (Track C item 1,
	// docs/plans/org-guardrail-control-wave-2026-09-21.md). Same class as
	// StateKeyPinMismatch: the authority record on disk is not the one the
	// organization signed, so nothing in it may be believed — including its
	// own expiry, which is why this row is resolved BEFORE the TTL row.
	//
	// It is reachable only when the node could actually CHECK (it holds the
	// org distribution key material and the caller set
	// Grant.Integrity). An unchecked grant keeps today's behaviour.
	StateGrantSignatureInvalid State = "grant_signature_invalid"
	// StateNoPolicy — a live grant, but the org has published no governance.
	StateNoPolicy State = "no_policy"
	// StateInert — a live grant and a delivered body, but nothing was
	// applied: the grant does not carry the authority the body needs, or the
	// accept path already marked it inert.
	StateInert State = "inert"
	// StateApplied — the delivered body was applied in full.
	StateApplied State = "applied"
)

// Reason values are the BOUNDED reason enum carried in Dropped and mapped at
// the policystate boundary onto the orgcontract wire reasons. The literals
// match orgcontract's, duplicated here for the same dependency-graph reason
// internal/policystate duplicates its family names: this is a pure decision
// package, not a wire package.
const (
	ReasonNotPreauthorized = "not_preauthorized"
	ReasonGrantExpired     = "grant_expired"
	ReasonIdentityChanged  = "identity_changed"
	ReasonKeyPinMismatch   = "key_pin_mismatch"
	// ReasonGrantSignatureInvalid is the node-local drop reason paired with
	// StateGrantSignatureInvalid. Like ReasonAuthorityRetired it is
	// node-local BY CONSTRUCTION — cmd/observer's governanceFacts collapses
	// every non-applied resolution to not_preauthorized before the ack wire,
	// and the server 400s the whole report on an unknown reason.
	ReasonGrantSignatureInvalid = "grant_signature_invalid"
	// ReasonAuthorityRetired records a directive dropped because the only
	// authority the grant carries for it is a RETIRED token (capture.raise).
	//
	// Adding a reason is wire-safe HERE and only here (review n5): the
	// server validates ack reasons against a closed set and 400s the WHOLE
	// report on an unknown one — the same trap that keeps break_glass
	// unemitted. This reason is node-local BY CONSTRUCTION because
	// cmd/observer's governanceFacts never forwards a govern reason to the
	// wire; it collapses every non-applied resolution to
	// not_preauthorized. A future reader who "helpfully" plumbs the richer
	// reason through to the ack will take the fleet's reporting down. Do
	// not.
	ReasonAuthorityRetired = "authority_retired"
)

// Dropped records one directive class the node refused to apply, and why.
//
// Its PRESENCE is what forces accepted_inert / not_preauthorized instead of
// effective, so a partial application is visible in fleet state. Its
// CONTENT is not: the wire carries only (status, reason, hash), and
// cmd/observer's Facts() collapses every non-applied resolution to the
// single reason not_preauthorized (review M4). Dropped is therefore
// NODE-LOCAL — rendered on the developer's own Enrolment page and by
// `observer org grant show`, and folded into Effective.Hash so a partial
// application can never hash-match the delivered body — but the admin sees
// only that SOMETHING was refused, never which class. Per-directive drop
// visibility is a Phase-2 wire item.
type Dropped struct {
	Directive string `json:"directive"`
	Reason    string `json:"reason"`
}

// Effective is what the node ACTUALLY applies. It is never the delivered
// body: it is the delivered body INTERSECTED with the grant's authority,
// with every dropped directive recorded.
type Effective struct {
	// Active is true when this node is GOVERNED: a live grant AND an
	// installed body. It is the single predicate every UI surface and the
	// dashboard's route guard short-circuit on, so an ungoverned node's
	// request path never changes shape.
	Active  bool   `json:"active"`
	State   State  `json:"state"`
	Version int64  `json:"version"`
	OrgName string `json:"org_name,omitempty"`

	// Managed is true when this node enrolled under Enterprise-Managed
	// Tenancy (managed-class consent: ManagedConsent(grant.ConsentMode) —
	// a managed token redemption or an IdP enrolment). It is the single
	// predicate the managed-only authorities are gated on and the flag the
	// developer-transparency banner (T8) renders "this machine is managed by
	// <OrgName>". False on every individual / BYO node, which is the default.
	Managed bool `json:"managed"`

	HiddenSections   []string `json:"hidden_sections"`
	ReadOnlySections []string `json:"read_only_sections"`
	HiddenSettings   []string `json:"hidden_settings"`
	ReadOnlySettings []string `json:"read_only_settings"`

	// Pinned is the settings.pin + feature.lock directive classes MERGED
	// into one map — dotted config path → typed value. It is what the
	// daemon materializes into the sidecar, and therefore what every
	// process on the machine reads through config.Load.
	//
	// A feature lock is a compile-time alias over a pin, so there is exactly
	// one enforcement path and a feature can never drift from the pin
	// implementing it. The two are gated on their OWN authority tokens
	// before they are merged here.
	Pinned map[string]any `json:"pinned,omitempty"`
	// Share is the org's capture.pin directive, as delivered. It is NOT the
	// effective share posture: the lowering merge against the node's own
	// local [org_client.share] happens at the org-push seam, because only
	// there is the local value known (§2.2). The org can only ever REDUCE
	// or pin; it can never raise.
	Share map[string]any `json:"share,omitempty"`
	// Features is the DERIVED, display-only mirror (§3), so the developer's
	// Enrolment page can say "your organization requires the guard to be on"
	// rather than "guard.enabled = true".
	Features map[string]bool `json:"features,omitempty"`

	Notice Notice `json:"notice"`

	// Authority is the grant's own token list, surfaced so the developer can
	// always read what this machine handed over.
	Authority []string `json:"authority,omitempty"`
	// UnknownAuthority holds grant tokens outside this build's closed
	// vocabulary: honoured by nothing, reported so the admin can see the node
	// did not act on them.
	UnknownAuthority []string `json:"unknown_authority,omitempty"`
	// Dropped lists the directive classes the node refused.
	Dropped []Dropped `json:"dropped,omitempty"`

	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// Hash is the content address of THIS resolved posture (what is running),
	// which by construction differs from the delivered BodyHash whenever
	// anything was dropped.
	Hash string `json:"hash,omitempty"`

	// featurePins is the feature block's expansion, held separately only
	// between its authority gate and the merge into Pinned. Unexported so no
	// surface can mistake it for a second enforcement path.
	featurePins map[string]any
}

// GrantsManagedExtraction reports whether this resolved posture authorizes the
// org to RAISE the node's extraction tiers — the Enterprise-Managed Tenancy
// full-observer-DB-access capability. True only when the node is managed
// (Effective.Managed, i.e. managed-class consent per ManagedConsent) AND the
// grant carries the extract.managed authority. It is the single predicate the
// managed share-raise (governance_wire.lowerShareOptions → RaiseBool) gates on,
// so the individual plane is provably excluded (Managed is false there, and
// HonoredAuthority strips extract.managed from an individual grant regardless).
func (e Effective) GrantsManagedExtraction() bool {
	return e.grantsExtraction(AuthorityExtractManaged)
}

// GrantsCodeintelExtraction reports whether this resolved posture authorizes the
// org to RAISE the codeintel_detail tier — the code-intelligence source-symbol
// graph aggregate (Arc 4 P5f). It is DISTINCT from GrantsManagedExtraction: the
// umbrella extract.managed grant does NOT unlock it, by operator ruling
// (highest-sensitivity tiers get their own explicit per-tier consent). True only
// when the node is managed AND the grant carries the extract.codeintel authority.
func (e Effective) GrantsCodeintelExtraction() bool {
	return e.grantsExtraction(AuthorityExtractCodeintel)
}

// GrantsProcessExtraction reports whether this resolved posture authorizes the
// org to RAISE the process_detail tier — the process-observability run/exit
// aggregate (Arc 4 P5g). DISTINCT from GrantsManagedExtraction and every other
// GrantsXxxExtraction: only the extract.process authority (on a managed node)
// satisfies it.
func (e Effective) GrantsProcessExtraction() bool {
	return e.grantsExtraction(AuthorityExtractProcess)
}

// GrantsTerminalExtraction reports whether this resolved posture authorizes the
// org to RAISE the terminal_detail tier — the terminal-run + remote-audit count
// aggregate (Arc 4 P5h). DISTINCT from every other GrantsXxxExtraction: only the
// extract.terminal authority (on a managed node) satisfies it. It is the gate
// on the deliberate, reviewed reversal of the terminal_run / remote_audit
// end-to-end never-ships pins — the raw tables still never cross, only this
// content-free aggregate under this explicit tier.
func (e Effective) GrantsTerminalExtraction() bool {
	return e.grantsExtraction(AuthorityExtractTerminal)
}

// GrantsTasksExtraction reports whether this resolved posture authorizes the
// org to RAISE the task_detail tier — the session task/todo checklist's status
// rows + transitions (node session-detail trickle-up W2). DISTINCT from every
// other GrantsXxxExtraction: only the extract.tasks authority (on a managed
// node) satisfies it; the umbrella extract.managed never does (operator
// decision D4). It gates the deliberate, reviewed reversal of migration 109's
// node-local pin — and even under it the item PROSE still needs the node's
// separate raw-content posture.
func (e Effective) GrantsTasksExtraction() bool {
	return e.grantsExtraction(AuthorityExtractTasks)
}

// GrantsToolAccountsExtraction reports whether this resolved posture authorizes
// the org to RAISE the tool_account_detail tier — the vendor login
// observations' binding enums + opaque account_key (W3). DISTINCT from every
// other GrantsXxxExtraction: only extract.tool_accounts (on a managed node)
// satisfies it. The raw identity (email/name/account_id) still needs the node's
// separate raw-content posture on top (decision D2).
func (e Effective) GrantsToolAccountsExtraction() bool {
	return e.grantsExtraction(AuthorityExtractToolAccounts)
}

// GrantsIntelExtraction reports whether this resolved posture authorizes
// RAISING the org-served Cloud Intelligence result rail — the node-authored
// [intelligence].org_enrichment gate (org-served-cloud-intelligence plan
// §2.1/W5). DISTINCT from every other GrantsXxxExtraction: only the
// extract.intel authority (on a managed node) satisfies it; the umbrella
// extract.managed never does (STRICT grantsExtraction, like its codeintel/
// process/terminal/tasks/tool_accounts siblings). It gates only the node's
// PULL of the org's derived enrichment results — nothing additional SHIPS.
func (e Effective) GrantsIntelExtraction() bool {
	return e.grantsExtraction(AuthorityExtractIntel)
}

// The HEADLINE per-tier extraction predicates (Arc 4 P4a). Each authorizes the
// RAISE of exactly ONE headline tier, and each is satisfied by EITHER its own
// token OR the umbrella extract.managed (grantsExtractionOrManaged) — so an
// admin can grant a single tier, while a legacy extract.managed-only grant
// still raises all six unchanged. This is the split of the former one-bloc
// umbrella raise into independent admin-configurable toggles.

// GrantsToolBodiesExtraction authorizes the RAISE of FullToolBodies (the four
// action body columns). Satisfied by extract.tool_bodies or the umbrella.
func (e Effective) GrantsToolBodiesExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractToolBodies)
}

// GrantsFoldersExtraction authorizes the RAISE of FullContent (raw project
// folders / git identity / paths). Satisfied by extract.folders or the umbrella.
func (e Effective) GrantsFoldersExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractFolders)
}

// GrantsTracesExtraction authorizes the RAISE of the obs.* full-traces family
// (structure + content + eval/admission). Satisfied by extract.traces or the
// umbrella.
func (e Effective) GrantsTracesExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractTraces)
}

// GrantsCacheExtraction authorizes the RAISE of CacheDetail (the cache_events
// aggregate). Satisfied by extract.cache or the umbrella.
func (e Effective) GrantsCacheExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractCache)
}

// GrantsRoutingExtraction authorizes the RAISE of both routing grains
// (RoutingSummary + RoutingDetail). Satisfied by extract.routing or the umbrella.
func (e Effective) GrantsRoutingExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractRouting)
}

// GrantsPredictionsExtraction authorizes the RAISE of LimitGauge (the
// limit_snapshots aggregate). Satisfied by extract.predictions or the umbrella.
func (e Effective) GrantsPredictionsExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractPredictions)
}

// The Plane B dual-mode gateway / RBAC-IA extraction predicates (design
// §5.3). GrantsTargetActionsExtraction, GrantsScopeExtraction, and
// GrantsPolicyStateExtraction are STRICT (grantsExtraction, no umbrella
// clause) — see AuthorityExtractTargetActions's doc comment for why.
// GrantsObsEgressExtraction is the one HEADLINE exception in this group,
// matching the rest of the obs.* family.

// GrantsTargetActionsExtraction authorizes the RAISE of
// target_action_allowlist (which action TYPES may ship a raw target). Only
// extract.target_actions satisfies it; the umbrella does not.
func (e Effective) GrantsTargetActionsExtraction() bool {
	return e.grantsExtraction(AuthorityExtractTargetActions)
}

// GrantsScopeExtraction authorizes the RAISE of the node's
// [org_client.scope] restriction lists (union / unrestricted-override /
// denylist-removal — see share.go's RaiseList / RaiseScopeUnrestricted /
// RaiseScopeDenylistRemoval). Only extract.scope satisfies it; the umbrella
// does not.
func (e Effective) GrantsScopeExtraction() bool {
	return e.grantsExtraction(AuthorityExtractScope)
}

// GrantsPolicyStateExtraction authorizes the RAISE of the policy_state share
// tier (effective-policy-state reports). Only extract.policy_state satisfies
// it; the umbrella does not.
func (e Effective) GrantsPolicyStateExtraction() bool {
	return e.grantsExtraction(AuthorityExtractPolicyState)
}

// GrantsObsEgressExtraction authorizes the RAISE of the obs.egress share tier
// (the T8 egress-routing-decision obs tier — internal/orgcontract/obsegress.go).
// Satisfied by extract.obs_egress OR the umbrella, consistent with its seven
// obs.* siblings which all raise under extract.traces-or-umbrella.
func (e Effective) GrantsObsEgressExtraction() bool {
	return e.grantsExtractionOrManaged(AuthorityExtractObsEgress)
}

// GrantsEnterpriseContent reports whether this resolved posture's grant is
// broad enough to count as the Enterprise-Managed-Tenancy equivalent of a
// node operator's own full_content / admin_managed opt-in (design §5.4's
// enterpriseGranted disjunct). It composes four EXISTING strict predicates
// rather than introducing a new token: a grant must authorize the umbrella
// AND all three highest-sensitivity tiers (codeintel, process, terminal)
// before shipsRawContent() honors it. This is deliberately a HIGH bar —
// narrower than any single extraction tier — because shipsRawContent()
// governs raw content columns tree-wide, not one tier.
//
// Invariant (mirrors the CLAUDE.md posture): raw content ships ONLY under a
// node operator's own local opt-in (FullContent / AdminManaged) OR this
// enterprise grant. There is still no remote toggle that forces it — the org
// can only ever RAISE what a managed node's own resolver already agreed sits
// under Enterprise-Managed Tenancy (e.Managed, ManagedConsent), exactly like
// every other Raise* lift in this package.
func (e Effective) GrantsEnterpriseContent() bool {
	return e.Managed &&
		e.GrantsManagedExtraction() &&
		e.GrantsCodeintelExtraction() &&
		e.GrantsProcessExtraction() &&
		e.GrantsTerminalExtraction()
}

// The MANAGED-ENFORCE predicates (Arc 4 P3, the §R23 lift). Each authorizes
// the org body's enforcement MODE to be HONORED for one Plane-B family on a
// managed node — the deliberate, reviewed reversal of "enforcement is
// node-owned" for the ENTERPRISE plane only (operator ruling §8a.2:
// org-authoritative, no developer break-glass). Each requires managed tenancy
// AND the specific enforce.* authority; there is no umbrella and the
// individual plane is structurally excluded (HonoredAuthority strips the token
// and grantsExtraction re-checks Managed). "Default ON" is realized by the
// managed mint granting these + the cohort's org policy authored as enforce,
// NOT by coercing the composed mode (operator decision): the composer honors
// whatever mode the org body carries, so publishing observe/off remains a real
// per-cohort opt-out lever.

// GrantsRoutingEnforcement authorizes honoring the org routing body's mode
// (the §R23 lift for model routing). Requires managed + enforce.routing.
func (e Effective) GrantsRoutingEnforcement() bool {
	return e.grantsExtraction(AuthorityEnforceRouting)
}

// GrantsAdmissionEnforcement authorizes honoring the org admission body's mode
// (the §R23 lift for the input-admission guardrail). Requires managed +
// enforce.admission.
func (e Effective) GrantsAdmissionEnforcement() bool {
	return e.grantsExtraction(AuthorityEnforceAdmission)
}

// GrantsEgressEnforcement authorizes honoring the org egress body's mode (the
// §R23 lift for the egress guardrail). Requires managed + enforce.egress.
func (e Effective) GrantsEgressEnforcement() bool {
	return e.grantsExtraction(AuthorityEnforceEgress)
}

// GrantsBudgetEnforcement authorizes treating the org's budget body as
// AUTHORITATIVE rather than merely lowering (the org-budget plan §3.3c).
// Requires managed + enforce.budget.
//
// Without it the node still applies an org budget, but only through
// [LowerFloat] / [LowerInt] — the org can tighten a developer's cap and never
// loosen it. With it, on a managed node, the org's numbers and enforcement
// mode replace the local ones.
func (e Effective) GrantsBudgetEnforcement() bool {
	return e.grantsExtraction(AuthorityEnforceBudget)
}

// GrantsAnyEnforcement reports whether this node is MANAGED and holds any of
// the four enforce.* authorities — i.e. whether the organization is
// authoritative over some enforcement point on this machine, rather than
// merely advisory.
//
// It is a capability question, not an authority-token question: the callers
// that need it (Track C item 2's route-drift posture) do not care WHICH
// enforcement point the org drives, only that it drives one, because that is
// what makes "this developer's AI tool is no longer routed through the
// managed proxy" a finding rather than a configuration choice.
func (e Effective) GrantsAnyEnforcement() bool {
	return e.GrantsRoutingEnforcement() ||
		e.GrantsAdmissionEnforcement() ||
		e.GrantsEgressEnforcement() ||
		e.GrantsBudgetEnforcement()
}

// grantsExtractionOrManaged is the shared gate behind every HEADLINE
// GrantsXxxExtraction predicate: managed tenancy AND (the specific per-tier
// token OR the umbrella extract.managed alias). The umbrella clause is what
// keeps a legacy extract.managed-only grant raising all six headline tiers
// after the split. The high-sensitivity tiers (codeintel/process/terminal) use
// grantsExtraction WITHOUT the umbrella clause on purpose — the umbrella must
// never unlock them (operator ruling).
func (e Effective) grantsExtractionOrManaged(tok string) bool {
	if !e.Managed {
		return false
	}
	for _, a := range e.Authority {
		if a == tok || a == AuthorityExtractManaged {
			return true
		}
	}
	return false
}

// grantsExtraction is the shared STRICT gate behind the high-sensitivity
// GrantsXxxExtraction predicates AND the GrantsXxxEnforcement predicates
// (Arc 4 P3): managed tenancy (Effective.Managed) AND the specific managed
// authority token present in the grant, with NO umbrella clause. HonoredAuthority
// has already stripped any managed authority from an individual grant, so the
// Managed guard is a second, independent belt-and-braces against the individual
// plane.
func (e Effective) grantsExtraction(tok string) bool {
	if !e.Managed {
		return false
	}
	for _, a := range e.Authority {
		if a == tok {
			return true
		}
	}
	return false
}

// IsPinned reports whether the org has fixed a config key, and what to.
func (e Effective) IsPinned(key string) (any, bool) {
	v, ok := e.Pinned[key]
	return v, ok
}

// ShareDirective returns the org's directive for a share key, if any. It is
// the org's REQUEST, not the effective posture: the lowering merge against
// the node's own local value happens at the org-push seam, which is the only
// place the local value is known.
func (e Effective) ShareDirective(key string) (any, bool) {
	v, ok := e.Share[key]
	return v, ok
}

// Notice is the honesty copy rendered verbatim by the node.
type Notice struct {
	OrgDisplayName string `json:"org_display_name,omitempty"`
	Contact        string `json:"contact,omitempty"`
	PolicyURL      string `json:"policy_url,omitempty"`
}

// IsNavSectionHidden reports whether the resolved posture hides a nav
// section. Nil-safe on the zero value (nothing hidden).
func (e Effective) IsNavSectionHidden(id string) bool { return contains(e.HiddenSections, id) }

// IsNavSectionReadOnly reports whether the resolved posture locks a nav
// section read-only.
func (e Effective) IsNavSectionReadOnly(id string) bool { return contains(e.ReadOnlySections, id) }

// IsSettingsSectionHidden / IsSettingsSectionReadOnly are the Settings
// sub-section twins.
func (e Effective) IsSettingsSectionHidden(id string) bool { return contains(e.HiddenSettings, id) }

func (e Effective) IsSettingsSectionReadOnly(id string) bool {
	return contains(e.ReadOnlySettings, id)
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
