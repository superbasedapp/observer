package orgcontract

// PolicyStateRow is ONE effective-state claim for one (enforcement_point,
// family) pair. Hash/version/enum/timestamp ONLY. Attribution (OrgID/UserEmail)
// is SERVER-STAMPED and MUST be empty on the wire (R2-S2). Pinned aggregate-only
// by TestPolicyStateRowWireShapeIsHashOnly.
//
// This is the P0-6 "effective policy state" reverse-channel row
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §2.1). It ships on
// the dedicated POST /api/agent/policy-ack endpoint inside PolicyStateReport —
// NOT on the PushEnvelope slice, so the orgpush.go privacy sentinel is
// untouched.
type PolicyStateRow struct {
	OrgID     string `json:"org_id"`     // empty-on-wire; server-stamped from claims.Aud
	UserEmail string `json:"user_email"` // empty-on-wire; server-stamped via memberByID(claims.Sub) (R3-B6)

	Family           string `json:"family"`            // §3 family enum (§2.4 mapping)
	EnforcementPoint string `json:"enforcement_point"` // proxy-admitter|proxy-egress|guard|router

	DesiredVersion int64 `json:"desired_version"` // last-fetched (or rejected) version
	RunningVersion int64 `json:"running_version"` // version EFFECTIVE in the live decision path (0 = nothing running)

	// EffectiveHash is the per-point hex identity (§2.4). ORG-RAIL points
	// (guard/router): EMPTY when RunningVersion==0 (first install /
	// not-yet-loaded / disabled) (R3-B2/R5-B2). LOCAL points
	// (admitter/egress): a live 64-hex hash at version 0 (local_effective),
	// empty when the feature is off (R5-B1).
	EffectiveHash string `json:"effective_hash"`

	Status string `json:"status"` // effective|accepted_inert|pending_restart|delivered_unaccepted|stale_lkg|break_glass|none
	Reason string `json:"reason"` // bounded enum code (§3), never free text (never PolicyResult.Detail)

	RestartRequired bool   `json:"restart_required"` // HasOrgRail && RunningVersion < CachedAcceptedVersion (independent of Status)
	Mode            string `json:"mode"`             // off|observe|enforce — NORMALIZED (advise->observe)
	LastSeen        string `json:"last_seen"`        // RFC3339 — point liveness at report time

	// AcceptedAuthority, ExtractionEffective, and DroppedClasses are gen2
	// fields (managed-tenancy authority visibility). They are ONLY
	// meaningful on the family="node.governance" row (pointNodeDashboard) —
	// a report carrying them on any other row is a 400 — and are omitted
	// entirely (empty) by a gen1 agent or a gen2 agent on an individual /
	// unbindable node.
	//
	// AcceptedAuthority is the closed set of authority tokens
	// (govern.KnownAuthority) this node's grant resolver actually honors —
	// what internal/govern/resolve.go granted, after any retirement/version
	// gating, not merely what the server offered.
	AcceptedAuthority []string `json:"accepted_authority,omitempty"`
	// ExtractionEffective is the subset of AcceptedAuthority that are
	// extraction tiers (govern.ExtractionAuthority) whose share raise is
	// actually applying at the node's push seam right now — distinct from
	// "accepted" because an accepted extraction authority can still be
	// inert (e.g. share.full_content off locally).
	ExtractionEffective []string `json:"extraction_effective,omitempty"`
	// DroppedClasses maps a directive class name (the closed set returned
	// by internal/govern/resolve.go's directiveClasses(): "sections",
	// "pinned", "share", "features") to why that class's directive was NOT
	// applied: one of ReasonNotPreauthorized, ReasonModeObserve,
	// ReasonSidecarUnwritable, or ReasonFamilyNotAccepted. A class present
	// and accepted is simply absent from this map.
	DroppedClasses map[string]string `json:"dropped_classes,omitempty"`

	// EffectivePins is the Track C item 3 field
	// (docs/plans/org-guardrail-control-wave-2026-09-21.md): the EFFECTIVE
	// value, on this machine right now, of every pinnable config key whose
	// shape makes a content leak impossible — a bool, or a string with a
	// CLOSED enum (internal/policyfam/nodegov.ReportableKeys is the
	// vocabulary, and nodegov.ReportedValueAllowed is the value check the
	// server applies). Keys are dotted config paths; values are the closed
	// spellings "true" / "false" / an enum member / "other".
	//
	// It answers the question the acked pins cannot: "is the pin the
	// organization published actually IN FORCE on that machine?" — a
	// question with legitimate non-tamper answers (a restart-bound key, a
	// value this node's own config.Validate refused) as well as the tamper
	// one. The server resolves which through internal/orgserver/fleethealth;
	// the node only states the fact.
	//
	// It is NEVER content: no int (a threshold the developer chose) and no
	// string_list (paths, action names) is reportable, structurally, in the
	// vocabulary table rather than by a promise here.
	//
	// Like the other gen2 fields it is meaningful ONLY on the
	// family="node.governance" row, omitted entirely by a gen1 agent, and
	// carried on the policy-ack rail — NOT on the PushEnvelope, so the
	// orgpush.go privacy sentinel is untouched.
	EffectivePins map[string]string `json:"effective_pins,omitempty"`

	// BundleIntegrity and LocalGuard are the gen3 fields (guard tamper
	// visibility, T-846 / T-848, docs/audits/guard-tamper-visibility-audit-
	// 2026-10-15.md rows b2 and a2). They are meaningful ONLY on the
	// family="guard.coding" row (enforcement_point "guard"); the server 400s
	// a report that carries either on any other row, and a pre-gen3 server
	// 400s them anywhere (DisallowUnknownFields), which is what the node's
	// generation ladder probes for (cmd/observer/policystate_wire.go strips
	// them on the next rung, so an older server keeps every gen2 field).
	//
	// BundleIntegrity is what the node found when it re-verified the org
	// policy bundle ON DISK at report time (signature, key pin and body hash
	// against the version it recorded when it accepted that bundle): one of
	// BundleIntegrityVerified / BundleIntegrityAbsent /
	// BundleIntegrityTampered. Empty = not reported (a pre-gen3 node).
	//
	// It is a snapshot at report time, not a history (T-880). The daemon
	// repairs a tampered or deleted bundle within seconds, so by the next
	// report the file normally verifies again and this reads verified;
	// tampered or missing appears only while the repair has not completed
	// (for example the re-download failed). A repaired tamper reaches the
	// organization through GuardTamper, which bundle_tampered reads.
	BundleIntegrity string `json:"bundle_integrity,omitempty"`

	// LocalGuard is the node's local guard configuration as the hook path
	// would resolve it right now, except that on a node with an org lock the
	// floorable switches are the values the developer set locally, before
	// the managed floor or a governance pin raised them (T-848 / T-875), so a
	// weakening attempt the node overrode still reaches the organization.
	// Booleans, closed enums, closed detector ids and a COUNT only: the
	// allow-list's regex text never travels. Nil = not reported (a pre-gen3
	// node).
	LocalGuard *LocalGuardPosture `json:"local_guard,omitempty"`

	// GuardTamper is the gen4 field (T-864, guard tamper re-test
	// 2026-10-16 gap 4): the org-held guard files this node's daemon found
	// changed or removed outside the daemon and repaired in the last
	// GuardTamperWindow. The repair is fast enough that the file verifies
	// again by the next report, so without this record a repaired edit
	// never reached the organization. Guard row only, like the gen3
	// fields; a gen3 server 400s it (DisallowUnknownFields), which the
	// node's generation ladder probes for. Nil = nothing repaired in the
	// window, or a node that predates it.
	GuardTamper *GuardTamperReport `json:"guard_tamper,omitempty"`

	// ProjectSectionStatus is the gen5 field (security plan section 7.11,
	// lane sec-p2b): per project in the signed project mapping this node
	// holds, whether its section is applied, not matched, unknown or not
	// delivered (projectsectionstatus.go). Guard row only, like the gen3 and
	// gen4 fields; a gen4 server 400s it (DisallowUnknownFields), which the
	// node's generation ladder probes for. Nil = the node holds no project
	// delivery, or predates the field. Org project ids and closed statuses
	// only: which directory matched never travels.
	ProjectSectionStatus []ProjectSectionState `json:"project_section_status,omitempty"`
	// ProjectSectionTruncated (gen5, same rung) says the node cut
	// ProjectSectionStatus to what the server accepts (more projects than
	// MaxProjectMappingProjects, or an entry ValidProjectSectionStatus would
	// refuse), so the list is partial and the org must not read it as
	// whole. Guard row only.
	ProjectSectionTruncated bool `json:"project_section_truncated,omitempty"`
	// ProjectFamilyStatus is the gen6 field (security plan section 7.11,
	// lane sec-p3): per project family section this node holds (a
	// security.scanning section riding a project envelope), its closed
	// status (projectfamilies.go). Guard row only; a gen5 server 400s it
	// (DisallowUnknownFields), which the node's generation ladder probes
	// for. It shares ProjectSectionTruncated. Nil = no family section held,
	// or a node that predates the field (the org then reads every family
	// section reaching the member as not delivered).
	ProjectFamilyStatus []ProjectFamilySectionState `json:"project_family_status,omitempty"`
	// ProjectFamilyTruncated is the gen7 field (lane SEC-P4 decision 11):
	// the node cut ProjectFamilyStatus to what the server accepts, so the
	// family list is partial. ProjectSectionTruncated keeps its gen5 meaning
	// (the project section list only); a gen6 server 400s this field
	// (DisallowUnknownFields), so the node's ladder folds it into
	// ProjectSectionTruncated for such a server, as before. Guard row only.
	ProjectFamilyTruncated bool `json:"project_family_truncated,omitempty"`

	// FamilyNotApplicable is the gen8 field (SECP-10, lane LEFT-SHARED,
	// policystate_na.go): on the security.scanning row only, each floor key
	// the node holds but cannot apply, with its closed reason. A gen7 server
	// 400s it (DisallowUnknownFields), which the node's generation ladder
	// probes for. Nil = every key applied, no floor held, or an older node.
	FamilyNotApplicable []FamilyKeyNotApplicable `json:"family_not_applicable,omitempty"`
}

// Bundle integrity values for PolicyStateRow.BundleIntegrity (gen3).
const (
	// BundleIntegrityVerified: the on-disk org bundle verifies (signature,
	// key pin, body hash).
	BundleIntegrityVerified = "verified"
	// BundleIntegrityAbsent: no org bundle on disk (nothing published yet,
	// or the file was deleted).
	BundleIntegrityAbsent = "absent"
	// BundleIntegrityTampered: a bundle file exists and does NOT verify (an
	// edited body, a forged key, corrupt JSON). A managed node enforces its
	// last verified org layer (an individual node runs without the org
	// layer), and the poll re-fetches the bundle at once (T-864, T-877).
	BundleIntegrityTampered = "tampered"
	// BundleIntegrityMissing (gen4, T-864): no org bundle on disk although
	// this node had accepted a verified one (it recorded the version when
	// it did). Distinct from absent, which is "nothing was ever published
	// here": a deletion is a tamper, and a managed node keeps enforcing its
	// last verified copy and re-fetches the bundle at once. A gen3 server
	// 400s the value; the node's ladder reports it as absent there.
	BundleIntegrityMissing = "missing"
)

// LocalGuardPosture is the gen3 effective local guard configuration a node
// reports on its guard policy-state row (T-848). Every field is a bool, a
// closed enum, a closed detector id or a count, so nothing a developer typed
// (a regex, a path) can cross the wire through it.
type LocalGuardPosture struct {
	// Enabled is [guard].enabled as the hook path resolves it.
	Enabled bool `json:"enabled"`
	// Mode is [guard].mode, normalized to off|observe|enforce.
	Mode string `json:"mode"`
	// PromptEnabled is [guard.prompt].enabled as the hook path resolves it.
	PromptEnabled bool `json:"prompt_enabled"`
	// PromptMode is the global [guard.prompt].mode: off|warn|redact|ask-once|block.
	PromptMode string `json:"prompt_mode"`
	// DetectorModes maps a prompt detector id to its EFFECTIVE mode, listed
	// only where it differs from PromptMode (an override that took effect).
	DetectorModes map[string]string `json:"detector_modes,omitempty"`
	// AllowListCount is how many [guard.prompt].allow patterns are
	// configured. The count only: the pattern text never travels.
	AllowListCount int `json:"allow_list_count"`

	// RuleChanges is the gen9 field (localrules.go): every rule change the
	// machine makes for itself, in its config's `[guard.rules] disable`
	// list, its user policy file, a project policy file or the trusted
	// per-project layer, with whether the machine runs it. Ids, closed
	// enums and project identity hashes only. A gen8 server 400s it
	// (DisallowUnknownFields), which the node's generation ladder probes
	// for. Nil = no local change, or a node that predates the field.
	RuleChanges []LocalRuleChange `json:"rule_changes,omitempty"`
	// RuleChangesTruncated (gen9) says the node cut RuleChanges to
	// MaxLocalRuleChanges, or left out a change whose rule id is not
	// reportable, so the list is partial.
	RuleChangesTruncated bool `json:"rule_changes_truncated,omitempty"`
	// RemovedDisables (gen9) is the `[guard.rules] disable` ids the daemon
	// removed from this managed machine's config file at its last start,
	// because the organization manages those rules and did not allow a local
	// change to them; RemovedDisablesAt is when (RFC3339). Empty when the
	// daemon removed nothing.
	RemovedDisables   []string `json:"removed_disables,omitempty"`
	RemovedDisablesAt string   `json:"removed_disables_at,omitempty"`
	// Inputs (gen9) summarises the guard engine inputs the machine sets for
	// itself (boundary, network, database, proxy, taint and MCP settings)
	// as shapes, counts, enums and bools (LocalGuardInputs). Nil = not
	// reported (an individual node, or one that predates the field).
	Inputs *LocalGuardInputs `json:"inputs,omitempty"`
	// Node (gen9) summarises the node-local settings that shape policy and
	// enforcement outside the rule layers (LocalNodePosture). Nil = not
	// reported.
	Node *LocalNodePosture `json:"node,omitempty"`
}

// Local guard weakening keys: the closed vocabulary of a LocalGuardPosture
// weakness (LocalGuardWeakenings). They are dotted config paths, so the org
// reason names the exact knob a developer would have to change back.
const (
	LocalGuardKeyEnabled       = "guard.enabled"
	LocalGuardKeyMode          = "guard.mode"
	LocalGuardKeyPromptEnabled = "guard.prompt.enabled"
	LocalGuardKeyPromptMode    = "guard.prompt.mode"
	LocalGuardKeyDetectors     = "guard.prompt.detectors"
	LocalGuardKeyAllow         = "guard.prompt.allow"
	// LocalGuardKeyRules (gen9): the machine relaxes or disables a rule for
	// itself (LocalGuardPosture.RuleChanges with Loosens), applied or not.
	LocalGuardKeyRules = "guard.rules"
	// LocalGuardKeyInputs (gen9): a guard engine input is weaker than the
	// shipped default (LocalGuardInputWeakenings names which).
	LocalGuardKeyInputs = "guard.inputs"
	// LocalGuardKeyNode (gen9): a node setting is weaker than the shipped
	// default (LocalNodeWeakenings names which).
	LocalGuardKeyNode = "node.settings"
)

// localGuardPromptRank orders the prompt-guard modes from weakest to
// strongest (the same order internal/guard ranks them). A mode outside the
// set ranks -1.
var localGuardPromptRank = map[string]int{"off": 0, "warn": 1, "redact": 2, "ask-once": 3, "block": 4}

// localGuardModeRank orders the command guard modes from weakest to strongest.
var localGuardModeRank = map[string]int{"off": 0, "observe": 1, "enforce": 2}

// LocalGuardPromptModeKnown reports whether m is a prompt-guard mode.
func LocalGuardPromptModeKnown(m string) bool { _, ok := localGuardPromptRank[m]; return ok }

// LocalGuardModeKnown reports whether m is a normalized command guard mode.
func LocalGuardModeKnown(m string) bool { _, ok := localGuardModeRank[m]; return ok }

// localGuardFloor is the managed-node floor a LocalGuardPosture is judged
// against when the organization published no value for that key (D-672: on
// a managed node org guard rules win and a local edit may not weaken them).
// A prompt mode below "redact" (off or warn: nothing ever blocks or asks) and
// a detector whose effective mode is below "redact" are weakenings; a
// non-empty local allow-list is a weakening because it exempts findings the
// organization never saw. Exported as LocalGuardPromptFloor so the node's
// config floor (internal/guardposture) raises a weaker local prompt mode to
// exactly the value this check accepts.
const localGuardPromptFloor = LocalGuardPromptFloor

// LocalGuardWeakenings returns, sorted, the LocalGuardKey* keys on which p is
// weaker than the managed-node floor. pinned carries the organization's
// PUBLISHED values for guard.enabled / guard.mode (the node.governance pins,
// "true"/"false" and an enum member); a published value replaces the
// built-in floor for that key, so an organization that deliberately runs
// guard in observe mode is not told its own choice is a weakening. A nil p
// (a pre-gen3 node) reports nothing: absence of evidence is not a finding.
//
// The rule is a table walked top-down (CLAUDE.md #5), one check per key.
func LocalGuardWeakenings(p *LocalGuardPosture, pinned map[string]string) []string {
	if p == nil {
		return nil
	}
	floorMode := "observe"
	if v, ok := pinned[LocalGuardKeyMode]; ok && LocalGuardModeKnown(v) {
		floorMode = v
	}
	floorEnabled := true
	if v, ok := pinned[LocalGuardKeyEnabled]; ok {
		floorEnabled = v == "true"
	}
	// A detector is judged against ITS OWN floor (LocalGuardDetectorFloor):
	// the lower of "redact" and the shipped default for that detector, so the
	// default set itself (email and the phone detectors ship off) is never a
	// weakening (T-864 gap 3: a false local_weakening on an untouched node).
	// LocalGuardWeakDetectors names them (T-888).
	weakDetector := len(LocalGuardWeakDetectors(p)) > 0
	// Every check stands on its own (T-876): a prompt guard switched off does
	// not hide a prompt mode or detectors set below the floor in the same
	// edit, so the organization sees every setting the developer lowered.
	checks := []struct {
		key  string
		weak bool
	}{
		{LocalGuardKeyEnabled, floorEnabled && !p.Enabled},
		{LocalGuardKeyMode, localGuardModeRank[p.Mode] < localGuardModeRank[floorMode]},
		{LocalGuardKeyPromptEnabled, !p.PromptEnabled},
		{LocalGuardKeyPromptMode, localGuardPromptRank[p.PromptMode] < localGuardPromptRank[localGuardPromptFloor]},
		{LocalGuardKeyDetectors, weakDetector},
		{LocalGuardKeyAllow, p.AllowListCount > 0},
		{LocalGuardKeyRules, len(LocalRuleLoosenings(p)) > 0},
		{LocalGuardKeyInputs, len(LocalGuardInputWeakenings(p.Inputs)) > 0},
		{LocalGuardKeyNode, len(LocalNodeWeakenings(p.Node)) > 0},
	}
	var out []string
	for _, c := range checks {
		if c.weak {
			out = append(out, c.key)
		}
	}
	return out
}

// PolicyStateReport is the POST /api/agent/policy-ack body. AgentVersion is
// build metadata, grammar-constrained server-side (R3-S4). Rows is the snapshot
// across all four points. ReportSeq is a strictly increasing per-daemon ordering
// key (R3-B7, made RESTART-SAFE in R4-B6), carried INSIDE the signed body so it is
// tamper-evident; the server orders latest-wins on ReportSeq (strict >) with a
// ts-gated reset-recovery fallback (§2.6).
type PolicyStateReport struct {
	AgentVersion string           `json:"agent_version"`
	ReportSeq    int64            `json:"report_seq"` // persisted monotonic counter; strictly increasing per daemon, restart-safe (R4-B6); MUST be > 0
	Rows         []PolicyStateRow `json:"rows"`

	// MachineIdentity is the gen2 managed-node machine binding id (matches
	// machineid.ForOrg's org-salted SHA-256 hex fingerprint) — report-level
	// because one report describes one machine. Empty for a gen1 agent, an
	// individual-tenancy node, or a managed node on a host with no stable
	// machine identity (unbindable). Distinguishes two machines reporting
	// for the SAME user: the server keys policy_state on
	// (org_id, user_id, machine_identity, enforcement_point, family), so an
	// empty value is its own valid key, not a collision with every other
	// unbindable report from the same user.
	MachineIdentity string `json:"machine_identity,omitempty"`

	// LiveCapabilities is the node's advertised capability-token list at report
	// time (Plane B §3, Sol S3; P6b). It carries content-free capability tokens
	// only — in particular the mode-capability token
	// ModeCapabilityToken(providers.SupportedModeSchemaVersion) — from which the
	// server derives the node's Gateway-Mode readiness
	// (ParseModeCapabilityVersion → planebmode.RecordCapabilityAck). omitempty on
	// both compat sides: a pre-P6 agent omits it (the server records no mode
	// capability for that node, exactly as today); a pre-P6 server ignores it.
	// This mirrors the node's own PolicyResourceOptions.LiveCapabilities.
	LiveCapabilities []string `json:"live_capabilities,omitempty"`
}

// Policy-state Status enum (§3.3) — the CLOSED set of effective-state statuses a
// PolicyStateRow may carry. Server-validated: any other value is a 400. The
// deferred statuses are enum-defined but NEVER populated this milestone (the
// server REJECTS them until P1-3/P0-10 implement them, R4-B5).
const (
	StatusEffective           = "effective"
	StatusAcceptedInert       = "accepted_inert"
	StatusPendingRestart      = "pending_restart"
	StatusDeliveredUnaccepted = "delivered_unaccepted"
	StatusStaleLKG            = "stale_lkg"
	StatusBreakGlass          = "break_glass" // P1-3/P0-10 — enum-defined, NOT populated this milestone
	StatusNone                = "none"
)

// Policy-state Reason enum (§3.3) — the CLOSED set of reason codes. A Reason is
// a typed code, never free text (never PolicyResult.Detail). Server-validated
// against the status<->reason pairing (§5.3). The deferred reasons are
// enum-defined but NEVER populated this milestone (R4-B5).
const (
	ReasonOK                      = "ok"
	ReasonNotPreauthorized        = "not_preauthorized" // P0-5 — populated: admission.input/egress.routing_guardrail org-rail accepted_inert (§7.2)
	ReasonModeObserve             = "mode_observe"
	ReasonRestartRequired         = "restart_required"
	ReasonSigInvalid              = "sig_invalid"
	ReasonKeyPinMismatch          = "key_pin_mismatch"
	ReasonVersionDowngrade        = "version_downgrade"
	ReasonLintFailed              = "lint_failed"
	ReasonCapabilityMismatch      = "capability_mismatch" // P0-5 — populated: admission.input/egress.routing_guardrail org-rail delivered_unaccepted (§7.2)
	ReasonControlPlaneUnreachable = "control_plane_unreachable"
	ReasonInconsistentObservation = "inconsistent_observation" // R2-B6
	ReasonLocalEffective          = "local_effective"          // R4-B1 — local point (admitter/egress) running a locally-configured effective policy; no org rail
	ReasonBreakGlassActive        = "break_glass_active"       // P1-3/P0-10 — enum-defined, NOT populated this milestone
	ReasonNoPolicy                = "no_policy"
	// ReasonVersionReplay is the P0-5 SignedPolicyResource accept-gate
	// rejection (plan §6.3/§6.5/§7.2): the incoming resource's version
	// equals the durable replay floor but its full signing-message digest
	// does not match the durably recorded one. A missing cache never
	// weakens this check — an equal-version envelope must always prove its
	// identity against the durable digest, not merely its version number.
	ReasonVersionReplay = "version_replay" // P0-5 — enabled with SignedPolicyResource accept path
	// ReasonSelectorMismatch is the P0-10 Phase B targeting-corroboration
	// rejection (docs/plans/policy-targeting-rollback-design-2026-08-13.md
	// §2): the delivered resource's signed selectors name an attribute value
	// that CONTRADICTS this node's locally-configured attribute
	// ([org_client.policy] node_workspace/node_environment/node_service). The
	// prior LKG stays installed. It pairs with delivered_unaccepted for the
	// admitter/egress points (never router), and it deliberately does NOT
	// reuse capability_mismatch: a server/agent attribute disagreement is a
	// rollout-targeting defect, and folding it into the capability bucket
	// would corrupt auto-halt diagnostics.
	ReasonSelectorMismatch = "selector_mismatch" // P0-10 Phase B — org/agent targeting disagreement
	// ReasonFamilyNotAccepted is the gen2 P4-2 reason: the node declined the
	// family entirely via its own [org_client.policy].accept_families
	// allow-list, as opposed to receiving-but-rejecting it (capability
	// mismatch / version skew). It pairs with delivered_unaccepted only.
	ReasonFamilyNotAccepted = "family_not_accepted" // gen2 — node-side accept_families opt-out
	// ReasonPostureLoosened is the result-based posture check's refusal
	// (roadmap F0-8): the body would have made the node weaker on one of its
	// family's posture axes, so the node kept its last known good. It pairs
	// with delivered_unaccepted only. Only a family with a posture evaluator
	// (security.scanning, terminals.isolation) can produce it, and an org
	// server old enough not to allow it cannot publish those families.
	ReasonPostureLoosened = "posture_loosened"
	// ReasonSidecarUnwritable is the gen2 P4-2 reason: the
	// dashboard.visibility directive's sidecar file could not be written
	// (§1.4.1), so the class was accepted by policy but never took effect
	// locally. Previously this borrowed ReasonNotPreauthorized, which
	// conflated a real preauthorization gap with a local I/O failure; it
	// pairs with accepted_inert only.
	ReasonSidecarUnwritable = "sidecar_unwritable" // gen2 — dashboard.visibility sidecar write failure
)

// RowIsOrgRailState classifies a (status, reason) pair as org-rail or local
// (P0-5 Phase S §7.0/§7.5 dual-mode discriminator). It is the single shared
// predicate for both the server-side PolicyAck validator
// (internal/orgserver/api) and the fleet-rollup reconciler
// (internal/orgserver/rollup) — proxy-admitter/proxy-egress rows now reach
// the full status set and must be classified by what they actually report,
// not by which enforcement point sent them. Guard/router rows are always
// org-rail in practice (they have no local overlay to report), but this
// function classifies purely on the status/reason shape so a caller never
// needs a point-identity branch of its own.
func RowIsOrgRailState(status, reason string) bool {
	switch status {
	case StatusDeliveredUnaccepted, StatusAcceptedInert, StatusEffective,
		StatusStaleLKG, StatusPendingRestart:
		return true
	case StatusNone:
		return reason == ReasonInconsistentObservation
	default:
		return false
	}
}
