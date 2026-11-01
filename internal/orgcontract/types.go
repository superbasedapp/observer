package orgcontract

// EnrollRequest is the body of POST /api/agent/enroll. The agent presents a
// one-time enrolment token (minted by an admin) and a freshly generated
// Ed25519 public key the server binds to the user record.
//
// The token is a compound "<token_id>.<secret>": the admin mints it once and
// hands the whole string to the developer, who runs `observer enroll <org-url>
// <token>`. The server resolves the user from the token_id and verifies the
// secret, so the developer never needs to know their SCIM user id — that is
// why this request carries no user_id field.
type EnrollRequest struct {
	OneTimeToken   string `json:"one_time_token"`   // "<token_id>.<secret>"
	AgentPublicKey string `json:"agent_public_key"` // base64url-encoded Ed25519 public key

	// Capabilities are tokens the enrolling node advertises so the server
	// shapes the signed grant to what this node can verify (today only
	// EnrolCapabilityInitialComponents; see GrantForNode). omitempty on both
	// sides of the compat invariant: an older server decodes the request
	// without DisallowUnknownFields and ignores it, and an older node sends
	// none, so the server never offers it a field it would fail to verify.
	Capabilities []string `json:"capabilities,omitempty"`
}

// EnrollResponse is the 200 body of POST /api/agent/enroll. The bearer is
// a signed JSON envelope (see BearerClaims) the agent stores in its OS
// keychain and presents on every push.
//
// UserID is the server-resolved SCIM user id the compound enrolment token
// bound to. The agent persists it in org_enrolment.user_id (a NOT NULL
// column) — the request carries no user_id, so the server must echo it back
// here for the agent to record its own identity without re-deriving it from
// the bearer claims.
type EnrollResponse struct {
	Bearer          string `json:"bearer"`
	BearerExpiresAt string `json:"bearer_expires_at"` // RFC3339
	OrgID           string `json:"org_id"`
	OrgName         string `json:"org_name"`
	UserID          string `json:"user_id"` // SCIM user id resolved from the token
	UserEmail       string `json:"user_email"`

	// OrgPolicyPublicKey is the base64url Ed25519 public half of the org's
	// POLICY signing key (guard spec §14.2), delivered at enrol time so the
	// agent can pin it (sha256 of the raw key bytes, stored in
	// guard_policy_state) before the first policy-bundle fetch. omitempty on
	// both sides of the compat invariant: a pre-G13 server omits the field
	// and the agent falls back to trust-on-first-fetch pinning; a pre-G13
	// agent ignores the unknown key. Servers without a configured policy
	// signing key also omit it — the field is never required.
	OrgPolicyPublicKey string `json:"org_policy_public_key,omitempty"`

	// Tenancy is the enrolment CLASS this node enrolled under:
	// TenancyIndividual (the default and only behaviour for a BYO node —
	// "Never server-forced" holds absolutely) or TenancyManaged (an
	// org-provisioned node that opts into comprehensive Enterprise-Managed
	// admin control). omitempty on both sides of the compat invariant: a
	// pre-managed server omits it and the node defaults to individual; a
	// pre-managed agent ignores the unknown key. It rides at the same
	// authenticated-TLS trust level as OrgID/OrgName; the managed
	// AUTHORITIES it unlocks live in the SIGNED Grant.Authority, and the node
	// honours them only when it recorded ConsentMode=managed from this field.
	Tenancy string `json:"tenancy,omitempty"`

	// ConsentMode / ConsentActor record HOW this enrolment was consented to
	// when the server itself knows the answer, which today means exactly one
	// case: an enrolment minted by the ACP-P6c IdP device-code rail
	// (enrolment_tokens.minted_via = 'idp'). ConsentMode is then "idp" and
	// ConsentActor is the VERIFIED address of the member who approved the
	// pairing in a browser after an enterprise-IdP sign-in — the identity
	// that replaces the spoofable local $USER the node would otherwise
	// record. Every other rail leaves both empty and the node resolves the
	// consent mode from tenancy exactly as before.
	//
	// omitempty on both sides of the compat invariant: a pre-P6c server never
	// emits them (the node falls back to token-rail semantics), and a pre-P6c
	// agent ignores the unknown keys.
	//
	// These ride at the ENVELOPE trust level (authenticated TLS, like OrgID
	// and Tenancy). The same two facts are also bound into the SIGNED
	// EnrolmentGrant for an idp mint, so a node holding a grant prefers the
	// signed copy and treats these as the fallback (see
	// orgclient.GrantOffer).
	ConsentMode  string `json:"consent_mode,omitempty"`
	ConsentActor string `json:"consent_actor,omitempty"`

	// Grant is the OPTIONAL enrolment grant (admin-controlled Plane B,
	// docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §2.3/§2.4):
	// the bounded authority this organization is OFFERING the enrolling
	// node. omitempty on both sides of the compat invariant: a
	// pre-governance server omits it (the node enrols ungoverned, exactly
	// as today), and a pre-governance agent ignores the unknown key.
	//
	// It is an OFFER, not a fact: the node writes a grant row only after
	// (a) the org policy key was pinned in this same enrolment, (b) the
	// signature verifies under that key, and (c) a human confirmed it on a
	// TTY (or --accept-governance was passed). Any of those failing means
	// the node enrols WITHOUT governance and says so loudly.
	Grant *EnrolmentGrant `json:"grant,omitempty"`
}

// Tenancy classes carried on EnrollResponse.Tenancy and stored both server-
// side (enrolment_tokens.tenancy) and node-side (org_enrolment.tenancy). The
// empty string is treated as TenancyIndividual everywhere so a pre-managed
// server or a pre-084 node behaves exactly as an individual node.
const (
	TenancyIndividual = "individual"
	TenancyManaged    = "managed"
)

// ValidTenancy reports whether s is a recognised tenancy class. The empty
// string is INVALID here (callers normalise it to TenancyIndividual first);
// this is the mint-time check that refuses an unknown class.
func ValidTenancy(s string) bool {
	return s == TenancyIndividual || s == TenancyManaged
}

// ManagedBindRequest is the body of POST /api/agent/managed-bind, the SECOND
// step of managed enrolment (Arc 4 P6a, plan §9). A node that enrolled under
// TenancyManaged presents its org-salted machine fingerprint so the server can
// bind one managed node to one machine and surface a collision to the admin.
// An individual/BYO node NEVER calls this endpoint and never computes a
// fingerprint — the individual plane sends no machine identity at all, which is
// why this rides its own bearer-authenticated request rather than a field on
// EnrollRequest.
//
// MachineIdentity is the opaque, one-way, org-salted hash from
// internal/machineid.ForOrg — never the raw OS machine id. The agent skips the
// call entirely (rather than sending "") on a host with no stable source, so a
// non-empty value is expected here.
type ManagedBindRequest struct {
	MachineIdentity string `json:"machine_identity"`
}

// ManagedBindResponse is the 200 body of POST /api/agent/managed-bind. Status
// is one of the ManagedBind* values. Collision is true only when the machine
// was already bound to a DIFFERENT active developer: under the server's
// "record" posture the bind still succeeds (evidence, not prevention) and
// Status is ManagedBindCollision, while under "enforce" the server returns 409
// instead of this body.
type ManagedBindResponse struct {
	Status    string `json:"status"`
	Collision bool   `json:"collision"`
}

// ManagedBind* are the ManagedBindResponse.Status values.
const (
	ManagedBindBound      = "bound"      // first binding for this (org, machine)
	ManagedBindRebound    = "rebound"    // same developer re-enrolling the same machine
	ManagedBindReassigned = "reassigned" // prior binding's developer deprovisioned; machine reassigned
	ManagedBindCollision  = "collision"  // machine already bound to a different ACTIVE developer (record posture)
)

// ManagedIntegrityReport is the body of POST /api/agent/managed-integrity, the
// Arc 4 P6b managed-integrity probe (plan §9). A managed node periodically
// reports tamper-EVIDENCE of circumvention on its host: a second/parallel
// observer install (SiblingObservers) and AI-tool proxy routes that have
// drifted away from the managed proxy (RouteDrift). Like ManagedBind it rides
// its OWN bearer-authenticated request, NOT the push envelope: an individual/BYO
// node never computes or sends this, so the individual plane is untouched by
// construction.
//
// EVIDENCE, not prevention: the fingerprint, sibling DBs and route configs all
// live on a host the developer controls and are spoofable. True prevention is
// OS ownership/MDM (the §5 legal-ownership gate). The report gives the admin
// visibility of evasion, never a lock.
//
// Content-floor: only counts and COARSE labels cross the wire. SiblingDetail is
// origin/OS labels (e.g. "windows/wsl-mnt"); DriftedTools is adapter tool names
// (e.g. "claude-code", "codex"). No filesystem paths, usernames, or config
// values are ever included.
type ManagedIntegrityReport struct {
	MachineIdentity  string   `json:"machine_identity"`
	SiblingObservers int      `json:"sibling_observers"`
	SiblingDetail    []string `json:"sibling_detail,omitempty"`
	RouteDrift       int      `json:"route_drift"`
	DriftedTools     []string `json:"drifted_tools,omitempty"`
	// CaptureCheckVersion distinguishes an older node that never ran the
	// capture-behavior checks from a current node that ran them and found no
	// risk. CaptureRisks and UnknownChecks are closed, content-free labels.
	CaptureCheckVersion int      `json:"capture_check_version,omitempty"`
	CaptureRisks        []string `json:"capture_risks,omitempty"`
	UnknownChecks       []string `json:"unknown_checks,omitempty"`
	// CaptureRiskItems names the tool and the hook file behind each capture
	// risk (T-847, tamper audit rows c1-c3). Additive and optional: an older
	// server drops the field, an older node never sends it, and the
	// CaptureRisks label list stays the closed summary every reader already
	// understands. See CaptureRiskItem for the content floor.
	CaptureRiskItems []CaptureRiskItem `json:"capture_risk_items,omitempty"`
	// CaptureRiskItemsOmitted is how many located risks the item bound left
	// out of CaptureRiskItems (T-873), so the organization can be told the
	// list is partial. The bound keeps the most actionable items
	// (CaptureRiskItemLess). Additive and optional like CaptureRiskItems: an
	// older server ignores the field (the decoder accepts unknown fields), and
	// an older node never sends it, which reads as zero.
	CaptureRiskItemsOmitted int `json:"capture_risk_items_omitted,omitempty"`
	// RoutesWritten names the AI tools whose proxy route Observer's
	// enrolment wrote for the first time within the last 24 hours (the CLI
	// enrol, or the managed daemon's route maintenance). Informational, never
	// a finding: a route put BACK after removal is the route_repaired capture
	// risk instead. Same closed vocabulary as DriftedTools. Additive and
	// optional: an older server ignores the field, an older node never sends
	// it.
	RoutesWritten []string `json:"routes_written,omitempty"`
	// UnroutableTools names the AI tools that are installed on this host,
	// not routed through the Observer proxy, and that Observer cannot route
	// here (no unattended route in the integration registry, or a config the
	// route writer does not cover), and that Observer never routed. It is
	// honest coverage, never drift. Same closed vocabulary and the same
	// additive rules as RoutesWritten.
	UnroutableTools []string `json:"unroutable_tools,omitempty"`
	// UnselectedTools names the AI tools that are installed on this host but
	// that the node's policy did not select (their adapter component is
	// available, not selected). Route maintenance never routes such a tool,
	// so it is never drift; the organization still sees it is there
	// ("installed, not selected by policy", T-915, D-770). Empty when the
	// admin turned route maintenance off. Same closed vocabulary and the same
	// additive rules as RoutesWritten: an older server ignores the field, an
	// older node never sends it.
	UnselectedTools []string `json:"unselected_tools,omitempty"`
	// RoutingOff is true when the node's route writer component
	// (integration.proxy-route) is not active, switched off by policy or not
	// in this build at all: the daemon then keeps no routes and no tool's
	// route is drift (T-915, D-771). RoutingOffTools names the installed AI
	// tools so the organization can see what routing would cover. Both are
	// false/empty when the admin turned route maintenance off. Additive like
	// RoutesWritten: an older server ignores them, an older node never sends
	// them.
	RoutingOff      bool     `json:"routing_off,omitempty"`
	RoutingOffTools []string `json:"routing_off_tools,omitempty"`
	// SupervisorMissing is true when the daemon keeps AI tool routes through
	// its proxy (the managed route posture is "maintain") and no process
	// supervisor was found to restart it (internal/supervisor: the systemd,
	// launchd or Windows service templates in deploy/supervisor/). The routes
	// stay in the tools' configs while the daemon is down, so those tools
	// then get ConnectionRefused until someone restarts it. A warning only:
	// nothing is refused. Additive: an older server ignores it.
	SupervisorMissing bool `json:"supervisor_missing,omitempty"`
	// RouteObservationVersion says whether this report carries the node's
	// per-surface traffic verdict (surface-gap arc Wave 1, OBS-6): 0 means
	// not reported (an older node, or a node that could not read its own
	// sessions), ManagedRouteObservationVersion means UnroutedSurfaces is
	// the complete answer, so an empty list is a clean reading. Deliberately
	// NOT omitempty, so a current node always states which one it sent; an
	// older node never sends the key, which decodes as 0, never as clean.
	RouteObservationVersion int `json:"route_observation_version"`
	// UnroutedSurfaces names the routable capture surfaces this node ran
	// sessions on, inside routeattest.ObservedWindow, that did not reach its
	// proxy (routeattest.SurfaceVerdict.ObservedBypass: bypass_suspect or
	// partial), as closed "tool/surface_kind" labels (UnroutedSurfaceLabel).
	// No host, path or count crosses. Additive: an older server ignores it.
	UnroutedSurfaces []string `json:"unrouted_surfaces,omitempty"`
	// ConfigLayerVersion says whether this report carries the node's
	// settings-layer reading (surface-gap arc decision DEC-7, findings CLI-5
	// and OBS-9): 0 means not reported (an older node, or a node that could
	// not read its project roots or run the effective-layer evaluator),
	// ManagedConfigLayerVersion means HookDisabledTools and ConfigLayerRisks
	// are the complete answer, so two empty lists are a clean reading.
	// Deliberately NOT omitempty, like RouteObservationVersion: an older node
	// never sends the key, which decodes as 0, never as clean.
	ConfigLayerVersion int `json:"config_layer_version"`
	// HookDisabledTools names the AI tools whose Observer hooks a vendor
	// settings layer (user, system, managed, project or environment) switches
	// off, read by the hook-off detection (internal/hookdisable through
	// diag.HookSwitchInputs). A switch that only stops a host replaying
	// another tool's hooks is not counted. Closed tool ids only
	// (ConfigLayerTools), never a path, key or value. Additive: an older
	// server ignores it.
	HookDisabledTools []string `json:"hook_disabled_tools,omitempty"`
	// ConfigLayerRisks names what the effective-layer evaluator
	// (agentconfig.EvaluateLayers) found that weakens capture or routing, as
	// closed "tool/finding" labels (ConfigLayerRiskLabel): a project or
	// higher layer that outranks Observer's route, a layer that turns hooks
	// off or replaces Observer's hook array, a sign-in mode that pins the
	// vendor host, an inactive provider. Informational findings
	// (hooks_off_overridden, mcp_first_file_only, provider_unverified) do not
	// cross. No file, project, key or value crosses. Additive: an older
	// server ignores it.
	ConfigLayerRisks []string `json:"config_layer_risks,omitempty"`
	// InactiveProviderTools names the AI tools whose proxy route Observer
	// wrote is in the config file but whose active provider is another one,
	// so their turns do not reach the proxy (proxyroute.RouteInactiveProvider,
	// surface-gap CLI-3). Its own drift-table row, never drift. Same closed
	// vocabulary as DriftedTools. Route coverage like UnroutableTools, with no
	// version of its own: an older server ignores it and an older node never
	// sends it (that node's ConfigLayerVersion 0 already reads not reported).
	InactiveProviderTools []string `json:"inactive_provider_tools,omitempty"`
}

// ManagedRouteObservationVersion is the per-surface route observation
// vocabulary this binary reports (ManagedIntegrityReport.
// RouteObservationVersion). Unsupported versions read as not reported.
const ManagedRouteObservationVersion = 1

// ManagedConfigLayerVersion is the settings-layer vocabulary this binary
// reports (ManagedIntegrityReport.ConfigLayerVersion). Unsupported versions
// read as not reported.
const ManagedConfigLayerVersion = 1

// CaptureRiskItem is one capture risk located on a hook artifact: the closed
// risk label, the registration target that owns the artifact and a
// home-relative label for the file.
//
// Content floor: Tool is an adapter registration target id (a closed-shape
// token such as "cursor" or "claude-code-windows"); File is a label, never an
// absolute path: "~/" plus the path under the developer's home, "~win/" plus
// the path under a Windows home seen from WSL, or "?/" plus the last two path
// elements when the file sits outside any home. No user name, no value read
// from the file. Events names the native hook events involved, when the probe
// knows them. NormalizeLabels enforces all of it on both sides.
//
// At (T-886) is when an ACT happened, RFC3339 UTC: the repair time of a
// hook_repaired item, the failure time of a hook_registration_failed one. It
// is set only on an act label (captureRiskClasses); normalization blanks it on
// a standing label and on a value that does not parse. The server reads a new
// At on an item it already saw as a new occurrence of the act (OccurrenceKey),
// so a repeat repair is a new event. Additive: an older server ignores the
// field and an older node never sends it, which keeps the Key-only reading.
//
// KeptCopy (T-884) is where a hook_repaired act kept the bytes it replaced, a
// label under the same floor as File. Like At it belongs to the act:
// normalization blanks it on a standing label and on an invalid label, and the
// known-risk memory drops it. Additive and optional like At, and not part of
// Key or OccurrenceKey.
type CaptureRiskItem struct {
	Risk     string   `json:"risk"`
	Tool     string   `json:"tool,omitempty"`
	File     string   `json:"file,omitempty"`
	Events   []string `json:"events,omitempty"`
	At       string   `json:"at,omitempty"`
	KeptCopy string   `json:"kept_copy,omitempty"`
}

// CaptureRiskChange is a CaptureRiskItem the SERVER first saw at FirstSeen
// (RFC3339) on a node that had already reported. It is derived server-side by
// comparing a report with the one before it and is never sent by a node.
type CaptureRiskChange struct {
	CaptureRiskItem
	FirstSeen string `json:"first_seen"`
}

// ManagedCaptureCheckVersion is the capture-behavior check vocabulary this
// binary reports. Unsupported versions remain unreported until the server can
// interpret their complete vocabulary.
const ManagedCaptureCheckVersion = 1

// Closed capture-risk labels. These describe positive host observations only;
// they never infer why a file or registration changed.
const (
	CaptureRiskHookRegistrationError = "hook_registration_error"
	CaptureRiskHookBinaryMismatch    = "hook_binary_mismatch"
	CaptureRiskHookConfigMissing     = "hook_config_missing"
	CaptureRiskCodexHookUntrusted    = "codex_hook_untrusted"
	CaptureRiskHookConfigChanged     = "hook_config_changed"
	// CaptureRiskAgentConfigDrift: a setting the org's AI tool policy
	// enforces no longer holds its value on this node (adapter config P7).
	// The detail rides PushEnvelope.AgentConfigState. Additive: an older
	// server drops the unknown label (NormalizeLabels), never the report.
	CaptureRiskAgentConfigDrift = "agent_config_drift"
	// The T-847 labels (tamper audit c1-c3). Additive like
	// agent_config_drift: an older server drops a label it does not know.
	//
	// CaptureRiskHookRegistrationDrift: a dry run of the node's own
	// idempotent auto-registration would add or rewrite Observer hook
	// entries, so a registered hook is missing or weakened (an event
	// removed, a matcher narrowed, the command changed) whatever the
	// checksum registry says.
	CaptureRiskHookRegistrationDrift = "hook_registration_drift"
	// CaptureRiskHookRegistryMissing: hook_checksums.json is gone while the
	// node has hooks it registers. Before T-847 this was only the unknown
	// check of the same name, so deleting the registry made a node look
	// healthier (audit c3).
	CaptureRiskHookRegistryMissing = "hook_registry_missing"
	// CaptureRiskHookRegistryEntryMissing: a detected registration target
	// has no entry in hook_checksums.json.
	CaptureRiskHookRegistryEntryMissing = "hook_registry_entry_missing"
	// CaptureRiskHookRepaired: auto-registration re-added or rewrote a hook
	// entry that was registered before (reported for 24 hours after the
	// repair, so a hook removed and healed between two reports is still
	// visible).
	CaptureRiskHookRepaired = "hook_repaired"
	// CaptureRiskHookRegistrationFailed (T-887): a registration pass on the
	// artifact ended in error (a refused repair of a file Observer does not
	// own, a write failure) within the last 24 hours, and the error has
	// since cleared. Reported for 24 hours after the failure, like
	// hook_repaired, so a failure fixed before the next ACCEPTED report (an
	// org outage) still reaches the organization. While the error holds,
	// hook_registration_error is reported instead. An act: the item carries
	// the failure time (CaptureRiskItem.At). Additive: an older server drops
	// the label, an older node never sends it.
	CaptureRiskHookRegistrationFailed = "hook_registration_failed"
	// CaptureRiskRouteRepaired (lane P1): on a managed node whose
	// organization governs an enforcement point in the API proxy, the
	// daemon's route maintenance put back an AI tool's proxy route that
	// Observer had written before and that was gone. Reported for 24 hours
	// after the repair, like hook_repaired; an act whose item carries the
	// repair time (CaptureRiskItem.At), the tool and a home-relative label of
	// the config file. Additive: an older server drops the label.
	CaptureRiskRouteRepaired = "route_repaired"
	// CaptureRiskRouteBypassObserved (surface-gap arc Wave 1, OBS-6): a
	// routable capture surface ran sessions inside routeattest.ObservedWindow
	// that did not reach this node's proxy; UnroutedSurfaces names them. A
	// standing condition, label-only (no located item). NormalizeLabels
	// derives it from UnroutedSurfaces on both sides, so it is present
	// exactly when that list is. Additive: an older server drops the label.
	CaptureRiskRouteBypassObserved = "route_bypass_observed" //nolint:gosec // G101: an enum value, not a credential
	// CaptureRiskHookSilentSurface (surface-gap arc Wave 5, OBS-7): a tool
	// with registered hooks captured sessions inside the doctor's liveness
	// window (hooks.liveness) on a surface where no hook ever fired, or none
	// at all. A standing condition, located on the tool only (no file): the
	// silent surfaces and session ids stay node-local, since per-session
	// org reach is decision D14. Additive: an older server drops the label.
	CaptureRiskHookSilentSurface = "hook_silent_surface"
	// The DEC-7 labels (surface-gap lane w4-wire). Each is a standing
	// condition, label-only (no located item), that NormalizeLabels derives
	// on both sides from its list (derivedCaptureRisks), so it is present
	// exactly when the list is. Additive: an older server drops a label it
	// does not know.
	//
	// CaptureRiskHookSwitchedOff: a vendor settings layer switches off the
	// hooks of the tools HookDisabledTools names.
	CaptureRiskHookSwitchedOff = "hook_switched_off"
	// CaptureRiskConfigLayerOverride: a settings layer decides against
	// Observer's route or hooks; ConfigLayerRisks names the tool and finding.
	CaptureRiskConfigLayerOverride = "config_layer_override"
	// CaptureRiskRouteInactiveProvider: a tool's active provider bypasses the
	// route Observer wrote; InactiveProviderTools names the tools.
	CaptureRiskRouteInactiveProvider = "route_inactive_provider"
	// The lane w6-governance labels (surface-gap arc Wave 6). Each is a
	// standing condition. Additive: an older server drops a label it does
	// not know (NormalizeLabels), and an older node never sends one.
	//
	// CaptureRiskShellWrapMissing (CLI-1b, D6): the organization keeps
	// command wrapping on for this managed node (node.governance pin
	// shell_wrap.org_maintain ON) and the wrap is not applied, so a bare
	// vendor command skips every launcher-only route. Label-only.
	CaptureRiskShellWrapMissing = "shell_wrap_missing"
	// CaptureRiskVendorPolicyBlocksMCP (S-15, D17): a cached vendor org
	// policy (Cline remote config, Factory org settings) keeps Observer's
	// MCP server from running in that tool. Located on the tool and a
	// home-relative label of the cache directory; no value read from the
	// cache crosses.
	CaptureRiskVendorPolicyBlocksMCP = "vendor_policy_blocks_mcp"
	// CaptureRiskVendorPolicyPinsRoute (S-15, D17): a cached vendor org
	// policy pins the tool's provider base URL to a host other than this
	// node's proxy, or vetoes a loopback route. Located like
	// CaptureRiskVendorPolicyBlocksMCP; the URL never crosses.
	CaptureRiskVendorPolicyPinsRoute = "vendor_policy_pins_route"
)

// Closed unknown-check labels. An unknown check is not a clean result and is
// surfaced separately from positive capture-risk observations.
const (
	CaptureUnknownRegistryMissing    = "hook_registry_missing"
	CaptureUnknownRegistryUnreadable = "hook_registry_unreadable"
	CaptureUnknownRegistryInvalid    = "hook_registry_invalid"
	CaptureUnknownRegistryEmpty      = "hook_registry_empty"
	CaptureUnknownConfigUnreadable   = "hook_config_unreadable"
	CaptureUnknownChecksumMissing    = "hook_checksum_missing"
	CaptureUnknownBinaryPath         = "running_binary_unknown"
	CaptureUnknownRecordedBinary     = "registered_binary_unknown"
	CaptureUnknownCodexTrust         = "codex_trust_unknown"
)

// ManagedIntegrityDetail is the versioned, bounded JSON persisted in the
// existing managed_integrity.detail column. It contains only server-normalized
// coarse labels and lets old rows remain readable without a schema migration.
type ManagedIntegrityDetail struct {
	CaptureCheckVersion int      `json:"capture_check_version,omitempty"`
	SiblingDetail       []string `json:"sibling_detail,omitempty"`
	DriftedTools        []string `json:"drifted_tools,omitempty"`
	CaptureRisks        []string `json:"capture_risks,omitempty"`
	UnknownChecks       []string `json:"unknown_checks,omitempty"`
	// CaptureRiskItems is the report's located risks (T-847).
	CaptureRiskItems []CaptureRiskItem `json:"capture_risk_items,omitempty"`
	// CaptureRiskItemsOmitted is how many located risks are not in
	// CaptureRiskItems: the node's bound plus any the server's size cap
	// trimmed (T-873). Zero on a row an older server wrote.
	CaptureRiskItemsOmitted int `json:"capture_risk_items_omitted,omitempty"`
	// RoutesWritten and UnroutableTools are the report's route coverage
	// labels (lane P1), stored as the node sent them after normalization.
	RoutesWritten   []string `json:"routes_written,omitempty"`
	UnroutableTools []string `json:"unroutable_tools,omitempty"`
	// UnselectedTools is the report's "installed, not selected by policy"
	// list (T-915), informational like the two above.
	UnselectedTools []string `json:"unselected_tools,omitempty"`
	// RoutingOff and RoutingOffTools are the report's "routing switched off
	// by policy" flag and the installed tools it names (D-771).
	RoutingOff      bool     `json:"routing_off,omitempty"`
	RoutingOffTools []string `json:"routing_off_tools,omitempty"`
	// SupervisorMissing is the report's supervisor warning (lane P1).
	SupervisorMissing bool `json:"supervisor_missing,omitempty"`
	// RouteObservationVersion and UnroutedSurfaces are the report's
	// per-surface traffic verdict (OBS-6), stored as normalized. The version
	// is not omitempty: a row an older server wrote lacks the key and reads
	// as 0, not reported, never as clean.
	RouteObservationVersion int      `json:"route_observation_version"`
	UnroutedSurfaces        []string `json:"unrouted_surfaces,omitempty"`
	// ConfigLayerVersion, HookDisabledTools, ConfigLayerRisks and
	// InactiveProviderTools are the report's settings-layer reading (DEC-7),
	// stored as normalized. The version is not omitempty for the same reason
	// as RouteObservationVersion: a row an older server wrote reads 0, not
	// reported.
	ConfigLayerVersion    int      `json:"config_layer_version"`
	HookDisabledTools     []string `json:"hook_disabled_tools,omitempty"`
	ConfigLayerRisks      []string `json:"config_layer_risks,omitempty"`
	InactiveProviderTools []string `json:"inactive_provider_tools,omitempty"`
	// RecentChanges are the located risks that appeared since an earlier
	// report, kept for ManagedIntegrityChangeWindow (server-derived).
	RecentChanges []CaptureRiskChange `json:"recent_changes,omitempty"`
	// KnownRisks is the server's bounded memory of every risk this machine
	// reported within ManagedIntegrityKnownWindow, with when it was last
	// reported (server-derived, never node-sent). It keeps a STANDING
	// condition that briefly vanished from a report (a deleted hash registry
	// hides the binary mismatches it would have found) from being raised as
	// a new event when it comes back. See DeriveCaptureRiskChanges.
	KnownRisks []KnownCaptureRisk `json:"known_risks,omitempty"`
}

// KnownCaptureRisk is one entry of ManagedIntegrityDetail.KnownRisks: a risk
// identity (a located item, or a label-only item for a bare label) and when
// the machine last reported it, RFC3339.
type KnownCaptureRisk struct {
	CaptureRiskItem
	LastSeen string `json:"last_seen"`
}

// ManagedIntegrityResponse is the 200 body of POST /api/agent/managed-integrity.
// The signal is fire-and-forget; the ack only confirms the server recorded it.
type ManagedIntegrityResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

// ManagedIntegrityState* are the derived health states surfaced on the admin
// Control Center. They are computed from a ManagedIntegrityReport via State();
// they are NOT sent on the wire (the node sends only the raw counts).
const (
	ManagedIntegrityOK         = "ok"               // no evidence of circumvention
	ManagedIntegritySibling    = "sibling_observer" // a parallel/second observer install detected
	ManagedIntegrityRouteDrift = "route_drift"      // AI-tool routes drifted off the managed proxy
	ManagedIntegrityBoth       = "both"             // both signals present
)

// State derives the Control Center health state from the report's counts. The
// ordering (both > either > ok) is what the admin badge renders.
func (r ManagedIntegrityReport) State() string {
	sibling := r.SiblingObservers > 0
	drift := r.RouteDrift > 0
	switch {
	case sibling && drift:
		return ManagedIntegrityBoth
	case sibling:
		return ManagedIntegritySibling
	case drift:
		return ManagedIntegrityRouteDrift
	default:
		return ManagedIntegrityOK
	}
}

// BearerClaims is the JSON envelope signed with the server's Ed25519 key.
// It is JWT-shaped but is not a JWT: there is no algorithm negotiation and
// no JWS library — one key type, one algorithm, decoded by hand. exp/iat
// are Unix seconds.
type BearerClaims struct {
	Iss string `json:"iss"` // issuer: the org server external URL
	Sub string `json:"sub"` // subject: the SCIM user id
	Aud string `json:"aud"` // audience: the org id
	Exp int64  `json:"exp"` // expiry, Unix seconds
	Iat int64  `json:"iat"` // issued-at, Unix seconds
	Jti string `json:"jti"` // unique token id (for the revocation list)
}

// PushEnvelope is the body of POST /api/agent/push (gzip-compressed on the
// wire). cursor_from/cursor_to bound the batch against the agent's local
// ingest cursor so the server can ACK a next_cursor and the agent can
// resume exactly once.
type PushEnvelope struct {
	AgentVersion string `json:"agent_version"`
	// MachineIdentity is the pushing node's org-salted machine fingerprint
	// (machineid.ForOrg — the SAME opaque value ManagedBindRequest and
	// PolicyStateReport carry), present ONLY for a node enrolled under
	// managed tenancy. It is ENVELOPE-level, not a per-row column: one push
	// comes from one machine, so repeating it on every session row would be
	// pure redundancy.
	//
	// The individual/BYO plane sends nothing here (orgclient's
	// ManagedMachineIdentity returns "" for an unmanaged enrolment, a host
	// with no stable machine id, or any load error), and omitempty keeps
	// those envelopes byte-identical to the pre-feature shape. The server
	// stamps it onto the sessions rows this push inserts, which is what
	// makes project_identity_signals.node_count a real count of MACHINES
	// rather than a copy of the developer count. Empty is "not tracked",
	// never "zero machines".
	MachineIdentity string `json:"machine_identity,omitempty"`
	// SourceNodeKey is the pushing DEVICE's stable identity for the managed-
	// node MCP relay ingest (doc3 §9.5, R8.28.g / R8.30.a): the lowercase hex
	// SHA-256 of the node's per-device agent-access public-key thumbprint
	// (SourceNodeKeyFromThumbprint). Distinct from the member-level agent
	// signing key push auth verifies and from MachineIdentity (managed-only,
	// org-salted). ENVELOPE-level like both: one push comes from one device.
	//
	// OPTIONAL both directions (the compat invariant): a pre-P4 agent sends
	// nothing and the server keys its relay rows 'member:' || member_id
	// (MemberSourceNodeKey); a pre-P4 server ignores the key. The server
	// accepts a supplied value ONLY when it matches an ACTIVE kind='node'
	// agent_credential of the authenticated member - a node cannot spoof
	// another device's key (400). omitempty keeps a node without an
	// agent-access key on a byte-identical envelope.
	SourceNodeKey string `json:"source_node_key,omitempty"`
	// UpdatePosture is the OPTIONAL self-reported update state of this node
	// (Enterprise Update Management §3.5): version / channel / os / arch /
	// state / target / manifest version / error CLASS / install method /
	// auto-apply / extension version. No hostname, no paths, no free text —
	// see UpdatePostureRow in update.go for the field-by-field rationale and
	// the structural pin that keeps it that way.
	//
	// ENVELOPE-level like MachineIdentity, and for the same reason: one push
	// comes from one node, so this is one fact about the pusher, not a
	// per-row column. It is composed by internal/store/updateposture.go and
	// called BY orgpush.go, so the privacy sentinel keeps forbidding the
	// node-local update_state / update_events table names inside that seam.
	//
	// omitempty keeps a pre-feature node's envelope BYTE-IDENTICAL to today's
	// accepted shape, and a pre-feature server ignores the unknown key — the
	// same compat invariant RoutingSummaries carries below.
	UpdatePosture *UpdatePostureRow `json:"update_posture,omitempty"`
	CursorFrom    int64             `json:"cursor_from"`
	CursorTo      int64             `json:"cursor_to"`
	Sessions      []SessionRow      `json:"sessions"`
	Actions       []ActionRow       `json:"actions"`
	APITurns      []APITurnRow      `json:"api_turns"`
	TokenUsage    []TokenUsageRow   `json:"token_usage"`
	// Deletions are the node's TOMBSTONES for cursor-wire rows it deleted as
	// a correction after pushing them (agent migration 141, lane R2-TOMB):
	// a dedup repair, a moved row, a retired identity. Node-local ageing
	// (retention) never produces one. The org deletes its copy only when the
	// copy's node_rev is OLDER than the tombstone's NodeRev (see
	// PushDeletion). OPTIONAL both directions: a pre-141 agent sends none, a
	// pre-R2-TOMB server ignores the key (and keeps the rows, exactly the old
	// behaviour); omitempty keeps an envelope without deletions
	// byte-identical to the previous shape.
	Deletions []PushDeletion `json:"deletions,omitempty"`
	// SessionManifests are the `observer org resync --deletions` HEAL for rows
	// deleted before tombstones existed: per session, a digest of every row
	// identity the node still holds, so the org removes the rows it holds for
	// that session that the node no longer does (see SessionManifest).
	// OPTIONAL both directions like Deletions.
	SessionManifests []SessionManifest `json:"session_manifests,omitempty"`
	// RoutingSummaries is the OPTIONAL §R19.4 aggregate (counts +
	// dollars by tier/reason only) — present only when the node
	// operator opted in via [org_client.share] routing_summary.
	// Optional both directions: v1.8.x servers ignore the key,
	// future servers tolerate its absence.
	RoutingSummaries []RoutingSummaryRow `json:"routing_summaries,omitempty"`

	// CacheSummaries is the OPTIONAL Arc 4 P5c cache-detail aggregate
	// (day × model × kind counts + tokens + cost delta only), present
	// only when the node ships the cache_detail tier (opt-in individual /
	// admin-raised managed). Optional both directions like RoutingSummaries.
	CacheSummaries []CacheSummaryRow `json:"cache_summaries,omitempty"`

	// CodeintelSummaries is the OPTIONAL Arc 4 P5f codeintel-detail aggregate
	// (per project-hash × language file/symbol/edge counts only), present only
	// when the node ships the codeintel_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.codeintel authority). No
	// symbol name, fqn, signature, or raw path ever crosses. Optional both
	// directions like RoutingSummaries.
	CodeintelSummaries []CodeintelSummaryRow `json:"codeintel_summaries,omitempty"`

	// ProcessSummaries is the OPTIONAL Arc 4 P5g process-detail aggregate
	// (per day × tool run/exit/duration counts only), present only when the
	// node ships the process_detail tier (opt-in individual / admin-raised
	// managed via the DISTINCT extract.process authority). No exe path, argv,
	// cwd, network body, or hash ever crosses. Optional both directions like
	// RoutingSummaries.
	ProcessSummaries []ProcessSummaryRow `json:"process_summaries,omitempty"`

	// SessionVerbositySummaries carries the W3.1 output-composition summary,
	// one row per session (byte totals by category + language split, never
	// content) — session-scoped enterprise wire, present only under
	// shipsRawContent() (full_content / admin_managed). Optional both
	// directions like RoutingSummaries. See internal/orgcontract/verbosity.go.
	SessionVerbositySummaries []SessionVerbosityRow `json:"session_verbosity,omitempty"`

	// SessionLOC carries the Lines-of-Code per-session AGGREGATE (one row per
	// session × project root: line counts by actor, the classifier version and
	// the human-capture flag). Unlike the session-scoped wires around it, this
	// one rides the DEFAULT metadata-only posture — a count of lines written is
	// the same disclosure class as SessionRow.TotalActions. The one field
	// gated on shipsRawContent() is the row's own LanguageMixJSON. Composed by
	// store.SelectSessionLOCSummaries (internal/store/locsummary.go, a separate
	// file so orgpush.go never names file_changes). Optional both directions
	// like RoutingSummaries. See internal/orgcontract/loc.go.
	SessionLOC []SessionLOCRow `json:"session_loc,omitempty"`

	// LOCDays carries the day-bucketed (day, project root) line-count
	// aggregate — the carrier for editor-reported human work that happens
	// outside any session (plan §2). Same default posture as SessionLOC.
	LOCDays []LOCDayRow `json:"loc_days,omitempty"`

	// SessionQuality carries the per-session quality score (BL2-ORG), one row
	// per session the node's scorer has written, windowed on scored_at so a
	// score that lands after its sessions row already shipped still goes out.
	// Derived numbers only, so it rides the DEFAULT metadata posture like
	// SessionLOC. Composed by store.SelectSessionQualityRows
	// (internal/store/sessionqualitysummary.go). Optional both directions: an
	// older server ignores the key, an older agent omits it. See
	// internal/orgcontract/sessionquality.go.
	SessionQuality []SessionQualityRow `json:"session_quality,omitempty"`

	// CommitOwnership carries commit ownership (lane F-PROJ): one row per
	// (project root, commit) this node's AI sessions contributed to, with the
	// owning session, the ranked contributors and their shares, plus an
	// identity-only row for a commit that fell out of HEAD. Ids and counts
	// ride the DEFAULT metadata posture like SessionLOC; the commit Subject is
	// gated on shipsRawContent(); no author identity and no path ever ship.
	// Composed by store.SelectCommitOwnershipRows
	// (internal/store/commitownersummary.go), so orgpush.go never names the
	// node-local commit tables. Optional both directions: an older server
	// ignores the key, an older agent omits it. See
	// internal/orgcontract/commitowner.go.
	CommitOwnership []CommitOwnershipRow `json:"commit_ownership,omitempty"`

	// DeliveryDays carries the delivery (commit to PR to merge) daily counts
	// from every node; PullRequests carries PR identity rows ONLY under
	// ShareOptions.shipsRawContent(). Composed by
	// store.SelectDeliveryWireRows (internal/store/deliverysummary.go). An
	// older server ignores both keys, an older agent omits them. See
	// internal/orgcontract/delivery.go.
	DeliveryDays []DeliveryDayRow `json:"delivery_days,omitempty"`
	PullRequests []PullRequestRow `json:"pull_requests,omitempty"`

	// SessionCacheSummaries carries the W2.1 session-scoped cache summary
	// (per session × model × kind × cause counts + token sums, no content) —
	// present only under shipsRawContent() (full_content / admin_managed);
	// the fleet day-aggregate CacheSummaries above is the separate teams-tier
	// surface. Optional both directions. See internal/orgcontract/cachesession.go.
	SessionCacheSummaries []SessionCacheRow `json:"session_cache,omitempty"`

	// SessionCacheEvents carries the PER-EVENT cache timeline (one row per
	// node cache_events row, capped per session) — the substrate the org
	// drawer feeds to the SAME cachetrack.BuildTimeline the node uses, so the
	// two Cache tabs cannot drift. Present only under shipsRawContent()
	// (full_content / admin_managed / enterprise-granted), the SessionCache
	// posture and deliberately NOT the teams-tier cache_detail flag, which
	// gates the content-free FLEET aggregate above and stays orthogonal in
	// both directions. The node's `detail` diagnostic JSON, the cache scope /
	// prefix hashes and the node-local anchor ids are all excluded by
	// construction. Composed by store.SelectSessionCacheEvents, which owns the
	// node-local read — orgpush.go names no cache_* table. Optional both
	// directions. See internal/orgcontract/cacheeventsession.go.
	SessionCacheEvents []SessionCacheEventRow `json:"session_cache_events,omitempty"`

	// SessionProcesses is the W2.2 session-scoped RAW process-run wire (one
	// row per process run: exe/cwd/argv-preview/metrics, capped per session
	// at push time) — present only under shipsRawContent() (full_content /
	// admin_managed); the fleet ProcessSummaries above stays the content-free
	// teams tier. Optional both directions. See
	// internal/orgcontract/processsession.go.
	SessionProcesses []SessionProcessRow `json:"session_processes,omitempty"`

	// SessionNetworkEvents is the W2.2b session-scoped RAW network-egress wire
	// (one row per process_events network row, joined to its optional
	// process_network_bodies excerpt when a plaintext capture source produced
	// one; capped per session at push time) — present only under
	// shipsRawContent() (full_content / admin_managed). Every network event
	// ships regardless of body availability — a non-proxied TLS connection is
	// metadata-only BY CAPTURE, never an omission. See
	// internal/orgcontract/networksession.go.
	SessionNetworkEvents []SessionNetworkEventRow `json:"session_network_events,omitempty"`

	// SessionTaskItems / SessionTaskTransitions are the W2 session task/todo
	// checklist wires (node session-detail trickle-up plan §2 "W2"), present
	// only when the node ships the task_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.tasks authority). The
	// status vocabulary, counters and transitions ship under that tier alone;
	// each item's PROSE (content/active_form/owner) additionally requires the
	// node's raw-content posture. Composed by store.SelectSessionTaskItems /
	// SelectSessionTaskTransitions, which own the node-local read — orgpush.go
	// names the task_* tables nowhere. Optional both directions like
	// RoutingSummaries. See internal/orgcontract/taskflowsession.go.
	SessionTaskItems       []SessionTaskItemRow       `json:"session_task_items,omitempty"`
	SessionTaskTransitions []SessionTaskTransitionRow `json:"session_task_transitions,omitempty"`

	// SessionToolAccounts is the W3 vendor-login observation wire (§2 "W3"),
	// present only when the node ships the tool_account_detail tier (opt-in
	// individual / admin-raised managed via the DISTINCT extract.tool_accounts
	// authority). Binding enums + the opaque account_key ship under that tier
	// alone; the raw identity (email/name/account_id) additionally requires
	// the node's raw-content posture (decision D2). Composed by
	// store.SelectSessionToolAccounts, which owns the node-local read.
	// Optional both directions. See internal/orgcontract/toolaccountsession.go.
	SessionToolAccounts []SessionToolAccountRow `json:"session_tool_accounts,omitempty"`

	// SessionHookActivity is the per-session hook liveness wire (surface-gap
	// DEC-5), present only when the node ships the hook_activity tier (opt-in
	// individual / admin-raised managed via extract.hook_activity or the
	// umbrella). Counts and coarse env classes ship under that tier alone; a
	// content-level env class (the CLAUDE_CONFIG_DIR hash) additionally
	// requires the node's raw-content posture. Composed by
	// store.SelectSessionHookActivity. Optional both directions: an older
	// server ignores the key. See internal/orgcontract/hookactivity.go.
	SessionHookActivity []HookActivitySessionRow `json:"session_hook_activity,omitempty"`

	// --- Org-parity Wave-3 per-developer enterprise wires. All ride
	// shipsRawContent() (full_content / admin_managed) like the session-
	// scoped wires above; each row type documents its own posture. All
	// optional both directions (older servers ignore, older agents omit).
	// See docs/plans/org-parity-full-depth-plan-2026-08-24.md §4. ---

	// AdvisorSuggestions is the W3.2 Suggestions/Advisor wire: one row per
	// active suggestion in the node's advisor digest, enterprise-raw
	// (paths/commands/evidence verbatim). See advisor.go.
	AdvisorSuggestions []AdvisorSuggestionRow `json:"advisor_suggestions,omitempty"`
	// ProjectPatterns is the W3.3 Discovery/Patterns wire: one row per
	// project × pattern kind × value, raw paths/commands. See patterns.go.
	ProjectPatterns []ProjectPatternRow `json:"project_patterns,omitempty"`
	// BenchmarkRuns / BenchmarkAttempts are the W3.4 wire: per-(run,config)
	// aggregates + terminal attempts (task prompts / judge rationales /
	// answer excerpts raw). See benchmark.go.
	BenchmarkRuns     []BenchmarkRunRow     `json:"benchmark_runs,omitempty"`
	BenchmarkAttempts []BenchmarkAttemptRow `json:"benchmark_attempts,omitempty"`
	// CompressionStats is the W3.5 wire: day × mechanism honest byte deltas
	// (saved vs evicted kept structurally separate). See compression.go.
	CompressionStats []CompressionStatRow `json:"compression_stats,omitempty"`
	// RoutingDevRows / CodeintelDevRows are the W2.3/W2.4 per-developer
	// variants of the teams-tier fleet aggregates (which stay untouched).
	// See routingdev.go / codeinteldev.go.
	RoutingDevRows   []RoutingDevRow   `json:"routing_dev,omitempty"`
	CodeintelDevRows []CodeintelDevRow `json:"codeintel_dev,omitempty"`
	// TerminalRuns / TerminalCommands / RemoteAudit are the W2.6 per-dev
	// terminal + remote-access visibility wires (command identity is
	// hash-only BY CAPTURE — the node never stores raw command text; peer
	// addresses raw). See terminaldev.go.
	TerminalRuns     []TerminalRunRow     `json:"terminal_runs,omitempty"`
	TerminalCommands []TerminalCommandRow `json:"terminal_commands,omitempty"`
	RemoteAudit      []RemoteAuditRow     `json:"remote_audit,omitempty"`
	// GuardPins / GuardApprovals are the W5.2 guard pin + exception-approval
	// current-state snapshots. See guardpins.go.
	GuardPins      []GuardPinRow      `json:"guard_pins,omitempty"`
	GuardApprovals []GuardApprovalRow `json:"guard_approvals,omitempty"`

	// TerminalSummaries + RemoteAuditSummaries are the OPTIONAL Arc 4 P5h
	// terminal-detail aggregates (per day×tool×kind terminal run/command counts,
	// and per day×kind×decision×principal remote-audit event counts), present
	// only when the node ships the terminal_detail tier (opt-in individual /
	// admin-raised managed via the DISTINCT extract.terminal authority). No
	// command, hash, session id, peer address, or route ever crosses. The
	// terminal_* / remote_audit raw tables stay pinned out of the wire; only
	// these aggregates cross, under this explicit tier. Optional both directions
	// like RoutingSummaries.
	TerminalSummaries    []TerminalSummaryRow    `json:"terminal_summaries,omitempty"`
	RemoteAuditSummaries []RemoteAuditSummaryRow `json:"remote_audit_summaries,omitempty"`
	// SandboxPosture + SandboxCapability are the OPTIONAL sandbox posture
	// aggregate (sandbox plan v2 section 8.4): per-day run counts by the
	// closed isolation and capture enums, and the node's capability enums.
	// Shipped under the terminal_detail tier, and only while the Sandboxes and
	// VMs module is active on the node. See sandboxposture.go. Optional both
	// directions.
	SandboxPosture    []SandboxPostureRow   `json:"sandbox_posture,omitempty"`
	SandboxCapability *SandboxCapabilityRow `json:"sandbox_capability,omitempty"`
	// SecurityPosture / SecurityFindings / AIChangeRecords are the OPTIONAL
	// security pillar wire (security plan 7.4, lane SEC-E2), composed through
	// the SecurityOrgProviders seam only while the security module is active
	// and the share level allows (an individual node sends none until its
	// operator sets [org_client.share].security). Every field is tag-classed
	// and raw fields ship only under shipsRawContent(). See securityrows.go.
	// Optional both directions: an old server ignores the keys.
	SecurityPosture  []SecurityPostureRow `json:"security_posture,omitempty"`
	SecurityFindings []SecurityFindingRow `json:"security_findings,omitempty"`
	AIChangeRecords  []AIChangeRecordRow  `json:"ai_change_records,omitempty"`
	// MCPRelayActivity is the HMAC-only daily aggregate of this node's MCP
	// relay decisions (Agent Access P4 W4e, doc3 §9.5). An individual node
	// attaches it only under [org_client.share].mcp_activity (R8.30.b); an
	// enrolled teams/enterprise node attaches it by capture posture (R9.5).
	// Composed by internal/store/mcprelaysummary.go through the
	// internal/mcprelay/record seam - orgpush.go names no relay table.
	// Optional both directions like RoutingSummaries.
	MCPRelayActivity []MCPRelayActivityRow `json:"mcp_relay_activity,omitempty"`
	// MCPRelayEvents are the per-record relay events (decision / completion /
	// gap / gap_resolution, R14.5), attached ONLY under shipsRawContent() -
	// the enrolled teams/enterprise L2 posture - and never on an individual
	// node. A CURSOR wire (PushCursor.MCPRelay) like GuardEvents: the server
	// de-dupes on (source_node_key, local_record_seq, record_kind).
	MCPRelayEvents []MCPRelayEventRow `json:"mcp_relay_events,omitempty"`
	// MCPInventory is the node's configured-MCP-server inventory (Agent
	// Access P11 item (c), R12.10 / R13.8 / R14.6; mcpinventory.go): FULL
	// under shipsRawContent(), REDUCED (identity + metadata, no raw locator)
	// otherwise; an individual node attaches it only under
	// [org_client.share].mcp_activity. Composed by
	// internal/store/mcpinventory.go through the MCPInventoryProviders seam.
	// Optional both directions like RoutingSummaries.
	MCPInventory []MCPInventoryRow `json:"mcp_inventory,omitempty"`

	// RoutingDetails is the OPTIONAL Arc 4 P5d routing-detail aggregate
	// (model-id-bearing per-decision rollup), present only when the node
	// ships the routing_detail tier (opt-in individual / admin-raised
	// managed). Optional both directions like RoutingSummaries.
	RoutingDetails []RoutingDetailRow `json:"routing_details,omitempty"`

	// LimitGauges is the OPTIONAL Arc 4 P5e predictions aggregate (per day ×
	// provider rate-limit utilization), present only when the node ships the
	// limit_gauge tier (opt-in individual / admin-raised managed). Optional
	// both directions like RoutingSummaries.
	LimitGauges []LimitGaugeRow `json:"limit_gauges,omitempty"`

	// SessionLimitSnapshots is the OPTIONAL per-session rate-limit window wire
	// (lane F-WIRE): the newest proxy-captured 5h / 7d window observation per
	// (session, provider) above the node's limit-snapshot cursor, so the org
	// session drawer renders the node's "% of limit spent" gauge. Metadata
	// only; ships under the limit_gauge tier or on a full-capture node.
	// Composed by store.SelectSessionLimitSnapshots
	// (internal/store/limitgauge.go, so orgpush.go never names
	// limit_snapshots). Optional both directions like RoutingSummaries. See
	// internal/orgcontract/limitsnapshot.go.
	SessionLimitSnapshots []SessionLimitSnapshotRow `json:"session_limit_snapshots,omitempty"`

	// GuardEvents are guard-layer verdict rows (v1.8.3+, guard spec
	// §14.3). omitempty keeps pre-guard envelopes byte-identical and
	// lets pre-guard servers ignore the key entirely (the standard
	// additive-compat posture: no required new fields in either
	// direction). Server-side ingest + rollups land with the G14
	// teams arc; until then an old server ACKs the batch and the
	// guard rows are simply not retained centrally.
	GuardEvents []GuardEventRow `json:"guard_events,omitempty"`

	// OTelContent are native-OTel content bodies (native-console Phase 2b,
	// v1.8.x+). Same additive-compat posture as GuardEvents: omitempty so
	// pre-feature envelopes stay byte-identical and an older server ignores
	// the key (ACKs the batch; content simply isn't retained centrally).
	// Present only when the node shares full content (full_content /
	// admin_managed) for the raw body — the hash ships regardless.
	OTelContent []OTelContentRow `json:"otel_content,omitempty"`

	// Org-tier observability (internal/obs) — the tiered, independently
	// node-opt-in disclosure ladder (docs/plans/obs-org-tier-plan-2026-06-29.md
	// §1). Each slice is present only under its own [org_client.share] flag
	// (default false, never server-forced) and is composed via the obs
	// provider seam in orgpush.go (which names no obs_* table — the privacy
	// sentinel stays green, like routing_summaries). Same additive-compat
	// posture as the other optional slices: pre-feature servers ignore the
	// keys, future servers tolerate their absence.
	//
	// T1 — aggregate rollup (counts + token/cost/latency sums; content-free).
	ObsSummaries []ObsSummaryRow `json:"obs_summaries,omitempty"`
	// T2 — trace + span STRUCTURE (topology/kind/name/model/tokens/cost/
	// latency/status/request_id; hashes only, never bodies).
	ObsTraces     []ObsTraceRow     `json:"obs_traces,omitempty"`
	ObsSpans      []ObsSpanRow      `json:"obs_spans,omitempty"`
	ObsSpanEvents []ObsSpanEventRow `json:"obs_span_events,omitempty"`
	// T3 — raw span CONTENT bodies (prompt/response/tool_io); content present
	// only under shipsRawContent(), content_hash always.
	ObsContent []ObsContentRow `json:"obs_content,omitempty"`
	// T4 — eval run health (summaries + scores; content-free).
	ObsEvalRuns []ObsEvalRow `json:"obs_eval_runs,omitempty"`
	// T5 — per-END-USER spend (org-budget guardrails plan §2.1). End-user
	// PII: present ONLY under ObsSummary AND shipsRawContent(), off by
	// default, never server-forced (same additive-compat posture as the
	// other optional slices).
	ObsEndUserSpend []ObsEndUserSpendRow `json:"obs_enduser_spend,omitempty"`
	// T6 — input-admission verdicts + policy snapshots (Plane-A admission
	// org tier, gap-audit 2026-07-10 §2.1 / #1a). Present only under the
	// node's own [org_client.share.obs] admission opt-in (default false,
	// never server-forced). Same additive-compat posture as the other
	// optional slices: pre-feature servers ignore the keys, future servers
	// tolerate their absence. Verdict PII/prose (Tenant/EndUser/
	// ReasonExcerpt) is gated by shipsRawContent(); policy Body always ships.
	ObsAdmissionEvents   []ObsAdmissionRow       `json:"obs_admission_events,omitempty"`
	ObsAdmissionPolicies []ObsAdmissionPolicyRow `json:"obs_admission_policies,omitempty"`
	// T7 — per-item eval scores (Plane-A eval-run detail org tier, gap-audit
	// 2026-07-10 §1 / §2.2 / §6). Present only under the node's own
	// [org_client.share.obs] eval_items opt-in (default false, never
	// server-forced). Distinct from ObsEvalRuns (T4), which carries run/scorer
	// AGGREGATES only; this tier carries the per-item scores that let the org
	// Evals page drill into one run and diff two runs cell-for-cell. The
	// verdict METADATA is content-free and always ships; the item content
	// excerpts (input/expected/output/rationale) are gated by shipsRawContent().
	// Same additive-compat posture as the other optional slices.
	ObsEvalItems []ObsEvalItemRow `json:"obs_eval_items,omitempty"`
	// ObsEgressDecisions carries the T8 egress-routing decision feed (W5.3).
	// Populated only when the node has opted in via
	// [org_client.share.obs].egress (default false). Optional both directions.
	ObsEgressDecisions []ObsEgressRow `json:"obs_egress_decisions,omitempty"`

	// BudgetPosture is the OPTIONAL enum-only self-report of whether the org's
	// BUDGET is actually holding on this node (org-budget plan §3.3d): the
	// enforcement point, the guard's mode, where the effective numbers came
	// from, the last fetch's state, and the coverage limit. NO cap value and NO
	// resolved scope — see BudgetPostureRow in budgetposture.go for why.
	//
	// ENVELOPE-level like MachineIdentity and UpdatePosture, and for the same
	// reason: one push comes from one node, so this is one fact about the
	// pusher, not a per-row column. It is composed by
	// internal/store/budgetposture.go and called BY orgpush.go through a func
	// seam, the RoutingSummaries pattern.
	//
	// omitempty keeps a pre-feature node's envelope BYTE-IDENTICAL to today's
	// accepted shape, and a pre-feature server ignores the unknown key.
	BudgetPosture *BudgetPostureRow `json:"budget_posture,omitempty"`

	// ComponentPosture is the OPTIONAL enum-only component posture of this
	// node (modular packaging plan 6.4, T-682): distro, catalog version, the
	// compiled and active digests, the governance source, and the state and
	// reason of every component that is not active. See ComponentPostureRow
	// in componentposture.go. Envelope-level and composed through a store
	// func seam like BudgetPosture; omitempty keeps a pre-feature node's
	// envelope byte-identical, and a pre-feature server ignores the key.
	ComponentPosture *ComponentPostureRow `json:"component_posture,omitempty"`

	// AgentConfigState is a MANAGED node's applied state of the org's AI tool
	// settings policy (adapter config phase P7, agentconfigstate.go): one row
	// per setting and target file, closed enums plus value hashes. ENVELOPE-
	// level like BudgetPosture and composed the same way, through a func seam
	// (internal/store/agentconfigorgstate.go), so orgpush.go names no node
	// table. Nil on an individual node and on a managed node holding no
	// policy; omitempty keeps every other envelope byte-identical, and a
	// pre-feature server ignores the unknown key.
	AgentConfigState *AgentConfigStateReport `json:"agent_config_state,omitempty"`

	// AgentConfigInventory is a MANAGED node's whole AI tool configuration
	// (D-112, T-427, agentconfiginventory.go): every catalogued setting found
	// in its tools' settings files and every instruction-family file, values
	// and text scrubbed of secrets. Composed through a func seam
	// (internal/store/agentconfiginventory.go) like AgentConfigState, only
	// under raw content and only when it changed since the last accepted
	// push. omitempty keeps every other envelope byte-identical, and a
	// pre-feature server ignores the unknown key.
	AgentConfigInventory *AgentConfigInventoryReport `json:"agent_config_inventory,omitempty"`
}

// PushResponse is the 200 body of POST /api/agent/push.
type PushResponse struct {
	// QueuedRows is the total row count of the envelope the collector durably
	// queued onto the shared log (stateless-collectors-durable-log plan §4.3).
	// It is the honest answer a stateless collector CAN give: the collector
	// only enqueues, so it cannot yet know the true applied/deduped totals
	// (those move to ingest health, computed by the apply worker).
	//
	// Compat rule (plan §6 criterion 10): a pre-arc node ignores this unknown
	// key and reads accepted_rows, which the collector MIRRORS from
	// queued_rows so the node still advances its cursor exactly as before; a
	// post-arc node may prefer queued_rows. omitempty keeps a legacy
	// synchronous-ingest response (QueuedRows == 0) byte-identical to today's
	// shape, so no existing wire golden or client changes.
	QueuedRows   int64 `json:"queued_rows,omitempty"`
	AcceptedRows int64 `json:"accepted_rows"`
	DedupedRows  int64 `json:"deduped_rows"`
	NextCursor   int64 `json:"next_cursor"`

	// GrantReplacement is the OPTIONAL delivery seam for an out-of-band
	// authority change (Plane B dual-mode gateway/RBAC-IA design §5.3, Sol
	// S4). The push cycle is the ONLY node->server round trip that both
	// authenticates the calling node (claims.Sub) and always returns a body
	// (no 304), so it is the smallest existing seam to hand an already-
	// enrolled node its freshly-signed replacement. omitempty on both sides
	// of the compat invariant: a pre-P2b server never emits it (nothing to
	// accept); a pre-P2b agent ignores the unknown key. A P2b agent decodes it
	// from the RAW response body (the generated client's typed 200 struct does
	// not carry it, so no OpenAPI regeneration is needed) and feeds it to
	// orgclient.Client.AcceptGrantReplacement, which verifies and applies it.
	// The node reports adoption back via HeaderGrantReplacementAck on its next
	// push — the fleet-ACK signal the server's posture-activation gate reads.
	GrantReplacement *GrantReplacement `json:"grant_replacement,omitempty"`

	// BreakGlassLeases is the OPTIONAL delivery seam for approved break-glass
	// credential leases owed to THIS node (Plane B design §4.2 rung 3, operator
	// Q5, P6). It rides the same already-authenticated push round trip as
	// GrantReplacement, as an omitempty slice (a node may have one pending lease
	// per provider upstream). Same compat invariant: a pre-P6 server never emits
	// it; a pre-P6 node ignores the unknown key. Each lease is self-contained and
	// signed (see breakglass.go); the node verifies, opens the per-machine seal,
	// and reports adoption back via HeaderBreakGlassAck. Node-side redemption is
	// a separate lane; this field only freezes the delivery contract.
	BreakGlassLeases []BreakGlassLease `json:"break_glass_leases,omitempty"`

	// BreakGlassRevokedLeaseIDs lists lease ids this node previously ACKed that
	// the server has since REVOKED early (an admin revoke before TTL — G1-
	// BREAKGLASS). TTL expiry needs no signal (the node enforces ExpiresAt
	// itself); an explicit revoke does, or a pulled lease would stay usable on
	// the node until its TTL. Advisory and idempotent: the node drops any
	// matching local lease and forgets unknown ids. Same omitempty compat
	// invariant as BreakGlassLeases.
	BreakGlassRevokedLeaseIDs []string `json:"break_glass_revoked_lease_ids,omitempty"`

	// PolicyVersions is the OPTIONAL policy-propagation nudge (2026-09-01):
	// the latest published version per policy-resource family. A node compares
	// it against what it last saw and triggers an immediate policy-resource
	// fetch when the server is ahead, so a publish converges within one push
	// interval instead of the policy poll interval (default hourly). This is a
	// version-number HINT riding an already-authenticated response — it carries
	// no body and forces nothing: delivery, the signature/pin gates, and the
	// [org_client.policy] accept_families opt-in all stay node-owned exactly as
	// before. Same omitempty compat invariant as the seams above: a pre-nudge
	// server never emits it; a pre-nudge agent ignores the unknown key.
	PolicyVersions map[string]int64 `json:"policy_versions,omitempty"`

	// UpdateVersions is the OPTIONAL update nudge (Enterprise Update
	// Management §3.5): the latest PUBLISHED manifest version this node is
	// eligible for, per channel. A node compares it against its own
	// last-accepted manifest version and fetches the SIGNED manifest with a
	// separate authenticated GET when the server is ahead. It carries no
	// document and forces nothing.
	//
	// Deliberately the same shape as PolicyVersions above rather than the
	// manifest itself: it keeps the push response small, and it makes the
	// manifest fetch independently authenticated and independently verifiable
	// instead of something smuggled inside a batch ACK. (Announcements, which
	// this rail is modelled on, do not ride the response body either — they
	// are a separate GET on the same cycle.)
	//
	// Because the node only fetches when the nudge says the server is ahead,
	// the steady state adds ZERO extra requests: with [update].enabled and no
	// published manifest, a node makes exactly the same set of requests to
	// exactly the same hosts as it does today.
	//
	// Same omitempty compat invariant as the seams above: a pre-feature
	// server never emits it and the node stays inert; a pre-feature agent
	// ignores the unknown key.
	UpdateVersions map[string]int64 `json:"update_versions,omitempty"`

	// SecurityPurpose is the org's stated purpose for its Code security
	// views (security plan 7.12, lane SEC-E3): a closed id from
	// SecurityPurposes, or SecurityPurposeUnset, sent only while
	// org.security is configured on the server. The node shows it in its
	// affected-worker notice, rendered from its own label table (never text
	// the server wrote). Same omitempty compat invariant as the seams above.
	SecurityPurpose string `json:"security_purpose,omitempty"`

	// SecurityVisibility is what the org's Code security views show under
	// its current settings (operator ruling P-089): the minimum group, the
	// fields switched off and whether the optional purpose statement is
	// shown. Sent with SecurityPurpose, only while org.security is
	// configured; the node's notice renders it from its own label table.
	// Same omitempty compat invariant as the seams above.
	SecurityVisibility *SecurityVisibility `json:"security_visibility,omitempty"`

	// RailVersions is the OPTIONAL rail nudge (2026-10-02 budget-latency arc,
	// P2): the current version of every node-pulled rail that is NOT a
	// policy-resource family (RailBudget, RailPricing, RailBundle,
	// RailRouting, RailAnnouncement, RailDisplay). The SAME map GET /api/agent/policy-version
	// returns, riding the push acknowledgment so a push still converges. A
	// HINT only, exactly like PolicyVersions: it carries no document; the node
	// fetches through each rail's own signed, pinned, monotonic path. A
	// separate key from PolicyVersions on purpose: an older node treats every
	// policy_versions key as a policy-resource family and would wake that
	// loop for a budget edit.
	RailVersions map[string]int64 `json:"rail_versions,omitempty"`

	// OrgName is the organization's CURRENT display name (T-862). An admin
	// may rename the org after a node enrolled (Settings > Server, or
	// `observer-org org rename`); the node records the name it reads here in
	// place of the one its enrolment stored, so `observer org status` and
	// the node dashboard follow the rename without a re-enrolment. It rides
	// the already-authenticated push acknowledgment at the same trust level
	// as EnrollResponse.OrgName, and it is a label only: it changes no
	// identity, key pin, grant or policy. The node applies it only when it
	// passes OrgNameProblem. omitempty on both sides of the compat invariant:
	// an older server never sends it (the node keeps its enrolment name) and
	// an older node ignores the unknown key.
	OrgName string `json:"org_name,omitempty"`
}

// Rail keys of PushResponse.RailVersions / PolicyVersionsDoc.RailVersions.
const (
	RailBudget       = "budget"
	RailPricing      = "pricing"
	RailBundle       = "bundle"
	RailRouting      = "routing"
	RailAnnouncement = "announcement"
	// RailDisplay is the developer cost-display rail (GET
	// /api/agent/display-policy, DisplayPolicyDoc); its version is the
	// org_display_settings counter the signed document carries. An older node
	// ignores the unknown key; an older server never sends it.
	RailDisplay = "display"
	// RailGrants is the per-caller access-grant rail (GET /api/agent/grants,
	// AccessGrantDoc); its version is org_access_grant_epoch, bumped on every
	// issue, revoke, extend and scheduled-start. An older node ignores the
	// unknown key; an older server never sends it.
	RailGrants = "grants"
	// RailMessages is the per-caller admin message rail (GET
	// /api/agent/messages, OrgMessageDoc). Its version is computed PER
	// CALLER: the highest message id in the caller's own threads combined
	// with the org's message-settings version, so a message to one developer
	// wakes only that developer's node. An older node ignores the unknown
	// key; an older server never sends it.
	RailMessages = "messages"
)

// OrgMessagesPath is the node's pull path for admin messages.
const OrgMessagesPath = "/api/agent/messages"

// OrgMessageReceiptsPath is where the node posts read/acknowledge receipts.
const OrgMessageReceiptsPath = "/api/agent/messages/receipts"

// PolicyVersionsPath is the node's lightweight policy-freshness probe
// (GET, enrolment bearer; ETag / If-None-Match -> 304).
const PolicyVersionsPath = "/api/agent/policy-version"

// The HELD policy-version probe (T-474: an org change reaches an ACTIVE node
// within seconds). An active node adds ?wait=<seconds> to the probe together
// with its If-None-Match; a server that supports holding keeps the request
// open while the version vector still matches that ETag, answers 200 the
// moment it moves, and answers 304 when the hold ends. It marks every answer
// to a hold it granted with HeaderPolicyVersionsHold. Both halves are
// additive: an older server ignores the query parameter and answers at once
// without the header (the node then keeps its pre-hold cadence), and an older
// node never asks. The body and every signed rail are unchanged.
const (
	// PolicyVersionsHoldParam is the query parameter carrying the requested
	// hold in whole seconds.
	PolicyVersionsHoldParam = "wait"
	// HeaderPolicyVersionsHold is set by a server that granted the hold; its
	// value is the hold it applied, in whole seconds.
	HeaderPolicyVersionsHold = "X-SBO-Policy-Hold"
	// MaxPolicyVersionsHoldSeconds caps the hold a server applies, whatever
	// a node asks for. It stays under the node's 30 s HTTP client timeout and
	// the org server's 60 s write timeout.
	MaxPolicyVersionsHoldSeconds = 25
)

// HeaderPushMinInterval is the org's push BACKPRESSURE hint on an accepted
// push (2026-10-02 budget-latency arc, P3): the minimum number of whole
// seconds this node should leave between two pushes. It only ever slows a
// node's activity-driven pushes (the node's own 15 s floor still applies, and
// its ceiling is unaffected); an absent header means no hint. Older nodes
// ignore it.
const HeaderPushMinInterval = "X-SBO-Push-Min-Interval"

// PolicyVersionsDoc is the probe's response body: the version vector of every
// node-pulled policy, and NOTHING else - no caps, no prices, no rules. It is
// UNSIGNED by design: it can only make a node call the existing signed rails,
// never apply, lower, raise or clear anything itself (docs/security.md
// POLICY-PROBE-1).
type PolicyVersionsDoc struct {
	// PolicyVersions is the latest published version per policy-resource
	// family (the push-ack nudge's map).
	PolicyVersions map[string]int64 `json:"policy_versions,omitempty"`
	// RailVersions is the per-rail version (see PushResponse.RailVersions).
	RailVersions map[string]int64 `json:"rail_versions"`
	// The wire name "probe_after_seconds" is RESERVED (T-533): it was declared
	// here as a server-advised probe interval that no server ever sent and no
	// node ever read, so it was removed. Removal is compatible both ways: a
	// server never emitted it (it was omitempty and always zero), and the node
	// decodes this document leniently. The node's own pacing is
	// internal/policyfresh (activity, backstop, held-probe gap). Never reuse
	// the name with another meaning.
}

// HeaderGrantReplacementAck is the request header a node sets on POST
// /api/agent/push to report the highest grant-replacement generation it has
// adopted (its stored enrolment grant's ReplacementGeneration, 0 when none).
// It is advisory bookkeeping over an ALREADY-authenticated push (the Ed25519
// per-push proof is the sole authenticator); the header can only report the
// node's OWN adoption and never widens access, exactly like
// HeaderAgentKeyFingerprint. The server records it into
// org_grant_replacement_ack, the fleet-ACK registry its posture-activation
// gate reads.
const HeaderGrantReplacementAck = "X-SBO-Grant-Replacement-Ack"

// Product posture classes (design §5.2). The org's product posture is chosen
// at org creation and served to both the dashboard and the fleet.
//
//   - ProductPostureTeams keeps today's opt-in algebra: under the teams posture
//     sharing is node-side opt-in, never server-forced, and the privacy
//     sentinel holds byte-for-byte (the posture-conditional truth of §5.3).
//   - ProductPostureEnterprise inverts the default at the GRANT layer: under the
//     enterprise posture enrolment auto-issues the full extract.* set (managed-
//     consent class), so effective sharing is ALL by default with zero node-side
//     edits — raw content ships via store.ShareOptions.EnterpriseGranted, a
//     resolved enrolment grant, never a live remote command.
//
// The empty string is treated as ProductPostureTeams everywhere so a pre-P2b
// server (which stores no posture) and a pre-P2b node behave exactly as teams.
const (
	ProductPostureTeams      = "teams"
	ProductPostureEnterprise = "enterprise"
)

// ValidProductPosture reports whether s is a recognised posture class. The
// empty string is INVALID here (callers normalise it to ProductPostureTeams
// first); this is the set-time check that refuses an unknown class.
func ValidProductPosture(s string) bool {
	return s == ProductPostureTeams || s == ProductPostureEnterprise
}

// PostureState is the 200 body of GET /api/agent/posture (node-facing) and the
// core of the dashboard's GET /api/org/posture. It is a READ of server state;
// it carries NO authority and grants nothing — the authority a node actually
// holds lives only in its signed EnrolmentGrant / GrantReplacement. It exists
// so a node (and the personal-plane data-authority classifier) has one honest,
// deterministic source for "what posture is this org, and what collection has
// the admin turned off".
type PostureState struct {
	// Posture is the ACTIVE posture (teams|enterprise).
	Posture string `json:"posture"`
	// PendingPosture is the target of an in-flight teams->enterprise flip that
	// has not yet cleared the fleet-ACK gate; empty when no flip is pending.
	PendingPosture string `json:"pending_posture,omitempty"`
	// ReplacementGeneration is the current fleet grant-replacement generation
	// (0 = none issued). A node compares it against its own adopted generation.
	ReplacementGeneration int64 `json:"replacement_generation"`
	// Collection is the org-side per-share-tier collection toggle map (design
	// §5.2 "org collection settings"): tier key -> enabled. Absent/true means
	// "collect"; false means the admin has LOWERED that tier fleet-wide. Only
	// tiers the admin has explicitly turned OFF are guaranteed present; a
	// missing key is enabled (the default-ALL-ON posture).
	Collection map[string]bool `json:"collection,omitempty"`
}

// PolicyBundle is the 200 body of GET /api/v1/policy-bundle (guard spec
// §14.2): one signed, versioned org guard-policy TOML rule set. The agent
// also persists the verified envelope verbatim as its local bundle cache
// (~/.observer/org-policy-bundle.json) so the guard's org layer loads with
// no network and re-checks the same signature at load time.
//
// Trust model: Signature covers PolicyBundleSigningMessage(Version,
// BundleTOML) under the org policy key. PublicKey rides along in EVERY
// envelope so verification is self-contained, but the key only counts as
// trusted when its PublicKeyPinHash matches the pin the agent recorded at
// enrolment (or on first fetch for pre-G13 enrolments). An envelope whose
// signature or pin check fails is REJECTED — the agent keeps its previous
// bundle and records an R-205 guard event.
//
// The bundle channel DISTRIBUTES policy (server → agent); it never widens
// content sharing (§14.1) — nothing in this type flows back to the server.
type PolicyBundle struct {
	// Version is the server-assigned monotonically increasing bundle
	// version. Agents reject a fetched version lower than the last one
	// they verified (downgrade protection); rolling back is done by
	// publishing the old content as a NEW version.
	Version int64 `json:"version"`
	// BundleTOML is the org guard-policy rule set in exactly the §4.4
	// user/project policy-file format ([[rule]] + [[override]] tables).
	BundleTOML string `json:"bundle_toml"`
	// Signature is base64url(Ed25519 signature) over
	// PolicyBundleSigningMessage(Version, BundleTOML).
	Signature string `json:"signature"`
	// PublicKey is the base64url Ed25519 public half of the signing key.
	PublicKey string `json:"public_key"`
	// SignedAt is the RFC3339 instant the bundle was signed (audit metadata;
	// not part of the signed message — Version is the integrity anchor).
	SignedAt string `json:"signed_at"`
	// Description is the operator's note for the version history.
	Description string `json:"description,omitempty"`
	// Binding is set on a v2 (bound) delivery only: the org and member the
	// signature also covers (policybinding.go). Absent on every v1 envelope,
	// so a released node, which never asks for v2, never sees it.
	Binding *PolicyBinding `json:"binding,omitempty"`
	// ProjectBinding is set on a v3 (project-audience) delivery only
	// (projectenvelope.go): the org, member, assignment epoch and, on the
	// composed bundle, the digest of the signed project mapping, or, on a
	// per-project envelope, the org project id. A v3 envelope carries no
	// Binding; a node never sees this field unless it asked for v3.
	ProjectBinding *ProjectBinding `json:"project_binding,omitempty"`
	// Projects rides the composed v3 bundle only: the signed project mapping
	// and one signed envelope per project whose sections reach the member.
	// It is NOT part of the composed bundle's own signature; the mapping is
	// bound by digest and epoch in ProjectBinding, and each envelope carries
	// its own v3 signature. The node strips it before caching the bundle.
	Projects *ProjectDelivery `json:"projects,omitempty"`
	// Families rides a per-project v3 envelope only, to a node that asked
	// for ProjectFamiliesCapability (projectfamilies.go, lane sec-p3): the
	// project's family sections, covered by the envelope's signature through
	// ProjectBinding.FamiliesDigest. Absent everywhere else.
	Families []ProjectFamilyMember `json:"families,omitempty"`
}

// SignedPolicyResource is the P0-5 unified, family-tagged, signed org
// policy resource (docs/plane-a/unified-policy-resource.md §6;
// docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md §4.1). It
// generalizes PolicyBundle (guard, family-implicit) into a family-tagged
// shape any of the seven policy rails (§3 of the design doc) can eventually
// ride, while v1 ships exactly two: admission.input and
// egress.routing_guardrail.
//
// Distribution mirrors PolicyBundle: GET /api/agent/policy/{family}, strong
// ETag (over the SIGNING MESSAGE digest, not Body alone — §4.4), 304 on
// If-None-Match. Trust model: Signature covers
// PolicyResourceSigningMessage(ID, Version, Family, CompilerVersion,
// BodyHash, SelectorsJSON, RequiredCapabilities) under the org's dedicated
// policy-resource signing key (domain-separated from PolicyBundle's key use
// — signing.go's sbo-policy-resource-v1 domain — even when both rails share
// literal key bytes). PublicKey rides in every response so verification is
// self-contained; it counts as trusted only once TOFU-pinned (the guard
// model, unified-policy-resource.md §7 gate 2).
//
// v1 fields are a DELIBERATE SUBSET of the design doc's full §6 shape:
// Selectors ships pre-serialized as SelectorsJSON, now carrying a real
// (canonical, grammar-checked) targeting predicate — P0-10 Phase B, see
// selectors.go and SelectorsJSON's own comment below; Rollout/RollbackTarget/
// Provenance are not part of this milestone (residual R2, plan §10). Adding
// any of those later is additive (CLAUDE.md #6): new fields join the
// signing message under the SAME domain-separation discipline, never a
// silent Body reinterpretation.
type SignedPolicyResource struct {
	// ID is the immutable resource identity. v1 uses the literal "default"
	// (plan v8 fork 4) — one resource per family, no per-selector targeting
	// yet.
	ID string `json:"id"`
	// Version is monotonic per ID. Rollback = republish old content as a
	// new HIGHER version, never a decrement.
	Version int64 `json:"version"`
	// Family selects the compiler + eligible enforcement points (design
	// doc §3 closed enum). v1: "admission.input" | "egress.routing_guardrail".
	Family string `json:"family"`
	// CompilerVersion pins the family compiler that produced Body, so a
	// decision's engine version is provable in evidence later (design §8.6).
	CompilerVersion string `json:"compiler_version"`
	// Body is the family's native spec as CANONICAL JSON (policyfam's
	// CompileBody output) — never the publisher's raw submitted bytes.
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(Body)) — the dedup + effective-hash
	// reconciliation identity (design §4.3).
	BodyHash string `json:"body_hash"`
	// RequiredCapabilities are the capability tokens an enforcement point
	// must advertise to accept this version (design §2 `required_capabilities`).
	// Normalized (sorted, deduped, grammar-checked) as part of the signing
	// message — see signing.go.
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	// SelectorsJSON is the pre-serialized §2 targeting predicate over the
	// CLOSED workspace|environment|service vocabulary (selectors.go). The
	// match-all predicate is the literal "{}"; a targeted resource carries
	// the canonical encoding CanonicalSelectorsJSON produces (compact,
	// sorted keys, no empty values), bounded by
	// MaxPolicyResourceSelectorsBytes. It is part of the signing message, so
	// tampering with it invalidates the signature; the agent additionally
	// re-derives the canonical form and rejects any non-canonical spelling
	// (closed_envelope_violation) before evaluating it, keeping the field's
	// grammar closed even though its VALUE is now open (P0-10 Phase B;
	// docs/plans/policy-targeting-rollback-design-2026-08-13.md §2).
	SelectorsJSON string `json:"selectors_json"`
	// Signature is base64url(Ed25519 signature) over
	// PolicyResourceSigningMessage(...).
	Signature string `json:"signature"`
	// PublicKey is the base64url Ed25519 public half of the signing key.
	PublicKey string `json:"public_key"`
	// SignedAt is the RFC3339 instant the resource was signed — UNTRUSTED
	// display metadata, not part of the signed message (Version + BodyHash
	// are the integrity anchors).
	SignedAt string `json:"signed_at"`
	// Description is the operator's note for the version history.
	Description string `json:"description,omitempty"`
	// Binding is set on a v2 (bound) delivery only: the org, member and
	// projection target the signature also covers (policybinding.go). Absent
	// on every stored row and every v1 delivery.
	Binding *PolicyBinding `json:"binding,omitempty"`
}

// SessionRow is a session as pushed to the server.
//
// Privacy posture (v1.8.0+): a session identifies its project via the
// CONTENT-FREE hashes ProjectRootHash + GitRemoteHash, which are always
// present and let the server map the session to a team via pre-shared
// project-root hash registration without ever seeing the developer's
// filesystem layout.
//
// ProjectRoot + GitRemote are the raw / human-readable values; they ship
// under store.ShareOptions.shipsRawContent() — TEAMS posture: ONLY when the
// node operator has set [org_client.share].full_content = true in their
// local config (a per-node opt-in; the org admin cannot force it on) OR the
// node is admin_managed (itself a node-authored provisioning config, never a
// remote toggle). ENTERPRISE posture adds a third, structurally distinct
// path: a managed node's own enrolment grant may satisfy
// govern.Effective.GrantsEnterpriseContent(), minted at enrolment under the
// org's chosen product_posture — never a live remote command (see
// internal/store/orgpush.go's ShareOptions doc for the full three-path
// statement). With none of the three, these fields are empty strings (json
// omitempty).
//
// Project Identity Resolver v2 (docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
// §3.2, agent migration 102 / server migration 121) widens the single origin
// remote into a full identity bundle. GitUpstreamRemoteHash, GitRemoteOwnerHash,
// GitUpstreamOwnerHash, RootCommitHash, ContentFingerprintHash, and
// WorkspaceHash are unsalted sha256 hashes that ship ALWAYS — joinable across
// nodes, disclosing nothing a raw value would not. IsWorktree is a
// content-free bool and also always ships. GitUpstreamRemote and Workspace
// are the two RAW counterparts among these new fields; like ProjectRoot /
// GitRemote above, they ship ONLY under store.ShareOptions.shipsRawContent()
// and are stripped per row in internal/store/orgpush.go::SelectUnpushedSince.
// There is no raw counterpart for the other four hashes (the pre-images —
// root_commit_sha, content_fingerprint — never leave the node in any share
// mode; the owner hashes have no raw form on the wire at all). An older agent
// omits every field in this block; the server degrades to remote-only
// resolution. All additive/omitempty for compat in both directions.
type SessionRow struct {
	ID string `json:"id"`

	// Content-free hashes — always present.
	ProjectRootHash string `json:"project_root_hash"`
	GitRemoteHash   string `json:"git_remote_hash,omitempty"`

	// Raw values — present only when the node opted in to full-content sharing.
	ProjectRoot string `json:"project_root,omitempty"`
	GitRemote   string `json:"git_remote,omitempty"`

	Tool         string `json:"tool"`
	Model        string `json:"model,omitempty"`
	GitBranch    string `json:"git_branch,omitempty"`
	StartedAt    string `json:"started_at"` // RFC3339
	EndedAt      string `json:"ended_at,omitempty"`
	TotalActions int    `json:"total_actions"`
	OrgID        string `json:"org_id"`
	UserEmail    string `json:"user_email"`

	// Project Identity Resolver v2 additions — content-free hashes, always
	// present when the node has resolved them (older agents omit them).
	GitUpstreamRemoteHash  string `json:"git_upstream_remote_hash,omitempty"`
	GitRemoteOwnerHash     string `json:"git_remote_owner_hash,omitempty"`
	GitUpstreamOwnerHash   string `json:"git_upstream_owner_hash,omitempty"`
	RootCommitHash         string `json:"root_commit_hash,omitempty"`
	ContentFingerprintHash string `json:"content_fingerprint_hash,omitempty"`
	WorkspaceHash          string `json:"workspace_hash,omitempty"`
	IsWorktree             bool   `json:"is_worktree,omitempty"`

	// Raw values — present only under shipsRawContent(). The only two
	// resolver-v2 fields with a raw counterpart on the wire.
	GitUpstreamRemote string `json:"git_upstream_remote,omitempty"`
	Workspace         string `json:"workspace,omitempty"`

	// Capture-surface attribution (node session-detail trickle-up W1;
	// agent migration 107 / server migration 139). METADATA, not content:
	// Surface is a CLOSED vocabulary (models.KnownSurface — cli | ide |
	// desktop | sdk | web) that the node's Store.SetSessionSurface refuses
	// to write outside of, and SurfaceHost is the bounded host token that
	// refines it (vscode | cursor | jetbrains | neovim | kiro |
	// claude-desktop | codex-desktop | ...). Neither can carry a path, a
	// prompt or a branch name, so both ship BY DEFAULT — unconditionally
	// populated by SelectUnpushedSince, with no share key and no
	// shipsRawContent() gate. Empty means UNKNOWN (a pre-107 agent, or a
	// session whose transcript was never re-scanned); a projection must
	// render that absence honestly and NEVER as "cli".
	Surface     string `json:"surface,omitempty"`
	SurfaceHost string `json:"surface_host,omitempty"`

	// ToolVersion is the captured AI-tool/CLI build version the node
	// resolved from a grounded on-disk field the adapter itself controls
	// (server migration 161 / pg 0027; agent migration 125,
	// internal/store/toolversion.go::SetSessionToolVersion, FIRST-WINS-
	// UNLESS-EMPTY). METADATA, not content: unlike Surface it is not a
	// closed vocabulary, but it is a bounded (64-rune), non-prose,
	// whitespace/control-char-rejected token
	// (internal/store/toolversion.go::validToolVersion) sourced only from a
	// vendor-authored field — never developer-typed text — so it ships BY
	// DEFAULT alongside Surface/SurfaceHost, with no share key and no
	// shipsRawContent() gate. Empty means UNKNOWN: a pre-125 agent, an
	// adapter with no grounded version source, or a session whose
	// transcript predates the field. Never rendered as a guess.
	ToolVersion string `json:"tool_version,omitempty"`

	// ToolVersionLast is the LATEST tool/CLI build the node saw for the
	// session (agent migration 162 / server migration 232 / pg 0099,
	// internal/store/toolversion.go::SetSessionToolVersion, which moves it
	// forward on every valid stamp while ToolVersion stays the first build
	// seen). Same METADATA class and same grammar as ToolVersion, so it ships
	// BY DEFAULT with no share key and no shipsRawContent() gate, and the
	// ingest re-validates it the same way. Empty means the node never
	// stamped it (an older agent, or a session not re-parsed since 162):
	// readers then treat it as equal to ToolVersion. A session where the two
	// differ was upgraded mid-session.
	ToolVersionLast string `json:"tool_version_last,omitempty"`

	// ParentThreadID is the node-local session-lineage pointer (agent
	// migrations 069/102, internal/store::SetSessionLineage) — for Cursor
	// the parent session of a sub-agent child, also Codex fork lineage
	// (server migration 162 / pg 0028). METADATA, not content: it is an
	// OPAQUE vendor-minted session id, never developer-typed text, and the
	// child session it points at already ships as its own SessionRow on the
	// wire, so shipping the pointer adds structure (fan-out), not content —
	// the same reasoning that lets ToolVersion ship unconditionally. It
	// ships BY DEFAULT, with no share key and no shipsRawContent() gate.
	// ForkedFromID and ThreadSource (the fork's existence/kind) stay
	// NODE-LOCAL and are deliberately NOT added here — only the pointer
	// itself ships. Empty means the session has no recorded parent. Lets
	// the org drawer's per-session tool-account column resolve a Cursor
	// CHILD session's account the way the node's
	// internal/store/toolaccount.go::LoadMessageAccounts already does, by
	// joining through this column (rollup/messageaccounts.go). See
	// docs/security.md ledger row LINEAGE-1.
	ParentThreadID string `json:"parent_thread_id,omitempty"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// ActionRow is an action as pushed to the server.
//
// Privacy posture (v1.8.0+):
//
//   - The classic four content columns (raw_tool_input, raw_tool_output,
//     preceding_reasoning, error_message) are intentionally absent — they
//     have never shipped.
//   - TargetHash and SourceFileHash are content-free and ALWAYS present.
//     They give the server stable dedup / cardinality signals (how often
//     does the same shell command run? how many distinct JSONL files?)
//     without revealing the underlying bytes.
//   - Target and SourceFile are the raw, human-readable values. The
//     2026-06-02 teams test found that these were shipping raw and
//     contained command bodies (run_command), assistant prose
//     (task_complete), and raw filesystem paths. v1.8.0 ships them under
//     store.ShareOptions.shipsRawContent() — TEAMS posture: ONLY when the
//     node operator has set [org_client.share].full_content = true (a
//     per-node opt-in the org admin cannot force on) OR admin_managed
//     (also node-authored, never a remote toggle). ENTERPRISE posture adds
//     the structurally distinct enrolment-grant path
//     (govern.Effective.GrantsEnterpriseContent(), minted at enrolment
//     under the org's chosen product_posture, never a live remote command
//     — see internal/store/orgpush.go's ShareOptions doc). With none of
//     the three, these fields are empty strings (json omitempty).
type ActionRow struct {
	SessionID     string `json:"session_id"`
	SourceEventID string `json:"source_event_id"`
	Timestamp     string `json:"timestamp"` // RFC3339
	Tool          string `json:"tool"`
	ActionType    string `json:"action_type"`

	// Content-free hashes — always present.
	TargetHash     string `json:"target_hash,omitempty"`
	SourceFileHash string `json:"source_file_hash"`

	// Raw values — present only when the node opted in to full-content sharing.
	Target     string `json:"target,omitempty"`
	SourceFile string `json:"source_file,omitempty"`

	// Tool-call BODIES — the four actions columns the local dashboard renders
	// inline. Present ONLY under the distinct full_tool_bodies tier
	// (ShareOptions.shipsToolBodies), which on an individual node is node-opt-in
	// and on a managed node the org may raise (extract.managed). They are NEVER
	// present under full_content/admin_managed alone. Additive/omitempty: a
	// pre-P2 server ignores them, a pre-P2 agent never sends them.
	RawToolInput       string `json:"raw_tool_input,omitempty"`
	RawToolOutput      string `json:"raw_tool_output,omitempty"`
	PrecedingReasoning string `json:"preceding_reasoning,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`

	TurnIndex   int   `json:"turn_index"`
	Success     bool  `json:"success"`
	DurationMs  int64 `json:"duration_ms"`
	IsSidechain bool  `json:"is_sidechain"`
	// MessageID is the id of the assistant/user MESSAGE this action belongs to
	// (actions.message_id on the node, e.g. an Anthropic "msg_…"), the key the
	// org message-metrics rollup buckets tool calls by. Without it the rollup
	// falls back to SourceEventID, which differs per adapter and shows 0 tools
	// per message for tools whose ids are not message ids (OpenCode, etc.).
	// CONTENT-FREE (an opaque provider id, never prose), so it ships in every
	// tier; empty when the node never recorded one. Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	MessageID string `json:"message_id,omitempty"`
	// EffortLevel is the reasoning-effort selection in force when the action
	// ran (minimal | low | medium | high | xhigh | max — accepted verbatim,
	// no enum check, matching the node's claudecode_effort sidecar posture).
	// Content-free (a closed vocabulary, never prose), so it ships in every
	// tier alongside the other action metadata. Extracted at push time from
	// the node's actions.metadata JSON; empty when the node never captured an
	// effort signal for this action (pre-feature rows, tools without an
	// effort concept). Additive/omitempty both directions: an older server
	// ignores it, an older agent never sends it.
	EffortLevel string `json:"effort_level,omitempty"`
	// StopReason is the turn-completion reason recorded on the action
	// (end_turn | max_tokens | stop_sequence | tool_use | …), extracted at
	// push time from the node's actions.metadata JSON ($.stop_reason) exactly
	// like EffortLevel. It is the JSONL-turn counterpart of APITurnRow's
	// proxy-observed StopReason: proxy sessions carry it on the api_turn, but a
	// JSONL-only (non-proxied) session records it only in the action metadata,
	// so without this field the org message table has no stop reason for those
	// turns. Content-free (a closed provider vocabulary, never prose), so it
	// ships in every tier; empty when the node never captured one (pre-feature
	// rows, tools without a stop-reason concept). Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	StopReason string `json:"stop_reason,omitempty"`
	OrgID      string `json:"org_id"`
	UserEmail  string `json:"user_email"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// APITurnRow is a proxy-observed API turn as pushed. Prompt/completion
// bodies are never present; only token counts, cost, timing, hashes
// (not content), and a parsed error class (a category, not a message).
//
// Privacy posture (v1.8.0+): ProjectRootHash is always present;
// ProjectRoot ships only when the node opted in to full-content sharing.
type APITurnRow struct {
	SessionID             string  `json:"session_id"`
	ProjectRootHash       string  `json:"project_root_hash,omitempty"`
	ProjectRoot           string  `json:"project_root,omitempty"`
	Timestamp             string  `json:"timestamp"` // RFC3339
	Provider              string  `json:"provider"`
	Model                 string  `json:"model,omitempty"`
	RequestID             string  `json:"request_id,omitempty"`
	InputTokens           int64   `json:"input_tokens"`
	OutputTokens          int64   `json:"output_tokens"`
	CacheReadTokens       int64   `json:"cache_read_tokens"`
	CacheCreationTokens   int64   `json:"cache_creation_tokens"`
	CacheCreation1hTokens int64   `json:"cache_creation_1h_tokens"`
	WebSearchRequests     int64   `json:"web_search_requests"`
	CostUSD               float64 `json:"cost_usd"`
	MessageCount          int     `json:"message_count"`
	ToolUseCount          int     `json:"tool_use_count"`
	SystemPromptHash      string  `json:"system_prompt_hash,omitempty"`
	MessagePrefixHash     string  `json:"message_prefix_hash,omitempty"`
	TimeToFirstTokenMS    int64   `json:"time_to_first_token_ms"`
	TotalResponseMS       int64   `json:"total_response_ms"`
	StopReason            string  `json:"stop_reason,omitempty"`
	HTTPStatus            int     `json:"http_status"`
	ErrorClass            string  `json:"error_class,omitempty"`
	OrgID                 string  `json:"org_id"`
	UserEmail             string  `json:"user_email"`
	// Route / RoutingGeneration / AuthoritySource are the Plane B per-turn
	// authority stamps (Sol S5 / Luna L15). CONTENT-FREE metadata — enum
	// strings + an integer generation, never any text from a request — so
	// they ship UNCONDITIONALLY (not gated by ShareOptions.shipsRawContent,
	// pinned by tests/invariant/privacy_test.go). omitempty on all three
	// keeps the wire backward-compatible both directions: an old agent
	// omits them and a new server reads direct/0/node defaults; a new agent
	// sends them and an old server ignores unknown keys.
	//
	// Route is "direct" | "gateway" | "fallback"; AuthoritySource is
	// "node" | "gateway" — the org rollup lets a gateway-authoritative row
	// win on a request_id collision so a mixed-mode window single-counts.
	Route             string `json:"route,omitempty"`
	RoutingGeneration uint64 `json:"routing_generation,omitempty"`
	AuthoritySource   string `json:"authority_source,omitempty"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
	// RequestClass is the client-declared kind of request (node agent
	// migration 144, org server migration 188 / pg 0054): one of the closed
	// internal/requestclass vocabulary (main | subagent | workflow |
	// compaction | auxiliary), or empty when the client sent no class hint.
	// CONTENT-FREE metadata (a closed enum, never request text), so it ships
	// in every posture like Route. Additive/omitempty both directions: an
	// older agent never sends it and the org stores NULL (never a guessed
	// class); an older server ignores the unknown key. The org re-validates
	// it against the vocabulary at ingest, so an unknown spelling lands NULL.
	RequestClass string `json:"request_class,omitempty"`
}

// GuardEventRow is a guard-layer audit event as pushed to the server
// (guard spec §14.3 central reporting).
//
// Privacy posture (guard spec §10.2 — mirrors ActionRow):
//
//   - rule_id, category, severity, decision, degraded_from, enforced,
//     source, tool, event_kind, timestamps and TargetHash are
//     content-free and always ship.
//   - Reason, TargetExcerpt and TaintOrigin are content-bearing
//     (verdict prose, a bounded excerpt of the command/path, a taint
//     source description). They ship under store.ShareOptions
//     .shipsRawContent() — the same gate as actions.target: TEAMS posture
//     ONLY when the node operator has set [org_client.share].full_content
//     = true or admin_managed (both node-authored; the org admin cannot
//     force either on), ENTERPRISE posture also via the structurally
//     distinct enrolment-grant path (EnterpriseGranted, minted at
//     enrolment, never a live remote command).
//     With the default config they are empty strings (json omitempty).
//   - ChainPrev/ChainHash are SHA-256 hex links of the node's
//     tamper-evidence chain (guard spec §10.4) — content-free, shipped
//     so server-side rollups can detect broken/truncated chains.
//
// Local row-id anchors (action_id / api_turn_id) are deliberately
// absent: they are meaningless outside the originating node.
type GuardEventRow struct {
	SessionID string `json:"session_id,omitempty"`
	Timestamp string `json:"timestamp"` // RFC3339
	Tool      string `json:"tool,omitempty"`
	EventKind string `json:"event_kind,omitempty"`
	RuleID    string `json:"rule_id"`
	Category  string `json:"category,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Decision  string `json:"decision,omitempty"`
	// DegradedFrom is the pre-degradation decision when a capability
	// downgrade applied (guard spec §6.2); empty otherwise.
	DegradedFrom string `json:"degraded_from,omitempty"`
	Enforced     bool   `json:"enforced"`
	Source       string `json:"source,omitempty"`

	// Content-free hash — always present when the event had a target.
	TargetHash string `json:"target_hash,omitempty"`

	// Content-bearing values — present only when the node opted in to
	// full-content sharing.
	Reason        string `json:"reason,omitempty"`
	TargetExcerpt string `json:"target_excerpt,omitempty"`
	TaintOrigin   string `json:"taint_origin,omitempty"`

	// Tamper-evidence chain links (content-free SHA-256 hex).
	ChainPrev string `json:"chain_prev,omitempty"`
	ChainHash string `json:"chain_hash,omitempty"`

	OrgID     string `json:"org_id"`
	UserEmail string `json:"user_email"`

	// GrantID is the org access grant that covered this event (request-grants
	// design §3.2; agent 152 / org 196). Zero (omitted) means no grant, and is
	// all a node or server that predates the design ever sends or reads.
	GrantID int64 `json:"grant_id,omitempty"`
}

// TokenUsageRow is an adapter-derived token-usage row as pushed. All
// fields are counts/metadata — no content.
//
// Privacy posture (v1.8.0+): ProjectRootHash + SourceFileHash are always
// present; ProjectRoot + SourceFile ship only when the node opted in to
// full-content sharing.
type TokenUsageRow struct {
	SessionID             string  `json:"session_id"`
	ProjectRootHash       string  `json:"project_root_hash,omitempty"`
	ProjectRoot           string  `json:"project_root,omitempty"`
	Timestamp             string  `json:"timestamp"` // RFC3339
	Tool                  string  `json:"tool"`
	Model                 string  `json:"model,omitempty"`
	InputTokens           int64   `json:"input_tokens"`
	OutputTokens          int64   `json:"output_tokens"`
	CacheReadTokens       int64   `json:"cache_read_tokens"`
	CacheCreationTokens   int64   `json:"cache_creation_tokens"`
	CacheCreation1hTokens int64   `json:"cache_creation_1h_tokens"`
	ReasoningTokens       int64   `json:"reasoning_tokens"`
	WebSearchRequests     int64   `json:"web_search_requests"`
	EstimatedCostUSD      float64 `json:"estimated_cost_usd"`
	Source                string  `json:"source"`
	Reliability           string  `json:"reliability"`
	SourceFileHash        string  `json:"source_file_hash"`
	SourceFile            string  `json:"source_file,omitempty"`
	SourceEventID         string  `json:"source_event_id"`
	// MessageID is the per-API-call / per-message id this usage row belongs to
	// (token_usage.message_id on the node), the key the org message-metrics
	// rollup joins token/cost columns to actions by. CONTENT-FREE opaque id;
	// empty when the node never recorded one. Additive/omitempty both
	// directions: an older server ignores it, an older agent never sends it.
	// (The proxy api_turn's message id is api_turns.request_id, already carried
	// as APITurnRow.RequestID — no new field needed there.)
	MessageID string `json:"message_id,omitempty"`
	// IsSidechain reports whether this usage row was emitted inside a Claude
	// Code sub-agent (Task) window — token_usage.is_sidechain on the node
	// (agent migration 087), the token counterpart of the ActionRow.IsSidechain
	// flag that has ridden the wire since the baseline. METADATA (one bool over
	// a row that already ships, closed by construction), so it ships BY DEFAULT:
	// populated unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate. Additive/omitempty both directions — an older
	// server ignores it, an older agent never sends it and the server lands the
	// same honest false the node would have stored.
	IsSidechain bool `json:"is_sidechain,omitempty"`
	// TurnID groups several per-inference token_usage rows into the SAME
	// user-turn — token_usage.turn_id on the node (agent migrations 032/033),
	// server migration 160 / pg 0026. The node's own Messages-tab bucket key
	// (dashboard.go's tokenGroupExpr) PREFERS turn_id over message_id/
	// source_event_id: for codex (and its openinterpreter retag), several
	// per-inference calls within one user-turn share a turn_id and merge into
	// ONE row. Before this field, the org rollup had no way to reproduce that
	// merge and over-counted (one row per token_usage row instead of one per
	// turn) — the §7 follow-up to the 2026-09-22 node-vs-org parity fix.
	// CONTENT-FREE opaque id (an adapter-minted grouping token, never
	// agent-authored text), so it is METADATA and ships BY DEFAULT: populated
	// unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate — same posture as IsSidechain/MessageID above.
	// Additive/omitempty both directions: an older agent that never sends the
	// key lands NULL/empty (byte-identical to a pre-160 row); an older server
	// ignores the new wire key.
	TurnID string `json:"turn_id,omitempty"`
	// GenMs is the per-model-call generation duration the adapter captured
	// for this row — token_usage.gen_ms on the node (agent migration 136),
	// server migration 174 / pg 0040. It feeds the Tok/s throughput figure
	// (internal/sessionmsg's Speed accumulator) the same way on both
	// engines: TimingWire.TpsMs sums GenMs across a message's contributing
	// token rows. NUMERIC metadata over a row that already ships (a
	// duration, never agent-authored text), so it ships BY DEFAULT: populated
	// unconditionally by SelectUnpushedSince with no share key and no
	// shipsRawContent() gate — same posture as IsSidechain/TurnID above.
	// Additive/omitempty both directions: an older agent that never sends
	// the key lands 0/NULL (byte-identical to a pre-174 row, and
	// indistinguishable from "not measured" — the same honest-absence shape
	// GenMs already has node-side); an older server ignores the new wire key.
	GenMs int64 `json:"gen_ms,omitempty"`
	// GenBasis names GenMs's basis (models.GenBasisNative /
	// GenBasisTranscript / GenBasisOTel on the node) — a closed,
	// capture-minted enum, never agent-authored text, so it is METADATA and ships BY DEFAULT alongside
	// GenMs under the same rule. GenTimingV (the adapter's gen-timing parser
	// version) deliberately has NO wire counterpart: it is a node-local
	// upsert-precedence input only, meaningless once GenMs/GenBasis have
	// already been chosen on the node — the same posture as the node-local
	// `fast` pricing flag next to token_usage's other wire fields.
	GenBasis  string `json:"gen_basis,omitempty"`
	OrgID     string `json:"org_id"`
	UserEmail string `json:"user_email"`
	// NodeRev is the node's change-sequence snapshot this row was read at
	// (agent migration 140 / server 178 / pg 0044, lane R2-RESEND): the org
	// ingest lets a re-sent row REPLACE the stored one only when its NodeRev is
	// strictly greater (newer-wins by node version, never by arrival order), so
	// a row the node changed after it first shipped - a token MAX-upgrade, an
	// action outcome, a reparented transcript, a session's later model /
	// ended_at / surface - converges on the org. Metadata (a counter), ships in
	// every posture. Additive/omitempty both directions: an older agent never
	// sends it (0 = first-wins, exactly the pre-178 behaviour) and an older
	// server ignores it.
	NodeRev int64 `json:"node_rev,omitempty"`
}

// OTelContentRow is one captured native-OTel content body on the wire
// (native-console integration, Phase 2b body-ingest Layer B). ContentHash
// always ships; Content (the raw, scrubbed body) ships only when the node
// shares full content (full_content or admin_managed) — gated in
// SelectUnpushedSince exactly like the other content-bearing columns.
type OTelContentRow struct {
	RequestID   string `json:"request_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	ToolUseID   string `json:"tool_use_id,omitempty"`
	Kind        string `json:"kind"`
	ContentHash string `json:"content_hash"`
	Content     string `json:"content,omitempty"`
	Timestamp   string `json:"timestamp"` // RFC3339
	OrgID       string `json:"org_id"`
	UserEmail   string `json:"user_email"`
}

// RoutingSummaryRow is the §R19.4 org rollup wire shape: AGGREGATE
// ONLY — counts and dollars by (day, tier, reason, mode). No model
// ids, no session detail, no per-decision rows: router_decisions and
// model_calibration stay node-local (privacy-sentinel-pinned); this
// aggregate is the only routing data that ever crosses the wire, and
// only when the node operator opts in via
// [org_client.share] routing_summary = true.
type RoutingSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same
	// stamping rule as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD).
	Day string `json:"day"`
	// Tier is the ORIGINAL model's tier class (an enum, not a model id).
	Tier string `json:"tier"`
	// Reason is the decision's primary closed-enum reason code.
	Reason string `json:"reason"`
	// Mode is advise | enforce.
	Mode string `json:"mode"`
	// Decisions / Applied are row counts.
	Decisions int64 `json:"decisions"`
	Applied   int64 `json:"applied"`
	// EstSavingsUSD / CacheForfeitUSD are decision-time estimate sums.
	EstSavingsUSD   float64 `json:"est_savings_usd"`
	CacheForfeitUSD float64 `json:"cache_forfeit_usd"`
}

// CacheSummaryRow is the Arc 4 P5c cache-detail aggregate — one row per
// (day, model, kind) of the node-local cache_events log (cache_segments /
// cache_entries / cache_events are otherwise NODE-LOCAL per spec §11 and
// never leave the agent). It carries only content-free counts: no prompt
// prefix, no raw scope (cache_scope is a hash), no path. It ships ONLY under
// the cache_detail tier (node opt-in on an individual node, admin-raised on a
// managed one) — the tier is what sanctions shipping per-turn cache-hit
// patterns the privacy sentinel otherwise treats as private.
type CacheSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the cache events.
	Day string `json:"day"`
	// Model is the model the cache belief/event is for.
	Model string `json:"model"`
	// Kind is the cache-event class (hit | write | expiry_rewrite | ...).
	Kind string `json:"kind"`
	// Events is the row count for the (day, model, kind) bucket.
	Events int64 `json:"events"`
	// TokensRead / TokensWritten are the summed cache token movements.
	TokensRead    int64 `json:"tokens_read"`
	TokensWritten int64 `json:"tokens_written"`
	// CostDeltaUSD is the summed write-vs-read cost delta estimate.
	CostDeltaUSD float64 `json:"cost_delta_usd"`
}

// CodeintelSummaryRow is the Arc 4 P5f codeintel-detail aggregate — one row per
// (project-hash, language) of the node-local code-intelligence index
// (codeintel_files / codeintel_nodes / codeintel_edges are otherwise
// NODE-LOCAL and never leave the agent). It carries only content-free STRUCTURE
// counts: no symbol name, no fully-qualified name, no signature excerpt, and no
// raw file or project path (the project path is one-way domain-separated-hashed
// on the node). It ships ONLY under the codeintel_detail tier (node opt-in on an
// individual node, admin-raised on a managed one via the DISTINCT
// extract.codeintel authority) — the highest-sensitivity extraction tier, so it
// gets its own explicit consent rather than riding the umbrella extract.managed.
type CodeintelSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// ProjectHash is the opaque one-way hash of the project's git-root path —
	// a stable grouping key that never discloses the path itself.
	ProjectHash string `json:"project_hash"`
	// Lang is the resolved language of the files in this bucket (e.g. go,
	// typescript). A public language label, never source.
	Lang string `json:"lang"`
	// Files / Symbols / Edges are the structure counts for the bucket:
	// indexed files, extracted symbols (nodes), and call/import edges.
	Files   int64 `json:"files"`
	Symbols int64 `json:"symbols"`
	Edges   int64 `json:"edges"`
}

// ProcessSummaryRow is the Arc 4 P5g process-detail aggregate — one row per
// (day, tool) of the node-local process-observability log (process_runs /
// process_events / process_network_bodies are otherwise NODE-LOCAL and never
// leave the agent). It carries only content-free counts: no executable path,
// no argv, no cwd, no network request/response body, and none of the
// process/network domain-separated hashes. It ships ONLY under the
// process_detail tier (node opt-in on an individual node, admin-raised on a
// managed one via the DISTINCT extract.process authority — the process/eBPF
// trees are a highest-sensitivity tier, so they get their own explicit
// consent rather than riding the umbrella extract.managed).
type ProcessSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping rule
	// as every other wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the process runs started.
	Day string `json:"day"`
	// Tool is the attributed AI tool (e.g. claude-code) or '' when unattributed.
	Tool string `json:"tool"`
	// Runs is the number of process runs in the bucket; Exited how many have
	// exited; NonzeroExits how many exited with a non-zero code.
	Runs         int64 `json:"runs"`
	Exited       int64 `json:"exited"`
	NonzeroExits int64 `json:"nonzero_exits"`
	// DurationMsSum is the summed wall-clock duration of the runs in the bucket.
	DurationMsSum int64 `json:"duration_ms_sum"`
}

// TerminalSummaryRow is one half of the Arc 4 P5h terminal-detail aggregate —
// one row per (day, tool, kind) of the node-local terminal_run log (joined to
// terminal_commands for the command count). terminal_run / terminal_commands /
// remote_audit are otherwise pinned ENTIRELY out of the push wire (dedicated
// end-to-end never-ships tests); this content-free count aggregate under the
// DISTINCT terminal_detail tier is the deliberate, reviewed reversal. It never
// carries a command, a project_root_hash, a correlation_token_hash, a cmd_hash,
// or a source_session_id.
type TerminalSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) the terminal runs launched.
	Day string `json:"day"`
	// Tool is the target tool (e.g. claude-code); Kind is handoff | fresh.
	Tool string `json:"tool"`
	Kind string `json:"kind"`
	// Runs / Ended / NonzeroExits are per-run counts; Commands is the number of
	// command boundaries observed across those runs.
	Runs         int64 `json:"runs"`
	Ended        int64 `json:"ended"`
	NonzeroExits int64 `json:"nonzero_exits"`
	Commands     int64 `json:"commands"`
}

// RemoteAuditSummaryRow is the other half of the Arc 4 P5h terminal-detail
// aggregate — one row per (day, kind, decision, principal) of the node-local
// remote_audit log. Content-free: it carries only the public event taxonomy
// (kind), the allow/deny/ok/fail decision, and the resolved capability class
// (principal: public|view|execute|anonymous) — never a session id, a peer
// address, a route, or a detail string.
type RemoteAuditSummaryRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the audit events.
	Day string `json:"day"`
	// Kind is the event kind; Decision the allow/deny/ok/fail verdict;
	// Principal the resolved capability class.
	Kind      string `json:"kind"`
	Decision  string `json:"decision"`
	Principal string `json:"principal"`
	// Events is the row count for the bucket.
	Events int64 `json:"events"`
}

// RoutingDetailRow is the Arc 4 P5d routing-detail aggregate — the
// MODEL-ID-BEARING per-decision rollup the tier-only RoutingSummaryRow omits:
// one row per (day, original_model, selected_model, turn_kind, mode) of the
// node-local router_decisions log. router_decisions / model_calibration are
// otherwise NODE-LOCAL (spec §R9.1); this content-free aggregate ships ONLY
// under the routing_detail tier (node opt-in / admin raise). Distinct from
// RoutingSummaryRow, which is model-id-free and ships under routing_summary.
type RoutingDetailRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD).
	Day string `json:"day"`
	// OriginalModel / SelectedModel are the ACTUAL model ids the decision
	// mapped between (unlike the tier-only summary).
	OriginalModel string `json:"original_model"`
	SelectedModel string `json:"selected_model"`
	// TurnKind is the classifier's turn-kind bucket; Mode is advise | enforce.
	TurnKind string `json:"turn_kind"`
	Mode     string `json:"mode"`
	// Decisions / Applied are row counts.
	Decisions int64 `json:"decisions"`
	Applied   int64 `json:"applied"`
	// EstSavingsUSD / CacheForfeitUSD are decision-time estimate sums.
	EstSavingsUSD   float64 `json:"est_savings_usd"`
	CacheForfeitUSD float64 `json:"cache_forfeit_usd"`
}

// LimitGaugeRow is the Arc 4 P5e predictions tier — one row per (day, provider)
// of the node-local limit_snapshots log (the 5h/weekly rate-limit gauge the
// Next-Message Cost & Limit Predictor records). limit_snapshots is otherwise
// NODE-LOCAL; this content-free aggregate — utilization stats only, no
// scope_hash, no session id, no raw headers — ships ONLY under the limit_gauge
// tier (node opt-in / admin raise).
type LimitGaugeRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the observations.
	Day string `json:"day"`
	// Provider is anthropic | openai.
	Provider string `json:"provider"`
	// Snapshots is the observation count for the (day, provider) bucket.
	Snapshots int64 `json:"snapshots"`
	// Max/Avg utilization of the 5h and weekly windows (0..1). Zero when the
	// provider never returned that window's header.
	Max5hUtil float64 `json:"max_5h_util"`
	Avg5hUtil float64 `json:"avg_5h_util"`
	Max7dUtil float64 `json:"max_7d_util"`
	Avg7dUtil float64 `json:"avg_7d_util"`
}

// --- Org-tier observability wire shapes (obs-org-tier plan §3) -------------
//
// All four tiers are AGGREGATE-or-STRUCTURE-or-GATED-CONTENT; none carries a
// raw body except ObsContentRow (gated by shipsRawContent()). They are
// composed in orgpush.go via the obs provider seam, so the privacy sentinel
// never sees an obs_* table name there. OrgID/UserEmail are agent-stamped like
// every other wire row.

// ObsSummaryRow is the T1 AGGREGATE rollup: per (day, model, provider,
// project_hash, source) counts + token/cost/latency sums. CONTENT-FREE — no
// trace ids, no span topology, no names, no bodies. Pinned aggregate-only by a
// reflect test. project_hash is the content-free key (sha256 of project_root),
// the same posture sessions/api_turns already ship; the raw path never enters
// this row.
type ObsSummaryRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	Day       string `json:"day"` // UTC YYYY-MM-DD

	Model       string `json:"model,omitempty"`
	Provider    string `json:"provider,omitempty"`
	ProjectHash string `json:"project_hash,omitempty"`
	Source      string `json:"source,omitempty"` // provenance tag (otlp_trace/sdk_otlp/…)

	Traces           int64   `json:"traces"`
	Spans            int64   `json:"spans"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	ErrorTraces      int64   `json:"error_traces"`
	DurationMsSum    int64   `json:"duration_ms_sum"` // sum+count → server derives mean
	DurationMsCount  int64   `json:"duration_ms_count"`
}

// ObsTraceRow is the T2 trace skeleton (STRUCTURE, hashes only). ProjectRoot
// ships only under shipsRawContent(); ProjectHash always.
type ObsTraceRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	TraceID     string  `json:"trace_id"`
	SessionID   string  `json:"session_id,omitempty"`
	ThreadID    string  `json:"thread_id,omitempty"`
	Source      string  `json:"source,omitempty"`
	Status      string  `json:"status,omitempty"`
	StartedAt   string  `json:"started_at,omitempty"`
	EndedAt     string  `json:"ended_at,omitempty"`
	ProjectHash string  `json:"project_hash,omitempty"`
	ProjectRoot string  `json:"project_root,omitempty"` // gated by shipsRawContent()
	RootSpanID  string  `json:"root_span_id,omitempty"`
	SpanCount   int64   `json:"span_count"`
	TotalTokens int64   `json:"total_tokens"`
	CostUSD     float64 `json:"cost_usd"`
}

// ObsSpanRow is the T2 span skeleton. RequestID is the CONTENT-FREE soft join
// key the server uses for the proxy-exact wedge (obs_spans × api_turns). Name
// is an operation label (chat/get_weather/…), not a body (§8 decision 2).
type ObsSpanRow struct {
	OrgID            string  `json:"org_id,omitempty"`
	UserEmail        string  `json:"user_email,omitempty"`
	TraceID          string  `json:"trace_id"`
	SpanID           string  `json:"span_id"`
	ParentSpanID     string  `json:"parent_span_id,omitempty"`
	Kind             string  `json:"kind,omitempty"`
	Name             string  `json:"name,omitempty"`
	StartedAt        string  `json:"started_at,omitempty"`
	EndedAt          string  `json:"ended_at,omitempty"`
	DurationMs       int64   `json:"duration_ms"`
	Status           string  `json:"status,omitempty"`
	Model            string  `json:"model,omitempty"`
	Provider         string  `json:"provider,omitempty"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	ReasoningTokens  int64   `json:"reasoning_tokens"`
	TotalTokens      int64   `json:"total_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	CostSource       string  `json:"cost_source,omitempty"`
	RequestID        string  `json:"request_id,omitempty"`
	ToolCallID       string  `json:"tool_call_id,omitempty"`
}

// ObsSpanEventRow is a T2 span-event (metadata only — name + time, no
// attribute bodies).
type ObsSpanEventRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	TraceID   string `json:"trace_id"`
	SpanID    string `json:"span_id"`
	Time      string `json:"time,omitempty"`
	Name      string `json:"name,omitempty"`
}

// ObsContentRow is the T3 raw span body, mirroring OTelContentRow: Content
// present only under shipsRawContent(), ContentHash always.
type ObsContentRow struct {
	OrgID       string `json:"org_id,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
	SpanID      string `json:"span_id"`
	Kind        string `json:"kind"` // prompt/response/tool_io
	ContentHash string `json:"content_hash"`
	Content     string `json:"content,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

// ObsEvalRow is the T4 eval-run health summary (content-free).
type ObsEvalRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	Day         string  `json:"day"`
	DatasetName string  `json:"dataset_name,omitempty"`
	RunName     string  `json:"run_name,omitempty"`
	ScorerName  string  `json:"scorer_name,omitempty"`
	Total       int64   `json:"total"`
	Passed      int64   `json:"passed"`
	MeanScore   float64 `json:"mean_score"`
	MinScore    float64 `json:"min_score"`
	Source      string  `json:"source,omitempty"` // offline/online
}

// ObsEndUserSpendRow is the T5 per-END-USER spend aggregate (org-budget
// guardrails plan §2.1) — the cross-instance attribution the node-local
// budget surfaces can't provide. EndUser is the hosted-app end-user id
// (obs_traces.user: OTel enduser.id / the admission `user` / the proxy
// X-Superbased-User header), NOT an org member — it is PII, so this row rides
// ONLY under shipsRawContent() (composed in orgpush.go under ObsSummary &&
// shipsRawContent). OrgID/UserEmail are agent-stamped, UserEmail = the pushing
// developer/operator (re-pinned server-side to the authenticated pusher);
// EndUser is app-shared and NOT re-pinned. Content-free otherwise (a $ + token
// + trace-count aggregate, no bodies).
type ObsEndUserSpendRow struct {
	OrgID       string  `json:"org_id,omitempty"`
	UserEmail   string  `json:"user_email,omitempty"`
	Day         string  `json:"day"` // UTC YYYY-MM-DD
	EndUser     string  `json:"end_user"`
	CostUSD     float64 `json:"cost_usd"`
	Traces      int64   `json:"traces"`
	TotalTokens int64   `json:"total_tokens"`
}

// ObsCursor bounds an incremental obs structure/content push (T2/T3). v1 uses
// windowed-recompute (the server upserts by composite key), so the cursor is a
// simple since-day; the obs-owned high-water cursor is a documented follow-up.
type ObsCursor struct {
	SinceDay string `json:"since_day,omitempty"`
}

// ObsSpanBatch is the T2 structure push payload (traces + spans + events +
// cursor) returned by the obs provider in one shot.
type ObsSpanBatch struct {
	Traces []ObsTraceRow     `json:"traces"`
	Spans  []ObsSpanRow      `json:"spans"`
	Events []ObsSpanEventRow `json:"events"`
	Cursor ObsCursor         `json:"cursor"`
}

// ObsAdmissionRow is one input-admission verdict on the wire (Plane-A
// admission org tier, gap-audit 2026-07-10 §2.1 / #1a). It mirrors one
// obs_admission_events row: the node judges an end-user request against its
// admission policy and records the verdict; this row ships that verdict to the
// org server so admins get a READ-ONLY, monitoring-only fleet view. Authoring
// stays node-side — there is deliberately NO remote policy write.
//
// Privacy posture (mirrors GuardEventRow / ObsContentRow): the verdict
// METADATA is content-free and always ships (decision/severity/criterion +
// judge facts + latency + the soft-join ids + the node hash-chain links +
// message_hash — the raw request text is NEVER stored on the node, only its
// hash). The three content-bearing columns — Tenant, EndUser (PII: the
// hosted-app end-user id, obs_admission_events.user) and ReasonExcerpt (verdict
// prose that may quote the request) — ship ONLY under
// ShareOptions.shipsRawContent(), zeroed in orgpush.go otherwise. OrgID /
// UserEmail are agent-stamped like every other wire row (UserEmail = the
// pushing developer/operator, re-pinned server-side; EndUser is app-shared and
// NOT re-pinned).
type ObsAdmissionRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// TS is the verdict instant (RFC3339).
	TS string `json:"ts"`
	// Mode is the policy mode that judged the request: observe | enforce
	// (off never records).
	Mode string `json:"mode"`
	// Decision is the node's stored verdict vocabulary: allow | flag | ask |
	// deny. It ships VERBATIM — do NOT translate on the agent wire. The web2
	// contract renders blocked verdicts (ask/deny) as "would_block", but that
	// display mapping is the SERVER rollup's job; the agent must ship exactly
	// what the node stored so the server has the raw vocabulary.
	Decision string `json:"decision"`
	// Severity is the criterion severity: info | warn | high | critical.
	Severity string `json:"severity"`
	// CriterionID is the criterion that fired ('' when none did).
	CriterionID string `json:"criterion_id,omitempty"`
	// PolicyHash is the soft join to the ObsAdmissionPolicyRow that judged
	// this verdict.
	PolicyHash string `json:"policy_hash"`
	// JudgeUsed reports whether an LLM judge was invoked (vs a purely
	// deterministic verdict).
	JudgeUsed bool `json:"judge_used"`
	// JudgeHosting is the judge hosting bucket: local | provider | aggregator
	// | private | off.
	JudgeHosting string `json:"judge_hosting,omitempty"`
	// Degraded is the degradation cause when the judge did not cleanly decide:
	// '' | timeout-failopen | cache | prefiltered.
	Degraded string `json:"degraded,omitempty"`
	// LatencyMS is the admission-pipeline latency for this verdict.
	LatencyMS int64 `json:"latency_ms"`
	// MessageHash is the content-free hash of the raw request (the raw request
	// is NEVER stored on the node — this is the only always-present request
	// provenance).
	MessageHash string `json:"message_hash"`
	// TraceID / RequestID are content-free SOFT join keys (to obs_spans /
	// api_turns) so a verdict renders as enrichment on the trajectory view.
	TraceID   string `json:"trace_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// PrevHash / RowHash are the node's tamper-evidence hash-chain links
	// (content-free SHA-256 hex). RowHash doubles as the server-side dedup key.
	PrevHash string `json:"prev_hash,omitempty"`
	RowHash  string `json:"row_hash"`

	// --- Content-bearing (PII / prose) — ship ONLY under shipsRawContent() ---
	// Tenant is the hosted-app tenant identifier.
	Tenant string `json:"tenant,omitempty"`
	// EndUser is the hosted-app end-user id (obs_admission_events.user) — PII.
	EndUser string `json:"end_user,omitempty"`
	// ReasonExcerpt is the verdict prose, which may quote the request.
	ReasonExcerpt string `json:"reason_excerpt,omitempty"`
}

// ObsAdmissionPolicyRow is one content-addressed admission policy snapshot on
// the wire (Plane-A admission org tier). It mirrors one
// obs_admission_policy_versions row. Body is the ADMIN's authored policy
// (config, not end-user content), so — like RoutingPolicyDoc.Body — it ALWAYS
// ships (never gated by shipsRawContent()); user requests never land in this
// table. OrgID / UserEmail are agent-stamped attribution.
type ObsAdmissionPolicyRow struct {
	OrgID         string `json:"org_id,omitempty"`
	UserEmail     string `json:"user_email,omitempty"`
	PolicyHash    string `json:"policy_hash"`
	CreatedAt     string `json:"created_at"`
	Mode          string `json:"mode"`
	Scope         string `json:"scope"`
	CriteriaCount int64  `json:"criteria_count"`
	Body          string `json:"body"`
}

// ObsAdmissionBatch is the admission push payload (verdict events + policy
// snapshots + cursor) returned by the obs provider in one shot, mirroring
// ObsSpanBatch. Windowed-recompute v1 (the server upserts by RowHash /
// PolicyHash), so the cursor is a simple since-day.
type ObsAdmissionBatch struct {
	Events   []ObsAdmissionRow       `json:"events"`
	Policies []ObsAdmissionPolicyRow `json:"policies"`
	Cursor   ObsCursor               `json:"cursor"`
}

// ObsEvalItemRow is one per-item eval score on the wire (Plane-A eval-run
// detail org tier, gap-audit 2026-07-10 §1 / §2.2 / §6). It mirrors one
// obs_eval_scores row (source='run', run_id set) joined to its run
// (obs_eval_runs), dataset (obs_datasets) and dataset item (obs_dataset_items)
// for identity + content. Distinct from ObsEvalRow (T4), which ships run/scorer
// AGGREGATES only; this row is the per-item granularity the org Evals page
// needs to drill into a single run and to diff two runs of the same dataset.
//
// Privacy posture (mirrors ObsContentRow / ObsAdmissionRow): the score
// METADATA is content-free and always ships — the run/dataset identity, the
// span/trace soft-join keys, the scorer, the score/pass verdict, the scored
// span's duration, the score instant, and the dataset item's content_hash (the
// raw input/output are stored on the node ONLY under its ContentGate; the hash
// is the always-present content-free signal). The four content-bearing columns
// — InputExcerpt, ExpectedExcerpt, OutputExcerpt (bounded snapshots of the
// dataset item's input/reference/output) and Rationale (the scorer's verdict
// prose, which may quote the item) — ship ONLY under
// ShareOptions.shipsRawContent(), zeroed in composeObsTiers otherwise. OrgID /
// UserEmail are agent-stamped like every other wire row.
type ObsEvalItemRow struct {
	// OrgID / UserEmail are the agent-stamped attribution.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// RunID is the node-local obs_eval_runs.id. It is meaningful only paired
	// with the pushing node (re-pinned user_email / pushed_by_user_id) — the
	// server keys a run by (org, node, run_id) and the rollup exposes an opaque
	// composite ref, never this bare integer, to the client.
	RunID   int64  `json:"run_id"`
	RunName string `json:"run_name,omitempty"`
	// DatasetID / DatasetName identify the run's dataset (obs_eval_runs.dataset_id
	// / obs_datasets.name). Same node-local caveat as RunID for the id.
	DatasetID   int64  `json:"dataset_id"`
	DatasetName string `json:"dataset_name,omitempty"`
	// ItemID is the obs_dataset_items.id (0 when the score had no item). SpanID /
	// TraceID are the content-free soft-join keys back to the trajectory view.
	ItemID  int64  `json:"item_id"`
	SpanID  string `json:"span_id,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
	// Scorer / Score / Passed / Source are the verdict (obs_eval_scores).
	Scorer string  `json:"scorer"`
	Score  float64 `json:"score"`
	Passed bool    `json:"passed"`
	Source string  `json:"source,omitempty"` // run | online (only 'run' ships)
	// DurationMs is the scored span's duration (obs_spans ended-started); 0 when
	// the span is gone or has no end. TS is the score instant (RFC3339).
	DurationMs int64  `json:"duration_ms"`
	TS         string `json:"ts"`
	// ContentHash is the dataset item's content-free signal (obs_dataset_items
	// .content_hash) — always present, even when the excerpts are withheld.
	ContentHash string `json:"content_hash,omitempty"`

	// --- Content-bearing (bounded excerpts / prose) — ship ONLY under
	// shipsRawContent() ---
	// InputExcerpt / ExpectedExcerpt / OutputExcerpt are bounded snapshots of the
	// dataset item's input / reference / output (obs_dataset_items), which are
	// themselves stored on the node ONLY under its ContentGate.
	InputExcerpt    string `json:"input_excerpt,omitempty"`
	ExpectedExcerpt string `json:"expected_excerpt,omitempty"`
	OutputExcerpt   string `json:"output_excerpt,omitempty"`
	// Rationale is the scorer's verdict prose (obs_eval_scores.rationale), which
	// may quote the item — gated with the excerpts.
	Rationale string `json:"rationale,omitempty"`
}

// ObsEvalItemBatch is the per-item eval push payload (scores + cursor) returned
// by the obs provider in one shot, mirroring ObsSpanBatch / ObsAdmissionBatch.
// Windowed-recompute v1 (the server upserts by the run/item/scorer natural
// key), so the cursor is a simple since-day.
type ObsEvalItemBatch struct {
	Items  []ObsEvalItemRow `json:"items"`
	Cursor ObsCursor        `json:"cursor"`
}

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

// RoutingPolicyDoc is the §R19.1 org-distributed policy document. The
// body is a TOML fragment using the [routing] vocabulary; the agent
// composes it with hard-constraints-first semantics
// (routingconfig.ComposeOrgPolicy) and STRUCTURALLY ignores any
// enabled/mode keys — enforcement is node-side opt-in by design
// (§R23: no remote enforce toggle exists).
type RoutingPolicyDoc struct {
	Version int64 `json:"version"`
	// Body is the TOML policy fragment.
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(body)).
	BodyHash string `json:"body_hash"`
	// Signature is base64(Ed25519 signature over body bytes) made with
	// the org server's policy signing key.
	//
	// This is the v1 rail and it is RELEASED, which is why it still
	// covers the bare body — see SignatureV2 below and docs/security.md
	// ledger row ROUTING-SIG-1.
	Signature string `json:"signature"`
	// SignatureV2 is base64(Ed25519 signature over
	// RoutingPolicySigningMessageV2(Version, Body)) — the
	// DOMAIN-SEPARATED, VERSION-BOUND signature that closes
	// ROUTING-SIG-1's version-replay and cross-rail confusion.
	//
	// ADDITIVE and omitempty on purpose, in BOTH compat directions: a
	// pre-v2 server's response is byte-identical (the field is simply
	// absent, and the agent falls back to verifying Signature), and a
	// pre-v2 agent ignores the extra key. An agent that RECEIVES a v2
	// signature verifies THAT and never falls back — the fallback is
	// for a document carrying no v2 at all, never for one whose v2
	// failed.
	SignatureV2 string `json:"signature_v2,omitempty"`
	// PublicKey is base64(Ed25519 public key) — TOFU-pinned by the
	// agent on first receipt (enrolment-channel trust, §R19.1).
	PublicKey string `json:"public_key"`
}

// OrgAnnouncementDoc is the rail-R3 org announcement document
// (docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4).
// It mirrors RoutingPolicyDoc field-for-field on purpose: the same
// versioned + signed + TOFU-pinned distribution mechanism carries it,
// and the agent verifies it with the same helper.
//
// The ONLY difference is what Body means. Here it is the plan §1
// announcement JSON — either one object or an array of them — and an
// EMPTY Body is the retraction: a published empty document is a valid,
// signed, version-bumped instruction to show nothing. (Retraction has
// to be a real published version, not a delete, because the agent's
// monotonic-version short-circuit is what makes the poll cheap.)
//
// Nothing about this document is a remote control: it can only ever
// put text in a dismissible banner. The node's [dashboard].
// org_announcements switch silences it locally, and there is no
// server-side toggle for that — same posture as share.full_content.
type OrgAnnouncementDoc struct {
	Version int64 `json:"version"`
	// Body is the announcement JSON (a §1 object or an array of them).
	// Empty means "retracted — show nothing".
	Body string `json:"body"`
	// BodyHash is hex(SHA-256(body)) — an integrity/dedup value for
	// display. It is NOT what authorizes the document; see Signature.
	BodyHash string `json:"body_hash"`
	// Signature is base64(Ed25519 signature over
	// AnnouncementSigningMessage(Version, Body)) made with the org
	// server's distribution signing key — the SAME key that signs
	// RoutingPolicyDoc, resolved through the one seam
	// orgserver/routingpolicy.SigningKeyWith: the configured
	// [policy].signing_key_path (the key the enrolment response delivers)
	// when the org has one, the routing_policy_keys row otherwise.
	//
	// The signed message is domain-separated and version-bound, NOT the
	// bare body: sharing one key across two rails is only safe if a
	// signature minted for one cannot verify on the other, and a
	// version-bumped replay of a captured document (an announcement, or
	// an old retraction) must not be accepted by a node.
	Signature string `json:"signature"`
	// PublicKey is base64(Ed25519 public key) — TOFU-pinned by the
	// agent on first receipt (enrolment-channel trust).
	PublicKey string `json:"public_key"`
}
