package orgcontract

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
	// (ValidConfigLayerTool), never a path, key or value. Additive: an older
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
	// CaptureRiskSandboxGatewayConfigDrift (OpenShell build lane O4,
	// revision 1 R-17): the config of a sandbox gateway Observer owns on
	// this node (the managed OpenShell gateway's gateway.toml) is no longer
	// what Observer wrote for it: changed or removed outside Observer since
	// the gateway was last started. TAMPER-EVIDENT, never tamper-proof: the
	// file, the record of what was started and the daemon all belong to the
	// same local OS user, who can rewrite all three together. A standing
	// condition, label-only (no path crosses). Additive: an older server
	// drops the label, an older node never sends it.
	CaptureRiskSandboxGatewayConfigDrift = "sandbox_gateway_config_drift"
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
	// CaptureUnknownSandboxGatewayConfig (lane O4): the read-back of a
	// sandbox gateway config Observer owns could not say whether it is
	// still Observer's (unreadable, or a record that does not parse); never
	// read as clean. Additive like the capture-risk label.
	CaptureUnknownSandboxGatewayConfig = "sandbox_gateway_config_unknown"
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
