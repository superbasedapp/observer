package dashapi

import (
	"context"
	"errors"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/settingslink"
)

// SandboxProber is the dashboard's self-owned seam onto the B9 sandboxed-
// terminal probe (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
// §5/§7). It is DEFINED here, not imported from internal/sandbox - the same
// injected-seam discipline as LaunchManager/BuildHandoff/DemoSeeder
// (CLAUDE.md #2: a domain package importing os/exec-adjacent machinery is a
// smell; the dashboard never learns the bwrap/git mechanics behind this
// call). cmd (U5) wires a thin adapter over the real probe
// (cmd/observer/terminal_sandbox.go) that implements this interface with
// plain data. A nil Options.SandboxProber IS the disabled state - see
// handleTerminalSandbox (fail-soft) and handleTerminalLaunch's fail-CLOSED
// sandbox validation (A5).
type SandboxProber interface {
	// ProbeSandbox reports the daemon's current sandbox availability. The
	// underlying probe is cached (~60s, per the plan's cache posture) so
	// this call is cheap to make on every dialog open / launch attempt. It
	// never returns an error: a probe failure IS a verdict (e.g.
	// "backend_missing"), not an exceptional condition - see
	// SandboxAvailability.
	ProbeSandbox(ctx context.Context) SandboxAvailability
}

// The verdicts the DASHBOARD layer itself produces, as opposed to the
// platform/backend verdicts internal/sandbox owns (sandbox.Verdict*). They
// live here because this package owns the wire shape and because the
// distinction between them is a dashboard-copy distinction: one names a
// switch the operator can flip on this very page, the other names a config
// fault that needs fixing first.
const (
	// VerdictDisabledByConfig: [terminal.sandbox].enabled is false, or no
	// sandbox seam is wired into this dashboard at all. Mirrors
	// sandbox.VerdictDisabledByConfig; re-declared so a dashboard consumer
	// never has to import the exec-adjacent package (CLAUDE.md #2).
	VerdictDisabledByConfig = "disabled_by_config"
	// VerdictRuntimeInitFailed: [terminal.sandbox].enabled is TRUE but the
	// daemon could not build the sandbox runtime (e.g. an unwritable or
	// non-absolute workspaces_dir). Distinct from disabled_by_config on
	// purpose: telling an operator who already enabled the feature that it
	// is "disabled by config" sends them to flip a switch that is already
	// on. Reason carries the construction error verbatim.
	VerdictRuntimeInitFailed = "runtime_init_failed"
	// VerdictNotInBuild: the terminal sandbox component (terminals.sandbox)
	// is compiled out of this binary (D-514). Like a missing backend it is a
	// capability gap of this daemon, so a sandboxed launch answers 501, and
	// the picker shows the option disabled with the reason.
	VerdictNotInBuild = "not_in_build"
	// VerdictProbeTimedOut: the dashboard's read of the sandbox probe (GET
	// /api/terminal/sandbox) did not answer within its deadline, so the
	// route answers this instead of holding the page (lane L2). The probe
	// keeps running in the background and the next read gets its answer.
	// Only the read route produces it; the launch gate never sees it, and an
	// unrecognised verdict is fail-closed there anyway.
	VerdictProbeTimedOut = "probe_timed_out"
	// VerdictProbeFailed: the probe stopped with an internal error (a panic
	// the read route recovered), so the route answers this rather than
	// failing the request (lane L2).
	VerdictProbeFailed = "probe_failed"
)

// SandboxAvailability is the dashboard-owned wire shape of a sandbox probe
// result - the GET /api/terminal/sandbox response body AND the value
// handleTerminalLaunch's fail-closed validation reasons over. Verdict is the
// closed vocabulary from the plan's §7 failure-honesty table: "available",
// "unsupported_platform", "backend_missing", "backend_too_old",
// "userns_denied", "tool_unmapped", "disabled_by_config",
// "runtime_init_failed", "workspace_prep_failed". Reason names the exact gap
// in human terms (e.g. which sysctl is denied, which bwrap version was
// found, which directory could not be created) so the New Terminal dialog's
// disabled copy can be honest rather than generic.
//
// An unrecognised verdict is fail-closed at the launch gate
// (statusForSandboxVerdict defaults to 501), so adding a verdict string here
// can never accidentally widen what a sandboxed launch is allowed to do.
type SandboxAvailability struct {
	Available bool   `json:"available"`
	Verdict   string `json:"verdict,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// ReasonListsRows: Reason lists every row of this host (the overall
	// answer when none is available), not one row's own reason (FX1-A4).
	ReasonListsRows bool `json:"reason_lists_rows,omitempty"`
	// Backend names the sandbox mechanism ("bwrap" in v1); BackendVersion is
	// the resolved binary's parsed version string. Both empty when the
	// backend itself could not be located.
	Backend        string `json:"backend,omitempty"`
	BackendVersion string `json:"backend_version,omitempty"`
	// HomeMode echoes the live [terminal.sandbox].home_mode ("tmpfs" or
	// "readonly") so the dialog can show what a sandboxed launch will do to
	// $HOME without a separate config read.
	HomeMode string `json:"home_mode,omitempty"`
	// Egress echoes the live [terminal.sandbox].egress network tier
	// ("internet", "proxy_only", "none" or "host"; SR27-SBX-1).
	Egress string `json:"egress,omitempty"`
	// DefaultOn mirrors [terminal.sandbox].default_on so the New Terminal
	// dialog can honor the operator's persisted default after restart.
	DefaultOn bool `json:"default_on"`
	// Sources is the per-workspace-source availability list ("live",
	// "clone-local", "clone-remote", "worktree") - the server's OWN
	// membership list handleTerminalLaunch validates a client-supplied
	// workspace_source against; never trust the client's string verbatim.
	Sources []SandboxSourceAvail `json:"sources,omitempty"`
	// Tools is the per-tool sandbox-launchability map, keyed by tool NAME
	// (e.g. "claude-code") - whether that tool has a grounded SandboxSpec
	// registry row (internal/integration) it can be launched under a
	// sandbox with. A tool absent from this map, or present with
	// Available=false, cannot be sandboxed (A3: v1 grounds only
	// claude-code; every other row carries an honest Note/Reason).
	Tools map[string]SandboxToolAvail `json:"tools,omitempty"`
	// Backends is the additive per-backend list (sandbox plan v2 section
	// 9): every registry row, offered or planned, with its availability on
	// this host from the one selection table (internal/sandboxselect), its
	// verification ("beta" when not live) and its computed capture level per
	// tier. Old clients ignore it; every field above keeps its meaning.
	Backends []SandboxBackendAvail `json:"backends,omitempty"`
	// Org is what the organization sets for this node's sandbox (sandbox
	// plan v2 section 9, lane SBX-P1B): the terminals.isolation floors in
	// force and the [terminal.sandbox] pins applied, which the Sandbox
	// isolation card shows read-only ("Set by your organization"). Absent
	// when the organization sets nothing, and on an older daemon.
	Org *SandboxOrgSettings `json:"org,omitempty"`
}

// SandboxOrgSettings is SandboxAvailability.Org.
type SandboxOrgSettings struct {
	// Floors are the isolation floors in force, keyed by the family's wire
	// key (min_isolation, allowed_backends, ...).
	Floors []SandboxOrgValue `json:"floors,omitempty"`
	// Pins are the applied settings.pin values, keyed by the
	// [terminal.sandbox] key without its prefix (home_mode, mask_paths, ...).
	Pins []SandboxOrgValue `json:"pins,omitempty"`
	// Managed are the keys the in-force sandbox managed body sets on this
	// node, each with its EFFECTIVE value (the body composed onto the local
	// block: mask_paths is the union, a pinned key keeps its pin), keyed
	// like Pins (lane SBX-P2E, P1c audit F10). The local value in
	// config.toml is unchanged and applies again when the body goes.
	Managed []SandboxOrgValue `json:"managed,omitempty"`
	// ManagedRefused are the body keys this node did not apply; Value is
	// the closed reason (pinned_by_org, sensitive_host_path, ...).
	ManagedRefused []SandboxOrgValue `json:"managed_refused,omitempty"`
}

// SandboxOrgValue is one organization-set value, ready to display.
type SandboxOrgValue struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// SandboxCloneWhere is a hosted row's clone location facts for the New
// Terminal dialog (decision SBXD-5): the setting, whether a launch may
// choose (only while the setting is auto), the places the row can clone
// now before a URL is typed, and why the others cannot. Values are
// internal/workspace CloneWhere's (auto, box, home).
type SandboxCloneWhere struct {
	// Setting is [terminal.sandbox.hosted].clone_where in force.
	Setting string `json:"setting"`
	// Fixed: the setting is box or home, so a launch cannot choose.
	Fixed bool `json:"fixed"`
	// Choices are the values a launch on this row can take now.
	Choices []string `json:"choices"`
	// Notes say, per value not in Choices, why (plain words).
	Notes map[string]string `json:"notes,omitempty"`
	// Rule is the setting's rule in plain words.
	Rule string `json:"rule"`
}

// SandboxBackendAvail is one entry of SandboxAvailability.Backends.
type SandboxBackendAvail struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Class    string `json:"class"`
	Location string `json:"location"`
	// Maturity is planned, preview or shipped; a planned row is listed so
	// the picker can say when it lands, and is never available.
	Maturity  string `json:"maturity"`
	Phase     string `json:"phase,omitempty"`
	Available bool   `json:"available"`
	// Verdict, Rule and Reason are the selection drop for an unavailable
	// row (rule S0 to S13), empty when available.
	Verdict string `json:"verdict,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Enabled is whether the row is in the enabled backends list
	// ([terminal.sandbox].backends after any organization pin, the master
	// switch aside), so a settings editor can show it checked.
	Enabled bool `json:"enabled"`
	// WhenEnabledAvailable, WhenEnabledVerdict and WhenEnabledReason say,
	// for a row dropped only because it is not enabled (verdict
	// disabled_by_config), what selection answers once it is: available,
	// or the next rule's drop. All empty for every other row, so a client
	// can tell "enable it and it runs" from "enabling it would not help".
	WhenEnabledAvailable bool   `json:"when_enabled_available,omitempty"`
	WhenEnabledVerdict   string `json:"when_enabled_verdict,omitempty"`
	WhenEnabledReason    string `json:"when_enabled_reason,omitempty"`
	// Verification is live, doc, fixture or inferred on this host; Beta is
	// true for anything not live (and for a version outside the tested
	// range), rendered as "beta" everywhere.
	Verification string   `json:"verification,omitempty"`
	Beta         bool     `json:"beta"`
	RegisterRef  string   `json:"register_ref,omitempty"`
	Version      string   `json:"version,omitempty"`
	Egress       []string `json:"egress,omitempty"`
	// CaptureByTier is the computed capture label per tier for a
	// proxy-routed tool that holds its own credential (the common case),
	// e.g. "full (gateway-guarded)" for internet through the gateway.
	CaptureByTier map[string]string `json:"capture_by_tier,omitempty"`
	// Component is the catalog id that owns the row's driver.
	Component string `json:"component"`
	// MasksWorkspaceSecrets is the registry's capability flag: the row can hide
	// the workspace's secret files inside the box on request
	// (sandboxbackend.Capability.CanMaskWorkspaceSecrets; decision D32). The
	// dashboard branches on this flag, never on the row's id.
	MasksWorkspaceSecrets bool `json:"masks_workspace_secrets,omitempty"`
	// WorkspaceSources are the workspace sources this row takes (a hosted
	// row: the live tree uploaded, or the vendor's own deliveries); nil
	// means every source this machine offers (Sources). A launch on the row
	// with any other source is refused, so the dialog offers only these.
	WorkspaceSources []string `json:"workspace_sources,omitempty"`
	// SourceDeliveries maps each source in WorkspaceSources to how the tree
	// reaches the box (internal/workspace Delivery values: "sync" is an
	// upload of a copy of a git repository's files, whose changes come back
	// as a diff; "remote_clone" is a clone made in the box), so the dialog
	// labels and checks a source by its delivery, never by the row id
	// (lane UX, items H5 and H8). Nil on a row that serves no
	// WorkspaceSources.
	SourceDeliveries map[string]string `json:"source_deliveries,omitempty"`
	// ToolNotices are, per tool name, the refusal a launch of that tool on
	// this row would meet before any box is made because the tool cannot
	// reach the box (no template set and no install way that can work
	// there; the launch's own rule, sandboxremote.PlanToolInstall, at the
	// configured network tier). Only tools that would be refused are
	// listed (lane UX, item H4).
	ToolNotices map[string]SandboxKeyNotice `json:"tool_notices,omitempty"`
	// HookNotices are, per sandbox-launchable tool, whether this machine's
	// guard checks the agent's tool calls in this row's box on a launch now
	// ([terminal.sandbox.hosted].guard_hooks, guard enforcement here, and
	// whether the tool's hooks can be set up in a box; lane HOOKS,
	// SBXD-6), with the sentence the New Terminal dialog shows. Where
	// gating does not apply the sentence is the no_hook_gating
	// disclosure's, which is then said here, per tool, and not with the
	// row's Disclosures. Nil on a row that is not hosted.
	HookNotices map[string]SandboxHookNotice `json:"hook_notices,omitempty"`
	// NetworkNotes are what the person is told before Start about the box's
	// own network at the configured tier: on a tier the provider does not
	// document (a hosted internet tier), that its traffic is the
	// provider's and the cloud metadata address is not known to be refused,
	// then what live runs saw (sandboxremote.TierNetworkNotes, the same
	// sentences the consent screen shows; lane UX, item H10).
	NetworkNotes []string `json:"network_notes,omitempty"`
	// WorkspaceSourceNotes says, in plain words and keyed by source, why a
	// source the row delivers is not in WorkspaceSources now (a hosted
	// box-side clone: the remote-clone switch off, a tier with no route to
	// the git host, no git hosts listed); a source the row never takes has
	// none.
	WorkspaceSourceNotes map[string]string `json:"workspace_source_notes,omitempty"`
	// CloneWhere is where the row's "Clone a remote URL" source may clone
	// (decision SBXD-5), for a hosted row that can clone either in its box
	// or on this machine; nil on every other row.
	CloneWhere *SandboxCloneWhere `json:"clone_where,omitempty"`
	// Hint is the driver's note about a known issue on this host that does
	// not make the row unavailable (for example a container runtime known
	// to fail, with the known-good one); empty when none.
	Hint string `json:"hint,omitempty"`
	// GatewayMode is the gateway that runs the row's boxes, for a row that
	// has one (managed_local or external; OpenShell lane O4); empty for
	// every other row. The org floor gateway_modes judges it.
	GatewayMode string `json:"gateway_mode,omitempty"`
	// Prerequisite is the driver's plain sentence of what the row needs on
	// this host (for the openshell row the docker group, which is
	// root-equivalent, or rootless Podman 5, which the probe still
	// refuses); empty when none. Shown as served, never restated.
	Prerequisite string `json:"prerequisite,omitempty"`
	// VersionPins are the version pin values the row's driver serves for
	// the dashboard's pin picker (the openshell row: its tested versions;
	// a pin to another version can never make it usable); absent when the
	// row has no pin. The picker reads them, never a hard-coded list.
	VersionPins []string `json:"version_pins,omitempty"`
	// Disclosures are what the user is told before first use, one per
	// closed registry disclosure, each with the daemon's own text for this
	// row's gateway mode (OpenShell lane O4). Old clients ignore it.
	Disclosures []SandboxDisclosure `json:"disclosures,omitempty"`
}

// SandboxDisclosure is one entry of SandboxBackendAvail.Disclosures: the
// closed registry id and the sentence the dashboard shows as served.
type SandboxDisclosure struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// SandboxSourceAvail is one entry of SandboxAvailability.Sources - whether a
// given workspace source ("live" / "clone-local" / "clone-remote" /
// "worktree") is currently usable, and why not when it isn't (e.g.
// "clone-remote" reporting Available=false with Reason
// "allow_remote_clone is not set").
type SandboxSourceAvail struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// SandboxToolAvail is one entry of SandboxAvailability.Tools - whether a
// tool has a grounded SandboxSpec row it can be sandboxed with, and why not
// when it doesn't (e.g. "state dirs not yet grounded - not
// sandbox-launchable", mirroring the registry's honest-Note discipline).
type SandboxToolAvail struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// HostedKey says, when set, what a hosted sandbox launch of this tool
	// meets on its model key under the configured key custody (the same
	// rule the launch walks, sandboxcred.HomeKey): a blocking notice when
	// the launch would be refused, an advisory one when it goes ahead with
	// something the person should know first. Nil when there is nothing to
	// say, or when no hosted row is listed.
	HostedKey *SandboxKeyNotice `json:"hosted_key,omitempty"`
}

// SandboxKeyNotice is a line a person reads before Start about the model
// key of a hosted launch: the closed code, the plain sentence, the
// technical detail (config keys and commands, for a "Technical details"
// tooltip only), and its Severity. A blocking notice is a refusal the
// launch would meet; an advisory one does not block Start (which keys the
// agent gets, or that it starts without one). An absent Severity (a daemon
// before it) reads as blocking, as every notice was then.
type SandboxKeyNotice struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Technical string `json:"technical,omitempty"`
	Severity  string `json:"severity,omitempty"`
	// Place is the settingslink place where the fix is made (the dialog
	// links there); omitted when the daemon names none, and the dialog then
	// links to its own default for the notice.
	Place settingslink.Place `json:"place,omitempty"`
	// Custody is the custody this launch resolved to (home_relay or
	// in_box_api_key; decision SBXD-1), for the "Technical details" tooltip
	// and the dialog's choice of controls. Absent from a daemon before it.
	Custody string `json:"custody,omitempty"`
	// KeepHome are the providers whose key, once stored on this machine,
	// would keep the key here (the dialog's paste field). Set only while
	// credential injection is selected.
	KeepHome []SandboxKeyProvider `json:"keep_home,omitempty"`
	// ToolKeys and LoginSeed are the tool's opt-in in-box key sources
	// (decision SBXD-4), present when the tool's registry row grounds one
	// and the launch puts the key in the box.
	ToolKeys  *SandboxKeySource `json:"tool_keys,omitempty"`
	LoginSeed *SandboxKeySource `json:"login_seed,omitempty"`
}

// SandboxKeyProvider names one provider for a person: its id and the key
// label ("OpenAI API key").
type SandboxKeyProvider struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// SandboxKeySource is one opt-in in-box key source of a tool: whether it is
// on for the tool in the config.
type SandboxKeySource struct {
	On bool `json:"on"`
}

// SandboxHookNotice is one tool's entry of SandboxBackendAvail.HookNotices:
// whether guard checks the agent's tool calls in the box, the closed reason
// (sandboxremote GuardHooksReason*), the sentence shown before Start and the
// internal detail for "Technical details".
type SandboxHookNotice struct {
	Gated     bool   `json:"gated"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Technical string `json:"technical,omitempty"`
}

// The closed SandboxKeyNotice.Severity vocabulary ("" reads as blocking).
const (
	SandboxKeyBlocking = "blocking"
	SandboxKeyAdvisory = "advisory"
)

// SandboxStepRefusal is a sandboxed launch refused before anything started
// (no workspace prepared, no box made) whose fix is a choice the person
// makes in Terminals > Settings, said in plain words: Message is the
// sentence the dashboard shows, Technical the detail behind it (config
// keys, commands), Code the closed refusal code. The dashboard answers it
// as a needs-setting refusal; a CLI prints Error(), which carries both.
type SandboxStepRefusal struct {
	Code      string
	Message   string
	Technical string
}

// Error is the refusal for a terminal or a log: the code, the sentence and
// the detail.
func (e *SandboxStepRefusal) Error() string {
	s := "terminal_sandbox: " + e.Code + ": " + e.Message
	if e.Technical != "" {
		s += " (" + e.Technical + ")"
	}
	return s
}

// SandboxRefusalText is the sentence a surface shows for err: the plain
// Message of a SandboxStepRefusal anywhere in its chain (never its code
// or technical detail, which Error() carries for a terminal or a log), else
// err.Error().
func SandboxRefusalText(err error) string {
	var step *SandboxStepRefusal
	if errors.As(err, &step) && strings.TrimSpace(step.Message) != "" {
		return step.Message
	}
	return err.Error()
}

// SandboxConsentRefusalCode is the closed "error" code of a hosted launch
// refused for its consent (the dashboard's 409 body).
const SandboxConsentRefusalCode = "consent_required"

// SandboxConsentRefusal is a hosted sandbox launch refused before anything
// started because the person's agreement to what leaves this machine is
// missing or no longer matches the launch (a changed upload scope, region,
// custody...). Provider is the hosted row id; Verdict is the closed
// sandboxremote consent verdict (consent_required, consent_changed_<field>,
// consent_stale_version, consent_tampered). The dashboard answers it with a
// 409 carrying both, so the New Terminal dialog shows the consent again
// instead of the raw sentence; a CLI prints Error().
type SandboxConsentRefusal struct {
	Provider string
	Verdict  string
}

// Error is the refusal for a terminal or a log, worded as before the type
// existed (the verdict in brackets, where to agree).
func (e *SandboxConsentRefusal) Error() string {
	return "terminal_sandbox: " + SandboxConsentRefusalCode + " (" + e.Verdict + "): review what leaves this machine and agree in Terminals > Settings > Hosted sandboxes, or run `observer sandbox hosted consent " + e.Provider + "`"
}

// SandboxSeizeRow is what the strace switch ([terminal.sandbox]
// .seccomp_allow_seize, lane ptrace) gives one sandbox that loads
// Observer's syscall filter, on this host now.
type SandboxSeizeRow struct {
	Backend string `json:"backend"`
	Label   string `json:"label"`
	// Lifted: a launch on the row would get PTRACE_SEIZE with the switch on.
	Lifted bool `json:"lifted"`
	// Ground is the containment ground ("pid_namespace" or "yama") when
	// Lifted.
	Ground string `json:"ground,omitempty"`
	// Reason says why PTRACE_SEIZE stays denied on the row when not Lifted.
	Reason string `json:"reason,omitempty"`
}

// SandboxSeizeHost is the sandbox module's answer for the strace switch:
// Yama's ptrace_scope as read now (YamaKnown false when it cannot be read)
// and one row per sandbox that loads Observer's filter.
type SandboxSeizeHost struct {
	YamaScope int
	YamaKnown bool
	Rows      []SandboxSeizeRow
}
