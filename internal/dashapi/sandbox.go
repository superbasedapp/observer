package dashapi

import (
	"context"
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

// The two verdicts the DASHBOARD layer itself produces, as opposed to the
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
	// Hint is the driver's note about a known issue on this host that does
	// not make the row unavailable (for example a container runtime known
	// to fail, with the known-good one); empty when none.
	Hint string `json:"hint,omitempty"`
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
}
