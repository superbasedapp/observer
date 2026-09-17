package dashboard

import (
	"context"
	"net/http"
)

// SandboxProber is the dashboard's self-owned seam onto the B9 sandboxed-
// terminal probe (docs/plans/b9-sandboxed-terminals-implementation-plan-2026-08-08.md
// §5/§7). It is DEFINED here, not imported from internal/sandbox — the same
// injected-seam discipline as LaunchManager/BuildHandoff/DemoSeeder
// (CLAUDE.md #2: a domain package importing os/exec-adjacent machinery is a
// smell; the dashboard never learns the bwrap/git mechanics behind this
// call). cmd (U5) wires a thin adapter over the real probe
// (cmd/observer/terminal_sandbox.go) that implements this interface with
// plain data. A nil Options.SandboxProber IS the disabled state — see
// handleTerminalSandbox (fail-soft) and handleTerminalLaunch's fail-CLOSED
// sandbox validation (A5).
type SandboxProber interface {
	// ProbeSandbox reports the daemon's current sandbox availability. The
	// underlying probe is cached (~60s, per the plan's cache posture) so
	// this call is cheap to make on every dialog open / launch attempt. It
	// never returns an error: a probe failure IS a verdict (e.g.
	// "backend_missing"), not an exceptional condition — see
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
)

// SandboxAvailability is the dashboard-owned wire shape of a sandbox probe
// result — the GET /api/terminal/sandbox response body AND the value
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
	// DefaultOn mirrors [terminal.sandbox].default_on so the New Terminal
	// dialog can honor the operator's persisted default after restart.
	DefaultOn bool `json:"default_on"`
	// Sources is the per-workspace-source availability list ("live",
	// "clone-local", "clone-remote", "worktree") — the server's OWN
	// membership list handleTerminalLaunch validates a client-supplied
	// workspace_source against; never trust the client's string verbatim.
	Sources []SandboxSourceAvail `json:"sources,omitempty"`
	// Tools is the per-tool sandbox-launchability map, keyed by tool NAME
	// (e.g. "claude-code") — whether that tool has a grounded SandboxSpec
	// registry row (internal/integration) it can be launched under a
	// sandbox with. A tool absent from this map, or present with
	// Available=false, cannot be sandboxed (A3: v1 grounds only
	// claude-code; every other row carries an honest Note/Reason).
	Tools map[string]SandboxToolAvail `json:"tools,omitempty"`
}

// SandboxSourceAvail is one entry of SandboxAvailability.Sources — whether a
// given workspace source ("live" / "clone-local" / "clone-remote" /
// "worktree") is currently usable, and why not when it isn't (e.g.
// "clone-remote" reporting Available=false with Reason
// "allow_remote_clone is not set").
type SandboxSourceAvail struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// SandboxToolAvail is one entry of SandboxAvailability.Tools — whether a
// tool has a grounded SandboxSpec row it can be sandboxed with, and why not
// when it doesn't (e.g. "state dirs not yet grounded — not
// sandbox-launchable", mirroring the registry's honest-Note discipline).
type SandboxToolAvail struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// handleTerminalSandbox serves GET /api/terminal/sandbox — the B9 sandbox
// probe surface (plan §5, mirroring the B5 GET /api/terminal/launch/models
// fail-soft pattern). It ALWAYS returns HTTP 200: an old daemon build 404s
// this route entirely (unknown path), while a live daemon always 200s with
// an honest verdict — including when the sandbox feature itself is absent
// (nil seam), which reports {"available":false,"verdict":"disabled_by_config",
// "reason":"…"} rather than an error status. This is deliberately DIFFERENT
// from handleTerminalLaunch's fail-CLOSED sandbox validation: that handler
// answers "can I honour a sandbox request RIGHT NOW" (and refuses the launch
// with 501/403/400 when it can't); this endpoint answers "what can this
// daemon do at all" — a read, never a refusal.
func (s *Server) handleTerminalSandbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.SandboxProber == nil {
		writeJSON(w, SandboxAvailability{
			Available: false,
			Verdict:   VerdictDisabledByConfig,
			Reason:    "sandbox support is not enabled on this daemon",
		})
		return
	}
	writeJSON(w, s.opts.SandboxProber.ProbeSandbox(r.Context()))
}
