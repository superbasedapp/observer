//go:build !sbo_omit_integration_shell_wrap

package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
)

// shellWrapSettingsSection is the Settings section the command-wrapping card
// renders under; a governance read-only / hidden pin on it refuses the
// writes here exactly as it refuses the section's generic config writes.
const shellWrapSettingsSection = "terminal"

// shellWrapApplyBody is the POST /api/shell-wrap/apply body.
type shellWrapApplyBody struct {
	Target string   `json:"target"`
	Tools  []string `json:"tools"`
	Shells []string `json:"shells"`
	DryRun bool     `json:"dry_run"`
}

// shellWrapDisableBody is the POST /api/shell-wrap/disable body.
type shellWrapDisableBody struct {
	Target string `json:"target"`
	DryRun bool   `json:"dry_run"`
}

// shellWrapServiceError answers a refused apply / disable (a malformed start-
// up file, an unavailable target, an unsafe path): a conflict with the
// machine's state, never a server fault.
func shellWrapServiceError(w http.ResponseWriter, prefix string, err error) {
	http.Error(w, prefix+err.Error(), http.StatusConflict)
}

// handleShellWrapStatus serves GET /api/shell-wrap/status: the recorded
// [shell_wrap] choice against the shims and start-up-file blocks on disk,
// with a per-row honesty label from integration.WrappedCommandFor. Owner-
// local (it names files in the operator's home), and it mints the confirm
// token the two write routes require.
func (s *Server) handleShellWrapStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ShellWrap == nil {
		http.Error(w, "command wrapping is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	target, err := shellwrapsvc.ParseTarget(r.URL.Query().Get("target"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok := setConfirmCookie(w, r)
	targets, err := s.opts.ShellWrap.Targets(r.Context())
	if err != nil {
		writeErr(w, fmt.Errorf("shell-wrap targets: %w", err))
		return
	}
	st, err := s.opts.ShellWrap.StatusFor(r.Context(), target)
	if err != nil {
		if errors.Is(err, shellwrapsvc.ErrTargetUnavailable) {
			shellWrapServiceError(w, "shell-wrap status: ", err)
			return
		}
		writeErr(w, fmt.Errorf("shell-wrap status: %w", err))
		return
	}
	writeJSON(w, map[string]any{"confirm_token": tok, "status": st, "target": target, "targets": targets})
}

// shellWrapGovernanceRefused applies the Settings-section pin to a write.
func (s *Server) shellWrapGovernanceRefused(w http.ResponseWriter, r *http.Request) bool {
	if s.opts.Governance == nil {
		return false
	}
	eff := s.opts.Governance(r.Context())
	if !eff.VisibilityActive() {
		return false
	}
	if eff.IsSettingsSectionHidden(shellWrapSettingsSection) || eff.IsSettingsSectionReadOnly(shellWrapSettingsSection) {
		writeGovernanceRefusal(w, http.StatusConflict, "governance_read_only", shellWrapSettingsSection, eff,
			"This setting is pinned by your organization and cannot be changed here.")
		return true
	}
	return false
}

// handleShellWrapApply serves POST /api/shell-wrap/apply: write the shims
// for the chosen commands and the PATH block into the chosen shells'
// start-up files (dry_run: compute and return the exact changes, write
// nothing). POST + JSON + the double-submit confirm token.
func (s *Server) handleShellWrapApply(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.ShellWrap == nil {
		http.Error(w, "command wrapping is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	var body shellWrapApplyBody
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode shell-wrap apply: "+err.Error(), http.StatusBadRequest)
		return
	}
	target, err := shellwrapsvc.ParseTarget(body.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !body.DryRun && s.shellWrapGovernanceRefused(w, r) {
		return
	}
	s.configWriteMu.Lock()
	out, err := s.opts.ShellWrap.Apply(r.Context(), shellwrapsvc.Request{Target: target, Tools: body.Tools, Shells: body.Shells, DryRun: body.DryRun})
	s.configWriteMu.Unlock()
	if err != nil {
		shellWrapServiceError(w, "", err)
		return
	}
	if !body.DryRun {
		s.notifyConfigSaved()
		s.recordManageAudit(r, "shell_wrap_apply", fmt.Sprintf("target=%s tools=%s shells=%s changes=%d",
			shellWrapTargetLabel(target), strings.Join(body.Tools, ","), strings.Join(body.Shells, ","), len(out.Changes)))
	}
	writeJSON(w, out)
}

// shellWrapTargetLabel names a target in an audit row.
func shellWrapTargetLabel(t shellwrapsvc.Target) string {
	if t == shellwrapsvc.TargetNative {
		return "native"
	}
	return string(t)
}

// handleShellWrapDisable serves POST /api/shell-wrap/disable: remove every
// shim and every marked block (each start-up file restored byte-for-byte).
func (s *Server) handleShellWrapDisable(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.ShellWrap == nil {
		http.Error(w, "command wrapping is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	var body shellWrapDisableBody
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode shell-wrap disable: "+err.Error(), http.StatusBadRequest)
		return
	}
	target, err := shellwrapsvc.ParseTarget(body.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// No governance read-only check: a section lock never blocks undo. The
	// one exception is the applier's own (surface-gap CLI-1b, operator
	// decision D6): on a managed node whose organization pinned
	// shell_wrap.org_maintain ON, the native disable answers 409 with
	// shellwrapsvc.ErrOrgMaintained. A developer is still never locked out
	// of a tool: every shim runs the real command when observer is missing,
	// and SBO_SHIM_BYPASS=1 always does.
	s.configWriteMu.Lock()
	out, err := s.opts.ShellWrap.DisableFor(r.Context(), target, body.DryRun)
	s.configWriteMu.Unlock()
	if err != nil {
		shellWrapServiceError(w, "", err)
		return
	}
	if !body.DryRun {
		s.notifyConfigSaved()
		s.recordManageAudit(r, "shell_wrap_disable", fmt.Sprintf("target=%s changes=%d", shellWrapTargetLabel(target), len(out.Changes)))
	}
	writeJSON(w, out)
}
