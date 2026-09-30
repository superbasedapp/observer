package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/shellwrap"
	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
)

// shellWrapSettingsSection is the Settings section the command-wrapping card
// renders under; a governance read-only / hidden pin on it refuses the
// writes here exactly as it refuses the section's generic config writes.
const shellWrapSettingsSection = "terminal"

// ShellWrapService is the dashboard's seam onto the command-wrapping shell
// integration (backlog item 7): cmd wires an *shellwrapsvc.Service, the ONE
// writer of the shim directory and the shell start-up-file blocks. Nil = not
// wired (the routes answer 501).
type ShellWrapService interface {
	Status(ctx context.Context) (shellwrap.Status, error)
	Apply(ctx context.Context, req shellwrapsvc.Request) (shellwrapsvc.Outcome, error)
	Disable(ctx context.Context, dryRun bool) (shellwrapsvc.Outcome, error)
}

// shellWrapApplyBody is the POST /api/shell-wrap/apply body.
type shellWrapApplyBody struct {
	Tools  []string `json:"tools"`
	Shells []string `json:"shells"`
	DryRun bool     `json:"dry_run"`
}

// shellWrapDisableBody is the POST /api/shell-wrap/disable body.
type shellWrapDisableBody struct {
	DryRun bool `json:"dry_run"`
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
	tok := setConfirmCookie(w, r)
	st, err := s.opts.ShellWrap.Status(r.Context())
	if err != nil {
		writeErr(w, fmt.Errorf("shell-wrap status: %w", err))
		return
	}
	writeJSON(w, map[string]any{"confirm_token": tok, "status": st})
}

// shellWrapGovernanceRefused applies the Settings-section pin to a write.
func (s *Server) shellWrapGovernanceRefused(w http.ResponseWriter, r *http.Request) bool {
	if s.opts.Governance == nil {
		return false
	}
	eff := s.opts.Governance(r.Context())
	if !eff.Active {
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
	if !body.DryRun && s.shellWrapGovernanceRefused(w, r) {
		return
	}
	s.configWriteMu.Lock()
	out, err := s.opts.ShellWrap.Apply(r.Context(), shellwrapsvc.Request{Tools: body.Tools, Shells: body.Shells, DryRun: body.DryRun})
	s.configWriteMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !body.DryRun {
		s.notifyConfigSaved()
		s.recordManageAudit(r, "shell_wrap_apply", fmt.Sprintf("tools=%s shells=%s changes=%d",
			strings.Join(body.Tools, ","), strings.Join(body.Shells, ","), len(out.Changes)))
	}
	writeJSON(w, out)
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
	// No governance check: undo is never blocked - a pin must not leave a
	// developer unable to take the shims back out of their own shell.
	s.configWriteMu.Lock()
	out, err := s.opts.ShellWrap.Disable(r.Context(), body.DryRun)
	s.configWriteMu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if !body.DryRun {
		s.notifyConfigSaved()
		s.recordManageAudit(r, "shell_wrap_disable", fmt.Sprintf("changes=%d", len(out.Changes)))
	}
	writeJSON(w, out)
}
