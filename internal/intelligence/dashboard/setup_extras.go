package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// Dashboard CLI parity, lane L2: the Claude Code status line, start at login
// and browser-capture setup controls. Each is a GET status (which mints the
// confirm token) plus a POST that previews (dry_run) or applies. The work is
// done by the seam cmd/observer wires over the same code the CLI runs; these
// handlers only gate, decode and audit. None of them starts, stops or
// restarts the daemon.

// setupExtrasMu serialises the three controls' writes against each other.
var setupExtrasMu sync.Mutex

// setupExtrasBody is the POST body shared by the three routes.
type setupExtrasBody struct {
	// Action is "install" or "remove" (the browser route only installs).
	Action string `json:"action"`
	// DryRun previews: the exact changes, nothing written.
	DryRun bool `json:"dry_run"`
	// Force (status line) replaces an entry Observer did not write.
	Force bool `json:"force"`
	// ExtensionID (browser) is the Chromium extension id; "" keeps the
	// placeholder the CLI writes.
	ExtensionID string `json:"extension_id"`
}

// parseSetupAction validates a request action against the closed vocabulary.
func parseSetupAction(s string) (dashapi.SetupAction, bool) {
	switch a := dashapi.SetupAction(s); a {
	case dashapi.SetupInstall, dashapi.SetupRemove:
		return a, true
	}
	return "", false
}

// setupExtrasGovernanceRefused applies the Settings-section pin to a write
// that changes the machine (an install). Removal and previews are never
// refused: a section lock never blocks undo.
func (s *Server) setupExtrasGovernanceRefused(w http.ResponseWriter, r *http.Request, section string) bool {
	if s.opts.Governance == nil {
		return false
	}
	eff := s.opts.Governance(r.Context())
	if !eff.VisibilityActive() {
		return false
	}
	if eff.IsSettingsSectionHidden(section) || eff.IsSettingsSectionReadOnly(section) {
		writeGovernanceRefusal(w, http.StatusConflict, "governance_read_only", section, eff,
			"This setting is pinned by your organization and cannot be changed here.")
		return true
	}
	return false
}

// setupExtrasError answers a seam error: malformed input is 400, a refusal
// from the machine's state is 409.
func setupExtrasError(w http.ResponseWriter, err error) {
	if errors.Is(err, dashapi.ErrSetupInput) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Error(w, err.Error(), http.StatusConflict)
}

// handleSetupStatusline serves GET (status + confirm token) and POST
// (preview or apply) on /api/setup/statusline.
func (s *Server) handleSetupStatusline(w http.ResponseWriter, r *http.Request) {
	svc := dashapi.StatuslineSetup(nil)
	if s.opts.SetupExtras != nil {
		svc = s.opts.SetupExtras.Statusline
	}
	if svc == nil {
		http.Error(w, "the status line control is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tok := setConfirmCookie(w, r)
		st, err := svc.Status(r.Context())
		if err != nil {
			writeErr(w, fmt.Errorf("statusline status: %w", err))
			return
		}
		writeJSON(w, map[string]any{"confirm_token": tok, "status": st})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var body setupExtrasBody
		if err := decodeJSONBody(r, &body); err != nil {
			http.Error(w, "decode statusline body: "+err.Error(), http.StatusBadRequest)
			return
		}
		action, ok := parseSetupAction(body.Action)
		if !ok {
			http.Error(w, `action must be "install" or "remove"`, http.StatusBadRequest)
			return
		}
		if action == dashapi.SetupInstall && !body.DryRun && s.setupExtrasGovernanceRefused(w, r, "tools") {
			return
		}
		setupExtrasMu.Lock()
		out, err := svc.Apply(r.Context(), action, body.DryRun, body.Force)
		setupExtrasMu.Unlock()
		if err != nil {
			setupExtrasError(w, err)
			return
		}
		if !body.DryRun && out.Changed {
			s.recordManageAudit(r, "setup_statusline", "action="+string(action))
		}
		writeJSON(w, out)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// handleSetupLoginStart serves GET and POST on /api/setup/login-start.
func (s *Server) handleSetupLoginStart(w http.ResponseWriter, r *http.Request) {
	svc := dashapi.LoginStartService(nil)
	if s.opts.SetupExtras != nil {
		svc = s.opts.SetupExtras.LoginStart
	}
	if svc == nil {
		http.Error(w, "the start at login control is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tok := setConfirmCookie(w, r)
		st, err := svc.Status(r.Context())
		if err != nil {
			writeErr(w, fmt.Errorf("login-start status: %w", err))
			return
		}
		writeJSON(w, map[string]any{"confirm_token": tok, "status": st})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var body setupExtrasBody
		if err := decodeJSONBody(r, &body); err != nil {
			http.Error(w, "decode login-start body: "+err.Error(), http.StatusBadRequest)
			return
		}
		action, ok := parseSetupAction(body.Action)
		if !ok {
			http.Error(w, `action must be "install" or "remove"`, http.StatusBadRequest)
			return
		}
		if action == dashapi.SetupInstall && !body.DryRun && s.setupExtrasGovernanceRefused(w, r, "health") {
			return
		}
		setupExtrasMu.Lock()
		out, err := svc.Apply(r.Context(), action, body.DryRun)
		setupExtrasMu.Unlock()
		if err != nil {
			setupExtrasError(w, err)
			return
		}
		if !body.DryRun && out.Changed {
			s.recordManageAudit(r, "setup_login_start", "action="+string(action))
		}
		writeJSON(w, out)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// handleSetupBrowser serves GET and POST on /api/setup/browser. The POST
// only installs the native-messaging host; removing it stays on
// Settings > Components (its deactivate step).
func (s *Server) handleSetupBrowser(w http.ResponseWriter, r *http.Request) {
	svc := dashapi.BrowserCaptureSetup(nil)
	if s.opts.SetupExtras != nil {
		svc = s.opts.SetupExtras.Browser
	}
	if svc == nil {
		http.Error(w, "browser capture setup is not wired on this dashboard", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		tok := setConfirmCookie(w, r)
		st, err := svc.Status(r.Context())
		if err != nil {
			writeErr(w, fmt.Errorf("browser status: %w", err))
			return
		}
		writeJSON(w, map[string]any{"confirm_token": tok, "status": st})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var body setupExtrasBody
		if err := decodeJSONBody(r, &body); err != nil {
			http.Error(w, "decode browser body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if body.Action != "" && body.Action != string(dashapi.SetupInstall) {
			http.Error(w, "only install is offered here; remove the host from Settings > Components", http.StatusBadRequest)
			return
		}
		if !body.DryRun && s.setupExtrasGovernanceRefused(w, r, "browser") {
			return
		}
		setupExtrasMu.Lock()
		out, err := svc.Apply(r.Context(), body.ExtensionID, body.DryRun)
		setupExtrasMu.Unlock()
		if err != nil {
			setupExtrasError(w, err)
			return
		}
		if !body.DryRun && out.Changed {
			s.recordManageAudit(r, "setup_browser", "action=install")
		}
		writeJSON(w, out)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}
