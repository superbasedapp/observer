package dashboard

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_policy.go is the Terminal launch-policy management surface
// (dashboard-management-surface plan §E/§7). The [terminal.launch] opt-ins —
// allow_fresh_agent, allowed_tools, allowed_project_roots — become
// consent-per-write controls on a DEDICATED route so the privilege-expanding
// allow_fresh_agent toggle is an isolated, audited write and never rides a bulk
// section save (plan §6 Q1).
//
// The whole route is CapabilityLocal (owner-loopback-only): both the GET (which
// mints the double-submit confirm token, §10) and the PUT (which writes config)
// are management surfaces a remote viewer must never reach — the same
// whole-route-Local posture P0 shipped for /api/config/section/ (the mux-shape
// deviation documented in registerRoutes). The write reuses the P0
// confirm-token + application/json + 415 discipline (requireJSONConfirm) and
// canonicalizes allowed_project_roots through the SAME internal/termsvc
// validator the spawn path uses — no reimplementation.

// terminalPolicyPayload is the read/write shape of [terminal.launch].
type terminalPolicyPayload struct {
	AllowFreshAgent     bool     `json:"allow_fresh_agent"`
	AllowedTools        []string `json:"allowed_tools"`
	AllowedProjectRoots []string `json:"allowed_project_roots"`
	// AllowShell is the SEPARATE default-OFF opt-in for a fresh plain-shell
	// launch — independent of AllowFreshAgent/AllowedTools (a bare shell is
	// not a member of the tool allow-list).
	AllowShell bool `json:"allow_shell"`
}

// handleTerminalPolicy serves GET/PUT /api/terminal/policy (whole-route Local).
func (s *Server) handleTerminalPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTerminalPolicyGet(w, r)
	case http.MethodPut:
		s.handleTerminalPolicyPut(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// handleTerminalPolicyGet returns the current [terminal.launch] policy, the
// launchable-tool SOURCE for the picker (from the capability registry, never a
// free-text field), and honest state flags. It mints a fresh confirm token so
// the PUT can echo it (§10).
//
// It ALSO reports the second, independent allow-list that decides whether a
// launched tool is ever captured — [observer.watch].enabled_adapters — plus the
// server-derived cross-check unwatched_allowed_tools (audit DI-07). Both are
// READ-ONLY here: enabled_adapters belongs to a different config section and is
// NOT part of the PUT payload. The cross-check is derived server-side by
// diag.AllowedToolsNotWatched so the SPA never reimplements the list's
// nil-vs-empty rule (nil = every adapter watched; non-nil empty = watch
// nothing) — one owner, two readers (this route and /api/terminal/sessions).
func (s *Server) handleTerminalPolicyGet(w http.ResponseWriter, r *http.Request) {
	confirmTok := setConfirmCookie(w, r)
	resp := map[string]any{
		"confirm_token":         confirmTok,
		"config_writable":       s.opts.ConfigPath != "",
		"terminal_enabled":      true,
		"allow_fresh_agent":     false,
		"allowed_tools":         []string{},
		"allowed_project_roots": []string{},
		"allow_shell":           false,
		// Runtime bounds (read-only here; written by the live-applying
		// /api/terminal/limits verb). Surfaced from this same GET so the UI has
		// both the current values and the confirm token from one fetch.
		"max_concurrent": 0,
		"idle_timeout":   "",
		// The launchable set the picker MUST source from (plan §E) — resolved
		// from the capability registry (dispatch on capability shape, never a
		// hardcoded tool list).
		"launchable_tools": launchableTools(),
		// [observer.watch].enabled_adapters AS LOADED: null = the key is absent
		// (default: every adapter watched), [] = the explicit "watch nothing"
		// intent. The distinction is load-bearing, so it is carried onto the
		// wire rather than normalized away.
		"enabled_adapters": []string(nil),
		// The DI-07 cross-check: allow-listed launchable tools an explicit
		// enabled_adapters list omits. They launch happily and record nothing.
		"unwatched_allowed_tools": []string{},
		// A [terminal.launch] write binds only on the next daemon start: the
		// launch policy is captured into the termsvc service at construction
		// (cmd terminalLaunchPolicy), never hot-reloaded — so the UI states the
		// restart honestly.
		"restart_required_on_save": true,
	}
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		resp["terminal_enabled"] = cfg.Terminal.Enabled
		resp["allow_fresh_agent"] = cfg.Terminal.Launch.AllowFreshAgent
		if cfg.Terminal.Launch.AllowedTools != nil {
			resp["allowed_tools"] = cfg.Terminal.Launch.AllowedTools
		}
		if cfg.Terminal.Launch.AllowedProjectRoots != nil {
			resp["allowed_project_roots"] = cfg.Terminal.Launch.AllowedProjectRoots
		}
		resp["max_concurrent"] = cfg.Terminal.MaxConcurrent
		resp["idle_timeout"] = cfg.Terminal.IdleTimeout
		resp["allow_shell"] = cfg.Terminal.Launch.AllowShell
		resp["enabled_adapters"] = cfg.Observer.Watch.EnabledAdapters
		if gap := diag.AllowedToolsNotWatched(cfg); len(gap) > 0 {
			resp["unwatched_allowed_tools"] = gap
		}
	}
	writeJSON(w, resp)
}

// handleTerminalPolicyPut writes [terminal.launch]. It requires the §10
// confirm token + application/json (the privilege-expanding write gets the same
// hardening as the remote arm verbs), validates every allowed_tool against the
// launchable capability set, and CANONICALIZES every allowed_project_root
// through internal/termsvc (real filesystem identity, symlink/UNC rejection) —
// the exact validator the spawn path re-runs. A single bad entry rejects the
// whole write (fail-closed) so the persisted policy is always fully validated.
func (s *Server) handleTerminalPolicyPut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured — server has no file to save to", http.StatusConflict)
		return
	}
	var body terminalPolicyPayload
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode terminal policy: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate allowed_tools against the launchable capability set.
	tools, err := validateLaunchableTools(body.AllowedTools)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Canonicalize allowed_project_roots via termsvc (reuse, don't reimplement).
	roots, err := canonicalizeProjectRoots(body.AllowedProjectRoots)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The full-config read-modify-write is serialized with the remote manage
	// verbs (remoteManageMu): those handlers also load→mutate→write the WHOLE
	// config, so an unserialized policy PUT that loaded before a concurrent
	// standing-terminal mint (or remote arm) would clobber that verb's freshly
	// persisted [remote] fields back to their pre-mint values on disk while the
	// live controller still honours them (finding 6). The lock covers exactly
	// load→write; validation above and the audit/notify below stay outside it.
	//
	// Fix 2: it ALSO takes configWriteMu (the settings.go section/pricing/backup
	// domain) so a policy PUT and a section save can't clobber one another.
	// Lock order is remoteManageMu (outer) → configWriteMu (inner), released in
	// reverse — the same order every manage verb uses (see remoteManageMu decl).
	remoteManageMu.Lock()
	s.configWriteMu.Lock()
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		s.configWriteMu.Unlock()
		remoteManageMu.Unlock()
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}
	cfg.Terminal.Launch.AllowFreshAgent = body.AllowFreshAgent
	cfg.Terminal.Launch.AllowedTools = tools
	cfg.Terminal.Launch.AllowedProjectRoots = roots
	cfg.Terminal.Launch.AllowShell = body.AllowShell
	werr := writeConfigToml(s.opts.ConfigPath, cfg)
	s.configWriteMu.Unlock()
	remoteManageMu.Unlock()
	if werr != nil {
		writeErr(w, werr)
		return
	}
	s.notifyConfigSaved()
	// Record the privilege-expanding write in the metadata-only remote_audit
	// tail (plan §4), so the Remote panel's audit shows who changed launch
	// policy — reuses the existing seam, no new table.
	s.recordManageAudit(r, "terminal_policy", fmt.Sprintf("allow_fresh_agent=%v tools=%d roots=%d allow_shell=%v", body.AllowFreshAgent, len(tools), len(roots), body.AllowShell))
	writeJSON(w, map[string]any{
		"saved":                 true,
		"allow_fresh_agent":     body.AllowFreshAgent,
		"allowed_tools":         tools,
		"allowed_project_roots": roots,
		"allow_shell":           body.AllowShell,
		"config_path":           s.opts.ConfigPath,
		"backup_path":           s.opts.ConfigPath + ".bak",
		"restart_required":      true,
	})
}

// validateLaunchableTools rejects any requested tool that is not in the
// launchable capability set (plan §E: the picker is sourced from the launchable
// set, never a free-text field). It de-dups + sorts for a stable persisted
// order. An empty request is valid (deny-all: no tool may fresh-launch).
func validateLaunchableTools(requested []string) ([]string, error) {
	launchable := map[string]struct{}{}
	for _, t := range launchableTools() {
		launchable[t] = struct{}{}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range requested {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if _, ok := launchable[t]; !ok {
			return nil, fmt.Errorf("tool %q is not launchable in the embedded terminal — pick from the launchable set", t)
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// canonicalizeProjectRoots validates + canonicalizes each requested root
// through termsvc.ValidateProjectRoot (validating each entry against an
// allow-list of itself), so the persisted policy holds only real, existing,
// non-UNC, symlink-resolved directories — the exact rules the spawn path
// enforces. An empty request is valid (no project_root may be set). A single
// bad entry rejects the whole write.
func canonicalizeProjectRoots(requested []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range requested {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		canonical, err := termsvc.ValidateProjectRoot(entry, []string{entry})
		if err != nil {
			return nil, fmt.Errorf("project root %q rejected: %w", entry, err)
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}
