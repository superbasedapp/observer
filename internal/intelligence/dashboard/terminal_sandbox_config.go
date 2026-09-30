package dashboard

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminalSandboxConfigPayload is the dashboard read/write shape of
// [terminal.sandbox]. It deliberately mirrors the complete v1 config block so
// the UI never has to hide an authority-expanding escape hatch in a raw TOML
// file. The route carrying it is owner-local and confirm-token-gated.
type terminalSandboxConfigPayload struct {
	Enabled                bool     `json:"enabled"`
	Backend                string   `json:"backend"`
	HomeMode               string   `json:"home_mode"`
	DefaultOn              bool     `json:"default_on"`
	AllowRemoteClone       bool     `json:"allow_remote_clone"`
	RemoteAllowedHosts     []string `json:"remote_allowed_hosts"`
	AllowWorktreeSource    bool     `json:"allow_worktree_source"`
	WorkspacesDir          string   `json:"workspaces_dir"`
	WorkspaceRetentionDays int      `json:"workspace_retention_days"`
	MaskPaths              []string `json:"mask_paths"`
	ExtraROBinds           []string `json:"extra_ro_binds"`
	ExtraRWBinds           []string `json:"extra_rw_binds"`
	PrepTimeoutSeconds     int      `json:"prep_timeout_seconds"`
	// Egress and AllowToolConfigWrites are pointers so a client that
	// predates them (and so omits them) KEEPS the saved values instead of
	// resetting them on every save.
	Egress                *string `json:"egress,omitempty"`
	AllowToolConfigWrites *bool   `json:"allow_tool_config_writes,omitempty"`
	// EgressAllowCIDRs is a pointer for the same reason: a client that
	// predates the private-destination allow-list keeps the saved list.
	EgressAllowCIDRs *[]string `json:"egress_allow_cidrs,omitempty"`
}

// handleTerminalSandboxConfig serves GET/PUT
// /api/terminal/sandbox/config. The probe endpoint at /api/terminal/sandbox
// remains a read-only report of the RUNNING daemon; this route edits the
// on-disk config that binds on the next restart.
func (s *Server) handleTerminalSandboxConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTerminalSandboxConfigGet(w, r)
	case http.MethodPut:
		s.handleTerminalSandboxConfigPut(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTerminalSandboxConfigGet(w http.ResponseWriter, r *http.Request) {
	confirmTok := setConfirmCookie(w, r)
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load sandbox config: %w", err))
		return
	}
	p := sandboxConfigPayload(cfg.Terminal.Sandbox)
	writeJSON(w, map[string]any{
		"confirm_token":            confirmTok,
		"config_writable":          s.opts.ConfigPath != "",
		"restart_required_on_save": true,
		"sandbox":                  p,
	})
}

func (s *Server) handleTerminalSandboxConfigPut(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured — server has no file to save to", http.StatusConflict)
		return
	}
	var body terminalSandboxConfigPayload
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode terminal sandbox config: "+err.Error(), http.StatusBadRequest)
		return
	}

	next, err := normalizedSandboxConfig(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Join the one whole-config write domain. Lock order is the established
	// remoteManageMu -> configWriteMu order used by terminal policy/limits.
	remoteManageMu.Lock()
	s.configWriteMu.Lock()
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err == nil {
		// Omitted optional fields keep their saved value (see the payload).
		if body.Egress == nil {
			next.Egress = cfg.Terminal.Sandbox.Egress
		}
		if body.AllowToolConfigWrites == nil {
			next.AllowToolConfigWrites = cfg.Terminal.Sandbox.AllowToolConfigWrites
		}
		if body.EgressAllowCIDRs == nil {
			next.EgressAllowCIDRs = cfg.Terminal.Sandbox.EgressAllowCIDRs
		}
		cfg.Terminal.Sandbox = next
		err = config.Validate(cfg)
	}
	if err == nil {
		err = writeConfigToml(s.opts.ConfigPath, cfg)
	}
	s.configWriteMu.Unlock()
	remoteManageMu.Unlock()
	if err != nil {
		writeErr(w, fmt.Errorf("save sandbox config: %w", err))
		return
	}

	s.notifyConfigSaved()
	s.recordManageAudit(r, "terminal_sandbox_config", fmt.Sprintf(
		"enabled=%v default_on=%v egress=%s egress_allow_cidrs=%d tool_config_writes=%v remote_clone=%v worktree=%v mask_paths=%d ro_binds=%d rw_binds=%d",
		next.Enabled, next.DefaultOn, next.Egress, len(next.EgressAllowCIDRs), next.AllowToolConfigWrites, next.AllowRemoteClone, next.AllowWorktreeSource,
		len(next.MaskPaths), len(next.ExtraROBinds), len(next.ExtraRWBinds),
	))
	writeJSON(w, map[string]any{
		"saved":            true,
		"sandbox":          sandboxConfigPayload(next),
		"config_path":      s.opts.ConfigPath,
		"backup_path":      s.opts.ConfigPath + ".bak",
		"restart_required": true,
	})
}

func sandboxConfigPayload(c config.TerminalSandboxConfig) terminalSandboxConfigPayload {
	egress := c.Egress
	if egress == "" {
		egress = "internet" // the empty value's meaning ([terminal.sandbox].egress)
	}
	writes := c.AllowToolConfigWrites
	cidrs := nonNilStrings(c.EgressAllowCIDRs)
	return terminalSandboxConfigPayload{
		Enabled:                c.Enabled,
		Backend:                c.Backend,
		HomeMode:               c.HomeMode,
		DefaultOn:              c.DefaultOn,
		AllowRemoteClone:       c.AllowRemoteClone,
		RemoteAllowedHosts:     nonNilStrings(c.RemoteAllowedHosts),
		AllowWorktreeSource:    c.AllowWorktreeSource,
		WorkspacesDir:          c.WorkspacesDir,
		WorkspaceRetentionDays: c.WorkspaceRetentionDays,
		MaskPaths:              nonNilStrings(c.MaskPaths),
		ExtraROBinds:           nonNilStrings(c.ExtraROBinds),
		ExtraRWBinds:           nonNilStrings(c.ExtraRWBinds),
		PrepTimeoutSeconds:     c.PrepTimeoutSeconds,
		Egress:                 &egress,
		AllowToolConfigWrites:  &writes,
		EgressAllowCIDRs:       &cidrs,
	}
}

func normalizedSandboxConfig(p terminalSandboxConfigPayload) (config.TerminalSandboxConfig, error) {
	p.Backend = strings.TrimSpace(p.Backend)
	if p.Backend == "" {
		p.Backend = "bwrap"
	}
	p.HomeMode = strings.TrimSpace(p.HomeMode)
	if p.HomeMode == "" {
		p.HomeMode = "tmpfs"
	}
	p.WorkspacesDir = strings.TrimSpace(p.WorkspacesDir)
	p.RemoteAllowedHosts = cleanStringList(p.RemoteAllowedHosts)
	p.MaskPaths = cleanStringList(p.MaskPaths)
	p.ExtraROBinds = cleanStringList(p.ExtraROBinds)
	p.ExtraRWBinds = cleanStringList(p.ExtraRWBinds)

	if p.WorkspacesDir != "" && !filepath.IsAbs(p.WorkspacesDir) {
		return config.TerminalSandboxConfig{}, fmt.Errorf("terminal.sandbox.workspaces_dir %q must be absolute", p.WorkspacesDir)
	}
	for name, paths := range map[string][]string{
		"mask_paths":     p.MaskPaths,
		"extra_ro_binds": p.ExtraROBinds,
		"extra_rw_binds": p.ExtraRWBinds,
	} {
		for _, path := range paths {
			if !filepath.IsAbs(path) {
				return config.TerminalSandboxConfig{}, fmt.Errorf("terminal.sandbox.%s entry %q must be absolute", name, path)
			}
		}
	}

	next := config.TerminalSandboxConfig{
		Enabled:                p.Enabled,
		Backend:                p.Backend,
		HomeMode:               p.HomeMode,
		DefaultOn:              p.DefaultOn,
		AllowRemoteClone:       p.AllowRemoteClone,
		RemoteAllowedHosts:     p.RemoteAllowedHosts,
		AllowWorktreeSource:    p.AllowWorktreeSource,
		WorkspacesDir:          p.WorkspacesDir,
		WorkspaceRetentionDays: p.WorkspaceRetentionDays,
		MaskPaths:              p.MaskPaths,
		ExtraROBinds:           p.ExtraROBinds,
		ExtraRWBinds:           p.ExtraRWBinds,
		PrepTimeoutSeconds:     p.PrepTimeoutSeconds,
	}
	if p.Egress != nil {
		next.Egress = strings.TrimSpace(*p.Egress)
	}
	if p.AllowToolConfigWrites != nil {
		next.AllowToolConfigWrites = *p.AllowToolConfigWrites
	}
	if p.EgressAllowCIDRs != nil {
		next.EgressAllowCIDRs = cleanStringList(*p.EgressAllowCIDRs)
	}
	// Validate against an otherwise-default config before taking the write
	// locks so request mistakes are a 400, not an internal-error-shaped 500.
	probe := config.Default()
	probe.Terminal.Sandbox = next
	if err := config.Validate(probe); err != nil {
		return config.TerminalSandboxConfig{}, err
	}
	return next, nil
}

func cleanStringList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
