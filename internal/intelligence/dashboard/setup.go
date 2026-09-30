// setup.go owns the dashboard surface for first-time / corrective
// configuration. Today the only tool wired up is Codex — the dashboard's
// Compression tab calls /api/setup/codex GET to discover whether the
// user's ~/.codex/config.toml is currently routed through this observer
// proxy and POST to (idempotently) write the routing config without the
// user having to touch the CLI.
//
// All mutation goes through internal/proxyroute.Registrar so the
// dashboard and `observer init --codex` share one code path. The
// per-conflict matrix (reserved openai block / non-loopback base_url /
// foreign top-level model_provider) is enforced inside the registrar;
// the dashboard simply surfaces the typed errors back to the browser
// and offers a "force" button for the cases that are recoverable.

package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
)

// codexSetupSnapshot is the GET /api/setup/codex response. The frontend
// uses Status to choose which CTA to render and would_register to know
// whether a default POST will succeed without --force.
type codexSetupSnapshot struct {
	Tool                 string `json:"tool"` // always "codex"
	ConfigPath           string `json:"config_path"`
	ConfigExists         bool   `json:"config_exists"`
	ProxyPort            int    `json:"proxy_port"`
	DesiredBaseURL       string `json:"desired_base_url"`
	DesiredModelProvider string `json:"desired_model_provider"`
	CurrentBaseURL       string `json:"current_base_url,omitempty"`
	CurrentModelProvider string `json:"current_model_provider,omitempty"`
	HasReservedBlock     bool   `json:"has_reserved_openai_block"`
	AuthMode             string `json:"auth_mode,omitempty"`

	// Status is one of:
	//   - "no_config":               ~/.codex/config.toml does not exist
	//   - "not_configured":          file exists, no observer provider
	//   - "routed_to_observer":      base_url + model_provider both set
	//   - "routed_partial":          provider block exists but model_provider not switched, OR vice-versa
	//   - "routed_to_other_observer": observer provider points at a non-matching loopback host
	//   - "reserved_block_present":  legacy [model_providers.openai] needs --force
	//   - "non_loopback":            our provider points at a non-loopback URL
	//   - "foreign_provider":        top-level model_provider is set to a third-party value
	Status string `json:"status"`

	// WouldRegister mirrors a non-force RegisterCodex DryRun: true if a
	// POST without {"force": true} would succeed.
	WouldRegister      bool   `json:"would_register"`
	WouldRegisterError string `json:"would_register_error,omitempty"`
}

// codexSetupPostRequest is the POST body shape.
type codexSetupPostRequest struct {
	Force  bool `json:"force"`
	DryRun bool `json:"dry_run"`
}

// codexSetupPostResponse is the POST response shape; mirrors
// proxyroute.RegistrationResult plus the snapshot the GET would return
// post-write so the frontend can re-render without a follow-up call.
type codexSetupPostResponse struct {
	Tool       string             `json:"tool"`
	ConfigPath string             `json:"config_path"`
	BaseURL    string             `json:"base_url"`
	Added      bool               `json:"added"`
	AlreadySet bool               `json:"already_set"`
	DryRun     bool               `json:"dry_run"`
	Error      string             `json:"error,omitempty"`
	Snapshot   codexSetupSnapshot `json:"snapshot"`
}

// handleSetupCodex serves /api/setup/codex.
//
//   - GET:  current state of ~/.codex/config.toml relative to this
//     observer's proxy port. Computes WouldRegister via DryRun=true
//     so the UI can pre-warn before the user clicks the button.
//   - POST: writes the registration. Body {"force": bool, "dry_run":
//     bool}; force forwards to proxyroute.RegisterOptions.Force,
//     dry_run forwards to DryRun.
func (s *Server) handleSetupCodex(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snap := s.codexSetupSnapshot()
		writeJSON(w, snap)
	case http.MethodPost:
		var body codexSetupPostRequest
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, err)
				return
			}
		}
		reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			ProxyPort: s.opts.ProxyPort,
			DryRun:    body.DryRun,
			Force:     body.Force,
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		res := reg.RegisterCodex()
		resp := codexSetupPostResponse{
			Tool:       res.Tool,
			ConfigPath: res.ConfigPath,
			BaseURL:    res.BaseURL,
			Added:      res.Added,
			AlreadySet: res.AlreadySet,
			DryRun:     res.DryRun,
		}
		if res.Error != nil {
			// Conflict cases (reserved block, non-loopback, foreign
			// provider) come back as errors that the user can recover
			// from with force=true. Surface 409 so the frontend can
			// distinguish from a 500 / encoder failure.
			resp.Error = res.Error.Error()
			resp.Snapshot = s.codexSetupSnapshot()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp.Snapshot = s.codexSetupSnapshot()
		writeJSON(w, resp)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// codexSetupSnapshot reads ~/.codex/config.toml (if any) and classifies
// the install relative to this observer's proxy port. Pure read.
func (s *Server) codexSetupSnapshot() codexSetupSnapshot {
	port := s.opts.ProxyPort
	if port <= 0 {
		port = 8820
	}
	desired := codexBaseURLFor(port)
	out := codexSetupSnapshot{
		Tool:                 "codex",
		ProxyPort:            port,
		DesiredBaseURL:       desired,
		DesiredModelProvider: proxyroute.ProviderName,
		AuthMode:             detectCodexAuthMode(),
	}
	home, err := os.UserHomeDir()
	if err != nil {
		out.Status = "no_config"
		out.WouldRegisterError = err.Error()
		return out
	}
	out.ConfigPath = filepath.Join(home, ".codex", "config.toml")

	raw, err := os.ReadFile(out.ConfigPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		out.Status = "no_config"
		out.WouldRegister = true
		return out
	case err != nil:
		out.Status = "no_config"
		out.WouldRegisterError = err.Error()
		return out
	}
	out.ConfigExists = true

	root := map[string]any{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &root); err != nil {
			out.Status = "not_configured"
			out.WouldRegisterError = err.Error()
			return out
		}
	}
	if mp, _ := root["model_provider"].(string); mp != "" {
		out.CurrentModelProvider = mp
	}
	providers, _ := root["model_providers"].(map[string]any)
	if _, ok := providers["openai"]; ok {
		out.HasReservedBlock = true
	}
	if ours, _ := providers[proxyroute.ProviderName].(map[string]any); ours != nil {
		if base, _ := ours["base_url"].(string); base != "" {
			out.CurrentBaseURL = base
		}
	}

	out.Status, out.WouldRegister, out.WouldRegisterError = classifyCodexStatus(out, desired)
	return out
}

// classifyCodexStatus maps a snapshot to a user-facing status string and
// computes whether a non-force registration would succeed. Pure
// function so tests don't need an FS.
func classifyCodexStatus(s codexSetupSnapshot, desired string) (status string, wouldRegister bool, wouldErr string) {
	if !s.ConfigExists {
		return "no_config", true, ""
	}
	if s.HasReservedBlock {
		return "reserved_block_present", false,
			"~/.codex/config.toml contains [model_providers.openai] which codex 0.128.0+ rejects (reserved built-in); pass force=true to remove it"
	}
	if s.CurrentBaseURL == "" {
		// No observer provider yet.
		if s.CurrentModelProvider != "" && s.CurrentModelProvider != proxyroute.ProviderName {
			return "foreign_provider", false,
				"top-level model_provider is set to " + s.CurrentModelProvider + "; pass force=true to switch to " + proxyroute.ProviderName
		}
		return "not_configured", true, ""
	}
	// We have an observer-named provider; how does its base_url compare?
	switch {
	case s.CurrentBaseURL == desired:
		if s.CurrentModelProvider == proxyroute.ProviderName {
			return "routed_to_observer", true, ""
		}
		return "routed_partial", true, ""
	case proxyroute.IsObserverBaseURL(s.CurrentBaseURL):
		// Loopback but different port — could be another observer
		// install. RegisterCodex treats this as AlreadySet so a
		// non-force POST is a no-op rather than a clobber.
		return "routed_to_other_observer", true, ""
	default:
		return "non_loopback", false,
			"the openai-observer provider is set to " + s.CurrentBaseURL + " which is non-loopback; pass force=true to overwrite"
	}
}

// codexBaseURLFor mirrors proxyroute.codexBaseURL (which is unexported).
// Kept here as a small helper so we don't need to widen proxyroute's API
// just for the snapshot endpoint.
func codexBaseURLFor(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/v1", port)
}

// claudeSetupSnapshot is the GET /api/setup/claude response. Reports
// install state (binary / credentials), the launcher command, AND the
// durable routing state (the `env.ANTHROPIC_BASE_URL` block in
// ~/.claude/settings.json that proxyroute.RegisterClaudeCode manages).
// POST writes that durable route — the dashboard sibling of
// `observer init --claude-code`'s proxy-route step (usability arc
// P1.5/L1).
type claudeSetupSnapshot struct {
	Tool                string `json:"tool"` // always "claude"
	ProxyPort           int    `json:"proxy_port"`
	ProxyURL            string `json:"proxy_url"`
	CredentialsPath     string `json:"credentials_path"`
	HasOAuthCredentials bool   `json:"has_oauth_credentials"`
	ClaudeBinaryFound   bool   `json:"claude_binary_found"`
	ClaudeBinaryPath    string `json:"claude_binary_path,omitempty"`
	LauncherCommand     string `json:"launcher_command"`

	// Status is one of:
	//   - "oauth_ready":         credentials.json present with a non-
	//                            empty claudeAiOauth.accessToken; the
	//                            launcher will re-export it as
	//                            ANTHROPIC_AUTH_TOKEN to defeat the
	//                            Pro/Max bypass.
	//   - "api_key_ready":       no credentials.json (or no OAuth
	//                            block); user is on ANTHROPIC_API_KEY.
	//                            Launcher still sets ANTHROPIC_BASE_URL
	//                            so the proxy captures.
	//   - "claude_not_installed": `claude` not on PATH.
	Status string `json:"status"`

	// Durable routing state (settings.json env block). Computed via a
	// DryRun RegisterClaudeCode so the UI can render the exact outcome
	// of clicking the route button before the user clicks it.
	SettingsPath     string `json:"settings_path,omitempty"`
	RoutedBaseURL    string `json:"routed_base_url,omitempty"`
	RoutedToObserver bool   `json:"routed_to_observer"`
	// WouldRegister=true → a non-force POST writes the route.
	// WouldRegister=false with no error → already routed (this install
	// or another loopback observer; see RoutedBaseURL).
	// WouldRegister=false with an error → conflict (non-loopback URL
	// the user set deliberately); POST with force=true overrides.
	WouldRegister      bool   `json:"would_register"`
	WouldRegisterError string `json:"would_register_error,omitempty"`
}

// claudeSetupPostResponse is the POST /api/setup/claude response shape;
// mirrors codexSetupPostResponse so the frontend handles both tools
// with one component.
type claudeSetupPostResponse struct {
	Tool       string              `json:"tool"`
	ConfigPath string              `json:"config_path"`
	BaseURL    string              `json:"base_url"`
	Added      bool                `json:"added"`
	AlreadySet bool                `json:"already_set"`
	DryRun     bool                `json:"dry_run"`
	Error      string              `json:"error,omitempty"`
	Snapshot   claudeSetupSnapshot `json:"snapshot"`
}

// handleSetupClaude serves /api/setup/claude.
//
//   - GET:  install state + durable-routing state relative to this
//     observer's proxy port (would_register computed via DryRun).
//   - POST: writes `env.ANTHROPIC_BASE_URL` into ~/.claude/settings.json
//     via proxyroute.RegisterClaudeCode. Body {"force": bool,
//     "dry_run": bool} — same contract as POST /api/setup/codex.
//     Conflicts (a non-loopback URL the user set deliberately) come
//     back 409 with the error + a fresh snapshot; force=true
//     overrides. This endpoint is invoked only by an explicit user
//     click — the opt-in invariant holds (no AI-client config is
//     written without explicit user action).
func (s *Server) handleSetupClaude(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.claudeSetupSnapshot())
	case http.MethodPost:
		var body codexSetupPostRequest // same {force, dry_run} shape
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, err)
				return
			}
		}
		port := s.opts.ProxyPort
		if port <= 0 {
			port = 8820
		}
		reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			ProxyPort: port,
			DryRun:    body.DryRun,
			Force:     body.Force,
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		res := reg.RegisterClaudeCode()
		resp := claudeSetupPostResponse{
			Tool:       res.Tool,
			ConfigPath: res.ConfigPath,
			BaseURL:    res.BaseURL,
			Added:      res.Added,
			AlreadySet: res.AlreadySet,
			DryRun:     res.DryRun,
		}
		if res.Error != nil {
			resp.Error = res.Error.Error()
			resp.Snapshot = s.claudeSetupSnapshot()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp.Snapshot = s.claudeSetupSnapshot()
		writeJSON(w, resp)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// claudeSetupSnapshot probes ~/.claude/.credentials.json (honoring
// CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR overrides) and resolves
// `claude` on PATH to classify the install. Pure read — no mutation.
func (s *Server) claudeSetupSnapshot() claudeSetupSnapshot {
	port := s.opts.ProxyPort
	if port <= 0 {
		port = 8820
	}
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	out := claudeSetupSnapshot{
		Tool:            "claude",
		ProxyPort:       port,
		ProxyURL:        proxyURL,
		LauncherCommand: fmt.Sprintf("observer claude --proxy %s", proxyURL),
	}
	out.CredentialsPath = resolveClaudeCredentialsPath()
	if hasOAuthAccessToken(out.CredentialsPath) {
		out.HasOAuthCredentials = true
	}
	// shellwrapsvc.LookPath skips a command-wrapping shim: a shim named
	// `claude` is not a Claude Code install.
	if path, err := shellwrapsvc.LookPath("claude"); err == nil {
		out.ClaudeBinaryFound = true
		out.ClaudeBinaryPath = path
	}
	switch {
	case !out.ClaudeBinaryFound:
		out.Status = "claude_not_installed"
	case out.HasOAuthCredentials:
		out.Status = "oauth_ready"
	default:
		out.Status = "api_key_ready"
	}

	// Durable-routing probe: a DryRun RegisterClaudeCode classifies the
	// settings.json env block without touching it. Best-effort — a
	// registrar construction failure (no resolvable home) just leaves
	// the routing fields zero.
	if reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
		ProxyPort: port,
		DryRun:    true,
	}); err == nil {
		res := reg.RegisterClaudeCode()
		out.SettingsPath = res.ConfigPath
		switch {
		case res.Error != nil:
			out.WouldRegisterError = res.Error.Error()
		case res.AlreadySet:
			out.RoutedBaseURL = res.BaseURL
			out.RoutedToObserver = res.BaseURL == proxyURL
			if !out.RoutedToObserver {
				out.WouldRegisterError = "ANTHROPIC_BASE_URL points at another local observer (" + res.BaseURL + "); POST with force=true to switch it here"
			}
		case res.Added:
			out.WouldRegister = true
		}
	}
	return out
}

// resolveClaudeCredentialsPath mirrors cmd/observer/claude.go's lookup
// order. Duplicated rather than depending across the cmd→internal
// boundary; both functions are tiny.
func resolveClaudeCredentialsPath() string {
	for _, env := range []string{"CLAUDE_CONFIG_DIR", "ANTHROPIC_CONFIG_DIR"} {
		if dir := os.Getenv(env); dir != "" {
			return filepath.Join(dir, ".credentials.json")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

// hasOAuthAccessToken returns true when path holds a parseable JSON
// document with a non-empty claudeAiOauth.accessToken. Missing file or
// malformed contents return false (the snapshot just falls back to
// api_key_ready).
func hasOAuthAccessToken(path string) bool {
	if path == "" {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc struct {
		ClaudeAiOauth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	return doc.ClaudeAiOauth.AccessToken != ""
}

// codexHookTrustSnapshot is the GET /api/setup/codex-hooks response.
// Surfaces the only user-actionable gap in the codex hook integration:
// each registered hook entry must be manually trusted via the codex
// `/hooks` slash command before codex will dispatch it. The trust
// hash algorithm is opaque (not exposed via any `codex` subcommand and
// changes across releases), so observer cannot pre-trust on the
// user's behalf — we surface the gap prominently and tell the user
// exactly what to do.
//
// Status values:
//
//   - "no_codex":          ~/.codex doesn't exist
//   - "no_hooks":          no observer-owned hooks in hooks.json
//   - "config_missing":    hooks.json has observer entries but
//     config.toml doesn't exist (codex never opened
//     since hook install)
//   - "needs_trust":       at least one observer hook lacks a
//     trusted_hash entry — user must run /hooks
//   - "all_trusted":       every observer hook is trusted; nothing to do
//   - "feature_disabled":  hooks file is set up but [features].hooks=false
//     in config.toml — codex won't dispatch hooks
//     regardless of trust state
type codexHookTrustSnapshot struct {
	Status             string   `json:"status"`
	HooksFile          string   `json:"hooks_file,omitempty"`
	ConfigFile         string   `json:"config_file,omitempty"`
	RegisteredEvents   []string `json:"registered_events,omitempty"`
	TrustedEvents      []string `json:"trusted_events,omitempty"`
	UntrustedEvents    []string `json:"untrusted_events,omitempty"`
	FeatureFlagEnabled bool     `json:"feature_flag_enabled"`
	Instruction        string   `json:"instruction,omitempty"`
}

// handleSetupCodexHooks serves /api/setup/codex-hooks (GET only).
// Read-only — codex's per-hook trust must be approved by the user
// inside codex itself; observer cannot mutate it.
func (s *Server) handleSetupCodexHooks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.codexHookTrustSnapshot())
}

// codexHookTrustSnapshot reads ~/.codex/hooks.json + ~/.codex/config.toml
// and computes the trust state across observer-owned hook entries. Pure
// read; never mutates.
func (s *Server) codexHookTrustSnapshot() codexHookTrustSnapshot {
	out := codexHookTrustSnapshot{}
	home, err := os.UserHomeDir()
	if err != nil {
		out.Status = "no_codex"
		return out
	}
	codexDir := filepath.Join(home, ".codex")
	if _, err := os.Stat(codexDir); err != nil {
		out.Status = "no_codex"
		return out
	}
	out.HooksFile = filepath.Join(codexDir, "hooks.json")
	out.ConfigFile = filepath.Join(codexDir, "config.toml")

	hooksRaw, err := os.ReadFile(out.HooksFile)
	if err != nil {
		out.Status = "no_hooks"
		return out
	}
	var hooksFile struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksRaw, &hooksFile); err != nil {
		out.Status = "no_hooks"
		return out
	}
	for event, groups := range hooksFile.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Type == "command" && strings.Contains(h.Command, " hook codex ") {
					out.RegisteredEvents = append(out.RegisteredEvents, event)
					break
				}
			}
		}
	}
	sort.Strings(out.RegisteredEvents)
	if len(out.RegisteredEvents) == 0 {
		out.Status = "no_hooks"
		return out
	}

	cfgRaw, err := os.ReadFile(out.ConfigFile)
	if err != nil {
		out.Status = "config_missing"
		out.UntrustedEvents = out.RegisteredEvents
		out.Instruction = codexHookTrustInstruction(out.UntrustedEvents)
		return out
	}
	root := map[string]any{}
	if len(cfgRaw) > 0 {
		_ = toml.Unmarshal(cfgRaw, &root)
	}
	if features, _ := root["features"].(map[string]any); features != nil {
		if v, _ := features["hooks"].(bool); v {
			out.FeatureFlagEnabled = true
		}
	}
	if !out.FeatureFlagEnabled {
		out.Status = "feature_disabled"
		out.UntrustedEvents = out.RegisteredEvents
		out.Instruction = "set [features].hooks = true in " + out.ConfigFile +
			" — observer init --codex sets this automatically; codex won't dispatch hooks without it"
		return out
	}

	hooksState, _ := root["hooks"].(map[string]any)
	state, _ := hooksState["state"].(map[string]any)
	trusted := map[string]bool{}
	for key, v := range state {
		entry, _ := v.(map[string]any)
		if hash, _ := entry["trusted_hash"].(string); hash == "" {
			continue
		}
		if !strings.HasPrefix(key, out.HooksFile+":") {
			continue
		}
		rest := strings.TrimPrefix(key, out.HooksFile+":")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) == 0 {
			continue
		}
		trusted[snakeToCamelEvent(parts[0])] = true
	}
	for _, e := range out.RegisteredEvents {
		if trusted[e] {
			out.TrustedEvents = append(out.TrustedEvents, e)
		} else {
			out.UntrustedEvents = append(out.UntrustedEvents, e)
		}
	}
	if len(out.UntrustedEvents) == 0 {
		out.Status = "all_trusted"
		return out
	}
	out.Status = "needs_trust"
	out.Instruction = codexHookTrustInstruction(out.UntrustedEvents)
	return out
}

func codexHookTrustInstruction(events []string) string {
	return "open `codex` and run /hooks to mark these entries trusted: " +
		strings.Join(events, ", ") + ". one-time setup; trust persists in ~/.codex/config.toml"
}

// snakeToCamelEvent converts e.g. "session_start" → "SessionStart".
// Mirrors snakeToCamel in internal/diag/doctor.go but is duplicated here
// to avoid a cross-package dep on diag for one trivial helper.
func snakeToCamelEvent(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "_")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}
