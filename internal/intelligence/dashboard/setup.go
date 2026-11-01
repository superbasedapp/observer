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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyauth"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
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
	// Undo removes the route instead of writing it (proxyroute.Unregister*,
	// the seam `observer uninstall` uses). Only this install's own route is
	// removed; force does not apply.
	Undo bool `json:"undo"`
}

// routeUndoResponse is the POST {"undo": true} response for both tools.
// Removed is true when the route was (or, with dry_run, would be) removed;
// false means there was nothing of this install's to remove, and BaseURL
// then names what the file points at, if anything.
type routeUndoResponse struct {
	Tool       string `json:"tool"`
	ConfigPath string `json:"config_path"`
	BaseURL    string `json:"base_url,omitempty"`
	Removed    bool   `json:"removed"`
	DryRun     bool   `json:"dry_run"`
	Error      string `json:"error,omitempty"`
	Snapshot   any    `json:"snapshot"`
}

// undoRoute runs one tool's route removal through clientwire.RouteRemover
// (the proxyroute undo `observer uninstall` runs) and answers
// the POST. A real removal is audited like the other dashboard writes.
func (s *Server) undoRoute(
	w http.ResponseWriter,
	r *http.Request,
	body codexSetupPostRequest,
	tool string,
	snapshot func() any,
) {
	// Review M3-05: removing a proxy route is a config write; it carries the
	// confirm token like every other dashboard write.
	if !requireJSONConfirm(w, r) {
		return
	}
	remove, ok := clientwire.RouteRemover(tool)
	if !ok {
		http.Error(w, "no removable proxy route for "+tool, http.StatusBadRequest)
		return
	}
	port := s.opts.ProxyPort
	if port <= 0 {
		port = 8820
	}
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
		Writer:      routeprov.WriterSetup,
		ProxyPort:   port,
		ClientToken: s.opts.ProxyClientToken,
		DryRun:      body.DryRun,
		Lock:        hook.LockSettingsFile,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	res := remove(reg)
	resp := routeUndoResponse{
		Tool:       res.Tool,
		ConfigPath: res.ConfigPath,
		BaseURL:    res.BaseURL,
		Removed:    res.Added && res.Error == nil,
		DryRun:     res.DryRun,
	}
	if res.Error != nil {
		resp.Error = res.Error.Error()
		resp.Snapshot = snapshot()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	if resp.Removed && !resp.DryRun {
		s.recordManageAudit(r, "proxy_route_undo", "tool="+res.Tool)
	}
	resp.Snapshot = snapshot()
	writeJSON(w, resp)
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
		if body.Undo {
			s.undoRoute(w, r, body, "codex",
				func() any { return s.codexSetupSnapshot() })
			return
		}
		reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			Writer:      routeprov.WriterSetup,
			ProxyPort:   s.opts.ProxyPort,
			ClientToken: s.opts.ProxyClientToken,
			DryRun:      body.DryRun,
			Force:       body.Force,
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
			// A client token in the route is masked (OSH-R-009).
			out.CurrentBaseURL = proxyauth.Redact(base)
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
	case proxyauth.SameRoute(s.CurrentBaseURL, desired):
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
	//   - "extension_ready":     no `claude` on PATH, but the Claude
	//                            Code VS Code extension is installed
	//                            (its install signal holds; WINNODE2
	//                            16b). There is no launcher to run; the
	//                            settings-file route still applies.
	//   - "claude_not_installed": neither.
	Status string `json:"status"`
	// EditorExtensionInstalled reports the Claude Code editor-extension
	// install signal (WINNODE2 16b).
	EditorExtensionInstalled bool `json:"editor_extension_installed,omitempty"`

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

	// ObservedRoute is the traffic verdict per capture surface (OBS-1):
	// what the node saw reach the proxy, as opposed to RoutedToObserver,
	// which only reads the settings file. Set by the handler (it needs the
	// request context); nil when the database is unavailable.
	ObservedRoute *observedRouteView `json:"observed_route,omitempty"`
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
		writeJSON(w, s.claudeSetupSnapshotObserved(r.Context()))
	case http.MethodPost:
		var body codexSetupPostRequest // same {force, dry_run} shape
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, err)
				return
			}
		}
		if body.Undo {
			s.undoRoute(w, r, body, "claude-code",
				func() any { return s.claudeSetupSnapshotObserved(r.Context()) })
			return
		}
		port := s.opts.ProxyPort
		if port <= 0 {
			port = 8820
		}
		reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			Writer:      routeprov.WriterSetup,
			ProxyPort:   port,
			ClientToken: s.opts.ProxyClientToken,
			DryRun:      body.DryRun,
			Force:       body.Force,
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
			resp.Snapshot = s.claudeSetupSnapshotObserved(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp.Snapshot = s.claudeSetupSnapshotObserved(r.Context())
		writeJSON(w, resp)
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// claudeSetupSnapshotObserved is claudeSetupSnapshot plus the observed
// per-surface traffic verdict, the shape GET /api/setup/claude serves.
func (s *Server) claudeSetupSnapshotObserved(ctx context.Context) claudeSetupSnapshot {
	snap := s.claudeSetupSnapshot()
	snap.ObservedRoute = s.observedRoute(ctx, models.ToolClaudeCode, time.Now())
	return snap
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
	// shimguard.LookPath skips a command-wrapping shim: a shim named
	// `claude` is not a Claude Code install.
	if path, err := shimguard.LookPath("claude"); err == nil {
		out.ClaudeBinaryFound = true
		out.ClaudeBinaryPath = path
	}
	out.EditorExtensionInstalled = s.installSignalHolds(models.ToolClaudeCode)
	switch {
	case !out.ClaudeBinaryFound && out.EditorExtensionInstalled:
		out.Status = "extension_ready"
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
		ProxyPort:   port,
		ClientToken: s.opts.ProxyClientToken,
		DryRun:      true,
	}); err == nil {
		res := reg.RegisterClaudeCode()
		out.SettingsPath = res.ConfigPath
		switch {
		case res.Error != nil:
			out.WouldRegisterError = res.Error.Error()
		case res.AlreadySet:
			out.RoutedBaseURL = res.BaseURL
			out.RoutedToObserver = proxyauth.SameRoute(res.BaseURL, proxyURL)
			if !out.RoutedToObserver {
				out.WouldRegisterError = "ANTHROPIC_BASE_URL points at another local observer (" + res.BaseURL + "); POST with force=true to switch it here"
			}
		case res.Added:
			out.WouldRegister = true
		}
	}
	return out
}

// resolveClaudeCredentialsPath names Claude Code's sign-in file through the
// one Claude config directory resolver the launcher uses
// (agentconfig.ClaudeConfigDir, FU-138), with the relocation variables read
// under the pinned-home rule (crossmount.HomeEnvAt): an isolated daemon reads
// none, so the probe stays under its own home. A relative
// CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR names no file (""), never a path
// joined against the daemon's working directory and never the ~/.claude
// default, which Claude Code does not read then.
func resolveClaudeCredentialsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return claudeCredentialsPathFor(home, crossmount.HomeEnvAt(home, nil))
}

// claudeCredentialsPathFor is resolveClaudeCredentialsPath with its inputs
// injected.
func claudeCredentialsPathFor(home string, getenv func(string) string) string {
	dir, _ := agentconfig.ClaudeConfigDir(agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home, Getenv: getenv})
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, ".credentials.json")
}

// claudeCredentialsMaxBytes caps the sign-in probe's read.
const claudeCredentialsMaxBytes int64 = 1 << 20

// hasOAuthAccessToken returns true when path holds a parseable JSON
// document with a non-empty claudeAiOauth.accessToken. Missing file or
// malformed contents return false (the snapshot just falls back to
// api_key_ready). The read is the bounded regular-file read, so a FIFO or a
// device at the path is refused instead of hanging the handler.
func hasOAuthAccessToken(path string) bool {
	if path == "" {
		return false
	}
	body, err := regularfile.Read(path, claudeCredentialsMaxBytes)
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
// each registered hook entry must be trusted inside codex (`/hooks`)
// before codex will dispatch it. The state is computed by
// internal/codextrust (the one owner, shared with `observer doctor`'s
// codex.hook_trust): it recomputes Codex's trust hash to tell a CHANGED
// entry from a trusted one, reads `enabled = false`, and lists every
// event Observer registers (from the integration registry) so an event a
// newer Observer adds shows up before hooks.json carries it. Read only:
// the hook writer records trust for Observer's own entries when it
// registers them (live check 2026-10-20), and this snapshot reports any
// entry that still lacks it.
//
// Status values:
//
//   - "no_codex":          ~/.codex doesn't exist
//   - "no_hooks":          no observer-owned hooks in hooks.json
//   - "config_missing":    hooks.json has observer entries but
//     config.toml doesn't exist (codex never opened
//     since hook install)
//   - "feature_disabled":  hooks file is set up but [features].hooks=false
//     in config.toml (codex won't dispatch hooks
//     regardless of trust state)
//   - "needs_trust":       at least one observer entry will not run
//     (never trusted, changed since trusted, or
//     switched off), so the user must visit /hooks
//   - "needs_register":    every present entry runs, but an event Observer
//     registers is missing from hooks.json
//   - "all_trusted":       every observer event is present and trusted
type codexHookTrustSnapshot struct {
	Status           string   `json:"status"`
	HooksFile        string   `json:"hooks_file,omitempty"`
	ConfigFile       string   `json:"config_file,omitempty"`
	RegisteredEvents []string `json:"registered_events,omitempty"`
	TrustedEvents    []string `json:"trusted_events,omitempty"`
	// UntrustedEvents is every present entry Codex will not run
	// (untrusted, modified or disabled).
	UntrustedEvents []string `json:"untrusted_events,omitempty"`
	ModifiedEvents  []string `json:"modified_events,omitempty"`
	DisabledEvents  []string `json:"disabled_events,omitempty"`
	MissingEvents   []string `json:"missing_events,omitempty"`
	// Entries is the per-event state table the card renders.
	Entries []codextrust.Entry `json:"entries,omitempty"`
	// HashVerified is false when no recorded trust hash reproduces (a
	// Codex release that hashes differently): a changed entry then cannot
	// be told apart from a trusted one.
	HashVerified       bool   `json:"hash_verified"`
	FeatureFlagEnabled bool   `json:"feature_flag_enabled"`
	Instruction        string `json:"instruction,omitempty"`
	// GateOff is true when a tool-gate event (diag.CodexToolGateEvents) is
	// among the events Codex will not run: Observer's Codex guard gate is
	// then off, not degraded (live check 2026-10-20).
	GateOff bool `json:"gate_off,omitempty"`
	// Origin names the home this snapshot read: "native", or the foreign
	// home (a WSL daemon's view of the Windows user's ~/.codex, which the
	// codex-windows hook bridge registers into).
	Origin string `json:"origin,omitempty"`
	// OtherHomes are the snapshots of every other home carrying Observer
	// Codex hooks. The top-level snapshot is the one that needs action
	// first, so the card leads with it.
	OtherHomes []codexHookTrustSnapshot `json:"other_homes,omitempty"`
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

// codexHookTrustSnapshot reads every home Observer registers Codex hooks
// into (the native ~/.codex, plus on a WSL daemon the Windows user's, see
// diag.ForeignCodexHomes) and leads with the one that needs action. Pure
// read; never mutates.
func (s *Server) codexHookTrustSnapshot() codexHookTrustSnapshot {
	home, err := os.UserHomeDir()
	if err != nil {
		return codexHookTrustSnapshot{Status: "no_codex"}
	}
	snaps := []codexHookTrustSnapshot{codexHookTrustSnapshotAt(filepath.Join(home, ".codex"), "native")}
	for _, h := range diag.ForeignCodexHomes("") {
		snap := codexHookTrustSnapshotAt(filepath.Join(h.Path, ".codex"), h.OS+" home "+h.Path)
		if !codexTrustIdle(snap.Status) {
			snaps = append(snaps, snap)
		}
	}
	lead := 0
	for i, sn := range snaps {
		if codexTrustNeedsAction(sn.Status) {
			lead = i
			break
		}
		if codexTrustIdle(snaps[lead].Status) && !codexTrustIdle(sn.Status) {
			lead = i
		}
	}
	out := snaps[lead]
	for i, sn := range snaps {
		if i != lead && !codexTrustIdle(sn.Status) {
			out.OtherHomes = append(out.OtherHomes, sn)
		}
	}
	return out
}

// codexTrustIdle reports a snapshot status with nothing to trust.
func codexTrustIdle(status string) bool { return status == "no_codex" || status == "no_hooks" }

// codexTrustNeedsAction reports a snapshot status the user must act on.
func codexTrustNeedsAction(status string) bool {
	return !codexTrustIdle(status) && status != "all_trusted"
}

// codexHookTrustSnapshotAt classifies the Observer Codex hooks under one
// .codex directory.
func codexHookTrustSnapshotAt(codexDir, origin string) codexHookTrustSnapshot {
	out := codexHookTrustSnapshot{Origin: origin}
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
	cfgRaw, cfgErr := os.ReadFile(out.ConfigFile)
	if cfgErr != nil {
		cfgRaw = nil
	}
	var expected []string
	if c, ok := integration.For(models.ToolCodex); ok {
		expected = c.Hook.RegisteredEvents()
	}
	rep, err := codextrust.Classify(codextrust.Input{
		HooksPath:     out.HooksFile,
		HooksJSON:     hooksRaw,
		ConfigTOML:    cfgRaw,
		Expected:      expected,
		Owned:         hook.IsObserverCodexHookCommand,
		NormalizePath: diag.CodexTrustPathKey,
	})
	if err != nil {
		// A broken config.toml still lets hooks.json say what is ours.
		rep, err = codextrust.Classify(codextrust.Input{
			HooksPath: out.HooksFile, HooksJSON: hooksRaw, Expected: expected,
			Owned:         hook.IsObserverCodexHookCommand,
			NormalizePath: diag.CodexTrustPathKey,
		})
		if err != nil {
			out.Status = "no_hooks"
			return out
		}
	}
	out.Entries = rep.Entries
	out.HashVerified = rep.HashVerified
	out.FeatureFlagEnabled = rep.FeatureHooks
	for _, e := range rep.Entries {
		if e.State != codextrust.StateMissing {
			out.RegisteredEvents = append(out.RegisteredEvents, e.Event)
		}
	}
	if len(out.RegisteredEvents) == 0 {
		out.Status = "no_hooks"
		out.Entries = nil
		return out
	}
	out.TrustedEvents = rep.Events(codextrust.StateTrusted)
	out.UntrustedEvents = rep.Events(codextrust.StateUntrusted, codextrust.StateModified, codextrust.StateDisabled)
	out.ModifiedEvents = rep.Events(codextrust.StateModified)
	out.DisabledEvents = rep.Events(codextrust.StateDisabled)
	out.MissingEvents = rep.Events(codextrust.StateMissing)

	switch {
	case cfgErr != nil:
		out.Status = "config_missing"
		out.TrustedEvents = nil
		out.UntrustedEvents = out.RegisteredEvents
		out.Instruction = codexHookTrustInstruction(out.UntrustedEvents, nil, nil)
	case !out.FeatureFlagEnabled:
		out.Status = "feature_disabled"
		out.UntrustedEvents = out.RegisteredEvents
		out.Instruction = "set [features].hooks = true in " + out.ConfigFile +
			" (the Set up wizard's Hooks step for codex sets this automatically); codex won't dispatch hooks without it"
	case len(out.UntrustedEvents) > 0:
		out.Status = "needs_trust"
		out.Instruction = codexHookTrustInstruction(out.UntrustedEvents, out.ModifiedEvents, out.DisabledEvents)
	case len(out.MissingEvents) > 0:
		out.Status = "needs_register"
		out.Instruction = "Observer also registers " + strings.Join(out.MissingEvents, ", ") +
			", which hooks.json does not carry yet: run the Set up wizard's Hooks step for codex (or restart the daemon, which auto-registers hooks), then trust the new entries in codex /hooks"
	default:
		out.Status = "all_trusted"
	}
	for _, e := range diag.CodexToolGateEvents() {
		for _, u := range out.UntrustedEvents {
			if u == e {
				out.GateOff = true
			}
		}
	}
	return out
}

// codexHookTrustInstruction tells the user exactly what to do inside
// codex, naming each event once under the action it needs. untrusted is
// every entry codex will not run (it includes modified and disabled).
// Re-registering (`observer init --codex`) records trust for Observer's own
// entries again, except one the user switched off, which only /hooks turns
// back on.
func codexHookTrustInstruction(untrusted, modified, disabled []string) string {
	other := map[string]bool{}
	for _, e := range append(append([]string{}, modified...), disabled...) {
		other[e] = true
	}
	var never []string
	for _, e := range untrusted {
		if !other[e] {
			never = append(never, e)
		}
	}
	var parts []string
	if len(never) > 0 {
		parts = append(parts, "trust "+strings.Join(never, ", "))
	}
	if len(modified) > 0 {
		parts = append(parts, "re-trust "+strings.Join(modified, ", ")+" (changed since you trusted it)")
	}
	if len(disabled) > 0 {
		parts = append(parts, "turn "+strings.Join(disabled, ", ")+" back on (switched off)")
	}
	prefix := "register hooks again (the Hooks step, or `observer init --codex`; it re-records Observer's trust), or open `codex`, run /hooks and "
	if len(never) == 0 && len(modified) == 0 {
		prefix = "open `codex`, run /hooks and "
	}
	return prefix + strings.Join(parts, "; ") +
		". Trust persists in ~/.codex/config.toml until the hook command changes."
}
