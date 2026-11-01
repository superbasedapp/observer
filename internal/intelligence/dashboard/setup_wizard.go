package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
)

// Setup-wizard write endpoints (usability arc P4.2 / review row B3):
// the dashboard's per-step siblings of `observer init`'s hooks and
// MCP registration, and (T-421) of `observer uninstall`'s removal. Each
// POST performs EXACTLY ONE tool's one integration write, and only ever
// runs from an explicit user click behind the wizard's preview→confirm
// flow: the opt-in invariant (no AI-client config write without explicit
// per-action consent) holds per write, not per wizard run.
//
// Which tools a step serves is internal/clientwire's answer (the registry's
// hook mechanisms and MCP formats, the predicates `observer init` and
// `observer uninstall` share), never a tool-name list here. A registration
// writes through the daemon's own auto-registration options when cmd
// injected them (the command the Connected tools probe compares against,
// T-376, and the owes-live filter that keeps a not-yet-live gate unwritten);
// a removal runs clientwire.Remover, the seam `observer uninstall` runs.

// setupWizardHome, when non-empty, overrides the user home the
// registries write into. Tests set it so a wizard POST can never
// touch the developer's real ~/.claude / ~/.cursor / ~/.codex.
var setupWizardHome string

type setupWizardRequest struct {
	Tool   string `json:"tool"`
	Force  bool   `json:"force"`
	DryRun bool   `json:"dry_run"`
	// Undo removes Observer's own entries instead of writing them (the
	// `observer uninstall` removal for this one tool and this one step).
	// Like every other dashboard removal it carries the confirm token.
	Undo bool `json:"undo"`
}

// registrationConfigPath mirrors `observer init`'s --config rule: the
// registered command carries --config only when this daemon runs a
// non-default config file, so wizard writes stay byte-identical to a
// plain `observer init` on a default install.
func (s *Server) registrationConfigPath() string {
	if s.opts.ConfigPath == "" {
		return ""
	}
	if def, err := config.ResolveGlobalPath(""); err == nil && def == s.opts.ConfigPath {
		return ""
	}
	return s.opts.ConfigPath
}

// wizardStepGate is one step's capability predicate pair: which tools it
// may register, and which it may remove.
type wizardStepGate struct {
	part     clientwire.Part
	register func(tool string) bool
	remove   func(tool string) bool
}

var (
	hooksStepGate = wizardStepGate{part: clientwire.PartHooks, register: clientwire.HookSupported, remove: clientwire.HookRemovable}
	mcpStepGate   = wizardStepGate{part: clientwire.PartMCP, register: clientwire.MCPSupported, remove: clientwire.MCPSupported}
)

func decodeWizardRequest(w http.ResponseWriter, r *http.Request, gate wizardStepGate) (setupWizardRequest, bool) {
	var req setupWizardRequest
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return req, false
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return req, false
	}
	allowed := gate.register
	verb := "register"
	if req.Undo {
		allowed, verb = gate.remove, "remove"
	}
	if req.Tool == "" || !allowed(req.Tool) {
		http.Error(w, fmt.Sprintf("Observer does not %s %s for tool %q", verb, gate.part, req.Tool), http.StatusBadRequest)
		return req, false
	}
	return req, true
}

// hookWriteOptions returns the registry options a wizard hooks write uses:
// the daemon's own auto-registration options when cmd injected them (so the
// written command is the one the Connected tools probe expects, and the
// owes-live filter applies), otherwise this binary plus the --config rule.
func (s *Server) hookWriteOptions(req setupWizardRequest) (hook.Options, error) {
	var opts hook.Options
	if s.opts.HookRegistryOptions != nil {
		o, err := s.opts.HookRegistryOptions()
		if err != nil {
			return hook.Options{}, err
		}
		opts = o
	} else {
		exe, err := os.Executable()
		if err != nil {
			return hook.Options{}, err
		}
		opts = hook.Options{BinaryPath: exe, ConfigPath: s.registrationConfigPath()}
	}
	opts.DryRun = req.DryRun
	opts.Force = req.Force
	if setupWizardHome != "" {
		opts.HomeDir = setupWizardHome
	}
	return opts, nil
}

// promptLaneEnabled reports whether the prompt-submit engine evaluates the
// hook lane ([guard.prompt] enabled and hook_lane), the same input `observer
// init` and `observer start` gate a prompt-only mechanism on.
func (s *Server) promptLaneEnabled() bool {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return false
	}
	return cfg.Guard.Prompt.Enabled && cfg.Guard.Prompt.HookLane
}

// handleSetupHooks serves POST /api/setup/hooks — register observer's
// hook entries into one tool's config file. {"tool", "force",
// "dry_run", "undo"}; conflicts come back 409 with the error + the partial
// result, force=true overrides (same contract as the routing POSTs).
func (s *Server) handleSetupHooks(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeWizardRequest(w, r, hooksStepGate)
	if !ok {
		return
	}
	if req.Undo {
		s.wizardRemove(w, r, req, clientwire.PartHooks)
		return
	}
	opts, err := s.hookWriteOptions(req)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !clientwire.HookRegistrationWanted(req.Tool, s.promptLaneEnabled(), opts.SkipEvent) {
		// Nothing this tool's mechanism registers is wanted right now (its
		// only binding is the prompt-submit gate and the prompt lane is
		// off, or every binding still owes a live test): the same answer
		// `observer init` and `observer start` give, said instead of a
		// write that would do nothing.
		writeJSON(w, map[string]any{
			"tool":        req.Tool,
			"hooks_added": []string{},
			"already_set": []string{},
			"dry_run":     req.DryRun,
			"skipped":     true,
			"skip_reason": "nothing to register: this tool's hooks serve only gates that are off or still owe a live test",
		})
		return
	}
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		writeErr(w, err)
		return
	}
	res := reg.Register(req.Tool)
	resp := map[string]any{
		"tool":        req.Tool,
		"config_path": res.ConfigPath,
		"hooks_added": res.HooksAdded,
		"already_set": res.AlreadySet,
		"dry_run":     res.DryRun,
	}
	if res.Skipped {
		resp["skipped"] = true
		resp["skip_reason"] = res.SkipReason
	}
	// Non-fatal: the hooks are (or would be) in place, but the host may not
	// run them as launched today (e.g. VT Code on Windows without sh.exe on
	// PATH). Omitted when there is nothing to say, so the shape is additive.
	if len(res.Warnings) > 0 {
		resp["warnings"] = res.Warnings
	}
	if res.Error != nil {
		resp["error"] = res.Error.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	writeJSON(w, resp)
}

// handleSetupMCP serves POST /api/setup/mcp — register the observer
// MCP server into one tool's config. Same request/conflict contract
// as handleSetupHooks. The wizard's MCP step carries the per-turn
// schema-overhead note and is never pre-selected — MCP stays opt-in
// (Default-On vs Opt-In; advisor E1 remediation routes through this
// consent flow only, per Q4).
func (s *Server) handleSetupMCP(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeWizardRequest(w, r, mcpStepGate)
	if !ok {
		return
	}
	if req.Undo {
		s.wizardRemove(w, r, req, clientwire.PartMCP)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, err)
		return
	}
	reg, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{
		BinaryPath: exe,
		DryRun:     req.DryRun,
		Force:      req.Force,
		HomeDir:    setupWizardHome,
		ConfigPath: s.registrationConfigPath(),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	res := reg.Register(req.Tool)
	resp := map[string]any{
		"tool":        req.Tool,
		"config_path": res.ConfigPath,
		"added":       res.Added,
		"already_set": res.AlreadySet,
		"dry_run":     res.DryRun,
	}
	if res.Skipped {
		resp["skipped"] = true
		resp["skip_reason"] = res.SkipReason
	}
	if res.Error != nil {
		resp["error"] = res.Error.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	writeJSON(w, resp)
}

// wizardRemoveResponse is a removal step's reply: the exact change to one
// file, entry by entry. Removed names what goes (hook events, or the
// observer MCP server); Kept names the user-authored entries the same file
// keeps, and the path of each whole file kept because it is not Observer's
// (FU-212). A dry run reports the change and writes nothing.
type wizardRemoveResponse struct {
	Tool          string   `json:"tool"`
	Undo          bool     `json:"undo"`
	Part          string   `json:"part"`
	ConfigPath    string   `json:"config_path,omitempty"`
	Removed       []string `json:"removed"`
	Kept          []string `json:"kept"`
	Skipped       bool     `json:"skipped,omitempty"`
	ChecksumMatch bool     `json:"checksum_match,omitempty"`
	DryRun        bool     `json:"dry_run"`
	Error         string   `json:"error,omitempty"`
}

// wizardRemove runs the `observer uninstall` removal of one part for one
// tool through clientwire.Remover (the CLI's own seam). Conflicts (a file
// modified since Observer wrote it) answer 409 with the reason; force=true
// removes Observer's entries anyway, exactly like `observer uninstall
// --force`.
func (s *Server) wizardRemove(w http.ResponseWriter, r *http.Request, req setupWizardRequest, part clientwire.Part) {
	// A removal is a config write: it carries the confirm token like every
	// other dashboard write (review M3-05).
	if !requireJSONConfirm(w, r) {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		writeErr(w, err)
		return
	}
	rem, err := clientwire.NewRemover(clientwire.RemoveOptions{
		BinaryPath: exe,
		HomeDir:    setupWizardHome,
		ProxyPort:  s.opts.ProxyPort,
		DryRun:     req.DryRun,
		Force:      req.Force,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := wizardRemoveResponse{Tool: req.Tool, Undo: true, Part: string(part), DryRun: req.DryRun, Removed: []string{}, Kept: []string{}}
	var rerr error
	m := rem.Remove(req.Tool, part)
	switch {
	case m.Hooks != nil:
		resp.ConfigPath = m.Hooks.ConfigPath
		resp.Removed = append(resp.Removed, m.Hooks.HooksRemoved...)
		resp.Kept = append(resp.Kept, m.Hooks.HooksKept...)
		// FU-212: a whole file kept because it is not Observer's is named
		// by its path.
		resp.Kept = append(resp.Kept, m.Hooks.FilesKeptForeign...)
		resp.Skipped = m.Hooks.Skipped
		resp.ChecksumMatch = m.Hooks.ChecksumMatch
		rerr = m.Hooks.Error
	case m.MCP != nil:
		resp.ConfigPath = m.MCP.ConfigPath
		if m.MCP.Removed {
			resp.Removed = append(resp.Removed, mcpregister.ServerName)
		}
		resp.Skipped = m.MCP.Skipped
		rerr = m.MCP.Error
	}
	if rerr != nil {
		resp.Error = rerr.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	if !req.DryRun && len(resp.Removed) > 0 {
		s.recordManageAudit(r, string(part)+"_unregister", fmt.Sprintf("tool=%s removed=%d", req.Tool, len(resp.Removed)))
	}
	writeJSON(w, resp)
}
