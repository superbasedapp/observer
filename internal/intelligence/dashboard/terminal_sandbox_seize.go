package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// terminal_sandbox_seize.go is the strace switch of the sandbox card (lane
// ptrace, PT-96, operator ruling 2026-11-10): the only writer of
// [terminal.sandbox].seccomp_allow_seize, which lifts PTRACE_SEIZE (and
// nothing else) from Observer's syscall filter so `strace <cmd>` works in a
// sandboxed terminal. Owner-local (class L) and confirm-token gated like the
// shell-wrap routes; an agent's POST is guard R-165's. The GET reports the
// switch and, through the injected Options.SandboxSeize seam (the sandbox
// module computes it; this package imports none of it), what the switch
// gives each sandbox on this host now: its containment ground, or why
// strace stays blocked there.

// terminalSandboxSeizePath is the route.
const terminalSandboxSeizePath = "/api/terminal/sandbox/ptrace-seize"

// terminalSandboxSeizeKey is the config key the route owns.
const terminalSandboxSeizeKey = "terminal.sandbox.seccomp_allow_seize"

// terminalSandboxSeizeBody is the POST body.
type terminalSandboxSeizeBody struct {
	Enabled *bool `json:"enabled"`
}

// handleTerminalSandboxSeize serves GET and POST /api/terminal/sandbox/ptrace-seize.
func (s *Server) handleTerminalSandboxSeize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTerminalSandboxSeizeGet(w, r)
	case http.MethodPost:
		s.handleTerminalSandboxSeizePost(w, r)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// terminalSandboxSeizeStatus is the GET answer (and the POST's, after a
// save). Without the seam (a build without the sandbox module) there are
// no rows and Yama is not known.
func (s *Server) terminalSandboxSeizeStatus(c config.TerminalSandboxConfig) map[string]any {
	host := dashapi.SandboxSeizeHost{}
	if s.opts.SandboxSeize != nil {
		host = s.opts.SandboxSeize()
	}
	rows := host.Rows
	if rows == nil {
		rows = []dashapi.SandboxSeizeRow{}
	}
	var yama any
	if host.YamaKnown {
		yama = host.YamaScope
	}
	return map[string]any{
		"enabled":    c.SeccompAllowSeize,
		"seccomp":    c.Seccomp,
		"yama_scope": yama,
		"rows":       rows,
	}
}

func (s *Server) handleTerminalSandboxSeizeGet(w http.ResponseWriter, r *http.Request) {
	tok := setConfirmCookie(w, r)
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load sandbox config: %w", err))
		return
	}
	out := s.terminalSandboxSeizeStatus(cfg.Terminal.Sandbox)
	out["confirm_token"] = tok
	out["config_writable"] = s.opts.ConfigPath != ""
	writeJSON(w, out)
}

// terminalSandboxSeizeGovernanceRefused applies a governance pin on the
// key's Settings section to turning the switch ON. Turning it off is never
// refused: a lock never blocks a lowering.
func (s *Server) terminalSandboxSeizeGovernanceRefused(w http.ResponseWriter, r *http.Request) bool {
	if s.opts.Governance == nil {
		return false
	}
	eff := s.opts.Governance(r.Context())
	if !eff.VisibilityActive() {
		return false
	}
	leaf, _ := configschema.Lookup(terminalSandboxSeizeKey)
	if eff.IsSettingsSectionHidden(leaf.Section) || eff.IsSettingsSectionReadOnly(leaf.Section) {
		writeGovernanceRefusal(w, http.StatusConflict, "governance_read_only", leaf.Section, eff,
			"This setting is pinned by your organization and cannot be changed here.")
		return true
	}
	return false
}

func (s *Server) handleTerminalSandboxSeizePost(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	var body terminalSandboxSeizeBody
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode strace switch: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Enabled == nil {
		http.Error(w, `the body needs "enabled": true or false`, http.StatusBadRequest)
		return
	}
	on := *body.Enabled
	if on && s.terminalSandboxSeizeGovernanceRefused(w, r) {
		return
	}
	s.commitConfigEdit(w, r, configEdit{
		section:     "terminal.sandbox",
		apply:       func(cfg *config.Config) { cfg.Terminal.Sandbox.SeccompAllowSeize = on },
		auditAction: "terminal_sandbox_ptrace_seize",
		auditDetailFor: func(cfg config.Config) string {
			return fmt.Sprintf("seccomp_allow_seize=%v seccomp=%v", cfg.Terminal.Sandbox.SeccompAllowSeize, cfg.Terminal.Sandbox.Seccomp)
		},
		extra: func(cfg config.Config) map[string]any {
			return map[string]any{"strace": s.terminalSandboxSeizeStatus(cfg.Terminal.Sandbox)}
		},
		afterWrite: func(config.Config) map[string]any {
			s.applySandboxLive(r)
			return nil
		},
	})
}
