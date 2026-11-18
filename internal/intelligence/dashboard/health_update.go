package dashboard

import (
	"errors"
	"log/slog"
	"net/http"
)

// "Update in a terminal" (lane L5 B-S5,
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the Settings > Health
// update card used to print `npm i -g ...` / `pipx upgrade ...` for the user
// to type. GET /api/health/update-terminal says whether this install can be
// updated from a dashboard terminal and with which command; POST spawns that
// command in the in-dashboard setup PTY (the Remote page's "Install in a
// terminal" mechanism, SetupSpec).
//
// The argv is a FIXED row of a table (health_update_plan.go), chosen by the
// install method internal/update.Detect reports for the running executable.
// No request input reaches it, and nothing is run through a shell. A build
// without the self-update component (sbo_omit_org_update) has no install
// method detection and answers "not available" (health_update_omit.go).

// updateTerminalPlan is what the card shows and what POST runs.
type updateTerminalPlan struct {
	// Available is true when POST would spawn Command.
	Available bool `json:"available"`
	// Method is the install method (internal/updatespec.Method), or empty
	// when this build cannot detect it.
	Method string `json:"method,omitempty"`
	// Command is the argv as one display string.
	Command string `json:"command,omitempty"`
	// Reason says why there is no terminal update (Available false), with
	// what to do instead.
	Reason string `json:"reason,omitempty"`

	argv []string
}

// handleHealthUpdateTerminal serves GET and POST /api/health/update-terminal
// (Local). GET returns the plan; POST (confirm token) spawns it in a setup
// PTY labelled "update" and returns {handle, command}. The update replaces
// the binary on disk; the running daemon keeps the old one until it is
// restarted (the card says so).
func (s *Server) handleHealthUpdateTerminal(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, runningUpdatePlan())
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	plan := runningUpdatePlan()
	if !plan.Available || len(plan.argv) == 0 {
		reason := plan.Reason
		if reason == "" {
			reason = "no update command for this install"
		}
		writeErrStatus(w, errors.New(reason), http.StatusConflict)
		return
	}
	if s.opts.LaunchManager == nil {
		writeTerminalUnavailable(w, "")
		return
	}
	handle, err := s.opts.LaunchManager.CreateSetup(SetupSpec{Argv: plan.argv, Label: "update"})
	if err != nil {
		writeSetupSpawnErr(w, err)
		return
	}
	if s.opts.Logger != nil {
		s.opts.Logger.Info("dashboard: update terminal spawned", slog.String("command", plan.Command))
	}
	writeJSON(w, map[string]any{"handle": handle, "command": plan.Command})
}
