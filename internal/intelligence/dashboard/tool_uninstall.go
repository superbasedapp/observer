package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Dashboard-installed tools: the record of every guided install the dashboard
// ran, and the matching Uninstall (operator ask 2026-10-02: "if we allow folks
// to install adapters from the dashboard, we also need to allow them to
// uninstall — at least the ones they installed from the dashboard").
//
// The dashboard package owns only the HTTP surface. The record (node-local
// tool_installs, agent migration 149), the exit tracking and the uninstall
// derivation sit behind the Options.ToolInstalls seam, which cmd/observer
// implements over internal/store and the pure internal/toolinstall table.
// As with install, the request contributes only a tool NAME and a record id:
// the uninstall argv is derived server-side from the RECORDED install argv and
// is never request input.

// toolInstallActionRequest is the body of POST /api/terminal/uninstall and
// POST /api/terminal/installs/forget: a tool NAME and the record id the
// operator confirmed. Nothing else is read.
type toolInstallActionRequest struct {
	Tool     string `json:"tool"`
	RecordID int64  `json:"record_id"`
}

// installKillSwitchOn reports the live [terminal.launch].allow_install value
// (nil seam = off, the install route's own fail-safe).
func (s *Server) installKillSwitchOn() bool {
	return s.opts.AllowToolInstall != nil && s.opts.AllowToolInstall()
}

// withKillSwitch applies the guided-install kill-switch to a record: when the
// switch is off nothing may be uninstalled from here (the same opt-in that
// gates install gates its reverse).
func (s *Server) withKillSwitch(rec ToolInstallRecord) ToolInstallRecord {
	if !s.installKillSwitchOn() {
		rec.CanUninstall = false
	}
	return rec
}

// dashboardInstallFor returns the record to attach to a preflight reply, or
// nil (no seam, no record, or a read error — never fatal to the preflight).
func (s *Server) dashboardInstallFor(ctx context.Context, tool string) *ToolInstallRecord {
	if s.opts.ToolInstalls == nil {
		return nil
	}
	rec, ok, err := s.opts.ToolInstalls.Lookup(ctx, tool)
	if err != nil {
		s.opts.Logger.Warn("dashboard: tool install record lookup failed", slog.String("tool", tool), slog.Any("err", err))
		return nil
	}
	if !ok || !toolSubject(rec) {
		return nil
	}
	rec = s.withKillSwitch(rec)
	return &rec
}

// toolSubject reports whether rec is an AI tool's record. The tool routes
// list and act on subject_kind tool only (sandbox installation lifecycle plan
// section 3.6): a sandbox setup record (subject_kind sandbox, agent migration
// 222) belongs to the sandbox setup routes and never shows here.
func toolSubject(rec ToolInstallRecord) bool {
	return rec.SubjectKind == "" || rec.SubjectKind == "tool"
}

// recordInstall records a just-spawned guided install. Fail-soft: the
// install is already running in the operator's terminal, so a record failure
// is logged and never turned into an error response.
func (s *Server) recordInstall(ctx context.Context, tool, handle string, argv []string, display string) {
	if s.opts.ToolInstalls == nil {
		return
	}
	if err := s.opts.ToolInstalls.RecordInstall(ctx, tool, handle, argv, display); err != nil {
		s.opts.Logger.Warn("dashboard: recording guided install failed", slog.String("tool", tool), slog.Any("err", err))
	}
}

// handleTerminalInstalls serves GET /api/terminal/installs — the latest
// dashboard-install record per tool (Settings > Connected tools). LOCAL: the
// records name this machine's install commands and paths.
func (s *Server) handleTerminalInstalls(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.ToolInstalls == nil {
		writeJSON(w, map[string]any{"available": false, "installs": []ToolInstallRecord{}})
		return
	}
	recs, err := s.opts.ToolInstalls.List(r.Context())
	if err != nil {
		writeErrStatus(w, fmt.Errorf("listing dashboard installs: %w", err), http.StatusInternalServerError)
		return
	}
	out := make([]ToolInstallRecord, 0, len(recs))
	for _, rec := range recs {
		if !toolSubject(rec) {
			continue
		}
		out = append(out, s.withKillSwitch(rec))
	}
	writeJSON(w, map[string]any{
		"available":     true,
		"allow_install": s.installKillSwitchOn(),
		"installs":      out,
	})
}

// decodeToolInstallAction reads and validates the action body.
func decodeToolInstallAction(w http.ResponseWriter, r *http.Request) (toolInstallActionRequest, bool) {
	var body toolInstallActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErrStatus(w, fmt.Errorf("invalid JSON body: %w", err), http.StatusBadRequest)
		return body, false
	}
	body.Tool = strings.TrimSpace(body.Tool)
	if body.Tool == "" {
		writeErrStatus(w, errors.New("missing tool"), http.StatusBadRequest)
		return body, false
	}
	if body.RecordID <= 0 {
		writeErrStatus(w, errors.New("missing record_id"), http.StatusBadRequest)
		return body, false
	}
	return body, true
}

// writeLedgerErr maps a ledger error to its status.
func writeLedgerErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrToolInstallNotFound):
		writeErrStatus(w, err, http.StatusNotFound)
	case errors.Is(err, ErrToolInstallStale), errors.Is(err, ErrToolUninstallUnsupported):
		writeErrStatus(w, err, http.StatusConflict)
	default:
		writeErrStatus(w, err, http.StatusInternalServerError)
	}
}

// handleTerminalUninstall serves POST /api/terminal/uninstall — the reverse of
// the guided install, offered ONLY for a tool this dashboard installed (per
// the node's record) on a channel with a defined uninstall. Same gates as
// POST /api/terminal/install, in the same order: confirm token FIRST, then
// LaunchManager nil -> 503, the [terminal.launch].allow_install kill-switch
// off -> 403, then no ledger -> 501. The body names a tool and the record id
// the operator confirmed; the argv is derived server-side from that record's
// RECORDED install argv (internal/toolinstall's channel table) and spawned in a
// visible local-only setup PTY labelled "uninstall:<tool>".
func (s *Server) handleTerminalUninstall(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		writeTerminalUnavailable(w, "")
		return
	}
	if !s.installKillSwitchOn() {
		writeGuidedUninstallOff(w)
		return
	}
	if s.opts.ToolInstalls == nil {
		writeErrStatus(w, errors.New("this dashboard runs without the install record (run via `observer start`)"), http.StatusNotImplemented)
		return
	}
	body, ok := decodeToolInstallAction(w, r)
	if !ok {
		return
	}
	var spawnErr error
	started, err := s.opts.ToolInstalls.Uninstall(r.Context(), body.Tool, body.RecordID, func(argv []string) (string, error) {
		h, err := s.opts.LaunchManager.CreateSetup(SetupSpec{Argv: argv, Label: "uninstall:" + body.Tool})
		spawnErr = err
		return h, err
	})
	if spawnErr != nil {
		writeSetupSpawnErr(w, spawnErr)
		return
	}
	if err != nil {
		writeLedgerErr(w, err)
		return
	}
	s.opts.Logger.Info("dashboard: guided tool uninstall spawned", slog.String("tool", body.Tool), slog.String("command", started.Command))
	writeJSON(w, started)
}

// handleTerminalInstallForget serves POST /api/terminal/installs/forget — hide
// a settled record (the honest exit for a vendor-script install with no
// defined uninstall, or a tool removed by hand). Never deletes the row and
// never touches the machine. Confirm-token gated and LOCAL like the rest.
func (s *Server) handleTerminalInstallForget(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.opts.ToolInstalls == nil {
		writeErrStatus(w, errors.New("this dashboard runs without the install record (run via `observer start`)"), http.StatusNotImplemented)
		return
	}
	body, ok := decodeToolInstallAction(w, r)
	if !ok {
		return
	}
	if err := s.opts.ToolInstalls.Forget(r.Context(), body.Tool, body.RecordID); err != nil {
		writeLedgerErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "tool": body.Tool, "record_id": body.RecordID})
}
