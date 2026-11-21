//go:build !sbo_omit_ingest_otlp

package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/telemetrywire"
)

// setup_telemetry.go is the Connected tools "Telemetry export" step (T-537,
// operator ruling D-343 "exporter wiring, opt-in per tool"): point a tool's
// own OpenTelemetry exporter at this node's OTLP receiver, or remove that
// wiring. The same seam `observer init --otlp-export` and `observer
// uninstall` use (clientwire.WireTelemetry), the same per-write consent as
// every wizard step: a dry-run preview first, nothing written until the
// user clicks. OFF by default: no code path writes it unasked.
//
// Unlike the older hooks / MCP registration, EVERY POST here carries the
// owner-local confirm token (preview included) and a real write is audited.

// telemetryStepGate offers the step exactly where clientwire does.
var telemetryStepGate = wizardStepGate{part: clientwire.PartTelemetry, register: clientwire.TelemetrySupported, remove: clientwire.TelemetrySupported}

// telemetrySetupResponse is the step's reply.
type telemetrySetupResponse struct {
	Tool       string   `json:"tool"`
	ConfigPath string   `json:"config_path,omitempty"`
	DryRun     bool     `json:"dry_run"`
	Undo       bool     `json:"undo,omitempty"`
	Changed    bool     `json:"changed"`
	Wired      bool     `json:"wired"`
	Summary    []string `json:"summary"`
	Conflict   string   `json:"conflict,omitempty"`
	Error      string   `json:"error,omitempty"`
	// AlreadySet mirrors the other steps' "nothing to do" flag so the
	// wizard's shared reply reader renders it the same way.
	AlreadySet bool `json:"already_set"`
	// SettingsLink is the dashboard place that fixes a refusal on the
	// receiver's side (P3-20): Settings > OTel export, whose "More settings"
	// card edits [ingest.otel] enabled / http_addr / allow_non_loopback.
	SettingsLink string `json:"settings_link,omitempty"`
	// Fields is the same place in the shape every "needs a setting" refusal
	// carries (internal/settingslink), which the SPA's one renderer reads.
	settingslink.Fields
}

// telemetryReceiverSettingsLink is where the node's OTLP receiver keys are
// edited ([ingest.otel] sits in the "otel" Settings section, configschema).
const telemetryReceiverSettingsLink = "/settings?section=otel"

// handleSetupTelemetry serves POST /api/setup/telemetry {"tool", "dry_run",
// "undo"}.
func (s *Server) handleSetupTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && !requireJSONConfirm(w, r) {
		return
	}
	req, ok := decodeWizardRequest(w, r, telemetryStepGate)
	if !ok {
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	op := telemetrywire.OpApply
	if req.Undo {
		op = telemetrywire.OpRemove
	} else if !cfg.Ingest.OTel.Enabled || strings.TrimSpace(cfg.Ingest.OTel.HTTPAddr) == "" {
		// Not a conflict with the user's file (there is nothing to force):
		// a precondition on this node, with the place that fixes it.
		writeJSONStatus(w, http.StatusPreconditionFailed, telemetrySetupResponse{
			Tool: req.Tool, DryRun: req.DryRun, Summary: []string{}, SettingsLink: telemetryReceiverSettingsLink, Fields: otelExportFields(),
			Error: "this node's OTLP receiver is off: turn it on in Settings > OTel export > More settings ([ingest.otel] enabled, with an HTTP address), restart the daemon, then come back here",
		})
		return
	}
	res := clientwire.WireTelemetry(req.Tool, op, clientwire.TelemetryOptions{
		HomeDir: setupWizardHome, Addr: cfg.Ingest.OTel.HTTPAddr, DryRun: req.DryRun,
		ReceiverRequiresToken: cfg.Ingest.OTel.AllowNonLoopback,
	})
	out := telemetrySetupResponse{
		Tool: req.Tool, ConfigPath: res.ConfigPath, DryRun: req.DryRun, Undo: req.Undo,
		Changed: res.Changed, Wired: res.Wired, Summary: res.Summary, Conflict: res.Conflict,
		AlreadySet: !res.Changed && res.Conflict == "" && res.Error == nil,
	}
	if out.Summary == nil {
		out.Summary = []string{}
	}
	switch {
	case errors.Is(res.Error, clientwire.ErrReceiverRequiresToken):
		out.Error, out.SettingsLink, out.Fields = res.Error.Error(), telemetryReceiverSettingsLink, otelExportFields()
		writeJSONStatus(w, http.StatusPreconditionFailed, out)
		return
	case res.Error != nil:
		out.Error = res.Error.Error()
		writeJSONStatus(w, http.StatusConflict, out)
		return
	case res.Conflict != "":
		out.Error = res.Conflict
		writeJSONStatus(w, http.StatusConflict, out)
		return
	}
	if !req.DryRun && res.Changed {
		action := "telemetry_export_register"
		if req.Undo {
			action = "telemetry_export_unregister"
		}
		s.recordManageAudit(r, action, fmt.Sprintf("tool=%s", req.Tool))
	}
	writeJSON(w, out)
}

// otelExportFields is the receiver refusal's deep link from the one table
// (Settings > OTel export, the same path as telemetryReceiverSettingsLink).
func otelExportFields() settingslink.Fields {
	l, _ := settingslink.For(settingslink.OTelExport)
	return l.Fields()
}
