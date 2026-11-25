package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// The local app lane's node API (S5, hosted AI gateway plan L7; L9 builds the
// "Your apps > Model calls" card on it):
//
//	GET    /api/apps/lanes        L  the lanes, their client base URLs, the
//	                                 model lists and the budget mode
//	POST   /api/apps/lanes        L  add a lane {id, upstream?, models?}
//	                                 (confirm token)
//	DELETE /api/apps/lanes/{id}   L  remove a lane (confirm token)
//
// Every route is owner-local (CapabilityLocal): a lane decides where an app's
// model calls and their provider key go. A write goes through
// config.EditAppLanes, the writer `observer apps lane add|remove` shares; a
// running daemon serves the change after its next start.

// appLanesBody is the GET /api/apps/lanes answer.
type appLanesBody struct {
	Lanes []applane.Lane `json:"lanes"`
	// Budget is the lane reservation's mode ([proxy.app_lanes] budget).
	Budget string `json:"budget"`
	// IncludeUsage is [proxy.app_lanes] include_usage.
	IncludeUsage bool `json:"include_usage"`
	// ProxyEnabled is [proxy] enabled: a lane needs the proxy.
	ProxyEnabled bool `json:"proxy_enabled"`
	// RestartRequired: a change takes effect at the daemon's next start.
	RestartRequired bool `json:"restart_required"`
	// Enforcement is the honest residual (section 2 of the plan): the app
	// keeps its provider key, so the lane enforces only calls sent through it.
	Enforcement string `json:"enforcement"`
	// CapSpend is where the app caps count spend from: "recorded"
	// ([observability] on) or "process" (off: only this daemon's calls
	// since it started), with CapSpendNote saying what that means.
	CapSpend     string `json:"cap_spend"`
	CapSpendNote string `json:"cap_spend_note,omitempty"`
}

// appLaneAddRequest is the POST /api/apps/lanes body.
type appLaneAddRequest struct {
	ID       string   `json:"id"`
	Upstream string   `json:"upstream"`
	Models   []string `json:"models"`
}

const appLaneEnforcement = "cooperative: the app holds its provider key, so the lane enforces only the calls sent through it"

// handleAppLanes serves GET and POST /api/apps/lanes.
func (s *Server) handleAppLanes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.appLanesConfig()
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, appLanesBodyOf(cfg))
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req appLaneAddRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		cfg, err := addAppLaneTo(s.opts.ConfigPath, req)
		if err != nil {
			writeAppLaneError(w, err)
			return
		}
		s.recordManageAudit(r, "app_lane_add", "id="+req.ID)
		writeJSON(w, appLanesBodyOf(cfg))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

// handleAppLaneItem serves DELETE /api/apps/lanes/{id}.
func (s *Server) handleAppLaneItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/apps/lanes/"), "/")
	if !applane.ValidLaneID(id) {
		http.Error(w, "invalid lane id", http.StatusBadRequest)
		return
	}
	cfg, err := config.EditAppLanes(s.opts.ConfigPath, func(p *config.ProxyConfig) error {
		return applane.Remove(id, p.Upstreams, p.AutoDefaultLane, p.AppLanes.Models)
	})
	if err != nil {
		writeAppLaneError(w, err)
		return
	}
	s.recordManageAudit(r, "app_lane_remove", "id="+id)
	writeJSON(w, appLanesBodyOf(cfg))
}

// addAppLaneTo validates and writes one lane through the shared rules
// (applane.ValidateAdd / Add.Apply), the dashboard twin of `observer apps
// lane add`.
func addAppLaneTo(configPath string, req appLaneAddRequest) (config.Config, error) {
	add, err := applane.ValidateAdd(req.ID, req.Upstream, req.Models)
	if err != nil {
		return config.Config{}, err
	}
	return config.EditAppLanes(configPath, func(p *config.ProxyConfig) error {
		return add.Apply(p.Upstreams, p.AgentUpstreams, &p.AppLanes.Models)
	})
}

// writeAppLaneError maps a lane write error to its status.
func writeAppLaneError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, applane.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, applane.ErrExists), errors.Is(err, applane.ErrAutoDefault), errors.Is(err, applane.ErrAgentLane):
		status = http.StatusConflict
	case errors.Is(err, applane.ErrInvalid):
		status = http.StatusBadRequest
	}
	writeJSONStatus(w, status, map[string]any{"error": "app_lane", "message": err.Error()})
}

// appLanesConfig loads the config the lanes are read from.
func (s *Server) appLanesConfig() (config.Config, error) {
	if s.opts.ConfigPath == "" {
		return config.Default(), nil
	}
	return loadConfigForDashboard(s.opts.ConfigPath)
}

// appLanesBodyOf builds the GET body from a config.
func appLanesBodyOf(cfg config.Config) appLanesBody {
	b := appLanesBody{
		Lanes:           applane.List(cfg.Proxy.Upstreams, cfg.Proxy.AppLanes.Models, cfg.Proxy.Port),
		Budget:          cfg.Proxy.AppLanes.BudgetMode(),
		IncludeUsage:    cfg.Proxy.AppLanes.IncludeUsage,
		ProxyEnabled:    cfg.Proxy.Enabled,
		RestartRequired: true,
		Enforcement:     appLaneEnforcement,
		CapSpend:        applane.CapSpendSource(cfg.Observability.Enabled),
	}
	if b.CapSpend == applane.CapSpendProcess {
		b.CapSpendNote = applane.CapSpendProcessNote
	}
	return b
}
