package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// The "Update automatically" switch on Settings > Health > Updates (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md, row B-S7). Before it
// the card printed "set [update].auto_apply = true" and the schema-driven
// Settings > Org section showed the key read-only: it is a *bool (unset means
// the managed-fleet default decides), which the generic editor's six kinds
// cannot express.
//
//	GET /api/update/auto-apply  L  the explicit value (null = unset), the confirm token, the config etag
//	PUT /api/update/auto-apply  L  {"auto_apply": true|false|null}; null removes the explicit value so the
//	                               default decides again; ?dry_run=1 previews the diff and writes nothing,
//	                               ?base_etag= refuses a config file that moved since the preview
//
// The write goes through the one config save pipeline (commitConfigEdit).
// update.auto_apply is annotated sensitive (configschema): it decides whether
// this node replaces its own binary. The real save carries the owner-local
// confirm token the GET mints. The route is whole-route Local, like the update
// apply route beside it. [update] binds at daemon start, so a save reports
// restart_required.

// updateAutoApplyView is GET /api/update/auto-apply.
type updateAutoApplyView struct {
	// AutoApply is [update].auto_apply as written in config.toml; nil when
	// the key is unset and the managed-fleet default decides.
	AutoApply *bool `json:"auto_apply"`
	// ConfirmToken is the owner-local token a PUT echoes.
	ConfirmToken string `json:"confirm_token,omitempty"`
	// ConfigEtag is config.toml's etag at read time (the PUT's base_etag).
	ConfigEtag string `json:"config_etag,omitempty"`
}

// updateAutoApplyRequest is a PUT body. Present is set by UnmarshalJSON so
// an explicit null (back to the default) differs from a missing field.
type updateAutoApplyRequest struct {
	AutoApply *bool
	Present   bool
}

// UnmarshalJSON accepts exactly {"auto_apply": true|false|null}.
func (req *updateAutoApplyRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k := range raw {
		if k != "auto_apply" {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	v, ok := raw["auto_apply"]
	if !ok {
		return fmt.Errorf("auto_apply is required (true, false or null)")
	}
	req.Present = true
	return json.Unmarshal(v, &req.AutoApply)
}

// handleUpdateAutoApply serves /api/update/auto-apply.
func (s *Server) handleUpdateAutoApply(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, err)
			return
		}
		v := updateAutoApplyView{AutoApply: cfg.Update.AutoApply}
		v.ConfirmToken = setConfirmCookie(w, r)
		if s.opts.ConfigPath != "" {
			v.ConfigEtag, _ = configEtag(s.opts.ConfigPath)
		}
		writeJSON(w, v)
	case http.MethodPut:
		s.updateAutoApplySave(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// updateAutoApplySave writes [update].auto_apply through the save pipeline.
func (s *Server) updateAutoApplySave(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	// The schema classifies the *bool as a file-only table, so the pipeline's
	// sensitive-tier rule does not see it; the route demands the token itself.
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"
	if !dryRun && !requireJSONConfirm(w, r) {
		return
	}
	var req updateAutoApplyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.commitConfigEdit(w, r, configEdit{
		section: "update",
		apply: func(cfg *config.Config) {
			if req.AutoApply == nil {
				cfg.Update.AutoApply = nil
				return
			}
			v := *req.AutoApply
			cfg.Update.AutoApply = &v
		},
		auditAction: "update_auto_apply",
		auditDetailFor: func(cfg config.Config) string {
			if cfg.Update.AutoApply == nil {
				return "auto_apply=default"
			}
			return fmt.Sprintf("auto_apply=%v", *cfg.Update.AutoApply)
		},
		extra: func(cfg config.Config) map[string]any {
			return map[string]any{"auto_apply": cfg.Update.AutoApply, "needs_confirm": true}
		},
	})
}
