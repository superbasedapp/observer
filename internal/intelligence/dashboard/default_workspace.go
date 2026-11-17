package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
)

// The "Default workspace" card (Terminals > Settings and Settings > Terminal):
// Observer's own scratch folder for steps that need a folder that is not one
// of the developer's projects (first user: the hosted sandbox consent step).
//
//	GET /api/workspace/default  L  the resolved folder {dir, builtin, builtin_dir,
//	                               configured, exists, ready, problem}, the confirm
//	                               token, the config etag
//	PUT /api/workspace/default  L  {"dir": "<abs>" | null}; null resets to the
//	                               built-in <home>/observer-workspace; ?dry_run=1
//	                               checks and previews the diff, writes and
//	                               creates nothing; ?base_etag= refuses a
//	                               config file that moved since the preview
//
// The rules and the folder creation are internal/defaultworkspace's (one
// owner). A real save checks the folder, sets it up (creates it when it is
// missing, writes its marker and makes it a git repository through
// Options.WorkspaceGitInit, so the hosted consent screen can list it), and
// only then writes [workspace].default_dir through the one config save
// pipeline (commitConfigEdit), with the owner-local confirm token. The key is
// owner-elsewhere in the schema, so the generic settings editor cannot skip
// the folder rules. Choosing the built-in folder stores nothing (the key is
// cleared), so the file never records the default.

// defaultWorkspaceView is GET /api/workspace/default.
type defaultWorkspaceView struct {
	Dir          string `json:"dir"`
	Builtin      bool   `json:"builtin"`
	BuiltinDir   string `json:"builtin_dir"`
	Configured   string `json:"configured"`
	Exists       bool   `json:"exists"`
	Ready        bool   `json:"ready"`
	Problem      string `json:"problem,omitempty"`
	ConfirmToken string `json:"confirm_token,omitempty"`
	ConfigEtag   string `json:"config_etag,omitempty"`
}

// defaultWorkspaceRequest is a PUT body; Reset is set when dir is an
// explicit null.
type defaultWorkspaceRequest struct {
	Dir   string
	Reset bool
}

// UnmarshalJSON accepts exactly {"dir": "<abs>" | null}.
func (req *defaultWorkspaceRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	for k := range raw {
		if k != "dir" {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	d, ok := raw["dir"]
	if !ok {
		return fmt.Errorf("dir is required (a folder path, or null to use the built-in folder)")
	}
	var ptr *string
	if err := json.Unmarshal(d, &ptr); err != nil {
		return fmt.Errorf("dir must be a string or null")
	}
	if ptr == nil {
		req.Reset = true
		return nil
	}
	req.Dir = *ptr
	return nil
}

// defaultWorkspaceEnv is the host facts the folder rules compare against.
func defaultWorkspaceEnv(cfg config.Config) defaultworkspace.Env {
	home, _ := os.UserHomeDir()
	return defaultworkspace.EnvFor(home, cfg.Observer.DBPath)
}

// defaultWorkspaceStatus renders the view's folder fields for cfg.
func defaultWorkspaceStatus(cfg config.Config) defaultWorkspaceView {
	s := defaultworkspace.Inspect(defaultWorkspaceEnv(cfg), cfg.Workspace.DefaultDir)
	return defaultWorkspaceView{
		Dir:        s.Dir,
		Builtin:    s.Builtin,
		BuiltinDir: s.BuiltinDir,
		Configured: s.Configured,
		Exists:     s.Exists,
		Ready:      s.Ready,
		Problem:    s.Problem,
	}
}

// handleDefaultWorkspace serves /api/workspace/default.
func (s *Server) handleDefaultWorkspace(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, err)
			return
		}
		v := defaultWorkspaceStatus(cfg)
		v.ConfirmToken = setConfirmCookie(w, r)
		if s.opts.ConfigPath != "" {
			v.ConfigEtag, _ = configEtag(s.opts.ConfigPath)
		}
		writeJSON(w, v)
	case http.MethodPut:
		s.defaultWorkspaceSave(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// defaultWorkspaceSave checks the folder, creates it on a real save, and
// writes [workspace].default_dir through the save pipeline.
func (s *Server) defaultWorkspaceSave(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	q := r.URL.Query()
	dryRun := q.Get("dry_run") == "1" || q.Get("dry_run") == "true"
	if !dryRun && !requireJSONConfirm(w, r) {
		return
	}
	var req defaultWorkspaceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	cur, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load current config: %w", err))
		return
	}
	env := defaultWorkspaceEnv(cur)
	// stored is the value written to the file: "" for the built-in folder.
	stored := ""
	target := defaultworkspace.BuiltinDir(env.Home)
	if !req.Reset {
		res := defaultworkspace.Resolve(req.Dir, env.Home)
		target = res.Dir
		if !res.Builtin {
			stored = res.Dir
		}
		if err := defaultworkspace.Check(env, req.Dir); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if target != "" && pathIsNotAFolder(target) {
			http.Error(w, "Something that is not a folder is already at that path.", http.StatusBadRequest)
			return
		}
	}
	// Every check that can refuse runs first (the rules above, then the
	// save pipeline's etag, validation and confirm token); the folder is
	// created and set up only in afterWrite, once the save went through, so
	// a refused save never leaves a folder the config does not point at
	// (review finding 8, 2026-11-12). A reset always saves (the built-in
	// folder is the default whatever it holds). A folder that passes the
	// rules but could not be created or made a repository (git missing) is
	// saved with a warning: Observer finishes it on the next start.
	setUp := func() map[string]any {
		out := map[string]any{"created": false, "initialized": false}
		if target == "" {
			return out
		}
		var initRepo defaultworkspace.InitRepo
		if s.opts.WorkspaceGitInit != nil {
			ctx := r.Context()
			initRepo = func(dir string) error { return s.opts.WorkspaceGitInit(ctx, dir) }
		}
		res, err := defaultworkspace.Ensure(env, target, initRepo)
		out["created"], out["initialized"] = res.Created, res.Initialized
		switch {
		case err == nil:
		case req.Reset:
			out["warning"] = "The built-in folder is not ready: " + err.Error()
		case !dirExists(target):
			out["warning"] = "The folder was saved but could not be created (" + err.Error() + "). Observer tries again when it starts."
		default:
			out["warning"] = "The folder is there but not set up yet (" + err.Error() + "). The hosted consent screen needs it to be a git repository; Observer tries again when it starts."
		}
		return out
	}
	s.commitConfigEdit(w, r, configEdit{
		section: "workspace",
		apply: func(cfg *config.Config) {
			cfg.Workspace.DefaultDir = stored
		},
		auditAction: "default_workspace",
		auditDetailFor: func(cfg config.Config) string {
			if cfg.Workspace.DefaultDir == "" {
				return "dir=builtin"
			}
			return "dir=set"
		},
		extra: func(cfg config.Config) map[string]any {
			return map[string]any{
				"workspace":     defaultWorkspaceStatus(cfg),
				"created":       false,
				"initialized":   false,
				"needs_confirm": true,
			}
		},
		afterWrite: func(cfg config.Config) map[string]any {
			out := setUp()
			out["workspace"] = defaultWorkspaceStatus(cfg)
			return out
		},
	})
}

// pathIsNotAFolder reports something other than a folder at p.
func pathIsNotAFolder(p string) bool {
	st, err := os.Stat(p) //nolint:gosec // G703: the owner's own workspace folder; only stat'd
	return err == nil && !st.IsDir()
}

// dirExists reports a folder at p.
func dirExists(p string) bool {
	st, err := os.Stat(p) //nolint:gosec // G703: the owner's own workspace folder; only stat'd
	return err == nil && st.IsDir()
}
