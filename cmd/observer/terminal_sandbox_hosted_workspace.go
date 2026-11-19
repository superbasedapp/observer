//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_workspace.go answers, before Start, whether a
// folder can be uploaded to a hosted box at all (lane UX, item H8): the New
// Terminal dialog asks with the folder it would launch in, and blocks Start
// on a hosted row whose source uploads (delivery sync) when the answer is
// no. The rule is sandboxremote.CheckUploadRoot, the launch's own root rules
// (PlanManifest and the repository-root rule of hostedListWorkspace); this
// file reads the facts only: the folder's resolved path, the home folder and
// git's top level through the hardened read-only envelope (hostedRepoTop).
// It never lists the folder's files, uploads nothing and calls no vendor.
//
// Decision SBXD-8: with [terminal.sandbox.hosted].upload_non_git on (the
// default, read from the effective config, so an organization pin holds), a
// folder that is not a repository answers OK with a note (how its files are
// chosen and that the changes come back as a diff file) that the dialog
// shows without blocking Start; off, it is refused as before.

// hostedWorkspaceRoute is GET /api/terminal/sandbox/hosted/workspace?dir=.
const hostedWorkspaceRoute = "GET /api/terminal/sandbox/hosted/workspace"

func init() {
	hostedExtraDashboardRoutes = append(hostedExtraDashboardRoutes, func(configPath string, gate func(http.HandlerFunc) http.HandlerFunc) []dashapi.ExtraRoute {
		load := func(ctx context.Context) (config.TerminalSandboxConfig, error) {
			return hostedCLIConfig(ctx, configPath)
		}
		return []dashapi.ExtraRoute{{Pattern: hostedWorkspaceRoute, Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			hostedWorkspaceServe(w, r, load)
		})}}
	})
}

// hostedWorkspaceView is the route's answer: the folder as asked, the
// folder as resolved, and the verdict.
type hostedWorkspaceView struct {
	Dir      string `json:"dir"`
	Resolved string `json:"resolved,omitempty"`
	sandboxremote.UploadRootVerdict
}

// hostedWorkspaceFacts reads the facts CheckUploadRoot needs for dir (a
// seam for tests).
var hostedWorkspaceFacts = func(ctx context.Context, dir string) (sandboxremote.UploadRootFacts, string) {
	resolved := dir
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		resolved = r
	}
	home, _ := os.UserHomeDir()
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	f := sandboxremote.UploadRootFacts{Root: filepath.ToSlash(resolved), Home: filepath.ToSlash(home)}
	if top, ok := hostedRepoTop(ctx, resolved); ok {
		f.IsRepository, f.RepositoryTop = true, filepath.ToSlash(top)
	}
	return f, resolved
}

// hostedWorkspaceHandler answers one folder under the shipped defaults
// (upload_non_git on); the route serves the effective config instead.
func hostedWorkspaceHandler(w http.ResponseWriter, r *http.Request) {
	hostedWorkspaceServe(w, r, func(context.Context) (config.TerminalSandboxConfig, error) {
		return config.Default().Terminal.Sandbox, nil
	})
}

// hostedWorkspaceServe answers one folder. A folder that is not an
// absolute existing directory is a 400, a config that does not load a 500
// (the dialog then blocks nothing; the launch still checks); the verdict
// is a 200 either way.
func hostedWorkspaceServe(w http.ResponseWriter, r *http.Request, load func(context.Context) (config.TerminalSandboxConfig, error)) {
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	if dir == "" || !filepath.IsAbs(dir) {
		http.Error(w, "dir must be an absolute folder", http.StatusBadRequest)
		return
	}
	dir = filepath.Clean(dir)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() { //nolint:gosec // G703: an owner-local (CapabilityLocal) read: only stat'd to say whether the owner's chosen folder exists; nothing is read or written
		http.Error(w, "dir is not a folder on this machine", http.StatusBadRequest)
		return
	}
	cfg, err := load(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, resolved := hostedWorkspaceFacts(r.Context(), dir)
	f.UploadNonGit = cfg.Hosted.UploadNonGit
	view := hostedWorkspaceView{Dir: dir, Resolved: resolved, UploadRootVerdict: sandboxremote.CheckUploadRoot(f)}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(view)
}
