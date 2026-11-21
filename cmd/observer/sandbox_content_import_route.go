//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// sandbox_content_import_route.go is the dashboard form of `observer sandbox
// content import <dir>` (dashboard CLI parity plan item B-G7): the microVM
// panel's "Import image set". It runs the CLI's own import
// (sandboxContentImportWith) on a folder this machine holds: offline, every
// kind verified against the vendor key compiled into this agent, the store's
// high-water mark and every file's size and sha256 before anything is
// installed, all or nothing. The debug image set (--debug-set and
// --debug-key) stays a CLI-only step: the route never takes a key, so a
// debug set is refused here whoever signed it. The route is Local, answers
// 404 while no driver that uses a sandbox content kind is selected, and
// needs the confirm token. One import runs at a time.

func init() {
	gatesSandboxRouteFuncs = append(gatesSandboxRouteFuncs, sandboxContentImportRoutes)
}

// sandboxImportRouteMu keeps imports from the dashboard to one at a time.
var sandboxImportRouteMu sync.Mutex

// sandboxImportRouteRun is the import the route runs (a test seam): the
// CLI's import with no debug key.
var sandboxImportRouteRun = func(store contentchan.Store, keys []ed25519.PublicKey, dir string) ([]sandboxImportStaged, error) {
	return sandboxContentImportWith(store, keys, dir, nil)
}

// sandboxImportRouteSelected reports whether a driver that uses a sandbox
// content kind is selected under cfg (the panel's own opt-in rule).
func sandboxImportRouteSelected(cfg config.Config) bool {
	snap := componentSnapshotForConfig(cfg)
	for _, r := range orgclient.SandboxContentKinds {
		if sandboxDriverSelected(snap, r.Component) {
			return true
		}
	}
	return false
}

// sandboxImportInstalled is one installed kind in the route's answer.
type sandboxImportInstalled struct {
	Kind    string `json:"kind"`
	Version int64  `json:"version"`
	Status  string `json:"status"`
}

// sandboxContentImportRoutes is the route (gatesSandboxRouteFuncs).
func sandboxContentImportRoutes(configPath string) []dashapi.ExtraRoute {
	return []dashapi.ExtraRoute{{
		Pattern: "POST /api/terminal/sandbox/content/import", Capability: dashapi.CapabilityLocal,
		Handler: func(w http.ResponseWriter, r *http.Request) { sandboxContentImportHandler(w, r, configPath) },
	}}
}

// sandboxContentImportHandler serves POST
// /api/terminal/sandbox/content/import: {"dir": "<absolute folder>"}.
func sandboxContentImportHandler(w http.ResponseWriter, r *http.Request, configPath string) {
	cfg, path, err := sandboxContentLoad(configPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !sandboxImportRouteSelected(cfg) {
		http.NotFound(w, r)
		return
	}
	if !hostedConfirmed(w, r) {
		return
	}
	var body struct {
		Dir string `json:"dir"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		http.Error(w, "a JSON body is required", http.StatusBadRequest)
		return
	}
	dir := strings.TrimSpace(body.Dir)
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		http.Error(w, "name the folder by its absolute path (it holds one folder per kind, as the release's image set archive unpacks)", http.StatusBadRequest)
		return
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		http.Error(w, "that path is not a folder on this machine", http.StatusBadRequest)
		return
	}
	if !sandboxImportRouteMu.TryLock() {
		http.Error(w, "an import is already running; wait for it to finish", http.StatusConflict)
		return
	}
	defer sandboxImportRouteMu.Unlock()
	env := sandboxContentEnvFor(cfg, path)
	got, err := sandboxImportRouteRun(env.store, env.trust.VendorKeys, dir)
	if err != nil {
		// Nothing was installed (the import is all or nothing); the reason
		// names the kind and the check that refused it.
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	out := make([]sandboxImportInstalled, 0, len(got))
	for _, s := range got {
		out = append(out, sandboxImportInstalled{Kind: string(s.kind), Version: s.version, Status: sandboxContentStatusLine(env.store, env.trust, s.kind)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"installed": out})
}
