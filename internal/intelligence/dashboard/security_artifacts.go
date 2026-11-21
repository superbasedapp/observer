//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_artifacts.go serves /api/security/artifacts, the Scanners
// card's artifact folders row (OS and CI vulnerability scanning plan
// section 14.6, M3L-2 item 4, operator ruling 2026-11-05): a project's
// candidate build output folders, discovered by folder name and file header
// only, and the developer's per-folder choice of which the dependency scan
// reads. Full artifact scanning is opt-in: every folder is off until the
// developer turns it on here. GET ?project=<root hash> lists the folders
// through the scanner seam (Options.ScannerDB, Artifacts) and mints the
// confirm token; PUT (or POST) ?project=<root hash> with {"dir": "...",
// "enabled": true|false} turns one on or off (ScannerDB.SetArtifact) with
// that token. Owner-local (a posture is never a remote viewer's action);
// 404 unless a dependency driver is selected, or in a build without one.
// Guard rule R-165 denies an agent writing to it.

type securityArtifactsResponse struct {
	dashapi.ArtifactFolders
	ConfirmToken string `json:"confirm_token,omitempty"`
}

// maxArtifactChangeBody caps a change request.
const maxArtifactChangeBody = 2048

func (s *Server) handleSecurityArtifacts(w http.ResponseWriter, r *http.Request) {
	sdb := s.opts.ScannerDB
	if sdb == nil || sdb.Artifacts == nil || sdb.SetArtifact == nil {
		writeCompiledOut(w, "security.deps")
		return
	}
	if !s.securityScannersActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "no dependency driver is selected: add security.scan.scalibr or security.scan.osv (and security.deps) under [components]",
		})
		return
	}
	root, ok := s.securityArtifactsRoot(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, err := sdb.Artifacts(r.Context(), root)
		if err != nil {
			http.Error(w, "artifact folders unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityArtifactsResponse{ArtifactFolders: v, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPut, http.MethodPost:
		if !requireJSONConfirm(w, r) {
			return
		}
		change, ok := decodeArtifactChange(r)
		if !ok {
			http.Error(w, "the body is not an artifact folder change", http.StatusBadRequest)
			return
		}
		if err := sdb.SetArtifact(r.Context(), root, change); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		v, err := sdb.Artifacts(r.Context(), root)
		if err != nil {
			http.Error(w, "artifact folders unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityArtifactsResponse{ArtifactFolders: v})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// securityArtifactsRoot resolves ?project=<root hash> to the project's root
// folder on this machine, answering 400/404 itself when it cannot.
func (s *Server) securityArtifactsRoot(w http.ResponseWriter, r *http.Request) (string, bool) {
	hash := r.URL.Query().Get("project")
	if hash == "" {
		http.Error(w, "name the project (?project=<root hash>)", http.StatusBadRequest)
		return "", false
	}
	index, err := securityProjectIndex(r.Context(), store.New(s.db()))
	if err != nil {
		http.Error(w, "projects unavailable", http.StatusInternalServerError)
		return "", false
	}
	ref, ok := index[hash]
	if !ok {
		http.Error(w, "unknown project", http.StatusNotFound)
		return "", false
	}
	if fi, err := os.Stat(ref.Root); err != nil || !fi.IsDir() {
		http.Error(w, "the project is not a folder on this machine", http.StatusNotFound)
		return "", false
	}
	return ref.Root, true
}

// decodeArtifactChange reads one change (capped, unknown fields refused, one
// JSON object only), so a mistyped field never turns a folder on.
func decodeArtifactChange(r *http.Request) (dashapi.ArtifactChange, bool) {
	var c dashapi.ArtifactChange
	if r.Body == nil {
		return c, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxArtifactChangeBody+1))
	if err != nil || len(b) > maxArtifactChangeBody || len(bytes.TrimSpace(b)) == 0 {
		return c, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || c.Dir == "" {
		return c, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, false
	}
	return c, true
}
