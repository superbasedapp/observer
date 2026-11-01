//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_sarifimport.go serves /api/security/import-sarif, the Code
// security page's SARIF upload (component security.scan.sarif-import, lane
// SEC-P4 decision 13). GET returns the producer picker, the file cap and
// the confirm token; POST {project, tool, sarif} records one file the
// developer picked through the injected seam (Options.SARIFImport), which
// calls the same function as `observer security import-sarif`. The route
// is owner-local, needs the confirm token its GET mints, caps the body at
// the CLI's own file cap, and answers 404 unless the component and its
// parent security.code are selected (opt-in). An import adds flag-only
// findings and closes nothing, so it cannot lower a gate: guard rule
// R-165 does not list it.

// sarifImportEnvelopeBytes is the room the upload body leaves beside the
// file for the project hash and the tool id.
const sarifImportEnvelopeBytes = 4 << 10

type securitySARIFImportResponse struct {
	Tools        []dashapi.SARIFImportTool `json:"tools"`
	MaxBytes     int                       `json:"max_bytes"`
	ConfirmToken string                    `json:"confirm_token,omitempty"`
}

// securitySARIFImportActive reports whether the upload is selected, with
// its parent security.code, through the daemon's one opt-in rule. With no
// component service or no rule wired it is not (fails closed).
func (s *Server) securitySARIFImportActive(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	sel := s.opts.SecuritySelected
	return ok && sel != nil && sel(snap, "security.code") && sel(snap, "security.scan.sarif-import")
}

func (s *Server) handleSecurityImportSARIF(w http.ResponseWriter, r *http.Request) {
	seam := s.opts.SARIFImport
	if seam == nil || seam.Import == nil {
		writeCompiledOut(w, "security.scan.sarif-import")
		return
	}
	if !s.securitySARIFImportActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "the SARIF import is not selected: add security.scan.sarif-import (and security.code) under [components]",
		})
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securitySARIFImportResponse{Tools: seam.Tools, MaxBytes: seam.MaxBytes, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req struct {
			Project string          `json:"project"`
			Tool    string          `json:"tool"`
			SARIF   json.RawMessage `json:"sarif"`
		}
		body := http.MaxBytesReader(w, r.Body, int64(seam.MaxBytes)+sarifImportEnvelopeBytes)
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "the file is over the SARIF cap", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		data := bytes.TrimSpace(req.SARIF)
		if len(data) == 0 || bytes.Equal(data, []byte("null")) {
			http.Error(w, "no SARIF file in the body", http.StatusBadRequest)
			return
		}
		if len(data) > seam.MaxBytes {
			http.Error(w, "the file is over the SARIF cap", http.StatusRequestEntityTooLarge)
			return
		}
		if !slices.ContainsFunc(seam.Tools, func(t dashapi.SARIFImportTool) bool { return t.ID == req.Tool }) {
			http.Error(w, "unknown tool", http.StatusBadRequest)
			return
		}
		root, ok := secsvc.RootsResolver(store.New(s.db()).ProjectRoots)(r.Context(), req.Project)
		if !ok {
			http.Error(w, "unknown project", http.StatusNotFound)
			return
		}
		rep, err := seam.Import(r.Context(), root, req.Tool, data)
		if err != nil {
			if errors.Is(err, dashapi.ErrSARIFImportInput) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "the import could not be recorded", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"report": rep})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
