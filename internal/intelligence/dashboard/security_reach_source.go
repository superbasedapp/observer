//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_reach_source.go serves the Scanners card's Go source check row
// (OS and CI vulnerability scanning plan section 14.5 item 3b, 3b-src):
//
//   - GET /api/security/reach/go-source?project=<root hash> reads the
//     project's opt-in, the isolation, the caps and the stored answers, and
//     mints the confirm token;
//   - PUT (or POST) on it with {"enabled": bool, "allow_unisolated": bool}
//     records or withdraws the opt-in (the developer's signed record);
//   - POST /api/security/reach/go-source/run?project=<root hash> starts one
//     run in the background (one at a time); the GET then reads running.
//
// Owner-local (the check runs this machine's Go toolchain on the project; a
// remote viewer never starts it); every write needs the confirm token.
// Guard rule R-165 denies an agent writing to either path. 404 unless a
// dependency driver is selected, or in a build without the seam.

type securityReachSourceResponse struct {
	dashapi.ReachSourceStatus
	ConfirmToken string `json:"confirm_token,omitempty"`
}

const maxReachSourceChangeBody = 256

func (s *Server) reachSourceSeam(w http.ResponseWriter, r *http.Request) (*dashapi.ScannerDB, string, bool) {
	sdb := s.opts.ScannerDB
	if sdb == nil || sdb.ReachSource == nil || sdb.SetReachSource == nil || sdb.RunReachSource == nil {
		writeCompiledOut(w, "security.reach.go")
		return nil, "", false
	}
	if !s.securityScannersActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "no dependency driver is selected: add security.scan.scalibr or security.scan.osv (and security.deps) under [components]",
		})
		return nil, "", false
	}
	root, ok := s.securityArtifactsRoot(w, r)
	return sdb, root, ok
}

func (s *Server) handleSecurityReachSource(w http.ResponseWriter, r *http.Request) {
	sdb, root, ok := s.reachSourceSeam(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		v, err := sdb.ReachSource(r.Context(), root)
		if err != nil {
			http.Error(w, "the Go source check is unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityReachSourceResponse{ReachSourceStatus: v, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPut, http.MethodPost:
		if !requireJSONConfirm(w, r) {
			return
		}
		change, ok := decodeReachSourceChange(r)
		if !ok {
			http.Error(w, "the body is not a Go source check opt-in change", http.StatusBadRequest)
			return
		}
		if err := sdb.SetReachSource(r.Context(), root, change); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		v, err := sdb.ReachSource(r.Context(), root)
		if err != nil {
			http.Error(w, "the Go source check is unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityReachSourceResponse{ReachSourceStatus: v})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSecurityReachSourceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sdb, root, ok := s.reachSourceSeam(w, r)
	if !ok {
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if err := sdb.RunReachSource(r.Context(), root); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	v, err := sdb.ReachSource(r.Context(), root)
	if err != nil {
		http.Error(w, "the Go source check is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(securityReachSourceResponse{ReachSourceStatus: v})
}

// decodeReachSourceChange reads one change (capped, unknown fields refused,
// one JSON object only), so a mistyped field never opts a project in.
func decodeReachSourceChange(r *http.Request) (dashapi.ReachSourceChange, bool) {
	var c dashapi.ReachSourceChange
	if r.Body == nil {
		return c, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxReachSourceChangeBody+1))
	if err != nil || len(b) > maxReachSourceChangeBody || len(bytes.TrimSpace(b)) == 0 {
		return c, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return c, false
	}
	return c, true
}
