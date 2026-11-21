//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"encoding/json"
	"net/http"
)

// security_scanners_trivydb.go serves /api/security/scanners/trivydb, the
// Scanners card's one-time accept of Trivy's vulnerability database (OS and
// CI vulnerability scanning plan section 6.7, lane OS-2 T): GET reads the
// image driver's state through the scanner seam (Options.ScannerDB, its
// Status().Image) and mints the confirm token; POST records the
// developer's accept given in the card's confirm dialog (ScannerDB.
// AcceptTrivyDB), which shows the hosts and the sizes. Owner-local
// (consent is never a remote viewer's action); 404 unless security.deps,
// security.scan.trivy and security.scan.image.trivy are all selected, or
// in a build without the Trivy image driver. Guard rule R-165 denies an
// agent posting to it.

type securityScannerTrivyDBResponse struct {
	Status       any    `json:"status"`
	ConfirmToken string `json:"confirm_token,omitempty"`
}

// trivyImageActive reports the Trivy image driver selected with what it
// needs, through Options.SecuritySelected (fails closed).
func (s *Server) trivyImageActive(r *http.Request) bool {
	snap, ok := s.comps.live(r.Context())
	sel := s.opts.SecuritySelected
	if !ok || sel == nil {
		return false
	}
	for _, id := range []string{"security.deps", "security.scan.trivy", "security.scan.image.trivy"} {
		if !sel(snap, id) {
			return false
		}
	}
	return true
}

func (s *Server) handleSecurityScannersTrivyDB(w http.ResponseWriter, r *http.Request) {
	sdb := s.opts.ScannerDB
	if sdb == nil || sdb.Status == nil || sdb.AcceptTrivyDB == nil {
		writeCompiledOut(w, "security.scan.image.trivy")
		return
	}
	if !s.trivyImageActive(r) {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{
			"error":  "not_selected",
			"detail": "the Trivy image driver is not selected: add security.scan.image.trivy (with security.scan.trivy and security.deps) under [components]",
		})
		return
	}
	status := func() (any, bool) {
		st, err := sdb.Status(r.Context())
		if err != nil || st.Image == nil {
			http.Error(w, "image driver state unavailable", http.StatusInternalServerError)
			return nil, false
		}
		return st.Image, true
	}
	switch r.Method {
	case http.MethodGet:
		st, ok := status()
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityScannerTrivyDBResponse{Status: st, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		if err := sdb.AcceptTrivyDB(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, ok := status()
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityScannerTrivyDBResponse{Status: st})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
