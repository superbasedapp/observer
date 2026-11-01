//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"encoding/json"
	"net/http"
)

// security_scanners_db.go serves /api/security/scanners/db, the Scanners
// card's one-time accept of the OSV database download (operator ruling
// PT-19 (2): ask once, then automatic). GET reads the state through the
// injected seam (Options.ScannerDB) and mints the confirm token; POST
// records the developer's accept given in the card's confirm dialog,
// which shows the size and the source. The route is owner-local (consent
// is never a remote viewer's action), answers 404 unless a dependency
// driver is selected (the same rule as GET /api/security/scanners), and
// guard rule R-165 denies an agent posting to it.

type securityScannerDBResponse struct {
	Status       any    `json:"status"`
	ConfirmToken string `json:"confirm_token,omitempty"`
}

func (s *Server) handleSecurityScannersDB(w http.ResponseWriter, r *http.Request) {
	sdb := s.opts.ScannerDB
	if sdb == nil || sdb.Status == nil {
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
	switch r.Method {
	case http.MethodGet:
		st, err := sdb.Status(r.Context())
		if err != nil {
			http.Error(w, "scanner database state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityScannerDBResponse{Status: st, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		if sdb.Accept == nil {
			writeCompiledOut(w, "security.deps")
			return
		}
		if err := sdb.Accept(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, err := sdb.Status(r.Context())
		if err != nil {
			http.Error(w, "scanner database state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityScannerDBResponse{Status: st})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
