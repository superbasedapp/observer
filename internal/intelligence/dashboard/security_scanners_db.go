//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
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
//
// The same POST records the OS release databases' one accept (OS-2, ruling
// Q1 (b)) when its body is {"os":true}: one route, so R-165's row for it
// covers both accepts and the route tables need no new entry. Any other
// body, or none, is the language databases' accept, as before.
//
// Every status this route (and GET /api/security/scanners) returns carries
// the exploit data's state, added here from the OSV store's files
// (withScannerExploit, security_scanners_exploit.go), never by the seam.

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
		_ = json.NewEncoder(w).Encode(securityScannerDBResponse{Status: s.withScannerExploit(st), ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		isOS, ok := scannerDBAcceptsOS(r)
		if !ok {
			http.Error(w, "the body is not JSON", http.StatusBadRequest)
			return
		}
		accept := sdb.Accept
		if isOS {
			accept = sdb.AcceptOS
		}
		if accept == nil {
			writeCompiledOut(w, "security.deps")
			return
		}
		if err := accept(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, err := sdb.Status(r.Context())
		if err != nil {
			http.Error(w, "scanner database state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityScannerDBResponse{Status: s.withScannerExploit(st)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// scannerDBAcceptsOS reports whether a POST's JSON body sets "os" true (read
// capped at 4 KB). An empty body is the language accept; a body that is not
// JSON is refused (ok false) rather than guessed, so a consent is never
// recorded for the other database set.
func scannerDBAcceptsOS(r *http.Request) (isOS, ok bool) {
	if r.Body == nil {
		return false, true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(b) > 4096 {
		return false, false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return false, true
	}
	var body struct {
		OS bool `json:"os"`
	}
	if json.Unmarshal(b, &body) != nil {
		return false, false
	}
	return body.OS, true
}
