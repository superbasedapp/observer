//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_lookup.go serves /api/security/lookup, the Privacy page's
// "Package lookup" card and the first-run choice beside it (OS and CI
// vulnerability scanning plan section 13.10, lane RM-2): whether this node
// downloads the OSV databases or looks its dependencies up at SuperBased,
// whether private package names are sent too, and the consent records
// behind each choice. GET reads the posture through the scanner seam
// (Options.ScannerDB, Lookup) and mints the confirm token; PUT (or POST)
// changes it (ScannerDB.SetLookup) with that token, every data-sending
// choice carrying its own consent in the same request, which the card
// asks for in a dialog that shows the consent's text before the click.
// Owner-local (a posture is never a remote viewer's action); 404 unless a
// dependency driver is selected, or in a build without one. Guard rule
// R-165 denies an agent writing to it; a managed node refuses every change
// (its organization decides).

type securityLookupResponse struct {
	Status       dashapi.PackageLookupStatus `json:"status"`
	ConfirmToken string                      `json:"confirm_token,omitempty"`
}

// maxLookupBody caps a change request.
const maxLookupBody = 4096

func (s *Server) handleSecurityLookup(w http.ResponseWriter, r *http.Request) {
	sdb := s.opts.ScannerDB
	if sdb == nil || sdb.Lookup == nil || sdb.SetLookup == nil {
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
		st, err := sdb.Lookup(r.Context())
		if err != nil {
			http.Error(w, "package lookup state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityLookupResponse{Status: st, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPut, http.MethodPost:
		if !requireJSONConfirm(w, r) {
			return
		}
		change, ok := decodeLookupChange(r)
		if !ok {
			http.Error(w, "the body is not a package lookup change", http.StatusBadRequest)
			return
		}
		if err := sdb.SetLookup(r.Context(), change); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, err := sdb.Lookup(r.Context())
		if err != nil {
			http.Error(w, "package lookup state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityLookupResponse{Status: st})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// decodeLookupChange reads one change (capped, unknown fields refused, one
// JSON object only), so a mistyped field never records a consent the
// developer did not see.
func decodeLookupChange(r *http.Request) (dashapi.PackageLookupChange, bool) {
	var c dashapi.PackageLookupChange
	if r.Body == nil {
		return c, false
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxLookupBody+1))
	if err != nil || len(b) > maxLookupBody || len(bytes.TrimSpace(b)) == 0 {
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
