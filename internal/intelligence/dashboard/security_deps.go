//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"encoding/json"
	"net/http"
)

// security_deps.go serves /api/security/deps, the Code security page's
// Package checks card (component security.deps; security pillar plan
// section 8.3). GET reads the install gate's state through the injected
// seam (Options.PackageChecks) and mints the confirm token; POST records
// that the developer read the online checks' disclosure here, which is the
// explicit consent that turns online checks on (a terminal start shows the
// text and records nothing). The route is owner-local: consent is never a
// remote viewer's action.

// securityDepsResponse is GET /api/security/deps.
type securityDepsResponse struct {
	Status       any    `json:"status"`
	ConfirmToken string `json:"confirm_token"`
}

// handleSecurityDeps serves GET and POST /api/security/deps.
func (s *Server) handleSecurityDeps(w http.ResponseWriter, r *http.Request) {
	pc := s.opts.PackageChecks
	if pc == nil || pc.Status == nil {
		writeCompiledOut(w, "security.deps")
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, err := pc.Status(r.Context())
		if err != nil {
			http.Error(w, "package checks state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityDepsResponse{Status: st, ConfirmToken: setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		if pc.Accept == nil {
			writeCompiledOut(w, "security.deps")
			return
		}
		if err := pc.Accept(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		st, err := pc.Status(r.Context())
		if err != nil {
			http.Error(w, "package checks state unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(securityDepsResponse{Status: st})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
