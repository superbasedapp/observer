package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// db_identity_guard.go is the daemon's half of "does this daemon serve my
// database" (decisions log L-125; the rule is dashapi.DaemonHandoff). A CLI
// that hands work to the running daemon names its database's identity in
// dashapi.DBIdentityRequestHeader. This guard answers that request with the
// daemon's own identity in dashapi.DBIdentityHeader and refuses it with 409
// when the two differ, so a CLI acting on another database never has its
// work done here. A request without the header (a browser, an older CLI) is
// served exactly as before and gets no identity header.

// dbIdentityGuard wraps next with the identity check; with no database path
// (a test server) it returns next unchanged.
func (s *Server) dbIdentityGuard(next http.Handler) http.Handler {
	own := dashapi.DBIdentity(s.opts.DBPath)
	if own == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := strings.TrimSpace(r.Header.Get(dashapi.DBIdentityRequestHeader))
		if want == "" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set(dashapi.DBIdentityHeader, own)
		if want != own {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "this daemon serves another database",
				"code":  dashapi.DBMismatchCode,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
