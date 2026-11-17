package dashboard

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

// connect.go serves the front door's one-sentence status (plan 06 section
// 19.3 rule 1, plan 07 M8.4): GET /api/connect/status, read by the top
// bar's account control, the Overview Get started panel and Settings >
// Account. The sentence is built by internal/frontdoor through the
// cmd-wired Options.ConnectStatus seam, from this machine's enrolment and
// company lock, with the sign-in state the Cloud account seam already probes
// (cached; a local credential read, never a network call).

// handleConnectStatus answers the status, or 501 when not wired.
func (s *Server) handleConnectStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.ConnectStatus == nil {
		http.Error(w, "the connect status is not wired on this dashboard (run `observer start`, or `observer connect --status` in a terminal)", http.StatusNotImplemented)
		return
	}
	writeJSON(w, s.opts.ConnectStatus(r.Context(), s.connectIdentity()))
}

// connectIdentity maps the Cloud account seam's sign-in view onto the front
// door's identity states: no seam, or an unreadable probe, is unknown.
func (s *Server) connectIdentity() frontdoor.Identity {
	v := s.opts.CloudAccount.SignInView()
	switch {
	case v == nil || !v.Known:
		return frontdoor.IdentityUnknown
	case v.SignedIn:
		return frontdoor.IdentitySignedIn
	}
	return frontdoor.IdentitySignedOut
}
