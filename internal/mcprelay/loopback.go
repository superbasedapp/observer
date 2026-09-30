package mcprelay

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
)

// maxLoopbackBody caps a loopback POST body.
const maxLoopbackBody = 1 << 20

// ServeLoopbackHTTP returns the streamable-HTTP relay handler a client's
// `superbased-relay` remote entry points at: POST /mcp/{slug} with one
// JSON-RPC message. Loopback HTTP cannot attest its caller, so every call
// is the node-wide `configured` principal (§12.2). The legacy GET SSE
// stream and DELETE session are not relayed this wave (405, honest).
//
// The composition root binds it to the loopback address only.
func (r *Relay) ServeLoopbackHTTP() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/{slug}", r.serveLoopback)
	return mux
}

func (r *Relay) serveLoopback(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	slug := req.PathValue("slug")
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxLoopbackBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, ErrorFrame(nil, CodeInvalidRequest, fmt.Sprintf("request body exceeds %d bytes", maxLoopbackBody)))
			return
		}
		writeJSON(w, http.StatusBadRequest, ErrorFrame(nil, CodeInvalidRequest, "failed to read body"))
		return
	}
	c := Call{
		Target: Target{VServer: slug}, Raw: body, Transport: localpdp.TransportLoopbackHTTP,
		ProtocolVersion: req.Header.Get("Mcp-Protocol-Version"), SessionID: req.Header.Get("Mcp-Session-Id"),
	}
	c.Corr = corrFromHeaders(req.Header)
	// No project context on loopback (P11 fold PF2, IE Q-IE-2 ruling): the
	// loopback caller is the node-wide principal (R2) and HeaderProjectDir is
	// NOT attested - it is ignored, so no loopback call carries
	// sbo_project_hash and project-scoped grants fail closed for it.
	v := r.Decide(req.Context(), c)
	if !v.Forward {
		if len(v.Refuse) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		writeJSON(w, http.StatusOK, v.Refuse)
		return
	}
	rp, err := r.ForwardHTTP(req.Context(), c, v)
	if err != nil {
		r.Complete(req.Context(), v, "unavailable", nil, err.Error())
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, ErrorFrame(v.Msg.ID, CodeUnavailable, "relay: "+err.Error()))
		return
	}
	r.Complete(req.Context(), v, rp.Outcome(), rp.Body, "")
	if rp.SessionID != "" {
		w.Header().Set("Mcp-Session-Id", rp.SessionID)
	}
	if rp.ContentType != "" {
		w.Header().Set("Content-Type", rp.ContentType)
	}
	if rp.RetryAfter != "" && rp.Status >= 500 {
		w.Header().Set("Retry-After", rp.RetryAfter)
	}
	w.WriteHeader(rp.Status)
	_, _ = w.Write(rp.Body)
}

// Correlation headers a coding-agent hook / the daemon may stamp on a
// loopback call (R11.8 anchors). They are the caller's claim; the relay
// carries them, the org records them at corr_confidence exact.
const (
	HeaderCodingSession = "X-Sbo-Coding-Session"
	HeaderTurnRef       = "X-Sbo-Turn-Ref"
	HeaderActionRef     = "X-Sbo-Action-Ref"
)

func corrFromHeaders(h http.Header) Correlation {
	return Correlation{CodingSessionID: h.Get(HeaderCodingSession), TurnRef: h.Get(HeaderTurnRef), ActionRef: h.Get(HeaderActionRef)}
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
