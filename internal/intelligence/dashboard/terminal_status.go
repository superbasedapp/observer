package dashboard

import (
	"context"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// terminal_status.go is the F4 agent-status surface. Status is DERIVED (fused
// from PTY recency + OSC hints + OOB/hook lifecycle by the terminal application
// service) and READ here — both the point-in-time GET and the event-driven WS
// stream are VIEW tier (read-only, plan §9). The dashboard defines the seam
// (TerminalStatusProvider) rather than importing the service, the same
// injected-seam discipline as LaunchManager.

// TerminalStatusResult is one run's fused status (metadata only; honest
// "unknown" + evidence + age so a hint is never presented as a fact).
type TerminalStatusResult struct {
	Handle     string  `json:"handle"`
	RunID      string  `json:"run_id,omitempty"`
	Status     string  `json:"status"`
	Evidence   string  `json:"evidence"`
	Confidence string  `json:"confidence"`
	AgeSeconds float64 `json:"age_seconds"`
	// PolicyStop is additively populated when this handle's PTY child was
	// stopped by an org-managed node's own node-intervention loop (see
	// policystop.go). Omitted when the seam is disabled or no matching audit
	// row exists — never fabricated.
	PolicyStop *PolicyStop `json:"policy_stop,omitempty"`
}

// TerminalStatusSubscription is one consumer of the live status stream. The
// caller MUST Close it when done.
type TerminalStatusSubscription interface {
	// Updates delivers status changes; closed when the subscription ends.
	Updates() <-chan TerminalStatusResult
	// Close releases the subscription.
	Close()
}

// TerminalStatusProvider is the dashboard's seam onto the terminal application
// service's status fusion (F4). The nil provider is the disabled state (the
// endpoints 503 / the WS closes immediately).
type TerminalStatusProvider interface {
	// StatusForHandle returns the current fused status for a live PTY handle.
	StatusForHandle(handle string) (TerminalStatusResult, bool)
	// Subscribe opens a live status stream across all live runs.
	Subscribe() TerminalStatusSubscription
}

// hideSetupStatusFromRemote reports whether a terminal STATUS query for handle
// must be hidden from the request principal: a REMOTE-exposed caller (listener
// provenance §4.4, resolved at the boundary) may not learn a privileged
// SpecSetup PTY's handle or its activity timing — mirroring visibleSnapshot's
// snapshot redaction and handleLaunchAdmin's 404 on a remote setup termination.
// The owner-trusted loopback listener is never remote-exposed, so the local
// owner still sees every status (their in-dashboard xterm needs it). Branches on
// session KIND (IsSetupSession), never tool/route name; a nil LaunchManager
// means no setup session can exist, so nothing is hidden.
func (s *Server) hideSetupStatusFromRemote(ctx context.Context, handle string) bool {
	if !remoteExposedFromContext(ctx) {
		return false
	}
	return s.opts.LaunchManager != nil && s.opts.LaunchManager.IsSetupSession(handle)
}

// handleTerminalStatus serves GET /api/terminal/<handle>/status (view tier). It
// is reached via the /api/terminal/ prefix route (the exact /launch + /sessions
// patterns take precedence in the mux).
func (s *Server) handleTerminalStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/terminal/")
	handle, tail, ok := strings.Cut(rest, "/")
	if !ok || tail != "status" || handle == "" {
		http.NotFound(w, r)
		return
	}
	if s.opts.TerminalStatus == nil {
		http.Error(w, "terminal status unavailable", http.StatusServiceUnavailable)
		return
	}
	// A remote-exposed caller may never learn a privileged setup PTY's handle or
	// activity: 404 exactly as handleLaunchAdmin does on a remote setup
	// termination, so the handle's existence stays unconfirmable. Checked before
	// StatusForHandle so no metadata is computed for a hidden handle.
	if s.hideSetupStatusFromRemote(r.Context(), handle) {
		http.NotFound(w, r)
		return
	}
	res, found := s.opts.TerminalStatus.StatusForHandle(handle)
	if !found {
		http.NotFound(w, r)
		return
	}
	if stop, ok := s.resolvePolicyStop(r.Context(), handle); ok {
		res.PolicyStop = &stop
	}
	writeJSON(w, res)
}

// handleTerminalStatusWS serves GET /ws/terminal/status (view tier): ONE
// multiplexed status stream for every live run (respecting the HTTP/1.1
// 6-connection limit — one stream, not N sockets). It emits a
// TerminalStatusResult JSON text frame on every status change until the client
// disconnects. Same-origin enforced by coder/websocket.Accept (CSWSH defense).
func (s *Server) handleTerminalStatusWS(w http.ResponseWriter, r *http.Request) {
	if s.opts.TerminalStatus == nil {
		http.NotFound(w, r)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()

	sub := s.opts.TerminalStatus.Subscribe()
	defer sub.Close()

	ctx := r.Context()
	// A reader goroutine surfaces client disconnect (we ignore inbound frames).
	go func() {
		for {
			if _, _, rerr := c.Read(ctx); rerr != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case upd, ok := <-sub.Updates():
			if !ok {
				return
			}
			// Omit privileged SETUP PTYs entirely from a remote-exposed caller's
			// status stream (§4.4) — including the initial per-handle seed the hub
			// pushes on Subscribe — so a paired remote device never learns a setup
			// handle or its activity timing. Same seam class as visibleSnapshot's
			// redaction; the local owner's loopback stream is unaffected.
			if s.hideSetupStatusFromRemote(ctx, upd.Handle) {
				continue
			}
			if werr := wsjson.Write(ctx, c, upd); werr != nil {
				return
			}
		}
	}
}
