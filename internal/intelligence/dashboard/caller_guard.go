package dashboard

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// caller_guard.go is the dashboard's one caller check (security ledger
// LAUNCH-1, lane callerid). It wraps the whole handler, so EVERY route on
// the loopback and the remotely exposed handler passes through it (pinned
// by TestCallerGuardCoversEveryRoute, which walks the registered routes),
// and it judges every request that can change anything: an unsafe method
// (POST, PUT, PATCH, DELETE), a WebSocket upgrade, or any request under
// /ws/ (the terminal bridge, whose writer lease types into a PTY). Reads
// pass. The decision, which
// identifies the process behind a local connection and refuses one inside
// a live Observer box, is the daemon's (Options.LoopbackCallerGate); this
// file only finds the connection's two ends and writes the refusal.

// callerRefusedCode is the JSON error code of a refusal.
const callerRefusedCode = "sandbox_caller"

// callerGuard wraps next with the caller check; with no gate it returns
// next unchanged.
func (s *Server) callerGuard(next http.Handler) http.Handler {
	gate := s.opts.LoopbackCallerGate
	if gate == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callerMutates(r) {
			client, server := requestEnds(r)
			if reason, refuse := gate(r.Context(), client, server, true); refuse {
				if s.callerRefusals.first(r.URL.Path) {
					s.opts.Logger.Warn("dashboard: refused a request from a sandboxed caller (logged once per path)",
						"method", r.Method, "path", r.URL.Path, "reason", reason)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": reason, "code": callerRefusedCode})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// callerRefusalLogPaths bounds the paths the refusal log remembers.
const callerRefusalLogPaths = 64

// callerRefusalLog remembers which paths a refusal was logged for, so a
// box that retries (a boxed Claude Code's statusline posting its plan
// readings, say) logs once per path, not once per request.
type callerRefusalLog struct {
	mu   sync.Mutex
	seen map[string]bool
}

// first reports whether path's refusal is the first one to log.
func (l *callerRefusalLog) first(path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen[path] || len(l.seen) >= callerRefusalLogPaths {
		return false
	}
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	l.seen[path] = true
	return true
}

// callerMutates reports whether the caller check judges r: an unsafe
// method, a WebSocket upgrade, or any request under /ws/ (every WebSocket
// route, judged by path too, so a handshake the upgrade test misses is
// still judged; callerid fixes-1, H1).
func callerMutates(r *http.Request) bool {
	return isUnsafeMethod(r.Method) || isWebSocketUpgrade(r) || strings.HasPrefix(r.URL.Path, "/ws/")
}

// requestEnds are the connection's client end (RemoteAddr) and the
// listener's end (http.LocalAddrContextKey). An end that cannot be parsed
// is the zero AddrPort; the gate treats an unknown client as local.
func requestEnds(r *http.Request) (client, server netip.AddrPort) {
	client, _ = netip.ParseAddrPort(r.RemoteAddr)
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if tcp, ok := a.(*net.TCPAddr); ok {
			server = tcp.AddrPort()
		} else {
			server, _ = netip.ParseAddrPort(a.String())
		}
	}
	return unmapped(client), unmapped(server)
}

// unmapped writes an IPv4-mapped IPv6 end as plain IPv4.
func unmapped(ap netip.AddrPort) netip.AddrPort {
	if !ap.IsValid() {
		return ap
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
