package dashboard

import (
	"net/http"
)

// Demo mode (usability arc P6.7 / review §8.2): seed a TEMPORARY
// database from embedded synthetic fixtures so an evaluator sees the
// full dashboard in seconds without wiring a tool. The real
// observer.db is never read or written on any demo path — the
// injected Options.DemoSeeder builds a separate temp-file database
// and every data endpoint reads through Server.db(), which swaps to
// the demo handle while active. No network is involved anywhere: the
// fixtures ship inside the binary.

// handleDemo serves GET /api/demo → {"available", "active"}. The web
// app's demo banner and the onboarding card's offer both key off this.
func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{
		"available": s.opts.DemoSeeder != nil,
		"active":    s.demoDB.Load() != nil,
	})
}

// handleDemoStart serves POST /api/demo/start. Idempotent: starting
// while already active reports the active state without reseeding.
func (s *Server) handleDemoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.DemoSeeder == nil {
		http.Error(w, "demo mode is not available on this server", http.StatusServiceUnavailable)
		return
	}
	s.demoMu.Lock()
	defer s.demoMu.Unlock()
	if s.demoDB.Load() != nil {
		writeJSON(w, map[string]any{"available": true, "active": true})
		return
	}
	demoDB, cleanup, err := s.opts.DemoSeeder(r.Context())
	if err != nil {
		s.opts.Logger.Error("demo seed failed", "err", err)
		http.Error(w, "demo seed failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.demoCleanup = cleanup
	s.demoDB.Store(demoDB)
	// Drop any memoized /api/status snapshot: the database every data
	// surface reads has just changed identity AND contents. The cache keys on
	// the *sql.DB pointer, which catches the common case, but pointer keying
	// alone cannot survive a start/stop round trip with no status request in
	// between — the real DB's pre-demo entry would still be live and would be
	// served as if nothing had happened. Invalidating at the swap makes the
	// guarantee explicit rather than incidental.
	s.statusSnap.invalidate()
	s.analytics.invalidate()
	s.opts.Logger.Info("demo mode started — data surfaces now serve the seeded sample database")
	writeJSON(w, map[string]any{"available": true, "active": true})
}

// handleDemoStop serves POST /api/demo/stop — the banner's one-click
// clear. Swaps reads back to the real database, then closes and
// deletes the temp one. Idempotent when already inactive.
func (s *Server) handleDemoStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.demoMu.Lock()
	defer s.demoMu.Unlock()
	if s.demoDB.Load() == nil {
		writeJSON(w, map[string]any{"available": s.opts.DemoSeeder != nil, "active": false})
		return
	}
	// Swap first so new requests hit the real DB, then tear down. An
	// in-flight query racing the close gets one transient error — the
	// page reloads after a clear, so nothing user-visible persists.
	s.demoDB.Store(nil)
	// Same reason as the start path: the operator clearing the banner expects
	// the REAL numbers back immediately, not whatever this cache last read
	// from the real database before demo mode began.
	s.statusSnap.invalidate()
	s.analytics.invalidate()
	if s.demoCleanup != nil {
		if err := s.demoCleanup(); err != nil {
			s.opts.Logger.Warn("demo cleanup", "err", err)
		}
		s.demoCleanup = nil
	}
	s.opts.Logger.Info("demo mode cleared — data surfaces back on the real database")
	writeJSON(w, map[string]any{"available": s.opts.DemoSeeder != nil, "active": false})
}
