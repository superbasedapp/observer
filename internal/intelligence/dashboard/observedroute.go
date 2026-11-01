package dashboard

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// observedroute.go is the dashboard's read of per-surface proxy traffic
// (surface-gap arc Wave 1, finding OBS-1). The capture pill and the
// Compression banner used to say "Active ... routes through this machine's
// proxy" from the Claude install status alone. They now read what the node
// actually saw: the sessions of each capture surface in the
// routeattest.ObservedWindow, and how many of them reached the proxy,
// judged by routeattest.AttestSurfaces against the registry. The same
// store query and judge feed the doctor's route.observed check.

// observedRouteView is the observed_route block of GET /api/setup/claude.
type observedRouteView struct {
	// WindowDays is the span the counts cover.
	WindowDays int `json:"window_days"`
	// Surfaces is one entry per capture surface group of the tool, ordered
	// by kind then host. Empty when the node has no session of the tool.
	Surfaces []observedSurfaceView `json:"surfaces"`
}

// observedSurfaceView is one capture surface's verdict.
type observedSurfaceView struct {
	Kind            string `json:"kind"`
	Host            string `json:"host,omitempty"`
	State           string `json:"state"`
	Sessions        int    `json:"sessions"`
	ProxiedSessions int    `json:"proxied_sessions"`
	// Routable: the surface's effective routability is routable_now.
	Routable bool `json:"routable"`
	// Bypass is SurfaceVerdict.ObservedBypass: a routable surface ran
	// sessions that never reached the proxy.
	Bypass bool   `json:"bypass"`
	Reason string `json:"reason"`
}

// observedRoute judges the tool's capture surfaces over the observed
// window. It returns nil when the database is unavailable or the query
// fails, so the snapshot stays readable and the pill falls back to the
// config verdict alone.
func (s *Server) observedRoute(ctx context.Context, tool string, now time.Time) *observedRouteView {
	database := s.db()
	if database == nil {
		return nil
	}
	rows, err := store.New(database).RouteObservedSince(ctx, now.Add(-routeattest.ObservedWindow))
	if err != nil {
		return nil
	}
	var traffic []routeattest.SurfaceTraffic
	for _, r := range rows {
		if r.Tool != tool {
			continue
		}
		traffic = append(traffic, routeattest.SurfaceTraffic{
			Tool: r.Tool, Kind: r.Surface, Host: r.SurfaceHost,
			Sessions: r.Sessions, ProxiedSessions: r.ProxiedSessions,
		})
	}
	out := &observedRouteView{
		WindowDays: int(routeattest.ObservedWindow / (24 * time.Hour)),
		Surfaces:   []observedSurfaceView{},
	}
	for _, v := range routeattest.AttestSurfaces(routeattest.WithDeclaredSurfaces(traffic), nil) {
		out.Surfaces = append(out.Surfaces, observedSurfaceView{
			Kind: v.Kind, Host: v.Host, State: string(v.State),
			Sessions: v.Sessions, ProxiedSessions: v.ProxiedSessions,
			Routable: v.Facts.Routable, Bypass: v.ObservedBypass(), Reason: v.Reason,
		})
	}
	return out
}
