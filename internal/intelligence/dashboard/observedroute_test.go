package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// seedObserved inserts sessions with their surface stamps and api_turns
// rows straight into the server's database.
func seedObserved(t *testing.T, srv *Server, sessions [][5]any) {
	t.Helper()
	database := srv.db()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?)`, now); err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		id, tool, kind, host, turns := s[0].(string), s[1].(string), s[2].(string), s[3].(string), s[4].(int)
		if _, err := database.Exec(
			`INSERT INTO sessions (id, project_id, tool, started_at, surface, surface_host) VALUES (?, 1, ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
			id, tool, now, kind, host); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < turns; i++ {
			if _, err := database.Exec(
				`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens) VALUES (?, ?, 'anthropic', 'm', 1, 1)`,
				id, now); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestSetupClaude_ObservedRoute pins OBS-1's backend half: GET
// /api/setup/claude carries the per-surface traffic verdict, counted per
// session, for the claude-code tool only.
func TestSetupClaude_ObservedRoute(t *testing.T) {
	cc := models.ToolClaudeCode
	// Beside the observed CLI group, every route row claude-code declares
	// (desktop, ide, the Xcode ide host, sdk, and any row added later)
	// reads unobserved when no session of it ran. The expected groups are
	// the observed one plus the registry's declared rows, ordered by kind
	// then host as the handler orders them (expectedObservedKeys).
	cases := []struct {
		name     string
		sessions [][5]any
		// observed is the CLI group's whole verdict; nil when the node has
		// no session of the tool (then no surface is listed at all).
		observed *observedSurfaceView
	}{
		{name: "no session of the tool reads no surface", sessions: [][5]any{{"x1", "codex", "cli", "", 1}}},
		{
			name:     "a proxied CLI counts each session once",
			sessions: [][5]any{{"c1", cc, "cli", "", 4}, {"c2", cc, "cli", "", 1}},
			observed: &observedSurfaceView{
				Kind: "cli", State: "attested", Sessions: 2, ProxiedSessions: 2, Routable: true,
				Reason: "all 2 sessions proxied",
			},
		},
		{
			name:     "an unproxied CLI is an observed bypass",
			sessions: [][5]any{{"c1", cc, "cli", "", 2}, {"c2", cc, "cli", "", 0}},
			observed: &observedSurfaceView{
				Kind: "cli", State: "partial", Sessions: 2, ProxiedSessions: 1, Routable: true, Bypass: true,
				Reason: "1 of 2 sessions proxied",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withFakeClaudeHome(t, "")
			srv := newSetupServer(t, 8820)
			seedObserved(t, srv, tc.sessions)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/setup/claude", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("GET: %d %s", rr.Code, rr.Body.String())
			}
			var got claudeSetupSnapshot
			decodeJSON(t, rr, &got)
			if got.ObservedRoute == nil {
				t.Fatal("observed_route missing")
			}
			if got.ObservedRoute.WindowDays != 7 {
				t.Errorf("window_days = %d", got.ObservedRoute.WindowDays)
			}
			surfaces := got.ObservedRoute.Surfaces
			if tc.observed == nil {
				if len(surfaces) != 0 {
					t.Fatalf("surfaces = %+v, want none", surfaces)
				}
				return
			}
			want := expectedObservedKeys(t, cc, *tc.observed)
			if len(surfaces) != len(want) {
				t.Fatalf("surfaces = %+v\nwant the groups %v", surfaces, want)
			}
			for i, s := range surfaces {
				if key := [2]string{s.Kind, s.Host}; key != want[i] {
					t.Fatalf("surface %d is %v, want %v (groups %v)", i, key, want[i], want)
				}
				if s.Kind == tc.observed.Kind && s.Host == tc.observed.Host {
					if !reflect.DeepEqual(s, *tc.observed) {
						t.Errorf("observed group = %+v\nwant %+v", s, *tc.observed)
					}
					continue
				}
				// A declared group nothing ran on: what every such row must
				// read, whatever its routability (the registry decides that).
				if s.State != "unobserved" || s.Sessions != 0 || s.ProxiedSessions != 0 || s.Bypass || s.Reason == "" {
					t.Errorf("declared group %v = %+v, want unobserved with no sessions, no bypass and a reason", want[i], s)
				}
			}
		})
	}
}

// expectedObservedKeys is the (kind, host) list the handler must serve for
// tool when only observed's group ran: that group plus every route row the
// registry declares for tool (a host-less row of the observed kind is that
// group), sorted by kind then host as routeattest.WithDeclaredSurfaces
// orders the handler's groups. It fails when the registry declares no row
// beyond the observed group, so the test cannot go silently empty.
func expectedObservedKeys(t *testing.T, tool string, observed observedSurfaceView) [][2]string {
	t.Helper()
	c, ok := integration.For(tool)
	if !ok {
		t.Fatalf("%s: no registry row", tool)
	}
	obsKey := [2]string{observed.Kind, observed.Host}
	seen := map[[2]string]bool{obsKey: true}
	out := [][2]string{obsKey}
	for _, sr := range c.RouteSurfaces {
		key := [2]string{sr.Kind, sr.Host}
		if seen[key] || (sr.Kind == observed.Kind && sr.Host == "") {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) == 1 {
		t.Fatalf("%s: declares no route row beyond %v; the test no longer covers declared surfaces", tool, obsKey)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

func TestObservedRouteNilDB(t *testing.T) {
	srv := &Server{}
	if got := srv.observedRoute(context.Background(), models.ToolClaudeCode, time.Now()); got != nil {
		t.Fatalf("got %+v, want nil", got)
	}
}
