package routeattest

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// declaredTool returns a registry tool with exactly one kind-wide declared
// surface, so the test never hard-codes which tool carries one.
func declaredTool(t *testing.T) (string, string) {
	t.Helper()
	for _, id := range integration.Tools() {
		c, _ := integration.For(id)
		if len(c.RouteSurfaces) == 1 && c.RouteSurfaces[0].Host == "" {
			return id, c.RouteSurfaces[0].Kind
		}
	}
	t.Skip("no registry tool declares exactly one kind-wide route surface")
	return "", ""
}

func TestWithDeclaredSurfaces(t *testing.T) {
	tool, kind := declaredTool(t)
	other := "zzz-other-kind"
	cases := []struct {
		name string
		in   []SurfaceTraffic
		want []SurfaceTraffic
	}{
		{name: "no rows gain nothing", in: nil, want: nil},
		{
			name: "a tool seen on another kind gains its declared surface",
			in:   []SurfaceTraffic{{Tool: tool, Kind: other, Sessions: 2}},
			want: []SurfaceTraffic{{Tool: tool, Kind: kind}, {Tool: tool, Kind: other, Sessions: 2}},
		},
		{
			name: "any host of the kind covers a kind-wide declaration",
			in:   []SurfaceTraffic{{Tool: tool, Kind: kind, Host: "somehost", Sessions: 1}},
			want: []SurfaceTraffic{{Tool: tool, Kind: kind, Host: "somehost", Sessions: 1}},
		},
		{
			name: "an exact row is kept as is",
			in:   []SurfaceTraffic{{Tool: tool, Kind: kind, Sessions: 3, ProxiedSessions: 1}},
			want: []SurfaceTraffic{{Tool: tool, Kind: kind, Sessions: 3, ProxiedSessions: 1}},
		},
		{
			name: "a tool with no registry row gains nothing",
			in:   []SurfaceTraffic{{Tool: "no-such-tool", Kind: kind, Sessions: 1}},
			want: []SurfaceTraffic{{Tool: "no-such-tool", Kind: kind, Sessions: 1}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]SurfaceTraffic(nil), tc.in...)
			got := WithDeclaredSurfaces(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
			if !reflect.DeepEqual(before, tc.in) && len(tc.in) > 0 {
				t.Fatalf("input modified: %+v", tc.in)
			}
		})
	}
}

// TestWithDeclaredSurfacesUnstamped: a tool whose unstamped sessions are
// judged as its Unstamped row gains no extra unobserved group for that row
// while an unstamped group is present (it would contradict the judgement).
func TestWithDeclaredSurfacesUnstamped(t *testing.T) {
	for _, id := range integration.Tools() {
		c, _ := integration.For(id)
		u, ok := c.UnstampedSurface()
		if !ok {
			continue
		}
		in := []SurfaceTraffic{{Tool: id, Sessions: 2}}
		for _, r := range WithDeclaredSurfaces(in) {
			if r.Kind == u.Kind && r.Host == u.Host {
				t.Errorf("%s: gained an unobserved %s group beside its unstamped group", id, u.Kind)
			}
		}
		return
	}
	t.Skip("no registry tool declares an Unstamped row")
}
