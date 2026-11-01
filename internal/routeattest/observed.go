package routeattest

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// observed.go holds what the node's two readers of per-surface traffic (the
// doctor's route.observed check and the dashboard's capture pill; surface-
// gap arc Wave 1) share, so they judge the same node the same way.

// ObservedWindow is how far back the node's per-surface traffic verdicts
// look: both readers count the sessions that started inside it. Seven days
// so a surface used a few times a week still has sessions to judge, while a
// route fixed last month no longer reads as a bypass.
const ObservedWindow = 7 * 24 * time.Hour

// WithDeclaredSurfaces returns rows plus a zero-count group for every
// surface the registry declares (Capability.RouteSurfaces) for a tool that
// already has a row, when no row covers that surface: an exact (Kind, Host)
// row is covered by that group, a kind-wide row (Host "") by any group of
// its kind. A tool with rows has run on this node, so its declared surface
// with no session reads "unobserved" instead of vanishing. A tool with no
// row gains nothing. The result is ordered by tool, kind, host; rows is not
// modified.
func WithDeclaredSurfaces(rows []SurfaceTraffic) []SurfaceTraffic {
	out := append([]SurfaceTraffic(nil), rows...)
	seenTool := map[string]bool{}
	seenGroup := map[[3]string]bool{}
	seenKind := map[[2]string]bool{}
	var tools []string
	for _, r := range rows {
		if !seenTool[r.Tool] {
			seenTool[r.Tool] = true
			tools = append(tools, r.Tool)
		}
		seenGroup[[3]string{r.Tool, r.Kind, r.Host}] = true
		seenKind[[2]string{r.Tool, r.Kind}] = true
	}
	for _, tool := range tools {
		c, ok := integration.For(tool)
		if !ok {
			continue
		}
		for _, sr := range c.RouteSurfaces {
			key := [3]string{tool, sr.Kind, sr.Host}
			if seenGroup[key] || (sr.Host == "" && seenKind[[2]string{tool, sr.Kind}]) {
				continue
			}
			// The unstamped group is already judged as this row; an extra
			// unobserved group would contradict it.
			if sr.Unstamped && seenKind[[2]string{tool, ""}] {
				continue
			}
			seenGroup[key] = true
			out = append(out, SurfaceTraffic{Tool: tool, Kind: sr.Kind, Host: sr.Host})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Host < b.Host
	})
	return out
}
