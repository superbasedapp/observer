package secquickscan

import (
	"context"
	"sync"
)

// routenote.go carries which git read a scan's change (R3-86) from the
// injected GitFunc back to the Result without changing GitFunc's shape: the
// engine puts a note in the scan's context, the daemon's GitFunc writes the
// route it ran into it (NoteGitRoute), and Scan copies it to
// Result.GitRoute, from where an unknown answer's detail tells the commit
// gate's message which git timed out or failed.

// GitRouteFallback is the route a GitFunc notes when it ran the WSL git
// because the Windows git failed (internal/gitroute's
// RouteDrvFsAfterWindows, policy.QuickScanGitDrvFsFallback): once noted it
// is what the result reports, whatever later reads ran with.
const GitRouteFallback = "wsl_git_drvfs_fallback"

type gitRouteKey struct{}

// gitRouteNote is one scan's note. The first route noted is the change's
// own read (the diff); a fallback noted at any read replaces it.
type gitRouteNote struct {
	mu    sync.Mutex
	set   bool
	route string
}

// withGitRouteNote returns ctx carrying a fresh note.
func withGitRouteNote(ctx context.Context) (context.Context, *gitRouteNote) {
	n := &gitRouteNote{}
	return context.WithValue(ctx, gitRouteKey{}, n), n
}

// NoteGitRoute records, in the scan whose context ctx is, which git one
// read ran with ("" for the host's own git). Outside a scan it does
// nothing.
func NoteGitRoute(ctx context.Context, route string) {
	n, ok := ctx.Value(gitRouteKey{}).(*gitRouteNote)
	if !ok || n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case !n.set:
		n.set, n.route = true, route
	case route == GitRouteFallback:
		n.route = route
	}
}

func (n *gitRouteNote) get() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.route
}
