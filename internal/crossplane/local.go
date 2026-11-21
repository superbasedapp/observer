package crossplane

import (
	"context"
	"time"
)

// The machine's half of the link (the node dashboard's Your apps pages): a
// local service's traces report a project root (sbo.project_root), and the
// machine's own projects table names the checkout and its git remote. The
// obs route (internal/obs/httpapi) reads the traces; the machine's store is
// reached only through a LocalLinker the daemon injects, so the obs tree
// never imports the Plane B store.

// LocalProject is one of the machine's coding projects a service links to.
type LocalProject struct {
	// Root is the checkout path (node-local data, never leaves the machine).
	Root string `json:"root"`
	// Name is the project's display name: the repository name of its git
	// remote, else the folder name.
	Name string `json:"name"`
	// Rule is RuleProjectRoot (the service reported this checkout) or
	// RuleRepository (another checkout of the same git remote).
	Rule string `json:"rule"`
}

// LocalSession is one of the machine's coding sessions on a linked project.
type LocalSession struct {
	SessionID   string  `json:"session_id"`
	Tool        string  `json:"tool"`
	ProjectRoot string  `json:"project_root"`
	StartedAt   string  `json:"started_at"`
	EndedAt     string  `json:"ended_at,omitempty"`
	CostUSD     float64 `json:"cost_usd"`
	Tokens      int64   `json:"tokens"`
}

// LocalBuild is the coding activity behind a set of project roots in a
// window: the linked projects, their sessions (newest first) and the priced
// build spend per UTC day.
type LocalBuild struct {
	Projects []LocalProject
	Sessions []LocalSession
	ByDay    []DayCost
	CostUSD  float64
	Tokens   int64
}

// LocalLinker resolves project roots a service reported to the machine's
// coding projects and their activity in [since, until).
type LocalLinker func(ctx context.Context, roots []string, since, until time.Time) (LocalBuild, error)
