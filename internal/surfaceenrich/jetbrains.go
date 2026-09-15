package surfaceenrich

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// jetbrainsSource lists the JetBrains AI Assistant task-history pointer
// files under one home: every
// <vendor>/<Product><ver>/aia-task-history/<task>.agentsession, decoded
// through jetbrainshost. A task whose agent never started a session has
// no .agentsession at all (only .events/.lastid), so the listing IS the
// set of hosted sessions. Files the helper cannot decode, or whose agent
// is outside the grounded table, are still returned (with an empty Tool
// / SessionID) so the enricher can ledger them once and stop looking,
// rather than re-reading them every tick.
func jetbrainsSource(h crossmount.HomeRoot, fs FS) []Candidate {
	var out []Candidate
	for _, dir := range jetbrainshost.TaskHistoryDirs(h, fs.ReadDir) {
		names, err := fs.ReadDir(dir.Path)
		if err != nil {
			continue // product installed, AI Assistant never used
		}
		for _, name := range names {
			if !strings.HasSuffix(strings.ToLower(name), jetbrainshost.AgentSessionExt) {
				continue
			}
			path := filepath.Join(dir.Path, name)
			c := Candidate{Path: path}
			if mt, err := fs.ModTime(path); err == nil {
				c.ModTime = mt
			}
			body, err := fs.ReadFile(path)
			if err != nil {
				continue // transient (being written); next tick
			}
			as, ok := jetbrainshost.ParseAgentSession(string(body))
			switch {
			case !ok:
				c.Unresolvable = "malformed .agentsession (expected acp.registry.<agent>:<session id>)"
			case as.Tool == "":
				c.Unresolvable = "ACP agent " + as.Agent + " has no owning-tool row in jetbrainshost"
			default:
				c.Tool = as.Tool
				c.Surface = jetbrainshost.Surface(as.SessionID, dir.Product)
			}
			out = append(out, c)
		}
	}
	return out
}
