package dashboard

import (
	"slices"
	"sync"
	"time"
)

// installSignalTTL bounds how often the install signals are re-read: the
// probe lists the VS Code extension folders and may resolve binaries, and
// /api/setup/claude is polled by the header.
const installSignalTTL = time.Minute

// installSignalCache holds the last Options.InstallSignalTools answer.
type installSignalCache struct {
	mu    sync.Mutex
	at    time.Time
	tools []string
}

// installSignalHolds reports whether tool's install signal holds on this
// machine (WINNODE2 16b), from Options.InstallSignalTools, re-read at most
// once per installSignalTTL. No seam wired reports false.
func (s *Server) installSignalHolds(tool string) bool {
	if s.opts.InstallSignalTools == nil {
		return false
	}
	c := &s.installSignals
	c.mu.Lock()
	defer c.mu.Unlock()
	now := s.now()
	if c.at.IsZero() || now.Sub(c.at) > installSignalTTL {
		c.tools, c.at = s.opts.InstallSignalTools(), now
	}
	return slices.Contains(c.tools, tool)
}
