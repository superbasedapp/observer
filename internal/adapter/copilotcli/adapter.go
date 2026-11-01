package copilotcli

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses GitHub Copilot CLI session data — two file shapes
// under one set of watch roots:
//
//   - <root>/.copilot/session-state/<uuid>/events.jsonl  (per-session events)
//   - <root>/.copilot/logs/process-<ts>-<pid>.log        (per-process debug log)
//
// See package doc for the three-tier token-capture story.
type Adapter struct {
	scrubber *scrub.Scrubber
	// watchRoots, when non-empty, overrides path discovery and is the
	// explicit list of directories to scan. Used by tests to point at
	// fixtures without depending on a real Copilot CLI install.
	watchRoots []string
}

// New returns a Copilot CLI adapter with the default scrubber.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New()}
}

// NewWithOptions customizes the scrubber and/or overrides watch roots.
// When watchRoots is non-empty, crossmount discovery is bypassed
// entirely — used by tests to point at fixtures.
func NewWithOptions(s *scrub.Scrubber, watchRoots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{scrubber: s, watchRoots: watchRoots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCopilotCLI }

// WatchPaths returns every plausible Copilot CLI watch root reachable
// from this process. Two paths per home (session-state + logs);
// order is native first, then cross-mount homes (WSL2 ↔ Windows).
//
// Layout is uniform across Linux / macOS / Windows — the npm-installed
// CLI always writes to `<home>/.copilot/`. Non-existent paths are
// dropped by the watcher at registration time.
func (a *Adapter) WatchPaths() []string {
	if len(a.watchRoots) > 0 {
		return a.watchRoots
	}
	var roots []string
	// COPILOT_HOME moves ~/.copilot (session-state and logs with it) on the
	// native side, resolved through the copilot-cli/user-settings artifact
	// the hook writer uses (CLI-4).
	if d := adapter.RelocatedToolHome("copilot-cli/user-settings", 0); d != "" {
		roots = append(roots, filepath.Join(d, "session-state"), filepath.Join(d, "logs"))
	}
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, candidateRoots(h)...)
	}
	return roots
}

// IsSessionFile matches the two shapes:
//
//   - `<session-state-root>/<uuid>/events.jsonl`
//   - `<logs-root>/process-<ts>-<pid>.log`
//
// AND constrains to under-WatchPaths per Invariant #48.
func (a *Adapter) IsSessionFile(path string) bool {
	if !isEventsFile(path) && !isLogFile(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

func isEventsFile(path string) bool {
	if filepath.Base(path) != "events.jsonl" {
		return false
	}
	// Parent must be a UUID-ish session dir; grandparent must end in
	// "session-state". That rules out an `events.jsonl` placed
	// somewhere unrelated.
	parent := filepath.Dir(path)
	if !looksLikeSessionUUID(filepath.Base(parent)) {
		return false
	}
	grand := filepath.Base(filepath.Dir(parent))
	return grand == "session-state"
}

func isLogFile(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "process-") || !strings.HasSuffix(base, ".log") {
		return false
	}
	// Parent must be the per-home `logs` dir.
	return filepath.Base(filepath.Dir(path)) == "logs"
}

// looksLikeSessionUUID is a permissive check — 36-char hex-with-hyphens
// is enough to filter out non-session paths without pulling in a
// full uuid parser.
func looksLikeSessionUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHexLower(r) {
				return false
			}
		}
	}
	return true
}

func isHexLower(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

// ParseSessionFile dispatches on filename. events.jsonl gets the
// event-stream parser; process-*.log gets the log parser (Tier 1 +
// Tier 2 token capture).
//
// Both parsers are byte-offset-incremental — callers persist the
// returned NewOffset in parse_cursors and resume from there.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if isEventsFile(path) {
		return a.parseEventsJSONL(ctx, path, fromOffset)
	}
	if isLogFile(path) {
		return a.parseProcessLog(ctx, path, fromOffset)
	}
	return adapter.ParseResult{NewOffset: fromOffset}, nil
}
