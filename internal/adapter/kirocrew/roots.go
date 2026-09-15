package kirocrew

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests override
// it to assert root discovery against fake homes without depending on the
// host's filesystem layout. Same pattern as kirocli.allHomesFunc /
// clinecli's env-root precedent.
var allHomesFunc = crossmount.AllHomes

// crewSubpath is the Kiro Crew data root relative to a home:
// `~/.kiro/crew`. Grounded on the operator's live Windows install
// 2026-09-03 — C:\Users\<u>\.kiro\crew, NOT %LOCALAPPDATA%, matching
// kiro-cli's own `~/.kiro/sessions` convention (see
// internal/adapter/kirocli/roots.go).
var crewSubpath = filepath.Join(".kiro", "crew")

// sessionsDir is the ONE subdirectory of the Crew data root this adapter
// watches. GROUNDED 2026-09-03 against a live signed-in Crew desktop run:
// the chat transcripts are `~/.kiro/crew/sessions/<thread>_<slot>.jsonl`
// (observed: `sessions/dashboard_chat-2-1700000002.jsonl`).
//
// The pre-grounding skeleton assumed `~/.kiro/crew/conversations/` from
// the vendor README's directory table. That directory DOES NOT EXIST on a
// live install — the whole tree was listed on the step-in host and there
// is no `conversations/` at any depth. `sessions/` is the real location.
const sessionsDir = "sessions"

// kirocrewHomeEnv is the vendor-documented override for the Crew data
// root (github.com/kirodotdev/kirocrew README). When set it replaces the
// whole `~/.kiro/crew` root, so the watched directory becomes
// `<KIROCREW_HOME>/sessions`.
const kirocrewHomeEnv = "KIROCREW_HOME"

// defaultRoots returns the watch roots for the Kiro Crew chat-transcript
// directory: KIROCREW_HOME (when set, made absolute and joined with
// "sessions") first, then `<home>/.kiro/crew/sessions` for every
// cross-mount-resolved home, deduped. Non-existent roots are kept — the
// watcher registry skips absent paths at registration time.
//
// No prefix collision with kirocli's roots. internal/adapter/kirocli
// watches `<home>/.kiro/sessions` (the CLI + IDE session tree); this
// package watches `<home>/.kiro/crew/sessions`. `sessions` and `crew` are
// SIBLING segments under the shared `<home>/.kiro` parent — neither
// string is a prefix of the other — so adapter.UnderAnyWatchRoot (a
// strict path-prefix test) never treats a file under one root as
// belonging to the other's watch root. defaults_test.go's
// TestRegistryRootsNonOverlapping pins this now that the package is
// registered.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	if home := adapter.AbsEnvRoot(kirocrewHomeEnv); home != "" {
		add(filepath.Join(home, sessionsDir))
	}

	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, crewSubpath, sessionsDir))
	}
	return roots
}

// crewRootOf returns the Kiro Crew DATA root (the parent of the watched
// `sessions` directory) for a session-file path — i.e. the directory
// holding `session_map.json`. Returns "" for a path that is not shaped
// like `<crewRoot>/sessions/<file>`.
func crewRootOf(sessionFile string) string {
	sessions := filepath.Dir(sessionFile)
	if filepath.Base(sessions) != sessionsDir {
		return ""
	}
	return filepath.Dir(sessions)
}
