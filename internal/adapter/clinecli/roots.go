package clinecli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// clineDataArtifact is the catalogued Cline row that sits directly in the
// data dir (~/.cline/data/globalState.json); its relocation rules
// (CLINE_DATA_DIR, then CLINE_DIR) are the vendor's data-dir ladder.
const clineDataArtifact = "cline/global-state"

// defaultDataRoots returns the native data dir when CLINE_DATA_DIR moves it
// (surface-gap FU-30): the sessions store and hooks.jsonl then live in
// $CLINE_DATA_DIR/{db,sessions,logs}, outside every <home>/.cline root. It is
// resolved through the cline/global-state artifact so the adapter, the
// route writer and the MCP writer read one ladder. CLINE_DIR alone needs no
// data root ($CLINE_DIR is a home root already), and a relative value names
// no directory the daemon can watch.
func defaultDataRoots() []string {
	return dataRootsFrom(os.Getenv, runtime.GOOS)
}

// dataRootsFrom is defaultDataRoots with the environment injected.
func dataRootsFrom(getenv func(string) string, goos string) []string {
	home, _ := os.UserHomeDir()
	got, err := agentconfig.ResolveArtifact(clineDataArtifact, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv})
	if err != nil || got.Status != agentconfig.PathResolved || got.RelocatedBy != "CLINE_DATA_DIR" {
		return nil
	}
	return []string{filepath.Dir(got.Path)}
}

// defaultRoots returns the Cline CLI home directory under every
// cross-mount-resolved $HOME. Cline CLI uses `<home>/.cline` on every
// OS (NOT %LOCALAPPDATA% on Windows — confirmed against a live install).
// This is simpler than the Hermes adapter's defaultRoots (no OS
// branching) but still walks the crossmount surface so a WSL2 observer
// reaches data living at `/mnt/c/Users/<u>/.cline/`.
//
// Respects CLINE_DIR when set on the running observer (rare — usually
// only set by the user inside their CLI shell). When set, CLINE_DIR
// adds to the per-home discovery on the running process's native side;
// cross-mount candidates from other OSes still contribute their default
// `<home>/.cline` paths. Mirrors how the Cline CLI's @cline/shared
// storage resolver reads the env.
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

	// CLINE_DIR wins on the native side when set.
	if env := strings.TrimSpace(os.Getenv("CLINE_DIR")); env != "" {
		add(env)
	}

	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		// Same layout on every OS — no branching.
		add(filepath.Join(h.Path, ".cline"))
	}
	return roots
}
