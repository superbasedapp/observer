package codebuddy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// configDirEnv is CodeBuddy Code's own data-home override. The vendor
// bundle (2.171.0) resolves its home as
// `process.env.CODEBUDDY_CONFIG_DIR || join(homedir(), ".codebuddy")`
// for settings, MCP config, jobs and the session store alike, so an
// operator who sets it moves `projects/` too.
const configDirEnv = "CODEBUDDY_CONFIG_DIR"

// defaultRoots returns `<data home>/projects` for every candidate data
// home: the CODEBUDDY_CONFIG_DIR override on the running observer's own
// side (made absolute — a relative value would otherwise resolve against
// the daemon's working directory), then `<home>/.codebuddy` under every
// cross-mount-resolved $HOME. The layout is identical on Linux, macOS and
// native Windows (`%USERPROFILE%\.codebuddy`, grounded 2026-10-21 on
// both OSes), so a WSL2 observer reaches Windows-side sessions over
// /mnt/c and vice versa with no OS branching. Non-existent roots are kept
// (the watcher drops them later); duplicates are removed by cleaned
// spelling, and the watcher folds aliased spellings via
// adapter.DedupRootsByIdentity.
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

	if env := strings.TrimSpace(os.Getenv(configDirEnv)); env != "" {
		if abs, err := filepath.Abs(env); err == nil {
			add(filepath.Join(abs, "projects"))
		}
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".codebuddy", "projects"))
	}
	return roots
}
