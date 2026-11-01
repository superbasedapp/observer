package dirac

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Dirac home layout (grounded 2026-10-21 against dirac-cli 0.5.22 on
// Windows 11 and WSL Ubuntu, and against the shipped bundle's own path
// resolvers):
//
//	<DIRAC_DIR or ~/.dirac>/data/tasks/<taskId>/   ← one task = one session
//
// The bundle resolves the home as `process.env.DIRAC_DIR ||
// path.join(os.homedir(), ".dirac")` on every OS (NOT %APPDATA% on
// Windows), and the data dir as `process.env.DIRAC_DATA_DIR ??
// <home>/data`. The `--config <path>` flag sets DIRAC_DIR for that one
// invocation only, so a per-invocation home is not discoverable here.
const (
	// homeDirName is the per-user Dirac home under $HOME.
	homeDirName = ".dirac"
	// dataDirName is the data directory inside the Dirac home.
	dataDirName = "data"
	// tasksDirName is the per-task directory parent inside the data dir.
	tasksDirName = "tasks"
)

// envLookup is the test seam over os.Getenv.
var envLookup = os.Getenv

// allHomesFunc is the test seam over crossmount.AllHomes.
var allHomesFunc = crossmount.AllHomes

// defaultRoots returns the `<data>/tasks` directory for every Dirac home
// this observer can reach: $DIRAC_DATA_DIR/tasks and $DIRAC_DIR/data/tasks
// when set on the running observer (absolutised, the vendor resolver's
// precedence), then `<home>/.dirac/data/tasks` under every
// cross-mount-resolved $HOME, so a WSL2 observer reaches a Windows-side
// install over /mnt/c and vice versa. Non-existent roots are kept (the
// registry skips them); duplicates collapse.
//
// The roots are deliberately the `tasks` directory, NOT the Dirac home:
// the home also holds `data/secrets.json`, `data/globalState.json` and
// `data/logs/`, none of which this adapter may ever be handed by the
// watcher. They never overlap cline-cli's `<home>/.cline` or the Cline
// extension's VS Code globalStorage roots.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}
	if env := strings.TrimSpace(envLookup("DIRAC_DATA_DIR")); env != "" {
		add(filepath.Join(env, tasksDirName))
	}
	if env := strings.TrimSpace(envLookup("DIRAC_DIR")); env != "" {
		add(filepath.Join(env, dataDirName, tasksDirName))
	}
	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, homeDirName, dataDirName, tasksDirName))
	}
	return adapter.DedupRootsByIdentity(roots)
}
