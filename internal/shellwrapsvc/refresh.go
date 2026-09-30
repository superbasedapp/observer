package shellwrapsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// RefreshOutcome is RefreshStale's result.
type RefreshOutcome struct {
	// ObserverPath is the path refreshed shims now run ("" when inactive).
	ObserverPath string `json:"observer_path,omitempty"`
	// Plan is every on-disk shim's decision (see shellwrap.PlanRefresh).
	Plan shellwrap.RefreshPlan `json:"plan"`
	// Rewritten are the shims actually rewritten.
	Rewritten []shellwrap.ShimRefresh `json:"rewritten"`
}

// RefreshStale is the start-time refresh (`observer start`): when the
// recorded choice is enabled, every marked shim for a recorded tool whose
// baked observer binary is gone is re-rendered to run the running binary. A
// baked binary that still exists (another install) is kept. It never creates a shim, never adds a tool, never touches a shell
// start-up file and never records anything in config.toml; when shell-wrap is
// not enabled it reads nothing beyond the config. The write rules are
// enable's: only a regular, marker-carrying file inside the shim directory,
// unchanged since it was read, is replaced - atomically, mode 0755.
func (s Service) RefreshStale(ctx context.Context) (RefreshOutcome, error) {
	if err := ctx.Err(); err != nil {
		return RefreshOutcome{}, err
	}
	applyMu.Lock()
	defer applyMu.Unlock()

	h, err := s.Host()
	if err != nil {
		return RefreshOutcome{}, err
	}
	cfg, err := s.loadConfig(s.configPath(h.Home))
	if err != nil {
		return RefreshOutcome{}, err
	}
	out := RefreshOutcome{Rewritten: []shellwrap.ShimRefresh{}}
	if !cfg.ShellWrap.Enabled {
		out.Plan, err = shellwrap.PlanRefresh(shellwrap.RefreshInput{GOOS: h.GOOS})
		return out, err
	}
	obs, err := s.observerPath()
	if err != nil {
		return out, err
	}
	shimDir := s.shimDir(h, cfg)
	tools, _ := configuredSelection(cfg)
	plan, err := shellwrap.PlanRefresh(shellwrap.RefreshInput{
		GOOS:             h.GOOS,
		Enabled:          true,
		Selected:         tools,
		ShimDir:          shimDir,
		ObserverPath:     obs,
		ResolvedObserver: s.resolveSymlinks(obs),
		Resolve:          s.resolveSymlinks,
		Exists:           s.fileExists,
		ObserverRunnable: s.observerRunnable,
		Shims:            inspectShims(shimDir),
	})
	if err != nil {
		return out, err
	}
	out.Plan, out.ObserverPath = plan, obs
	var errs []error
	for _, r := range plan.Rewrites() {
		if err := rewriteShim(shimDir, r); err != nil {
			errs = append(errs, err)
			continue
		}
		out.Rewritten = append(out.Rewritten, r)
	}
	return out, errors.Join(errs...)
}

// fileExists reports whether p is (or links to) a regular file.
func (s Service) fileExists(p string) bool {
	if s.FileExists != nil {
		return s.FileExists(p)
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// observerRunnable reports whether p is (or links to) a regular file that
// can be executed. A running binary that was replaced or removed reports a
// path such as "<path> (deleted)" on Linux, which fails the stat.
func (s Service) observerRunnable(p string) bool {
	if s.ObserverRunnable != nil {
		return s.ObserverRunnable(p)
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	return runtime.GOOS == "windows" || fi.Mode().Perm()&0o111 != 0
}

// resolveSymlinks returns p with symlinks resolved, or p when it cannot be
// (a path that no longer exists is compared as spelled).
func (s Service) resolveSymlinks(p string) string {
	eval := s.EvalSymlinks
	if eval == nil {
		eval = filepath.EvalSymlinks
	}
	if r, err := eval(p); err == nil && r != "" {
		return r
	}
	return p
}

// rewriteShim replaces one planned shim, re-checking immediately before the
// write that the file is still the marked, regular file the plan was made
// against and that it sits directly in the shim directory.
func rewriteShim(shimDir string, r shellwrap.ShimRefresh) error {
	if filepath.Dir(r.Path) != filepath.Clean(shimDir) || filepath.Base(r.Path) != r.FileName {
		return fmt.Errorf("shellwrapsvc: refresh %s: not directly inside the shim dir - not touched", r.Path)
	}
	fi, err := os.Lstat(r.Path)
	if err != nil {
		return fmt.Errorf("shellwrapsvc: refresh %s: %w", r.Path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("shellwrapsvc: refresh %s: not a regular file - not touched", r.Path)
	}
	cur, err := os.ReadFile(r.Path) /* #nosec G304 -- a marked shim inside the observer-owned shim directory */
	if err != nil {
		return fmt.Errorf("shellwrapsvc: refresh %s: %w", r.Path, err)
	}
	if !shellwrap.IsShim(cur) || string(cur) != r.Before {
		return fmt.Errorf("shellwrapsvc: refresh %s: changed since it was read - not touched", r.Path)
	}
	if err := fsatomic.WriteFile(r.Path, []byte(r.Content), fsatomic.Options{FilePerm: 0o755, DirPerm: 0o755, TempPattern: ".sbo-shim-*.tmp"}); err != nil {
		return fmt.Errorf("shellwrapsvc: refresh %s: %w", r.Path, err)
	}
	return nil
}
