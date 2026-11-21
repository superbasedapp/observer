package guardrecipesvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
)

// ConfigWriter writes [guard] keys into config.toml: it loads the file the
// way the caller's surface does, applies edit to the [guard] section,
// validates and saves only the keys that changed (comments kept). The CLI
// passes FileConfigWriter; the dashboard wraps the same function in its
// config-write locks.
type ConfigWriter func(edit func(*config.GuardConfig)) error

// FileConfigWriter is the ConfigWriter over one config file: config.Load,
// the edit, config.Validate, then config.StructuralPatches + config.PatchFile
// under the process-wide config lock, so only the edited keys are written and
// a governance overlay the load applied is never baked into the file. The
// edit runs on the file's own [guard] values (writableGuard): on a managed
// node the loaded mode is the floored or pinned one, and diffing against it
// would hide a write that changes only the file (sweep finding RC-8).
func FileConfigWriter(configPath string) ConfigWriter {
	return func(edit func(*config.GuardConfig)) error {
		if configPath == "" {
			return errors.New("config path unresolved")
		}
		return config.WithConfigLock(func() error {
			prev := config.Default()
			if _, err := os.Stat(configPath); err == nil {
				loaded, err := config.Load(config.LoadOptions{GlobalPath: configPath})
				if err != nil {
					return fmt.Errorf("load config: %w", err)
				}
				prev = loaded
			} else if !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("stat config: %w", err)
			}
			prev.Guard = writableGuard(prev.Guard)
			next := prev
			edit(&next.Guard)
			if err := config.Validate(next); err != nil {
				return err
			}
			patches, err := config.StructuralPatches(prev, next)
			if err != nil {
				return fmt.Errorf("diff config: %w", err)
			}
			if len(patches) == 0 {
				return nil
			}
			if _, err := config.PatchFile(configPath, next, patches); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			return nil
		})
	}
}

// Result is what an apply or remove did.
type Result struct {
	Preview *Preview `json:"preview"`
	// Wrote is the recipe file written (apply) or removed (remove).
	Wrote string `json:"wrote"`
	// ConfigChanged reports that [guard] keys were written.
	ConfigChanged bool `json:"config_changed"`
}

// Apply writes the selection's recipe file and, at global scope, [guard]
// level, mode and [guard.prompt] mode. It refuses while the preview has a
// problem (the compiled file does not lint, a pack row could only lower a
// rule, or the change would drop a policy layer). Order: the recipe file
// first, then config; a config write that fails puts the previous recipe
// file back, so the two never disagree.
func Apply(env Env, set *guardrecipe.Set, req Request, write ConfigWriter) (*Result, error) {
	p, err := planApply(env, set, req)
	if err != nil {
		return nil, err
	}
	if len(p.preview.Problems) > 0 {
		return nil, fmt.Errorf("guardrecipesvc.Apply: the recipe cannot be applied: %s", strings.Join(p.preview.Problems, "; "))
	}
	restore, err := replaceFile(p.preview.Path, p.text)
	if err != nil {
		return nil, fmt.Errorf("guardrecipesvc.Apply: %w", err)
	}
	res := &Result{Preview: p.preview, Wrote: p.preview.Path}
	if p.preview.Scope == guardrecipe.ScopeGlobal && p.fileMoves {
		if err := write(p.edit); err != nil {
			if rerr := restore(); rerr != nil {
				return nil, fmt.Errorf("guardrecipesvc.Apply: config write failed (%w) and restoring the previous recipe file failed too: %w", err, rerr)
			}
			return nil, fmt.Errorf("guardrecipesvc.Apply: config write failed, the previous recipe file is back: %w", err)
		}
		res.ConfigChanged = true
	}
	return res, nil
}

// Remove deletes a scope's applied recipe file and, at global scope, puts
// back the [guard] level, mode and prompt mode the first apply replaced
// (each only while it still holds what the recipe set). It refuses while the
// preview has a problem (the remove would drop a policy layer: the person's
// own file names a rule only the recipe defines). ok is false when the
// scope had no recipe.
func Remove(env Env, set *guardrecipe.Set, scope guardrecipe.Scope, projectRoot string, write ConfigWriter) (*Result, bool, error) {
	p, ok, err := planRemove(env, set, scope, projectRoot)
	if err != nil || !ok {
		return nil, ok, err
	}
	if len(p.preview.Problems) > 0 {
		return nil, true, fmt.Errorf("guardrecipesvc.Remove: the recipe cannot be removed: %s", strings.Join(p.preview.Problems, "; "))
	}
	old, err := os.ReadFile(p.preview.Path) //nolint:gosec // the managed recipe file this package owns
	if err != nil {
		return nil, true, fmt.Errorf("guardrecipesvc.Remove: %w", err)
	}
	if err := os.Remove(p.preview.Path); err != nil {
		return nil, true, fmt.Errorf("guardrecipesvc.Remove: %w", err)
	}
	res := &Result{Preview: p.preview, Wrote: p.preview.Path}
	if scope == guardrecipe.ScopeGlobal && p.fileMoves {
		if err := write(p.edit); err != nil {
			if rerr := writeAtomic(p.preview.Path, old); rerr != nil {
				return nil, true, fmt.Errorf("guardrecipesvc.Remove: config write failed (%w) and restoring the recipe file failed too: %w", err, rerr)
			}
			return nil, true, fmt.Errorf("guardrecipesvc.Remove: config write failed, the recipe file is back: %w", err)
		}
		res.ConfigChanged = true
	}
	return res, true, nil
}

// replaceFile writes data to path atomically and returns a func that puts
// back what was there before (the old bytes, or no file).
func replaceFile(path string, data []byte) (func() error, error) {
	old, err := os.ReadFile(path) //nolint:gosec // the managed recipe file this package owns
	existed := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := writeAtomic(path, data); err != nil {
		return nil, err
	}
	return func() error {
		if existed {
			return writeAtomic(path, old)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}, nil
}

// syncFile flushes a file to stable storage (a variable so a test can count
// the calls).
var syncFile = func(f *os.File) error { return f.Sync() }

// writeAtomic writes data to path through a temp file in the same
// directory and a rename, owner-only (the directory is created 0700). The
// temp file is synced before the rename and the directory after it where the
// platform supports that, so a crash leaves the old file or the new one,
// never an empty one (sweep finding RC-14). Two processes writing the same
// path are not serialized here: the last rename wins.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guard-recipe-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := syncFile(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory's entries after a rename, best effort: on
// Windows a directory handle cannot be synced, and the file itself is
// already on disk either way.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir) //nolint:gosec // the managed recipe file's own directory
	if err != nil {
		return
	}
	_ = syncFile(d)
	_ = d.Close()
}

// SaveUserRecipe writes one of the person's own recipes into the
// guard-recipes directory after it parses on its own and against the
// catalog (its extends target must exist). A built-in name is refused. It
// changes no policy: a saved recipe takes effect only when applied.
func SaveUserRecipe(env Env, name string, raw []byte) (*guardrecipe.Recipe, error) {
	if !guardrecipe.NameRx.MatchString(name) {
		return nil, fmt.Errorf("%q is not a recipe name (lowercase letters, digits and dashes)", name)
	}
	dir := guard.RecipeDir(env.Config.Guard, env.Home)
	if dir == "" {
		return nil, errors.New("no user policy file is configured, so there is no guard-recipes directory")
	}
	set, err := Catalog(env)
	if err != nil {
		return nil, err
	}
	if r, ok := set.Get(name); ok && r.Source == guardrecipe.SourceBuiltin {
		return nil, fmt.Errorf("%q is a built-in recipe: save your copy under another name", name)
	}
	r, err := guardrecipe.Parse(name, raw, guardrecipe.SourceUser)
	if err != nil {
		return nil, err
	}
	probe, err := guardrecipe.Builtin()
	if err != nil {
		return nil, err
	}
	for _, other := range set.All() {
		if other.Source == guardrecipe.SourceUser && other.Name != name {
			probe.AddUser(other.Name, other.Raw)
		}
	}
	probe.AddUser(name, raw)
	if _, ok := probe.Get(name); !ok {
		return nil, fmt.Errorf("recipe %s does not fit the catalog: %v", name, probe.Issues)
	}
	// It must compile alone (a level as a level, a pack as a pack) and lint
	// clean, so a saved recipe is one that can be applied.
	sel := guardrecipe.Selection{Scope: guardrecipe.ScopeGlobal}
	if r.Kind == guardrecipe.KindLevel {
		sel.Level = name
	} else {
		sel.Packs = []string{name}
	}
	compiled, err := guardrecipe.Compile(probe, sel, compileCatalog(env), guardrecipe.Meta{})
	if err != nil {
		return nil, err
	}
	if len(compiled.Problems) > 0 {
		return nil, fmt.Errorf("recipe %s cannot be applied: %s", name, strings.Join(compiled.Problems, "; "))
	}
	if problems := guard.Lint(compiled.Text, "user"); len(problems) > 0 {
		return nil, fmt.Errorf("recipe %s does not lint: %s", name, problems[0])
	}
	if err := writeAtomic(filepath.Join(dir, name+".toml"), raw); err != nil {
		return nil, fmt.Errorf("guardrecipesvc.SaveUserRecipe: %w", err)
	}
	return r, nil
}

// DeleteUserRecipe removes one of the person's own recipes. A recipe still
// applied somewhere keeps working (the applied file is a snapshot); the
// catalog then lists it as missing.
func DeleteUserRecipe(env Env, name string) error {
	if !guardrecipe.NameRx.MatchString(name) {
		return fmt.Errorf("%q is not a recipe name", name)
	}
	dir := guard.RecipeDir(env.Config.Guard, env.Home)
	if dir == "" {
		return errors.New("no guard-recipes directory is configured")
	}
	if b, err := guardrecipe.Builtin(); err == nil {
		if _, ok := b.Get(name); ok {
			return fmt.Errorf("%q is a built-in recipe and cannot be deleted", name)
		}
	}
	if err := os.Remove(filepath.Join(dir, name+".toml")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("no user recipe named %q", name)
		}
		return fmt.Errorf("guardrecipesvc.DeleteUserRecipe: %w", err)
	}
	return nil
}
