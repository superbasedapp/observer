package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hook/hermesplugin"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// HermesOptions parameterise RegisterHermes / UnregisterHermes /
// RegisterHermesMCP / UnregisterHermesMCP. All fields are optional;
// zero values fall back to the canonical Hermes home discovery
// (~/.hermes on Linux/macOS/WSL, %LOCALAPPDATA%\hermes on Windows
// native, with HERMES_HOME overriding either).
type HermesOptions struct {
	// HermesHome overrides Hermes home discovery. Useful for tests and
	// for operators using `hermes -p <name>` profiles where each
	// profile lives in a separate home.
	HermesHome string
	// BinaryPath is the absolute path to the observer binary. When
	// set, RegisterHermes writes it into the plugin's OBSERVER_BIN
	// environment so the plugin doesn't need PATH lookup. When empty
	// the plugin defaults to "observer" from $PATH.
	BinaryPath string
	// ConfigPath is the absolute path to the observer config.toml.
	// When set, it's written into the plugin's OBSERVER_CONFIG env
	// so the plugin can pass --config to observer's hook subcommand.
	ConfigPath string
	// DryRun: log intended writes but don't touch the filesystem.
	DryRun bool
	// Force overwrites a plugin file that does not read as Observer's (the
	// previous bytes are kept at <file>.bak), as --force does for every
	// other hook writer. Without it RegisterHermes refuses (FU-207).
	Force bool
}

const (
	// HermesPluginDirName is the leaf directory name we write under
	// the user's <hermes-home>/plugins/. Matches the manifest
	// `name:` key so Hermes's loader picks it up cleanly.
	HermesPluginDirName = "superbased-observer"
	// HermesConfigFile is the per-home Hermes config file. We read +
	// merge it for MCP registration; we never write hooks into it
	// (hooks live in the plugin directory).
	HermesConfigFile = "config.yaml"
)

// resolveHermesHome returns the resolved Hermes home directory for
// the running platform. Precedence: explicit HermesOptions.HermesHome
// (the caller's profile-aware resolution, cmd/observer hermesResolveHome)
// > the hermes/user-config artifact's relocation rules (HERMES_HOME, then
// HERMES_DATA_DIR_SUFFIX on the platform default ~/.hermes or
// %LOCALAPPDATA%\hermes).
func resolveHermesHome(opts HermesOptions) (string, error) {
	if opts.HermesHome != "" {
		return opts.HermesHome, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("hook.resolveHermesHome: %w", err)
	}
	// The home is the process's own, never pinned: the one pinned-home
	// rule (crossmount.HomeEnv, R-188 F1) decides whether HERMES_HOME is
	// read, so an isolated HOME installs under itself.
	h, err := hermesHomeResolve(crossmount.HomeEnv("", nil), home, runtime.GOOS)
	if err != nil {
		return "", fmt.Errorf("hook.resolveHermesHome: %w", err)
	}
	return h, nil
}

// hermesHomeArtifact is the catalogued Hermes row that sits directly in
// the Hermes home.
const hermesHomeArtifact = "hermes/user-config"

// hermesHomeResolve is the one Hermes home ladder, the hermes/user-config
// artifact's relocation rules (HERMES_HOME, expanded; else the platform
// default %LOCALAPPDATA%\hermes on Windows, <home>/.hermes elsewhere, with
// HERMES_DATA_DIR_SUFFIX on its name), with the environment and home
// injected. A relative HERMES_HOME is an error: Hermes reads it against its
// own working directory. Profiles are the caller's (they live in a file).
func hermesHomeResolve(getenv func(string) string, home, goos string) (string, error) {
	got, err := agentconfig.ResolveArtifact(hermesHomeArtifact, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv})
	if err != nil {
		return "", err
	}
	switch got.Status {
	case agentconfig.PathResolved:
		return filepath.Dir(hostNative(got.Path)), nil
	case agentconfig.PathRelocationUnresolved:
		return "", fmt.Errorf("%s is set to a relative path, which Hermes reads against its own working directory; set an absolute path", got.RelocatedBy)
	}
	return "", nil
}

// hermesHomeFrom is hermesHomeResolve for detection: "" when nothing
// resolves. resolveHermesHome (the installer) and
// Registry.InstalledOutOfBand (detection) both use the same ladder, so
// detection looks exactly where the installer would write.
func hermesHomeFrom(getenv func(string) string, home, goos string) string {
	h, err := hermesHomeResolve(getenv, home, goos)
	if err != nil {
		return ""
	}
	return h
}

// hermesPluginPath returns the full path to the
// `<hermes-home>/plugins/superbased-observer/` directory we write into.
func hermesPluginPath(opts HermesOptions) (string, error) {
	home, err := resolveHermesHome(opts)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "plugins", HermesPluginDirName), nil
}

// RegisterHermes installs the SuperBased Observer Python plugin into
// the user's Hermes plugins directory. Idempotent: re-running against
// an existing install overwrites the plugin files with the embedded
// copies — useful after an `npm i -g @superbased/observer` upgrade
// since the plugin sources may have been refreshed.
//
// Returns the absolute plugin path written and any error. On DryRun
// the path is returned but no filesystem changes happen.
//
// The rendered plugin defaults `OBSERVER_BIN` to opts.BinaryPath so
// the hook subprocess doesn't depend on PATH resolution at runtime
// (validation 2026-06-06 caught this on Windows: the npm shim on
// PATH is broken when node isn't installed, and the plugin's
// fire-and-forget subprocess silently no-op'd against it). When
// BinaryPath is empty the placeholder falls back to the bare
// "observer" PATH lookup — mostly to keep unit tests that don't
// resolve a real executable working; production callers should
// always pass an absolute path.
func RegisterHermes(opts HermesOptions) (string, error) {
	pluginDir, err := hermesPluginPath(opts)
	if err != nil {
		return "", err
	}
	replaced, err := hermesPluginConflicts(pluginDir, opts)
	if err != nil {
		return pluginDir, err
	}
	if opts.DryRun {
		return pluginDir, nil
	}
	for _, p := range replaced {
		if err := backupForeignCommandCodeMod(p.path, p.data); err != nil {
			return pluginDir, fmt.Errorf("hook.RegisterHermes: %w", err)
		}
	}
	if err := hermesplugin.WritePlugin(pluginDir, opts.BinaryPath); err != nil {
		return pluginDir, fmt.Errorf("hook.RegisterHermes: %w", err)
	}
	return pluginDir, nil
}

// hermesPluginConflicts is RegisterHermes's foreign-file guard in front of
// hermesplugin.WritePlugin, which writes whole plugin files (FU-207, the
// guard every whole-file writer in the registry has): a plugin file that
// does not read as Observer's (hermesplugin.LooksLikePluginFile), or a
// bridge whose OBSERVER_BIN default is a binary not judged an Observer
// binary (FU-192), is refused without opts.Force and nothing is written.
// With Force it returns the files whose bytes the write replaces. There is
// no managed repair here: Hermes is wired only by `observer init --hermes`.
func hermesPluginConflicts(pluginDir string, opts HermesOptions) ([]replacedExtra, error) {
	var out []replacedExtra
	for _, rel := range hermesplugin.Files() {
		p := filepath.Join(pluginDir, filepath.FromSlash(rel))
		have, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("hook.RegisterHermes: read %s: %w", p, err)
		}
		bin, hasBin := hermesplugin.ObserverBinDefault(have)
		foreignBin := hasBin && !observerBinaryJudged(bin, opts.BinaryPath)
		if hermesplugin.LooksLikePluginFile(rel, have) && !foreignBin {
			continue
		}
		if !opts.Force {
			if foreignBin {
				return nil, foreignBinaryError("hook.RegisterHermes", "", p)
			}
			return nil, foreignFileError("hook.RegisterHermes", p)
		}
		out = append(out, replacedExtra{path: p, data: have})
	}
	return out, nil
}

// HermesRemoval is what UnregisterHermes did in the plugin directory.
type HermesRemoval struct {
	// PluginDir is the plugin directory.
	PluginDir string
	// Removed names the files removed (or, on DryRun, that would be).
	Removed []string
	// KeptForeign names the files kept because they are not Observer's
	// (ForeignFileReason): kept byte for byte, with or without --force.
	KeptForeign []string
	// DirRemoved is true when the directory was removed, empty once
	// Observer's files were gone (on DryRun: would be).
	DirRemoved bool
}

// UnregisterHermes removes the SuperBased Observer plugin files and then
// the plugin directory when nothing else is left in it. Safe against an
// already-uninstalled state.
//
// FU-212: a file is removed only when it reads as Observer's: a plugin file
// WritePlugin wrote in any version (hermesplugin.LooksLikePluginFile) whose
// bridge runs an observer binary (FU-192), or the bytecode CPython compiled
// from Observer's __init__.py (hermesplugin.IsBytecodeOf); its bytes are
// compared again before the delete. Anything else in the directory (a
// user's file, a plugin file that is not Observer's) is kept byte for byte,
// with or without --force, and named in KeptForeign, and so the directory
// stays. The directory is never removed with RemoveAll.
//
// Refuses a directory whose name doesn't match HermesPluginDirName:
// defends against the operator passing a mis-configured HermesHome that
// points at a real Hermes plugin they actually want to keep.
func UnregisterHermes(opts HermesOptions) (HermesRemoval, error) {
	pluginDir, err := hermesPluginPath(opts)
	if err != nil {
		return HermesRemoval{}, err
	}
	out := HermesRemoval{PluginDir: pluginDir}
	if filepath.Base(pluginDir) != HermesPluginDirName {
		return out, fmt.Errorf("hook.UnregisterHermes: refusing to remove %s: basename %q != %q", pluginDir, filepath.Base(pluginDir), HermesPluginDirName)
	}
	if fi, err := os.Lstat(pluginDir); os.IsNotExist(err) {
		return out, nil
	} else if err != nil {
		return out, fmt.Errorf("hook.UnregisterHermes: stat: %w", err)
	} else if !fi.IsDir() {
		out.KeptForeign = []string{pluginDir}
		return out, nil
	}
	plan, err := hermesRemovalPlan(pluginDir, opts.BinaryPath)
	if err != nil {
		return out, err
	}
	out.KeptForeign = plan.kept
	for _, f := range plan.remove {
		out.Removed = append(out.Removed, f.path)
		if opts.DryRun {
			continue
		}
		if err := removeEmptyConfigFile(f.path, f.data); err != nil {
			return out, fmt.Errorf("hook.UnregisterHermes: %w", err)
		}
	}
	if len(out.KeptForeign) > 0 {
		return out, nil
	}
	if opts.DryRun {
		out.DirRemoved = true
		return out, nil
	}
	// os.Remove never deletes a directory that still holds anything: a
	// file that appeared since the plan keeps it.
	_ = os.Remove(filepath.Join(pluginDir, "__pycache__"))
	out.DirRemoved = os.Remove(pluginDir) == nil
	return out, nil
}

// hermesPlan is UnregisterHermes's decision over the plugin directory.
type hermesPlan struct {
	remove []replacedExtra
	kept   []string
}

// hermesRemovalPlan walks pluginDir (it and its __pycache__, no deeper)
// and sorts every entry into Observer's to remove or kept (FU-212).
func hermesRemovalPlan(pluginDir, binaryPath string) (hermesPlan, error) {
	var plan hermesPlan
	read := func(p string) ([]byte, error) { return regularfile.Read(p, maxSettingsFileBytes) }
	var source []byte
	ours := map[string]bool{}
	for _, rel := range hermesplugin.Files() {
		p := filepath.Join(pluginDir, filepath.FromSlash(rel))
		have, err := read(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		ours[rel] = true
		bin, hasBin := hermesplugin.ObserverBinDefault(have)
		if err != nil || !hermesplugin.LooksLikePluginFile(rel, have) || (hasBin && !observerBinaryJudged(bin, binaryPath)) {
			plan.kept = append(plan.kept, p)
			continue
		}
		plan.remove = append(plan.remove, replacedExtra{path: p, data: have})
		if rel == "__init__.py" {
			source = have
		}
	}
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return plan, fmt.Errorf("hook.UnregisterHermes: %w", err)
	}
	for _, e := range entries {
		switch {
		case ours[e.Name()]:
		case e.Name() == "__pycache__" && e.IsDir():
			kept, remove := hermesBytecode(filepath.Join(pluginDir, e.Name()), source, read)
			plan.kept = append(plan.kept, kept...)
			plan.remove = append(plan.remove, remove...)
		default:
			plan.kept = append(plan.kept, filepath.Join(pluginDir, e.Name()))
		}
	}
	sort.Strings(plan.kept)
	return plan, nil
}

// hermesBytecode sorts the plugin's __pycache__: the bytecode of Observer's
// __init__.py (source, nil when that file is not being removed) is removed,
// anything else kept.
func hermesBytecode(dir string, source []byte, read func(string) ([]byte, error)) (kept []string, remove []replacedExtra) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{dir}, nil
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		have, err := read(p)
		if err != nil || source == nil || !hermesplugin.IsBytecodeOf("__pycache__/"+e.Name(), have, source) {
			kept = append(kept, p)
			continue
		}
		remove = append(remove, replacedExtra{path: p, data: have})
	}
	return kept, remove
}
