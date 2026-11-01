package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	toolhost "github.com/marmutapp/superbased-observer/internal/toolresolve/host"
)

// installSignalProbe is the injected I/O of installSignalTools.
type installSignalProbe struct {
	// home is the user home the extension folders are under.
	home string
	// readDir lists a directory (os.ReadDir).
	readDir func(string) ([]os.DirEntry, error)
	// resolves reports whether a Binary spec resolves on this machine.
	resolves func(integration.BinaryResolveSpec) bool
}

// installSignalTools returns, sorted, the registry tools whose
// Capability.InstallSignals hold on this machine (WINNODE item 5): auto-wiring
// then treats them as installed although their config home does not exist
// yet. It dispatches on the signal's kind, never on the tool.
func installSignalTools(rows []integration.Capability, p installSignalProbe) []string {
	var exts map[string]bool // lazily: the installed extension ids
	var out []string
	for _, c := range rows {
		for _, sig := range c.InstallSignals {
			hit := false
			switch sig.Kind {
			case integration.InstallSignalEditorExtension:
				if exts == nil {
					exts = installedEditorExtensions(p)
				}
				hit = exts[strings.ToLower(sig.ExtensionID)]
			case integration.InstallSignalBinary:
				hit = c.Binary != nil && p.resolves != nil && p.resolves(*c.Binary)
			}
			if hit {
				out = append(out, c.Tool)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// installedEditorExtensions lists the extension ids installed in the VS
// Code-family extensions folders: a directory "<publisher>.<name>-<version>"
// (an optional "-<platform>" suffix follows the version).
func installedEditorExtensions(p installSignalProbe) map[string]bool {
	ids := map[string]bool{}
	if p.home == "" || p.readDir == nil {
		return ids
	}
	for _, rel := range integration.EditorExtensionDirs {
		entries, err := p.readDir(filepath.Join(p.home, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if id, ok := extensionIDOf(e.Name()); ok {
				ids[id] = true
			}
		}
	}
	return ids
}

// extensionIDOf splits an extension folder name at the "-<digit>" that
// starts its version: "anthropic.claude-code-2.1.312-win32-x64" is
// "anthropic.claude-code".
func extensionIDOf(name string) (string, bool) {
	name = strings.ToLower(name)
	for i := 1; i+1 < len(name); i++ {
		if name[i] == '-' && name[i+1] >= '0' && name[i+1] <= '9' {
			id := name[:i]
			return id, strings.Contains(id, ".")
		}
	}
	return "", false
}

// installSignalToolsFor is the production probe. homeDir is the wiring's
// home override ("" = the real home); under an override (tests, a
// cross-home wiring) no binary is resolved, because the resolver walks this
// process's PATH, which belongs to the real home.
func installSignalToolsFor(homeDir string) []string {
	p := installSignalProbe{home: homeDir, readDir: os.ReadDir}
	if homeDir == "" {
		env := toolhost.NewEnv(toolhost.Options{})
		p.home = env.Home
		p.resolves = func(spec integration.BinaryResolveSpec) bool {
			switch toolresolve.Resolve(spec, env).Verdict {
			case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
				return true
			default:
				return false
			}
		}
	}
	return installSignalTools(integration.Capabilities(), p)
}
