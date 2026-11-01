package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launch_routegate_auth.go: the launcher's read of a saved sign-in choice
// that can outrank a gated route (surface-gap review CLI-6, lane w4-layers).
// A product such as Gemini CLI decides its host from the sign-in mode it
// saved (security.auth.selectedType, an administrator's enforcedType) or a
// .env variable it loads (GOOGLE_GENAI_USE_GCA) before it reads the base URL
// the launcher sets. The launcher still routes, and names the key it found
// so the developer knows which setting may send the session to the vendor.
//
// Key presence only: a settings file is decoded through its catalogue row's
// own format engine (never a PrivNever file, the evaluator's rule) and only
// the key's presence is used; a .env file is read by name through
// agentconfig.DotenvKeysPresent. No value is printed or logged. It
// dispatches on the registry row's Gate shape, never the tool.

// launchFiles is the launcher's file boundary for these reads. A package
// variable so tests stay inside their own temp directory.
var launchFiles = struct {
	home       func() (string, error)
	cwd        func() (string, error)
	read       func(string) ([]byte, error)
	goos       string
	systemRoot string
}{os.UserHomeDir, os.Getwd, os.ReadFile, runtime.GOOS, ""}

// launchDirs is the home and the launch directory ("" each when unknown).
func launchDirs() (home, project string) {
	if h, err := launchFiles.home(); err == nil {
		home = h
	}
	if d, err := launchFiles.cwd(); err == nil {
		project = d
	}
	return home, project
}

// expandLaunchFile resolves one registry file entry: "~/" under home,
// "<project>/" under project, "" when the base it names is unknown. An
// absolute or relative path is returned as given.
func expandLaunchFile(entry, home, project string) string {
	switch {
	case strings.HasPrefix(entry, "~/"):
		if home == "" {
			return ""
		}
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(entry, "~/")))
	case strings.HasPrefix(entry, "<project>/"):
		if project == "" {
			return ""
		}
		return filepath.Join(project, filepath.FromSlash(strings.TrimPrefix(entry, "<project>/")))
	}
	return entry
}

// dotenvKeysIn returns "<file>: <KEY>" for each of keys a .env file in files
// sets (names only).
func dotenvKeysIn(files, keys []string, home, project string) []string {
	var out []string
	for _, entry := range files {
		p := expandLaunchFile(entry, home, project)
		if p == "" {
			continue
		}
		b, err := launchFiles.read(p)
		if err != nil {
			continue
		}
		for _, k := range agentconfig.DotenvKeysPresent(b, keys) {
			out = append(out, p+": "+k)
		}
	}
	return out
}

// gateAuthPins returns, for one launch, every saved sign-in source the gate
// names that is present: "<file>: <key>" for a settings key or a .env
// variable, "<VAR> (launch environment)" for a variable already exported.
// Empty when nothing is saved.
func gateAuthPins(g *integration.RouteGate, lookup func(string) (string, bool)) []string {
	if g == nil || (len(g.AuthSettingKeys) == 0 && len(g.DotenvKeys) == 0) {
		return nil
	}
	home, project := launchDirs()
	getenv := func(k string) string { v, _ := lookup(k); return v }
	var out []string
	for _, k := range g.AuthSettingKeys {
		r, err := agentconfig.ResolveArtifact(k.File, agentconfig.PathEnv{
			GOOS: launchFiles.goos, Home: home, Project: project, Getenv: getenv,
			SystemRoot: launchFiles.systemRoot, Relocate: true,
		})
		if err != nil || r.Status != agentconfig.PathResolved || r.Path == "" {
			continue
		}
		row, ok := settingsRow(k.File)
		if !ok {
			continue
		}
		b, err := launchFiles.read(r.Path)
		if err != nil {
			continue
		}
		if _, ok := agentconfig.LookupDotted(agentconfig.DecodeTree(row, b), k.Key); ok {
			out = append(out, r.Path+": "+k.Key)
		}
	}
	for _, k := range g.DotenvKeys {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			out = append(out, k+" (launch environment)")
		}
	}
	return append(out, dotenvKeysIn(g.DotenvFiles, g.DotenvKeys, home, project)...)
}

// settingsRow is the catalogue row of a settings file the launcher may read:
// never a PrivNever file (the evaluator's own rule, agentconfigsvc
// snapshot), decoded through its own format engine (JSONC included).
func settingsRow(id string) (agentconfig.FileRow, bool) {
	for _, r := range agentconfig.Files() {
		if r.ID == id {
			return r, r.WriteNeeds != agentconfig.PrivNever
		}
	}
	return agentconfig.FileRow{}, false
}

// authPinnedCaveat is the routed launch's note naming the saved sign-in
// sources (key names and files only).
func authPinnedCaveat(label string, pins []string) string {
	return "observer " + label + ": note: a saved sign-in choice may send this session to the vendor directly, past the proxy (" +
		strings.Join(pins, "; ") + "); if it is not the API-key mode this route carries, change or unset it"
}
