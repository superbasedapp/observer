//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hook/hermesplugin"
	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// launch_trust_own.go tells Observer's own entries in the developer's home
// config (its hooks, status line, MCP server and plugins) from everything
// else, for the user-scope config baseline and for a launch-time check at
// the home directory (docs/security.md SECP-5; plans decision log P-037,
// and the SEC-TRUST4 merge audit findings 1 and 2).
//
// An entry counts as Observer's only when BOTH hold:
//   - its shape is one Observer's registrars write (the registrars' own
//     recognisers, plus the exact prefixes they write: hook.Observer*Binaries);
//   - the executable it names is Observer's (repoTrustOwnBinaries): the
//     running binary (os.Executable, symlinks resolved), the command a
//     registration from it writes (registrationCommand: the npm bin link or
//     pip console script when one resolves to this install), or a
//     binary_path the registration record (~/.observer/hook_checksums.json)
//     holds for an earlier registration. A binary named observer at any
//     other path is not.
//
// Plugin files count only when their bytes are what Observer writes:
// the Hermes plugin directory file by file against the embedded plugin
// (hermesplugin.IsInstalledFile), a plugin shim against the embedded
// template with only its profile filled in (pluginshim.RenderedBinaries).

// repoTrustRunningBinary is the running observer binary, symlinks
// resolved (absoluteBinaryPath); a test replaces it.
var repoTrustRunningBinary = absoluteBinaryPath

// repoTrustOwnBinaries is what an Observer entry's executable must name.
type repoTrustOwnBinaries struct {
	// ids are the identities diag.HookBinaryMatches compares a token with:
	// the running binary with its registration command, then one per
	// recorded binary_path.
	ids []diag.HookBinaryIdentity
	// literal are the same paths as written, for the plugin files that
	// embed the binary (the Hermes plugin's OBSERVER_BIN default).
	literal []string
}

// repoTrustOwnBinariesFor builds the set for home: the running binary and
// the registration record under home. There is no other record of what
// Observer registered, so a home with no record trusts the running binary
// only.
func repoTrustOwnBinariesFor(home string) repoTrustOwnBinaries {
	var o repoTrustOwnBinaries
	if real, err := repoTrustRunningBinary(); err == nil && real != "" {
		cmd := registrationCommand(real)
		o.ids = append(o.ids, diag.HookBinaryIdentity{Command: cmd, Real: real})
		o.literal = append(o.literal, real, cmd)
	}
	if home != "" {
		for _, p := range hook.RecordedBinaryPaths(hook.ChecksumsPathFor(home), os.ReadFile) {
			o.ids = append(o.ids, diag.HookBinaryIdentity{Command: p})
			o.literal = append(o.literal, p)
		}
	}
	return o
}

// owns reports whether tok names one of the binaries.
func (o repoTrustOwnBinaries) owns(tok string) bool {
	if strings.TrimSpace(tok) == "" {
		return false
	}
	for _, id := range o.ids {
		if diag.HookBinaryMatches(tok, id) {
			return true
		}
		if runtime.GOOS == "windows" && windowsSamePath(tok, id) {
			return true
		}
	}
	return false
}

// windowsSamePath compares a token with an identity case-insensitively,
// as Windows paths are.
func windowsSamePath(tok string, id diag.HookBinaryIdentity) bool {
	t := strings.ToLower(filepath.Clean(tok))
	for _, p := range []string{id.Command, id.Real} {
		if p != "" && strings.ToLower(filepath.Clean(p)) == t {
			return true
		}
	}
	return false
}

// ownsAny reports whether any spelling names one of the binaries.
func (o repoTrustOwnBinaries) ownsAny(toks []string) bool {
	for _, t := range toks {
		if o.owns(t) {
			return true
		}
	}
	return false
}

// repoTrustObserverOwnedRows are the agent-config catalogue rows whose whole
// path is Observer's own (written only by Observer's registration): a file
// under one is Observer's only while it is exactly a file Observer wrote.
var repoTrustObserverOwnedRows = map[string]bool{"hermes/observer-plugin": true}

// repoTrustObserverOwnRule is one row of the Observer-entry table: the
// reason codes it judges and the test that decides them.
type repoTrustObserverOwnRule struct {
	codes map[string]bool
	own   func(o repoTrustOwnBinaries, it sectrust.OwnItem) bool
}

// repoTrustObserverOwnRules is the Observer-entry table, walked top-down:
// each row's shape test is the recogniser registration itself uses, and
// each then requires the named executable to be Observer's.
var repoTrustObserverOwnRules = []repoTrustObserverOwnRule{
	{codes: map[string]bool{"hook_command": true}, own: func(o repoTrustOwnBinaries, it sectrust.OwnItem) bool {
		return o.ownsAny(hook.ObserverHookCommandBinaries(it.Content))
	}},
	{codes: map[string]bool{"statusline_command": true}, own: func(o repoTrustOwnBinaries, it sectrust.OwnItem) bool {
		return o.ownsAny(hook.ObserverStatuslineCommandBinaries(it.Content))
	}},
	{codes: map[string]bool{"mcp_server_command": true}, own: func(o repoTrustOwnBinaries, it sectrust.OwnItem) bool {
		return observerMCPEntry(it.Key, it.Content, o.owns)
	}},
	{codes: map[string]bool{"plugin_code": true}, own: func(o repoTrustOwnBinaries, it sectrust.OwnItem) bool {
		bin, wsl, ok := pluginshim.RenderedBinaries([]byte(it.Content))
		return ok && o.owns(bin) && (wsl == "" || o.owns(wsl))
	}},
}

// repoTrustObserverOwn is a check's Request.Own over files relative to
// home (the user-scope baseline, a launch at home): a reason in a file
// under a catalogue row Observer owns that is exactly what Observer wrote,
// or one a row of the Observer-entry table recognises.
func repoTrustObserverOwn(home string, paths []agentconfig.TrustPath) func(sectrust.OwnItem) bool {
	return repoTrustObserverOwnWith(repoTrustOwnBinariesFor(home), paths)
}

// repoTrustObserverOwnWith is repoTrustObserverOwn over a given set.
func repoTrustObserverOwnWith(o repoTrustOwnBinaries, paths []agentconfig.TrustPath) func(sectrust.OwnItem) bool {
	var ownDirs []string
	for _, p := range paths {
		for _, src := range p.Sources {
			if repoTrustObserverOwnedRows[src] {
				ownDirs = append(ownDirs, strings.TrimSuffix(p.Rel, "/"))
			}
		}
	}
	return func(it sectrust.OwnItem) bool {
		for _, d := range ownDirs {
			if rel, ok := strings.CutPrefix(it.File, d+"/"); ok {
				return it.Code == "plugin_code" && hermesplugin.IsInstalledFile(rel, []byte(it.Content), o.literal)
			}
		}
		for _, r := range repoTrustObserverOwnRules {
			if r.codes[it.Code] {
				return r.own(o, it)
			}
		}
		return false
	}
}

// repoTrustOwnAt is a launch-time check's Request.Own for root: the
// Observer-entry test when root is the developer's home directory (a launch
// in ~, or anywhere under a home-directory repository, where the project
// table reads ~/.claude/settings.json and the other home config files
// Observer registers into), nil for any other root. A repository elsewhere
// gets no Observer exception: an entry in Observer's shape committed to a
// repository is the repository's, whatever it names.
func repoTrustOwnAt(root string) func(sectrust.OwnItem) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !repoTrustSameDir(root, home) {
		return nil
	}
	return repoTrustObserverOwn(home, agentconfig.TrustPaths())
}

// repoTrustSameDir compares two directories after resolving symlinks.
func repoTrustSameDir(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		p = filepath.Clean(p)
		if runtime.GOOS == "windows" {
			p = strings.ToLower(p)
		}
		return p
	}
	return a != "" && b != "" && norm(a) == norm(b)
}

// repoTrustDashboardOwn is the dashboard's seam onto repoTrustOwnAt
// (dashapi.Options.RepoTrustOwn), in plain types so the dashboard's
// options do not import the trust check.
func repoTrustDashboardOwn(root string) func(code, file, key, content string) bool {
	own := repoTrustOwnAt(root)
	if own == nil {
		return nil
	}
	return func(code, file, key, content string) bool {
		return own(sectrust.OwnItem{Code: code, File: file, Key: key, Content: content})
	}
}

// observerMCPEntry reports whether an MCP stdio entry is Observer's: named
// as Observer names its entry (the shared name, or the legacy Hermes name
// an older build wrote), running an observer binary that owns
// accepts with the arguments Observer writes (`serve [--config <path>]`)
// and nothing else. content is the entry's command, arguments and
// environment joined by spaces (a path may hold spaces, so each " serve"
// split is tried).
func observerMCPEntry(key, content string, owns func(string) bool) bool {
	name := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		name = key[i+1:]
	}
	if name != mcpregister.ServerName && name != hook.HermesLegacyMCPServerName {
		return false
	}
	for i := strings.Index(content, " serve"); i > 0; {
		bin, rest := content[:i], content[i+1:]
		args := []string{rest}
		if cfg, ok := strings.CutPrefix(rest, "serve --config "); ok {
			args = []string{"serve", "--config", cfg}
		}
		if hook.IsObserverBinary(bin) && owns(bin) && mcpregister.IsObserverServeArgs(args) {
			return true
		}
		next := strings.Index(content[i+1:], " serve")
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return false
}
