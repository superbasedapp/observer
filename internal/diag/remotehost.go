package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// doctorHomeRoot is the home these editor reads walk. The native origin lets
// vscodehost follow this process's %APPDATA% on Windows (a roaming profile
// off the default drive); a pinned home (a sandboxed doctor, a test) must
// resolve under itself, never the real profile.
func doctorHomeRoot(home string, pinned bool) crossmount.HomeRoot {
	origin := "native"
	if pinned {
		origin = "pinned"
	}
	return crossmount.HomeRoot{Path: home, OS: runtime.GOOS, Origin: origin}
}

// Bounds of the remote-host scan: workspaces per product, bytes per
// workspace.json (a few hundred bytes in practice).
const (
	remoteHostMaxWorkspaces = 2000
	remoteHostMaxFileBytes  = 64 << 10
)

// checkRemoteHosts is the honest D7 report for VS Code-family Remote
// windows on hosts Observer cannot reach (surface-gap IDE-1): a Remote-SSH,
// dev container, Codespace or tunnel window runs its agent on another
// machine, whose home no writer reaches (no hook, MCP entry or proxy route
// is written there) and from which the proxy's loopback address is not this
// machine's, so the session's capture is lost too. WSL windows are reachable
// by the Windows to WSL twins and are not reported here.
//
// The evidence is the editor's own record of the folders it opened: each
// desktop product's workspaceStorage/<id>/workspace.json, whose "folder" or
// "workspace" URI is vscode-remote://<authority>/... for a Remote window.
// One WARN when any uncovered remote workspace is found, none otherwise.
func checkRemoteHosts(home string, pinned bool) (Check, bool) {
	counts := map[vscodehost.RemoteKind]int{}
	h := doctorHomeRoot(home, pinned)
	for _, ref := range vscodehost.WorkspaceStorageDirs(h) {
		if ref.Product.Remote {
			continue
		}
		for kind, n := range remoteWorkspaceKinds(ref.Path, agentconfigsvc.ReadRegularFile) {
			counts[kind] += n
		}
	}
	return remoteHostsCheck(counts)
}

// remoteWorkspaceKinds classifies the workspace.json files under one
// workspaceStorage directory, counting each uncovered remote kind. Every
// file is read through read (bounded, regular files only).
func remoteWorkspaceKinds(dir string, read func(string, int64) ([]byte, error)) map[vscodehost.RemoteKind]int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[vscodehost.RemoteKind]int{}
	for i, e := range entries {
		if i >= remoteHostMaxWorkspaces {
			break
		}
		if !e.IsDir() {
			continue
		}
		raw, err := read(filepath.Join(dir, e.Name(), "workspace.json"), remoteHostMaxFileBytes)
		if err != nil {
			continue
		}
		var ws struct {
			Folder    string `json:"folder"`
			Workspace string `json:"workspace"`
		}
		if json.Unmarshal(raw, &ws) != nil {
			continue
		}
		uri := ws.Folder
		if uri == "" {
			uri = ws.Workspace
		}
		if kind, ok := vscodehost.RemoteKindOf(uri); ok && !kind.CoveredByCrossOS() {
			out[kind]++
		}
	}
	return out
}

// remoteHostsCheck renders the counts: nil when there is nothing to report.
func remoteHostsCheck(counts map[vscodehost.RemoteKind]int) (Check, bool) {
	if len(counts) == 0 {
		return Check{}, false
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		n := counts[vscodehost.RemoteKind(k)]
		unit := "workspaces"
		if n == 1 {
			unit = "workspace"
		}
		parts = append(parts, fmt.Sprintf("%s (%d %s)", k, n, unit))
	}
	return Check{
		Name:    "vscode.remote_hosts",
		Status:  StatusWarn,
		Message: "remote host not covered: " + strings.Join(parts, ", "),
		Details: []string{
			"a VS Code-family Remote window on these hosts runs its agent on another machine or container: Observer writes no hook, MCP entry or proxy route there, and 127.0.0.1 there is not this machine, so those sessions are not captured either",
			"only WSL windows are reachable (the Windows to WSL targets); SSH and container hosts are reported, not written (D7)",
		},
	}, true
}

// codexInWSLKey is the Codex extension's switch that runs its agent in WSL
// (developers.openai.com/codex/ide/settings).
const codexInWSLKey = "chatgpt.runCodexInWindowsSubsystemForLinux"

// codexInWSLSet reports whether a VS Code-family settings.json (JSON with
// comments and trailing commas) sets the switch to true. The file is parsed
// as JSONC, so a commented-out line never counts; an unparseable file
// answers false (the editor would not apply it either).
func codexInWSLSet(raw []byte) bool {
	std, err := hujson.Standardize(raw)
	if err != nil {
		return false
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(std, &settings) != nil {
		return false
	}
	var on bool
	return json.Unmarshal(settings[codexInWSLKey], &on) == nil && on
}

// checkCodexInWSL is CX-5's honest floor: when a desktop editor's user
// settings run the Codex extension's agent inside WSL, the agent reads the
// distro's ~/.codex, which a Windows daemon's codex writers do not touch
// until the codex-wsl targets (hooks and route) are switched on after live
// check WSL-4. One WARN naming the editors, none otherwise.
func checkCodexInWSL(home string, pinned bool) (Check, bool) {
	h := doctorHomeRoot(home, pinned)
	var hosts []string
	for _, ref := range vscodehost.UserDirs(h) {
		if ref.Product.Remote {
			continue
		}
		raw, err := agentconfigsvc.ReadRegularFile(filepath.Join(ref.Path, "settings.json"), 1<<20)
		if err == nil && codexInWSLSet(raw) {
			hosts = append(hosts, ref.Product.Host)
		}
	}
	return codexInWSLCheck(hosts)
}

// codexInWSLCheck renders the row for the editors that set the switch.
func codexInWSLCheck(hosts []string) (Check, bool) {
	if len(hosts) == 0 {
		return Check{}, false
	}
	return Check{
		Name:    "codex.runs_in_wsl",
		Status:  StatusWarn,
		Message: "the Codex extension runs its agent in WSL (" + strings.Join(hosts, ", ") + "): it reads the distro's ~/.codex, which Observer does not write yet",
		Details: []string{
			"codex-wsl (hooks) and the codex-wsl proxy route are " + hook.LiveGateNote("WSL-4") + "; until then that agent has no Observer hook or route",
		},
	}, true
}
