package vtcode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Store-layout names. VT Code's per-workspace store is
// `<workspace>/.vtcode/sessions/<session-id>/events.jsonl`; its global
// per-user archive is `<state dir>/sessions/<session-id>.json`.
const (
	workspaceDirName = ".vtcode"
	sessionsDirName  = "sessions"
	eventsFileName   = "events.jsonl"
	sessionPrefix    = "session-"
	autoTaskPrefix   = "auto-task-"
	logsDirName      = "logs"
)

// sessionIDPrefixes are the session-id shapes VT Code writes, grounded
// live on 0.180.2: `session-<workspace>-<UTC ts>_<n>-<pid>` for the TUI
// and `vtcode exec`, and `auto-task-<unix seconds>` for the autonomous
// `--auto` / `--full-auto` runs (their run summary prints
// "Session: auto-task-1792585041" and the store holds
// `.vtcode/sessions/auto-task-<n>/{events.jsonl,manifest.json,session.lock}`).
var sessionIDPrefixes = []string{sessionPrefix, autoTaskPrefix}

// hasSessionIDPrefix reports whether name starts with one of the
// session-id prefixes (case-insensitive).
func hasSessionIDPrefix(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sessionIDPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// defaultStateRoots returns the global session-archive directory
// (`<state dir>/sessions`) under every cross-mount-resolved home, so a
// WSL2 observer also sees the Windows-side archive under
// /mnt/c/Users/<u>/AppData/Roaming and a Windows observer the WSL one
// under \\wsl.localhost\<distro>\home\<u>.
//
// Grounded per OS from `vtcode --version` (0.180.2), which prints the
// resolved directories:
//
//   - Linux:   State directory ~/.local/state/vtcode (XDG). A native
//     $XDG_STATE_HOME override is honoured for this process only — it is
//     not meaningful for a foreign home.
//   - Windows: State directory %APPDATA%\vinhnx\vtcode\state (Roaming,
//     NOT %LOCALAPPDATA%).
//   - macOS:   not grounded (no host); no root is emitted rather than a
//     guessed Application Support path. See the package doc.
//
// Non-existent roots are kept (the watcher skips them); duplicates are
// dropped.
func defaultStateRoots() []string {
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
	if runtime.GOOS == "linux" {
		if xdg := adapter.AbsEnvRoot("XDG_STATE_HOME"); xdg != "" {
			add(filepath.Join(xdg, "vtcode", sessionsDirName))
		}
	}
	for _, h := range crossmount.AllHomes() {
		for _, r := range stateRootsForHome(h) {
			add(r)
		}
	}
	return roots
}

// stateRootsForHome returns the global session-archive directory for one
// home, keyed by the home's LOGICAL OS. An OS with no grounded layout
// yields nil.
func stateRootsForHome(h crossmount.HomeRoot) []string {
	if h.Path == "" {
		return nil
	}
	switch h.OS {
	case crossmount.OSWindows:
		return []string{filepath.Join(h.Path, "AppData", "Roaming", "vinhnx", "vtcode", "state", sessionsDirName)}
	case crossmount.OSLinux:
		return []string{filepath.Join(h.Path, ".local", "state", "vtcode", sessionsDirName)}
	default:
		return nil
	}
}

// discoverRoots builds the full watch-root set: the global state roots
// plus the per-workspace `<workspace>/.vtcode/sessions` directories named
// by every archived session's `metadata.workspace_path`.
//
// The workspace set is a SNAPSHOT taken at construction (the crush
// precedent): a workspace first used after the daemon started is not
// tailed live until the next restart. Its sessions are still captured
// when VT Code writes the global archive JSON (at session end), because
// that file is itself a session file whose parse re-reads the workspace
// events.jsonl — see Adapter.ParseSessionFile.
func discoverRoots() []string {
	state := defaultStateRoots()
	roots := append([]string(nil), state...)
	seen := map[string]struct{}{}
	for _, r := range roots {
		seen[r] = struct{}{}
	}
	for _, sr := range state {
		for _, ws := range workspaceSessionDirs(sr) {
			if _, ok := seen[ws]; ok {
				continue
			}
			seen[ws] = struct{}{}
			roots = append(roots, ws)
		}
	}
	return roots
}

// workspaceSessionDirs lists the global archive JSONs in stateRoot and
// returns each one's `<workspace>/.vtcode/sessions` directory, resolved
// for this process. Best-effort: unreadable entries are skipped.
func workspaceSessionDirs(stateRoot string) []string {
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() || !isArchiveName(e.Name()) {
			continue
		}
		statePath := filepath.Join(stateRoot, e.Name())
		meta, ok := readArchiveMeta(statePath)
		if !ok {
			continue
		}
		ws := resolveWorkspacePath(statePath, meta.WorkspacePath)
		if ws == "" {
			continue
		}
		dir := filepath.Clean(filepath.Join(ws, workspaceDirName, sessionsDirName))
		if _, dup := seen[dir]; dup {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out
}

// resolveWorkspacePath maps an archived `workspace_path` onto a path this
// process can open. statePath is the archive JSON the value came from: a
// POSIX workspace recorded by a WSL install and read by a Windows observer
// through `\\wsl.localhost\<distro>\...` is re-rooted under that same UNC
// distro prefix. Everything else (a Windows drive path read from WSL, a
// native path) goes through crossmount.TranslateForeignPath, whose
// never-fail contract returns unrecognised input unchanged.
func resolveWorkspacePath(statePath, ws string) string {
	ws = strings.TrimSpace(ws)
	if ws == "" {
		return ""
	}
	if strings.HasPrefix(ws, "/") {
		if prefix := wslUNCPrefix(statePath); prefix != "" {
			return prefix + strings.ReplaceAll(ws, "/", `\`)
		}
		return filepath.Clean(ws)
	}
	return filepath.Clean(crossmount.TranslateForeignPath(ws))
}

// wslUNCPrefix returns the `\\wsl.localhost\<distro>` (or `\\wsl$\<distro>`)
// prefix of p, or "" when p is not a WSL UNC path. Forward-slash spellings
// are accepted; the returned prefix uses backslashes.
func wslUNCPrefix(p string) string {
	norm := strings.ReplaceAll(p, "/", `\`)
	lower := strings.ToLower(norm)
	for _, host := range []string{`\\wsl.localhost\`, `\\wsl$\`} {
		if !strings.HasPrefix(lower, host) {
			continue
		}
		rest := norm[len(host):]
		distro, _, _ := strings.Cut(rest, `\`)
		if distro == "" {
			return ""
		}
		return norm[:len(host)] + distro
	}
	return ""
}

// archiveMeta is the subset of a global archive JSON's `metadata` object
// the adapter consumes. Discovery (readArchiveMeta) decodes only this;
// the message history is decoded by archive.go for parsing.
type archiveMeta struct {
	WorkspacePath   string `json:"workspace_path"`
	Model           string `json:"model"`
	Provider        string `json:"provider"`
	ReasoningEffort string `json:"reasoning_effort"`
}

// readArchiveMeta decodes the `metadata` object of a global archive JSON.
func readArchiveMeta(path string) (archiveMeta, bool) {
	b, err := os.ReadFile(path) //nolint:gosec // path is an archive JSON under a watch root
	if err != nil {
		return archiveMeta{}, false
	}
	var f struct {
		Metadata archiveMeta `json:"metadata"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return archiveMeta{}, false
	}
	return f.Metadata, true
}

// isArchiveName reports whether name has the global archive's
// `<session-id>.json` shape. (No `auto-task-*` archive was observed; the
// prefix is accepted so one is picked up if a later build writes it.)
func isArchiveName(name string) bool {
	return hasSessionIDPrefix(name) && strings.HasSuffix(strings.ToLower(name), ".json")
}

// isWorkspaceSessionsRoot reports whether root is a per-workspace
// `.vtcode/sessions` directory rather than a global archive directory.
func isWorkspaceSessionsRoot(root string) bool {
	clean := filepath.Clean(root)
	return strings.EqualFold(filepath.Base(clean), sessionsDirName) &&
		strings.EqualFold(filepath.Base(filepath.Dir(clean)), workspaceDirName)
}
