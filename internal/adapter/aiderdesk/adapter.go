package aiderdesk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// ToolName is the tool id the adapter will write once it is registered.
// It lives here, not in internal/models, while the package is
// unregistered (a models.Tool* constant is a capability claim).
const ToolName = "aider-desk"

// fixtureREADME is named in the parse refusal.
const fixtureREADME = "testdata/aiderdesk/README.md"

// The store's names, from the vendor bundle (doc.go).
const (
	// dirName is the default AIDER_DESK_DIR segment.
	dirName = ".aider-desk"
	// homeEnv relocates the home directory whole.
	homeEnv = "AIDER_DESK_HOME_DIR"
	// dirEnv renames the ".aider-desk" segment (AIDER_DESK_DIR), under
	// the os home when homeEnv is unset and under every project.
	dirEnv = "AIDER_DESK_DIR"
	// mcpServersFile is the MCP servers file in the home and in a
	// project's .aider-desk directory.
	mcpServersFile = "mcp-servers.json"
	// tasksDir holds one directory per task under <project>/.aider-desk.
	tasksDir = "tasks"
	// contextFile is a task's conversation file.
	contextFile = "context.json"
)

var _ adapter.Adapter = (*Adapter)(nil)

// Adapter is the skeleton adapter.Adapter for AiderDesk task contexts. It
// is not registered anywhere.
type Adapter struct {
	roots []string
}

// New returns an adapter watching the tasks directories of the given
// project roots (AiderDesk keeps tasks inside each project, not under a
// home; the project list lives in the app's settings store, which holds
// provider keys and is never read, so discovery is the caller's).
func New(projectRoots []string) *Adapter {
	return &Adapter{roots: TaskRoots(projectRoots)}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return ToolName }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return append([]string(nil), a.roots...) }

// TaskRoots returns <project>/.aider-desk/tasks for each project root,
// deduplicated, kept whether or not it exists.
func TaskRoots(projectRoots []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range projectRoots {
		if strings.TrimSpace(p) == "" {
			continue
		}
		r := filepath.Join(filepath.Clean(p), dirName, tasksDir)
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// IsSessionFile implements adapter.Adapter: exactly
// <root>/<task id>/context.json under a watch root (never a
// context.pre-compaction.NNN.json snapshot, a task's settings.json or
// todos.json, or a file nested deeper, such as a task worktree's).
func (a *Adapter) IsSessionFile(path string) bool {
	if filepath.Base(path) != contextFile {
		return false
	}
	task := filepath.Dir(path)
	return adapter.UnderAnyWatchRoot(path, a.roots) && containsString(a.roots, filepath.Dir(task))
}

// ParseSessionFile implements adapter.Adapter by refusing to guess: no
// event, one warning, and the offset at the file's size so the watcher
// never spins on it.
func (a *Adapter) ParseSessionFile(_ context.Context, path string, _ int64) (adapter.ParseResult, error) {
	var size int64
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	return adapter.ParseResult{
		NewOffset: size,
		Warnings:  []string{fmt.Sprintf("aiderdesk: %s not parsed: the AiderDesk task context shape is grounded from vendor source only (live check LCR-60); see %s", filepath.Base(path), fixtureREADME)},
	}, nil
}

// HomeDir is AiderDesk's home directory, as the vendor resolves it
// (AIDER_DESK_HOME_DIR = env || join(os home, AIDER_DESK_DIR), with
// AIDER_DESK_DIR = env || ".aider-desk"): AIDER_DESK_HOME_DIR when it holds
// an absolute path, else <home>/<AIDER_DESK_DIR or .aider-desk>. A relative
// AIDER_DESK_HOME_DIR is an error (AiderDesk would read it against its own
// working directory), and so is an AIDER_DESK_DIR that climbs out of the
// home or a missing home. getenv is injected (nil reads nothing). Errors
// name the variable, never its value.
func HomeDir(home string, getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if v := strings.TrimSpace(getenv(homeEnv)); v != "" {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("aiderdesk: %s is set to a relative path, which AiderDesk reads against its own working directory; nothing is resolved (set an absolute path)", homeEnv)
		}
		return filepath.Clean(v), nil
	}
	if home == "" {
		return "", fmt.Errorf("aiderdesk: no home directory")
	}
	seg, err := DirSegment(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, seg), nil
}

// DirSegment is the AIDER_DESK_DIR segment (default ".aider-desk"). The
// vendor joins it onto the home (and each project) with path.join, so a
// leading separator is kept as part of the join; a value with a ".."
// element would leave the home and is refused.
func DirSegment(getenv func(string) string) (string, error) {
	v := ""
	if getenv != nil {
		v = strings.TrimSpace(getenv(dirEnv))
	}
	if v == "" {
		return dirName, nil
	}
	for _, el := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if el == ".." {
			return "", fmt.Errorf("aiderdesk: %s climbs out of the home directory; nothing is resolved", dirEnv)
		}
	}
	return filepath.Clean(strings.TrimLeft(filepath.FromSlash(v), `/\`)), nil
}

// MCPServersPath is the global MCP servers file under HomeDir.
func MCPServersPath(home string, getenv func(string) string) (string, error) {
	d, err := HomeDir(home, getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, mcpServersFile), nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
