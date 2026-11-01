//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"strings"
)

// D-MU4: inside a Seatbelt box whose home is blinded (home_mode tmpfs) the
// profile denies ~/.gitconfig and ~/.config/git, so every git command
// failed with "unable to access '/Users/<u>/.gitconfig': Operation not
// permitted" (rc 128) on any Mac that has one. bwrap's tmpfs home shows no
// such file, so git there runs with no global config and no global ignore
// file. Seatbelt matches that view: GIT_CONFIG_GLOBAL points at a file in
// the run's TMPDIR, which sets core.excludesFile to an empty file beside
// it, and core.attributesFile to an empty file as well, so git never opens
// the user's global config or its default ignore and attributes paths
// (~/.config/git/ignore, ~/.config/git/attributes; MACUSER merge L3). The
// user's files are deliberately not
// granted read-only instead: a global git config can carry credential
// helpers and tokens in url rewrites, and .gitconfig is on the sandbox's
// never-bind list (orgcontract/sandboxbinds.go). XDG_CONFIG_HOME is left
// alone because other tools read their bound configs through it.

// seatbeltGitConfigName and seatbeltGitIgnoreName are the run-local files.
const (
	seatbeltGitConfigName     = "observer-gitconfig"
	seatbeltGitIgnoreName     = "observer-gitignore"
	seatbeltGitAttributesName = "observer-gitattributes"
)

// seatbeltRunFile is one file the helper writes into the run's TMPDIR
// before the agent starts.
type seatbeltRunFile struct {
	Path    string
	Content string
}

// seatbeltWithGitIsolation returns env with GIT_CONFIG_GLOBAL pointing at
// the run-local git config (any inherited value replaced) and the files
// that config names. tempDir is the run's TMPDIR.
func seatbeltWithGitIsolation(env []string, tempDir string) ([]string, []seatbeltRunFile) {
	cfg := filepath.Join(tempDir, seatbeltGitConfigName)
	ignore := filepath.Join(tempDir, seatbeltGitIgnoreName)
	attrs := filepath.Join(tempDir, seatbeltGitAttributesName)
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if k, _, _ := cutEnv(kv); k == "GIT_CONFIG_GLOBAL" {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "GIT_CONFIG_GLOBAL="+cfg)
	files := []seatbeltRunFile{
		{Path: cfg, Content: "[core]\n\texcludesFile = " + gitConfigQuote(ignore) + "\n\tattributesFile = " + gitConfigQuote(attrs) + "\n"},
		{Path: ignore, Content: ""},
		{Path: attrs, Content: ""},
	}
	return out, files
}

// gitConfigQuote quotes a path as a git config value.
func gitConfigQuote(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(p) + `"`
}
