package gitview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// program.go lets the one git exec envelope run a git other than the host's
// own "git" on PATH (R3-86): a WSL daemon reading a checkout on a Windows
// drive runs the Windows git.exe through WSL interop, with the same -C pin,
// the same -c overrides, the same caps and timeout, and the same subcommand
// argv, because a working-tree diff across the DrvFs bridge from the WSL
// git takes tens of seconds and git.exe takes a few hundred milliseconds.
// Which program runs for which root is internal/gitroute's decision; this
// file only runs it.

// Program names the git one invocation runs, when it is not the host's own
// git on PATH. The zero value is the host's git, -C root.
type Program struct {
	// Path is the program's absolute path on this host.
	Path string
	// Dir is the repository directory spelled the way the program reads it
	// (`D:\x\y` for a Windows git), passed as -C. Empty passes root.
	Dir string
	// Interop marks a Windows program started through WSL interop. Its
	// environment crosses only through WSLENV, so the envelope names exactly
	// its own variables and the caller's extra ones there (never this
	// process's WSLENV, never GIT_ASKPASS, whose /bin/false is a Linux path),
	// and it starts in root so its working directory is a drive path.
	Interop bool
}

// binary returns the program to start and the -C directory.
func (p Program) binary(root string) (string, string) {
	bin, dir := "git", root
	if p.Path != "" {
		bin = p.Path
	}
	if p.Dir != "" {
		dir = p.Dir
	}
	return bin, dir
}

// RunReadOnlyNoLazyFetchProgram is RunReadOnlyNoLazyFetchEnv run with prog:
// the same envelope, caps and -c overrides, GIT_NO_LAZY_FETCH=1 always set.
// root is still this host's spelling of the repository: the sandbox-copy
// refusal (HostGitRefused) and, for an interop program, the working
// directory read it. A program that cannot start is ErrGitUnavailable
// (wrapped with the cause).
func RunReadOnlyNoLazyFetchProgram(ctx context.Context, root string, prog Program, maxBytes int, timeout time.Duration, extraEnv []string, args ...string) ([]byte, bool, error) {
	if maxBytes <= 0 {
		maxBytes = maxOutputBytes
	}
	if timeout <= 0 {
		timeout = perCommandTimeout
	}
	env := append(append([]string(nil), extraEnv...), noLazyFetchEnv)
	return runGitCapped(ctx, root, prog, maxBytes, timeout, env, args...)
}

// maxVersionBytes caps `git --version` output.
const maxVersionBytes = 4 << 10

// ProgramVersion runs `<prog.Path> --version` (no repository, no -C, no
// config read) within timeout and returns its first line. It is how a
// resolver confirms that a candidate is the git it expects before any
// repository is read with it.
func ProgramVersion(ctx context.Context, prog Program, timeout time.Duration) (string, error) {
	if prog.Path == "" {
		return "", errors.New("gitview.ProgramVersion: no program")
	}
	if timeout <= 0 {
		timeout = perCommandTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, prog.Path, "--version") //nolint:gosec // G204: a resolver's candidate git binary, fixed argv
	cmd.Env = append(os.Environ(), gitEnvOverrides...)
	if prog.Interop {
		cmd.Env = interopEnv(os.Environ(), interopEnvOverrides())
	}
	cmd.WaitDelay = waitDelay
	var out cappedBuffer
	out.cap = maxVersionBytes
	cmd.Stdout = &out
	cmd.Stderr = &cappedBuffer{cap: maxVersionBytes}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrGitUnavailable, prog.Path, err)
	}
	line, _, _ := bytes.Cut(out.Bytes(), []byte("\n"))
	return strings.TrimSpace(string(line)), nil
}

// interopEnvOverrides are the envelope variables a Windows git can read:
// gitEnvOverrides without GIT_ASKPASS (a Linux path; GIT_TERMINAL_PROMPT=0
// already stops any prompt).
func interopEnvOverrides() []string {
	out := make([]string, 0, len(gitEnvOverrides))
	for _, kv := range gitEnvOverrides {
		if strings.HasPrefix(kv, "GIT_ASKPASS=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// interopClearedVars are the git variables an interop git.exe must never
// take from the Windows side (R3-89). A Windows program started through WSL
// interop inherits the Windows user's own environment, which this daemon
// cannot see: a user-set GIT_DIR, GIT_WORK_TREE or GIT_INDEX_FILE would point
// the read at another repository or index, GIT_CONFIG_* would inject or
// relocate configuration, GIT_EXEC_PATH would choose the helper programs, and
// GIT_EXTERNAL_DIFF would run a program. Naming a variable in WSLENV with an
// empty (or absent) Linux value UNSETS it for the Windows program (probed
// 2026-11-11: a GIT_DIR set on the Windows side reaches git.exe unless
// WSLENV names it, and an empty named value leaves it unset there), so the
// envelope names each one with an empty value. GIT_CONFIG_COUNT cleared
// disables every GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n> pair. A variable the
// caller sets explicitly (extraEnv) keeps the caller's value.
var interopClearedVars = []string{
	"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
	"GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
	"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
	"GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
	"GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS",
	"GIT_REPLACE_REF_BASE", "GIT_NO_REPLACE_OBJECTS", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE",
	"GIT_ATTR_SOURCE", "GIT_ATTR_NOSYSTEM", "GIT_QUARANTINE_PATH",
	"GIT_LITERAL_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS",
}

// interopEnv is base without its WSLENV, plus set, plus the cleared git
// variables (empty), plus a WSLENV naming exactly those: the only variables
// WSL interop hands the Windows program, and the only Windows-side ones it
// replaces. A user's WSLENV (which may forward GIT_DIR, a path translated
// with /p, or anything else) never reaches it, and a git variable the
// Windows user set does not either.
func interopEnv(base, set []string) []string {
	out := make([]string, 0, len(base)+len(set)+len(interopClearedVars)+1)
	for _, kv := range base {
		if strings.HasPrefix(kv, "WSLENV=") {
			continue
		}
		out = append(out, kv)
	}
	names := make([]string, 0, len(set)+len(interopClearedVars))
	seen := map[string]bool{}
	for _, kv := range set {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" || strings.ContainsAny(name, ":/") {
			continue
		}
		out = append(out, kv)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, name := range interopClearedVars {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name+"=")
		names = append(names, name)
	}
	return append(out, "WSLENV="+strings.Join(names, ":"))
}
