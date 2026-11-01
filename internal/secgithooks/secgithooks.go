package secgithooks

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

// Hook is one hook Observer manages.
type Hook struct {
	// Name is the hook file name.
	Name string
	// Verb is the `observer security` verb the block runs.
	Verb string
	// Stdin marks a hook git feeds on stdin (pre-push: the refs being
	// pushed). The block saves it to a temporary file, feeds the check from
	// it and restores it for the rest of the hook, so the developer's own
	// hook below (and git-lfs's) still reads every line.
	Stdin bool
}

// Hooks are the managed hooks.
var Hooks = []Hook{
	{Name: "pre-commit", Verb: "precommit"},
	{Name: "pre-push", Verb: "prepush", Stdin: true},
}

// RefuseExit is the exit status `observer security precommit | prepush`
// returns for a refusal (a blocking finding), and the only one that stops
// the hook (lane sec-gate2, decision log P-025): observer's generic error is
// 1 (an unknown verb on an older binary, a config error), and every status
// but this one fails open.
const RefuseExit = 43

// The block markers. The begin line names how to remove the block, so a
// developer reading the hook knows what wrote it.
const (
	beginMarker = "# >>> superbased-observer security githook (remove with: observer security githooks uninstall) >>>"
	endMarker   = "# <<< superbased-observer security githook <<<"
	shebang     = "#!/bin/sh"
)

// ErrNotShell refuses a hook that is not a shell script.
var ErrNotShell = errors.New("the existing hook is not a shell script, so Observer will not edit it; chain `observer security precommit` from it yourself")

// shellInterpreters are the interpreters a hook's first line may name for
// the block to be inserted.
var shellInterpreters = []string{"sh", "bash", "dash", "zsh", "ksh"}

// isShellScript reports whether text starts with a shebang naming a POSIX
// shell (directly or through env).
func isShellScript(text string) bool {
	line, _, _ := strings.Cut(text, "\n")
	line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if !strings.HasPrefix(line, "#!") {
		return false
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return false
	}
	interp := filepath.Base(fields[0])
	if interp == "env" && len(fields) > 1 {
		interp = fields[1]
	}
	for _, s := range shellInterpreters {
		if interp == s {
			return true
		}
	}
	return false
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// Block renders the marked block for hook h, running the observer binary
// at observerPath. Only RefuseExit (a blocking finding) stops the hook: the
// status is caught with `rc=0; cmd || rc=$?`, so a `sh -e` hook does not
// abort on another status, and the block ends with an if (status 0 when it
// does not refuse), so a hook that is only this block exits 0. A Stdin
// hook's block saves git's stdin to a temporary file, feeds the check from
// it and restores it with `exec <"$tmp"` for the rest of the hook; when no
// temporary file can be made the check is skipped and stdin left alone.
func Block(h Hook, observerPath string) string {
	var b strings.Builder
	b.WriteString(beginMarker + "\n")
	b.WriteString("sbo_obs=" + shellQuote(observerPath) + "\n")
	b.WriteString("if [ -x \"$sbo_obs\" ]; then\n")
	refuse := "if [ \"$sbo_rc\" -eq " + strconv.Itoa(RefuseExit) + " ]; then exit 1; fi\n"
	if h.Stdin {
		b.WriteString("  sbo_in=$(mktemp \"${TMPDIR:-/tmp}/sbo-" + h.Name + ".XXXXXX\" 2>/dev/null) || sbo_in=\n")
		b.WriteString("  if [ -n \"$sbo_in\" ] && cat >\"$sbo_in\"; then\n")
		b.WriteString("    sbo_rc=0\n")
		b.WriteString("    \"$sbo_obs\" security " + h.Verb + " \"$@\" <\"$sbo_in\" || sbo_rc=$?\n")
		b.WriteString("    exec <\"$sbo_in\"\n")
		b.WriteString("    rm -f \"$sbo_in\" 2>/dev/null || :\n")
		b.WriteString("    " + refuse)
		b.WriteString("  fi\n")
	} else {
		b.WriteString("  sbo_rc=0\n")
		b.WriteString("  \"$sbo_obs\" security " + h.Verb + " \"$@\" || sbo_rc=$?\n")
		b.WriteString("  " + refuse)
	}
	b.WriteString("fi\n")
	b.WriteString(endMarker + "\n")
	return b.String()
}

// Has reports whether text carries Observer's block.
func Has(text string) bool {
	return strings.Contains(text, beginMarker) && strings.Contains(text, endMarker)
}

// Current reports whether text carries Observer's block for hook h exactly
// as this release renders it (for the observer path the block names). An
// older rendering, a previous release's exit code or stdin handling that
// can fail open or swallow git's stdin, or a hand-edited block, is not
// current: a status shows it as outdated, never installed, until an
// install replaces it (lane sec-gate3 milestone 2d).
func Current(text string, h Hook) bool {
	i, end, ok := blockSpan(text)
	if !ok {
		return false
	}
	block := text[i:end]
	path, ok := blockObserverPath(block)
	if !ok {
		return false
	}
	want := Block(h, path)
	return strings.TrimSuffix(block, "\n") == strings.TrimSuffix(want, "\n")
}

// blockObserverPath reads the observer path a block names on its
// `sbo_obs='...'` line (shellQuote's form), false when the line is missing
// or not in that form.
func blockObserverPath(block string) (string, bool) {
	for _, line := range strings.Split(block, "\n") {
		v, ok := strings.CutPrefix(line, "sbo_obs=")
		if !ok {
			continue
		}
		if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
			return "", false
		}
		inner := strings.ReplaceAll(v[1:len(v)-1], `'"'"'`, "'")
		if shellQuote(inner) != v {
			return "", false
		}
		return inner, true
	}
	return "", false
}

// Install returns the hook text with Observer's block: a new file (shebang
// and block) when existing is empty, the block right after the shebang of
// an existing shell hook otherwise (so it runs first and the rest still
// runs), the text unchanged when the block is already there. A hook that
// is not a shell script is ErrNotShell.
func Install(existing, block string) (string, error) {
	if i, end, ok := blockSpan(existing); ok {
		// Already there: an older rendering (a previous release's exit
		// code or stdin handling) is replaced in place, so an upgrade does
		// not leave a block that can no longer refuse.
		return existing[:i] + block + existing[end:], nil
	}
	if existing == "" {
		return shebang + "\n" + block, nil
	}
	if !isShellScript(existing) {
		return "", ErrNotShell
	}
	first, rest, hasRest := strings.Cut(existing, "\n")
	if !hasRest {
		return first + "\n" + block, nil
	}
	return first + "\n" + block + rest, nil
}

// Remove returns the hook text without Observer's block, byte-exact: the
// text as it was before Install. empty reports that nothing but the
// shebang Observer wrote is left, so the caller removes the file. A text
// without the block is returned unchanged.
func Remove(text string) (out string, empty bool) {
	i, end, ok := blockSpan(text)
	if !ok {
		return text, false
	}
	out = text[:i] + text[end:]
	return out, strings.TrimSpace(out) == shebang
}

// blockSpan is where Observer's block sits in text: from its begin marker
// to just past its end marker's newline. ok is false without both markers.
func blockSpan(text string) (start, end int, ok bool) {
	i := strings.Index(text, beginMarker)
	if i < 0 {
		return 0, 0, false
	}
	j := strings.Index(text[i:], endMarker)
	if j < 0 {
		return 0, 0, false
	}
	end = i + j + len(endMarker)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return i, end, true
}

// HooksDirRefusal says why a hooks directory is refused, "" when it may be
// written: it must be inside the repository's working tree or its git
// directory. A core.hooksPath pointing anywhere else (a shared directory,
// a hook manager's global store) is refused with a reason, never written.
func HooksDirRefusal(hooksDir, worktree, gitDir string) string {
	if !filepath.IsAbs(hooksDir) {
		return "git did not report an absolute hooks directory"
	}
	for _, base := range []string{worktree, gitDir} {
		if base == "" {
			continue
		}
		rel, err := filepath.Rel(base, hooksDir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
	}
	return "core.hooksPath points outside this repository (" + hooksDir + "); Observer installs hooks only inside it. Point core.hooksPath into the repository or chain `observer security precommit` from your hook manager"
}
