//go:build !sbo_omit_security

package secsvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secgithooks"
)

// The opt-in local git hooks' file operations (component
// security.githooks; security pillar plan section 5.8, ledger SECP-14;
// lane sec-c3), shared by `observer security githooks` and the Code
// security page: where a repository's hooks are, whether Observer may
// write there, and the install, uninstall and status over the pure
// internal/secgithooks text edits. Git runs only through the injected
// read-only envelope.

// githookGitTimeout bounds each git call of the install flow.
const githookGitTimeout = 10 * time.Second

// GithookTarget is where a repository's hooks go.
type GithookTarget struct {
	Root     string
	HooksDir string
	// Refusal says why the directory is not written ("" when it may be).
	Refusal string
}

// githookConfigScopes are the config scopes read for core.hooksPath, in
// git's precedence order. The read-only envelope forces core.hookspath
// empty on its own command line (so a repository's hooks never run from a
// read), and a scoped `git config` read ignores that override.
var githookConfigScopes = []string{"--worktree", "--local", "--global", "--system"}

// ResolveGithookTarget finds where a repository's hooks are (a
// core.hooksPath from the first config scope that sets one, relative to
// the working tree; else the common git directory's hooks, shared by every
// worktree) and whether Observer may write there.
func ResolveGithookTarget(ctx context.Context, run GitRunner, root string) (GithookTarget, error) {
	t := GithookTarget{Root: root}
	git := func(args ...string) (string, error) {
		out, _, err := run(ctx, root, 4096, githookGitTimeout, args...)
		return strings.TrimSpace(string(out)), err
	}
	gitDir, err := git("rev-parse", "--absolute-git-dir")
	if err != nil {
		return t, fmt.Errorf("%s: not a git repository git can read: %w", root, err)
	}
	common, err := git("rev-parse", "--git-common-dir")
	if err != nil || common == "" {
		common = gitDir
	} else if !filepath.IsAbs(common) {
		common = filepath.Join(root, common)
	}
	dir := filepath.Join(common, "hooks")
	for _, scope := range githookConfigScopes {
		v, err := git("config", scope, "--get", "core.hooksPath")
		if err != nil || v == "" {
			continue
		}
		if strings.HasPrefix(v, "~/") {
			if home, herr := os.UserHomeDir(); herr == nil {
				v = filepath.Join(home, v[2:])
			}
		}
		if !filepath.IsAbs(v) {
			v = filepath.Join(root, v)
		}
		dir = v
		break
	}
	t.HooksDir = filepath.Clean(dir)
	t.Refusal = secgithooks.HooksDirRefusal(t.HooksDir, root, filepath.Clean(common))
	return t, nil
}

// GithookStatus is one hook's state.
type GithookStatus struct {
	Hook      string `json:"hook"`
	Installed bool   `json:"installed"`
	// Outdated reports a block an earlier release wrote (or one edited by
	// hand), which may fail open or swallow git's stdin: Installed is
	// false, and an install replaces it in place.
	Outdated bool `json:"outdated"`
	// Foreign reports an existing hook Observer chains to (or would).
	Foreign bool `json:"foreign"`
}

// readHook reads one hook file, refusing a symlink or a non-regular file
// (Observer never writes through a link).
func readHook(path string) (text string, mode fs.FileMode, exists bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", 0o755, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, true, fmt.Errorf("%s is not a regular file (a link or a directory); Observer will not edit it", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a hook file inside the repository's own hooks directory, checked above.
	if err != nil {
		return "", 0, true, err
	}
	return string(b), fi.Mode().Perm(), true, nil
}

// writeHook writes a hook atomically (a new temporary file beside it, then
// a rename), keeping its mode and making it executable. The temporary file
// is created exclusively under a random name, so a link planted at a
// predictable name in a hooks directory that is repository content (a
// husky-style core.hooksPath) is never written through (RB1 sweep finding
// P4).
func writeHook(path, text string, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".observer-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(text)
	if werr == nil {
		werr = f.Chmod(mode | 0o700)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// GithooksStatus reports each managed hook's state.
func GithooksStatus(t GithookTarget) ([]GithookStatus, error) {
	var out []GithookStatus
	for _, h := range secgithooks.Hooks {
		text, _, exists, err := readHook(filepath.Join(t.HooksDir, h.Name))
		if err != nil {
			return nil, err
		}
		has := secgithooks.Has(text)
		current := has && secgithooks.Current(text, h)
		rest, empty := secgithooks.Remove(text)
		out = append(out, GithookStatus{Hook: h.Name, Installed: current, Outdated: has && !current, Foreign: exists && !empty && strings.TrimSpace(rest) != ""})
	}
	return out, nil
}

// InstallGithooks writes Observer's block into both hooks.
func InstallGithooks(t GithookTarget, observerPath string) error {
	if t.Refusal != "" {
		return errors.New(t.Refusal)
	}
	if err := os.MkdirAll(t.HooksDir, 0o755); err != nil {
		return err
	}
	// Plan both first, so a refused second hook leaves the first unwritten.
	type plan struct {
		path, text string
		mode       fs.FileMode
	}
	var plans []plan
	for _, h := range secgithooks.Hooks {
		path := filepath.Join(t.HooksDir, h.Name)
		existing, mode, _, err := readHook(path)
		if err != nil {
			return err
		}
		next, err := secgithooks.Install(existing, secgithooks.Block(h, observerPath))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if next != existing {
			plans = append(plans, plan{path, next, mode})
		}
	}
	for _, p := range plans {
		if err := writeHook(p.path, p.text, p.mode); err != nil {
			return err
		}
	}
	return nil
}

// UninstallGithooks takes Observer's block out of both hooks, byte-exact,
// and removes a hook file Observer created.
func UninstallGithooks(t GithookTarget) (removed int, err error) {
	for _, h := range secgithooks.Hooks {
		path := filepath.Join(t.HooksDir, h.Name)
		text, mode, exists, err := readHook(path)
		if err != nil {
			return removed, err
		}
		if !exists || !secgithooks.Has(text) {
			continue
		}
		rest, empty := secgithooks.Remove(text)
		if empty {
			err = os.Remove(path)
		} else {
			err = writeHook(path, rest, mode)
		}
		if err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// The AI change record writers (component security.provenance, security
// pillar plan 7.10; lane sec-f2a): the git note under secchange.NotesRef
// and the prepare-commit-msg trailer block, both only in a repository a
// person consented for. Neither rewrites history: a note is a separate
// ref, and the trailer step runs while a commit is being made.

// GitWriter runs one git invocation that writes (a note), at root, with
// stdin, under timeout. The cmd layer injects it; this package starts no
// process.
type GitWriter func(ctx context.Context, root string, stdin []byte, timeout time.Duration, args ...string) ([]byte, error)

// WriteChangeNote appends a change record envelope to the commit's note
// under secchange.NotesRef. written is false when the note already holds
// it. The read goes through the read-only runner; only the append writes.
func WriteChangeNote(ctx context.Context, read GitRunner, write GitWriter, root, sha string, envelope []byte) (written bool, err error) {
	if !isCommitSHA(sha) {
		return false, fmt.Errorf("secsvc.WriteChangeNote: %q is not a commit id", sha)
	}
	existing, _, rerr := read(ctx, root, 1<<20, githookGitTimeout, "notes", "--ref="+secchange.NotesRef, "show", sha)
	if rerr == nil && secchange.NoteHas(existing, envelope) {
		return false, nil
	}
	body := append(bytes.TrimSpace(envelope), '\n')
	if _, err := write(ctx, root, body, githookGitTimeout, "notes", "--ref="+secchange.NotesRef, "append", "-F", "-", sha); err != nil {
		return false, fmt.Errorf("secsvc.WriteChangeNote: %w", err)
	}
	return true, nil
}

// ReadChangeNote returns the commit's note body under secchange.NotesRef,
// nil when it has none.
func ReadChangeNote(ctx context.Context, read GitRunner, root, sha string) []byte {
	if !isCommitSHA(sha) {
		return nil
	}
	out, _, err := read(ctx, root, 1<<20, githookGitTimeout, "notes", "--ref="+secchange.NotesRef, "show", sha)
	if err != nil {
		return nil
	}
	return out
}

func isCommitSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// TrailerHookInstalled reports whether the repository's prepare-commit-msg
// hook carries the trailer block.
func TrailerHookInstalled(t GithookTarget) (bool, error) {
	text, _, _, err := readHook(filepath.Join(t.HooksDir, secchange.TrailerHookName))
	if err != nil {
		return false, err
	}
	return secchange.HasTrailerBlock(text), nil
}

// InstallTrailerHook writes the trailer block into the repository's
// prepare-commit-msg hook (after an existing shell hook's shebang, or as a
// new hook).
func InstallTrailerHook(t GithookTarget, observerPath string) error {
	if t.Refusal != "" {
		return errors.New(t.Refusal)
	}
	if err := os.MkdirAll(t.HooksDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(t.HooksDir, secchange.TrailerHookName)
	existing, mode, _, err := readHook(path)
	if err != nil {
		return err
	}
	next, err := secchange.InstallTrailerBlock(existing, secchange.TrailerBlock(observerPath))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if next == existing {
		return nil
	}
	return writeHook(path, next, mode)
}

// UninstallTrailerHook takes the trailer block out, byte-exact, and
// removes a hook file Observer created. removed is false when there was no
// block.
func UninstallTrailerHook(t GithookTarget) (removed bool, err error) {
	path := filepath.Join(t.HooksDir, secchange.TrailerHookName)
	text, mode, exists, err := readHook(path)
	if err != nil || !exists || !secchange.HasTrailerBlock(text) {
		return false, err
	}
	rest, empty := secchange.RemoveTrailerBlock(text)
	if empty {
		return true, os.Remove(path)
	}
	return true, writeHook(path, rest, mode)
}
